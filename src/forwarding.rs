//! Port forwarding (mirrors the forwarding functions of the Go client:
//! `ForwardTCP`/`ForwardUDP`, `ReverseTCP`/`ReverseUDP`, `DynamicForward` and
//! the reverse-forwarding pumps).
//!
//! Local forwarding (`-L`) accepts connections/datagrams on a local socket and
//! opens one `direct-tcp`/`direct-udp` channel per connection/peer. Reverse
//! forwarding (`-R`) requests the forwarding from the server; the channels the
//! server then opens (`open-request-reverse-tcp,<dest>`,
//! `open-request-reverse-udp,<local>,<remote>`) are served automatically by the
//! conversation's stream dispatcher (see [`crate::conversation`]). Dynamic
//! forwarding (`-D`) binds a minimal SOCKS5 proxy (CONNECT only, no
//! authentication) and tunnels the requested connections through
//! `direct-tcp` channels.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::channel::Channel;
use crate::conversation::ConversationInner;
use crate::error::Result;
use crate::message::{Message, SshDataType};

/// How long the local socket may still be read after the channel direction
/// ended, so that a half-closed connection keeps working while the peer
/// answers, without letting a never-closing socket park the forwarding
/// forever (mirrors `forwardingDrainTimeout`).
pub(crate) const FORWARDING_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// How many distinct sources may have a channel open on one UDP forwarding at
/// the same time (mirrors `maxUDPForwardPeers`).
const MAX_UDP_FORWARD_PEERS: usize = 1000;

/// The size of the buffers reading UDP datagrams (mirrors the Go client's
/// 1500-byte buffers).
const UDP_BUF_SIZE: usize = 1500;

/// How the two directions of a TCP forwarding pump interact when one of them
/// ends (mirrors the Go client's forwarding pumps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPumpMode {
    /// Local forward (`forwardTCPInBackground`): the channel ending half-closes
    /// the socket, and the socket direction drains for
    /// [`FORWARDING_DRAIN_TIMEOUT`].
    Forward,
    /// Reverse forward (`forwardReverseTCPInBackground`): the channel ending
    /// half-closes the socket; the socket direction runs until the socket ends.
    Reverse,
    /// SOCKS5 tunnel (`serveSocks5Connect`): the first direction to end closes
    /// everything.
    Tunnel,
}

/// Pump data between a channel and a TCP socket, in both directions, until
/// the connection ends (mirrors the Go client's `forwardTCPInBackground`,
/// `forwardReverseTCPInBackground` and `serveSocks5Connect`).
async fn pump_tcp(channel: Channel, socket: TcpStream, mode: TcpPumpMode) {
    let (mut socket_read, mut socket_write) = socket.into_split();
    // Set when either direction ends.
    let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);

    // channel -> socket
    let channel1 = channel.clone();
    let done_tx1 = done_tx.clone();
    let mut done_rx1 = done_rx.clone();
    let to_socket = tokio::spawn(async move {
        loop {
            let msg = if mode == TcpPumpMode::Tunnel {
                // the first direction to end closes everything
                tokio::select! {
                    _ = done_rx1.changed() => break,
                    msg = channel1.next_message() => msg,
                }
            } else {
                channel1.next_message().await
            };
            match msg {
                Ok(Some(Message::Data(m))) if m.data_type == SshDataType::None => {
                    if socket_write.write_all(&m.data).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {}  // other messages are ignored
                Ok(None) => break, // the channel ended
                Err(_) => break,
            }
        }
        // half-close the socket: the peer may still have an answer on the way
        let _ = socket_write.shutdown().await;
        let _ = done_tx1.send(true);
    });

    // socket -> channel
    let channel2 = channel.clone();
    let mut drain_deadline: Option<tokio::time::Instant> = None;
    let mut buf = vec![0u8; channel2.max_packet_size().max(1024) as usize];
    let socket_direction = async {
        loop {
            let res = if let Some(deadline) = drain_deadline {
                // the other direction ended: drain what is left, bounded
                match tokio::time::timeout_at(deadline, socket_read.read(&mut buf)).await {
                    Ok(res) => res,
                    Err(_) => break, // the drain deadline expired
                }
            } else {
                let read = socket_read.read(&mut buf);
                tokio::pin!(read);
                tokio::select! {
                    _ = done_rx.changed() => match mode {
                        TcpPumpMode::Tunnel => break, // the first direction to end closes everything
                        TcpPumpMode::Forward => {
                            drain_deadline =
                                Some(tokio::time::Instant::now() + FORWARDING_DRAIN_TIMEOUT);
                            continue;
                        }
                        TcpPumpMode::Reverse => continue, // run until the socket ends
                    },
                    res = &mut read => res,
                }
            };
            match res {
                Ok(0) => break, // the socket ended
                Ok(n) => {
                    if channel2
                        .write_data(&buf[..n], SshDataType::None)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    socket_direction.await;
    // the socket direction ended: finish the channel (a FIN) and signal the
    // other direction
    channel2.close();
    let _ = done_tx.send(true);

    let _ = tokio::join!(to_socket);
    // both halves are dropped here: the socket is fully closed
}

/// Pump data between a reverse-forwarding channel and the local TCP socket it
/// was opened for (mirrors the Go client's `forwardReverseTCPInBackground`).
pub(crate) async fn pump_reverse_tcp(channel: Channel, socket: TcpStream) {
    pump_tcp(channel, socket, TcpPumpMode::Reverse).await
}

/// Pump datagrams between a reverse-forwarding channel and the connected UDP
/// socket it was opened for (mirrors the Go client's
/// `forwardReverseUDPInBackground`).
pub(crate) async fn pump_reverse_udp(channel: Channel, socket: UdpSocket) {
    let socket = Arc::new(socket);
    // channel datagrams -> socket
    let channel1 = channel.clone();
    let socket1 = socket.clone();
    let to_socket = tokio::spawn(async move {
        while let Ok(Some(datagram)) = channel1.receive_datagram().await {
            if socket1.send(&datagram).await.is_err() {
                break;
            }
        }
    });
    // socket -> channel datagrams
    let channel2 = channel.clone();
    let socket2 = socket.clone();
    let to_channel = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        while let Ok(n) = socket2.recv(&mut buf).await {
            if channel2.send_datagram(&buf[..n]).await.is_err() {
                break;
            }
        }
        channel2.close();
    });
    let _ = tokio::join!(to_socket, to_channel);
}

/// Forward TCP connections arriving on `local` to `remote` (mirrors the Go
/// client's `ForwardTCP`). Returns the address the listener is bound to.
pub(crate) async fn forward_tcp(
    conv: &Arc<ConversationInner>,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(local).await?;
    let bound = listener.local_addr()?;
    let conv2 = conv.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _peer) = tokio::select! {
                _ = conv2.closed.cancelled() => break,
                res = listener.accept() => match res {
                    Ok(v) => v,
                    Err(_) => break, // the listener is closed
                },
            };
            let conv3 = conv2.clone();
            tokio::spawn(async move {
                match conv3.open_tcp_forwarding_channel(remote).await {
                    Ok(channel) => pump_tcp(channel, socket, TcpPumpMode::Forward).await,
                    Err(e) => {
                        // the session cannot carry a tunnel any more: drop the
                        // pending connection instead of leaving it hanging
                        tracing::debug!("could not open a TCP forwarding channel to {remote}: {e}");
                    }
                }
            });
        }
    });
    Ok(bound)
}

/// Forward UDP datagrams arriving on `local` to `remote` (mirrors the Go
/// client's `ForwardUDP`). One channel per source address, bounded. Returns
/// the address the socket is bound to.
pub(crate) async fn forward_udp(
    conv: &Arc<ConversationInner>,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<SocketAddr> {
    let socket = Arc::new(UdpSocket::bind(local).await?);
    let bound = socket.local_addr()?;
    let peers: Arc<std::sync::Mutex<HashMap<SocketAddr, Channel>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let conv2 = conv.clone();
    let socket2 = socket.clone();
    let peers2 = peers.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        loop {
            let (n, src) = tokio::select! {
                _ = conv2.closed.cancelled() => break,
                res = socket2.recv_from(&mut buf) => match res {
                    Ok(v) => v,
                    Err(_) => break,
                },
            };
            // one channel per source address; the table is only locked for
            // short, synchronous sections (never across an await)
            let existing = peers2.lock().unwrap().get(&src).cloned();
            let channel = match existing {
                Some(channel) => channel,
                None => {
                    // open a new channel for this peer
                    let channel = match conv2.open_udp_forwarding_channel(remote).await {
                        Ok(channel) => channel,
                        Err(e) => {
                            // the session cannot carry a tunnel any more
                            tracing::debug!(
                                "could not open a UDP forwarding channel to {remote}: {e}"
                            );
                            break;
                        }
                    };
                    let mut peers = peers2.lock().unwrap();
                    if peers.len() >= MAX_UDP_FORWARD_PEERS {
                        // bounded: a peer which goes away quietly is never
                        // noticed, and an unbounded table is memory the
                        // network gets to ask for and keep
                        drop(peers);
                        channel.close();
                        continue;
                    }
                    // the datagrams coming back on the channel are sent back
                    // to the peer they came from
                    let socket3 = socket2.clone();
                    let peers3 = peers2.clone();
                    let channel2 = channel.clone();
                    tokio::spawn(async move {
                        while let Ok(Some(datagram)) = channel2.receive_datagram().await {
                            if socket3.send_to(&datagram, src).await.is_err() {
                                break;
                            }
                        }
                        // the peer may come back later and get a channel again
                        peers3.lock().unwrap().remove(&src);
                    });
                    peers.insert(src, channel.clone());
                    channel
                }
            };
            if channel.send_datagram(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    Ok(bound)
}

/// Bind a local SOCKS5 proxy and tunnel the connections asked for by SOCKS5
/// clients through the conversation (mirrors the Go client's `DynamicForward`).
/// Only CONNECT requests with "no authentication" are supported. Returns the
/// address the listener is bound to.
pub(crate) async fn dynamic_forward(
    conv: &Arc<ConversationInner>,
    local: SocketAddr,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(local).await?;
    let bound = listener.local_addr()?;
    let conv2 = conv.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _peer) = tokio::select! {
                _ = conv2.closed.cancelled() => break,
                res = listener.accept() => match res {
                    Ok(v) => v,
                    Err(_) => break,
                },
            };
            let conv3 = conv2.clone();
            tokio::spawn(async move {
                handle_socks5_conn(conv3, socket).await;
            });
        }
    });
    Ok(bound)
}

/// Serve one SOCKS5 client connection: negotiate "no authentication", read one
/// CONNECT request, open a `direct-tcp` channel to the target and pump the
/// tunnel (mirrors the Go client's `handleSOCKS5Conn`/`serveSocks5Connect`).
async fn handle_socks5_conn(conv: Arc<ConversationInner>, mut socket: TcpStream) {
    // greeting: VER NMETHODS METHODS...
    let mut header = [0u8; 2];
    if socket.read_exact(&mut header).await.is_err() {
        return;
    }
    if header[0] != 0x05 {
        return;
    }
    let mut methods = vec![0u8; header[1] as usize];
    if socket.read_exact(&mut methods).await.is_err() {
        return;
    }
    // only "no authentication" is offered
    if !methods.contains(&0x00) {
        let _ = socket.write_all(&[0x05, 0xff]).await;
        return;
    }
    if socket.write_all(&[0x05, 0x00]).await.is_err() {
        return;
    }

    // request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut request = [0u8; 4];
    if socket.read_exact(&mut request).await.is_err() {
        return;
    }
    if request[0] != 0x05 {
        return;
    }
    if request[1] != 0x01 {
        // only CONNECT is supported (REP = command not supported)
        let _ = socket
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }
    let host = match request[3] {
        0x01 => {
            let mut b = [0u8; 4];
            if socket.read_exact(&mut b).await.is_err() {
                return;
            }
            Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            if socket.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut domain = vec![0u8; len[0] as usize];
            if socket.read_exact(&mut domain).await.is_err() {
                return;
            }
            match String::from_utf8(domain) {
                Ok(domain) => Host::Domain(domain),
                Err(_) => {
                    // REP = address type not supported
                    let _ = socket
                        .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                }
            }
        }
        0x04 => {
            let mut b = [0u8; 16];
            if socket.read_exact(&mut b).await.is_err() {
                return;
            }
            Host::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => {
            // REP = address type not supported
            let _ = socket
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };
    let mut port_buf = [0u8; 2];
    if socket.read_exact(&mut port_buf).await.is_err() {
        return;
    }
    let port = u16::from_be_bytes(port_buf);

    // resolve the target (the Go implementation resolves FQDNs on the client
    // side, so the channel header carries an IP address)
    let target = match host {
        Host::Ip(ip) => SocketAddr::new(ip, port),
        Host::Domain(domain) => {
            let resolved = tokio::net::lookup_host((domain.as_str(), port)).await;
            match resolved.and_then(|mut addrs| {
                addrs.next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved")
                })
            }) {
                Ok(addr) => addr,
                Err(_) => {
                    // REP = host unreachable
                    let _ = socket
                        .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                }
            }
        }
    };

    let channel = match conv.open_tcp_forwarding_channel(target).await {
        Ok(channel) => channel,
        Err(_) => {
            // the session cannot carry the tunnel: answer the SOCKS client
            // instead of leaving it hanging without a response
            // (REP = host unreachable)
            let _ = socket
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };

    // success reply: VER REP RSV ATYP BND.ADDR BND.PORT, with the local address
    // of the client connection as the bound address
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    match socket.local_addr() {
        Ok(SocketAddr::V4(addr)) => {
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        _ => {
            // IPv6 (or unknown): 0.0.0.0:0, which clients ignore
            reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    if socket.write_all(&reply).await.is_err() {
        channel.close();
        return;
    }

    // the tunnel is torn down as soon as either side ends
    pump_tcp(channel, socket, TcpPumpMode::Tunnel).await;
}

/// The target of a SOCKS5 CONNECT request, before resolution.
enum Host {
    Ip(IpAddr),
    Domain(String),
}
