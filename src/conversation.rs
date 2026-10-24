//! The conversation: one QUIC connection carrying many SSH3 channels (mirrors
//! `conversation.go` in the Go implementation).
//!
//! A conversation is established by the extended CONNECT request (see
//! [`crate::h3`]); the request stream then stays open as the *conversation
//! control stream*. Its QUIC stream ID routes the conversation's datagrams
//! (`varint(controlStreamID) || varint(channelID) || payload`) and identifies
//! the conversation in every channel header.
//!
//! The conversation runs three background tasks for its whole lifetime:
//!
//! - a datagram router, dispatching incoming QUIC datagrams to channels (and
//!   queueing them, bounded, for channels which do not exist yet);
//! - a bidirectional stream dispatcher, turning incoming channel streams into
//!   [`Channel`]s: reverse-forwarding channels are confirmed and served
//!   automatically, everything else is queued for [`ConversationInner::accept_channel`];
//! - a watcher marking the conversation closed when the QUIC connection ends.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::channel::{
    self, CANCEL_READ_ERROR_CODE, Channel, ChannelInner, SSH_FRAME_TYPE, build_channel_header,
    build_forwarding_additional_bytes, build_request_reverse_additional_bytes, channel_read_limit,
    parse_channel_header, parse_reverse_tcp_dest, parse_reverse_udp_addrs,
    skip_channel_additional_bytes,
};
use crate::error::{Error, Result};
use crate::forwarding;
use crate::version::Version;
use crate::wire::{MAX_FIELD_LENGTH, SliceReader, WireReader};

/// The maximum packet size announced for channels this client opens (mirrors
/// the Go client's `30000`).
pub(crate) const DEFAULT_MAX_PACKET_SIZE: u64 = 30000;

/// The default datagram queue size of channels (mirrors the Go client's `10`).
pub(crate) const DEFAULT_DATAGRAM_QUEUE_SIZE: u64 = 10;

/// How many channels may have datagrams waiting for them in one conversation
/// (mirrors `maxDanglingDatagramQueues`).
const MAX_DANGLING_QUEUES: usize = 100;

/// How many datagrams are kept for a single unknown channel (mirrors
/// `danglingDatagramQueueLen`).
const DANGLING_QUEUE_LEN: usize = 10;

/// The channel routing tables of a conversation: the datagram senders of all
/// channels, and the datagrams received for channels which do not exist (yet).
struct ChannelTables {
    channels: HashMap<u64, mpsc::Sender<Bytes>>,
    dangling: HashMap<u64, VecDeque<Bytes>>,
}

/// The stream halves of a channel kept alive after the channel's handle was
/// dropped.
///
/// The SSHOQ server ends the whole conversation when the stream of a
/// session-like channel ends (its per-channel read loop runs
/// `defer conv.Close()`), and dropping a quinn `SendStream` implicitly
/// finishes it: a finished session channel must therefore not have its stream
/// dropped, or the next channel opened on the conversation would be rejected
/// ("could not find SSH3 conversation"). The conversation parks such channels
/// here until it is closed; [`Channel::close`] unparks them, so closing a
/// session channel still ends the conversation, as documented.
struct ParkedChannel {
    channel_id: u64,
    // held only to keep the streams alive: dropping a quinn `SendStream`
    // finishes it, and dropping a `RecvStream` stops it
    #[allow(dead_code)]
    send: Arc<Mutex<quinn::SendStream>>,
    #[allow(dead_code)]
    recv: Arc<Mutex<WireReader>>,
}

/// Whether the server treats the end of this channel type's stream as the end
/// of the whole conversation (its accept loop runs session channels with a
/// `defer conv.Close()`), making the channel worth parking when its handle is
/// dropped. Forwarding channels and `sftp` channels are served by dedicated
/// handlers which end on their own.
fn is_session_like(channel_type: &str) -> bool {
    !matches!(
        channel_type,
        "direct-tcp" | "direct-udp" | "request-reverse-tcp" | "request-reverse-udp" | "sftp"
    )
}

/// The shared state of a conversation.
pub(crate) struct ConversationInner {
    pub(crate) conn: quinn::Connection,
    /// The send half of the conversation control stream. It is never written
    /// to after the conversation is established, but it must stay open for the
    /// whole conversation (finishing it would end the stream the datagrams are
    /// routed by).
    control_send: Arc<Mutex<quinn::SendStream>>,
    /// The QUIC stream ID of the conversation control stream.
    pub(crate) control_stream_id: u64,
    /// The conversation ID, exported from the TLS keying material.
    pub(crate) conversation_id: [u8; 32],
    /// The maximum packet size announced in open confirmations sent for
    /// channels opened by the peer.
    pub(crate) max_packet_size: u64,
    /// The datagram queue size of channels opened by the peer.
    pub(crate) default_datagram_queue_size: u64,
    tables: std::sync::Mutex<ChannelTables>,
    /// The stream halves of session-like channels whose handle was dropped
    /// (see [`ParkedChannel`]); keeping them alive prevents the implicit FIN
    /// of a dropped quinn `SendStream` from ending the conversation.
    parked: std::sync::Mutex<Vec<ParkedChannel>>,
    accept_tx: mpsc::UnboundedSender<Channel>,
    accept_rx: Mutex<mpsc::UnboundedReceiver<Channel>>,
    /// Cancelled when the conversation is closed (by [`ConversationInner::close`]
    /// or because the QUIC connection ended).
    pub(crate) closed: CancellationToken,
    /// The version the peer announced during the conversation establishment.
    pub(crate) peer_version: Version,
}

impl ConversationInner {
    /// Build a conversation around an established extended CONNECT request
    /// stream, and spawn its background tasks.
    pub(crate) fn new(
        conn: quinn::Connection,
        control_send: quinn::SendStream,
        control_recv: quinn::RecvStream,
        conversation_id: [u8; 32],
        peer_version: Version,
    ) -> Arc<Self> {
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let conv = Arc::new(ConversationInner {
            control_stream_id: u64::from(control_send.id()),
            control_send: Arc::new(Mutex::new(control_send)),
            conn,
            conversation_id,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            default_datagram_queue_size: DEFAULT_DATAGRAM_QUEUE_SIZE,
            tables: std::sync::Mutex::new(ChannelTables {
                channels: HashMap::new(),
                dangling: HashMap::new(),
            }),
            parked: std::sync::Mutex::new(Vec::new()),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            closed: CancellationToken::new(),
            peer_version,
        });
        conv.spawn_background(control_recv);
        conv
    }

    fn spawn_background(self: &Arc<Self>, control_recv: quinn::RecvStream) {
        // The server sends nothing on the control stream, but its receive half
        // is drained so that a FIN (or stray data) can never wedge anything.
        tokio::spawn(async move {
            let mut reader = WireReader::new(control_recv, MAX_FIELD_LENGTH);
            let _ = reader.drain().await;
        });
        // Route the conversation's datagrams to their channels.
        let conv = self.clone();
        tokio::spawn(async move {
            conv.datagram_router().await;
        });
        // Turn incoming bidirectional streams into channels.
        let conv = self.clone();
        tokio::spawn(async move {
            conv.bidi_dispatcher().await;
        });
        // Drain the unidirectional streams the server opens (its HTTP/3
        // control stream, QPACK streams, ...).
        crate::h3::spawn_uni_stream_drainer(self.conn.clone(), self.closed.clone());
        // The conversation ends with the QUIC connection.
        let conv = self.clone();
        tokio::spawn(async move {
            let err = conv.conn.closed().await;
            tracing::debug!("the QUIC connection closed: {err}");
            conv.close();
        });
    }

    /// Open a channel of the given type on a new bidirectional stream.
    ///
    /// `additional_bytes` are appended to the channel-open header (forwarding
    /// channels); `send_header_eagerly` sends the header right away instead of
    /// waiting for the first message (mirrors the Go client: `session` and
    /// `sftp` channels send their header lazily, forwarding and
    /// request-reverse channels eagerly).
    pub(crate) async fn open_channel(
        self: &Arc<Self>,
        channel_type: &str,
        max_packet_size: u64,
        datagrams_queue_size: u64,
        additional_bytes: Option<Vec<u8>>,
        send_header_eagerly: bool,
    ) -> Result<Channel> {
        let (send, recv) = self.conn.open_bi().await?;
        let channel_id = u64::from(send.id());
        let header = build_channel_header(
            self.control_stream_id,
            channel_type,
            max_packet_size,
            additional_bytes,
        );
        let (tx, rx) = mpsc::channel(datagrams_queue_size.max(1) as usize);
        self.register_channel(channel_id, tx);
        let channel = Channel {
            inner: Arc::new(ChannelInner {
                channel_id,
                conversation_stream_id: self.control_stream_id,
                channel_type: channel_type.to_string(),
                max_packet_size,
                send: Arc::new(Mutex::new(send)),
                recv: Arc::new(Mutex::new(WireReader::new(
                    recv,
                    channel_read_limit(max_packet_size),
                ))),
                datagrams_rx: Mutex::new(rx),
                conversation: self.clone(),
                header: Mutex::new(Some(header)),
                usable: AtomicBool::new(true),
                confirmed: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
        };
        if send_header_eagerly {
            channel.maybe_send_header().await?;
        }
        // The server ends the whole conversation when the stream of a
        // session-like channel ends, and dropping a quinn `SendStream`
        // implicitly finishes it: park the channel's stream halves so that
        // dropping the `Channel` handle of a finished session (e.g. at the
        // end of `Client::run_command`) does not close the conversation.
        if is_session_like(channel_type) {
            self.park_channel(&channel);
        }
        Ok(channel)
    }

    /// Park a channel's stream halves: keep them alive after the channel's
    /// handle is dropped, so the channel's stream is not implicitly finished
    /// (which, for a session-like channel, would end the conversation).
    fn park_channel(&self, channel: &Channel) {
        self.parked.lock().unwrap().push(ParkedChannel {
            channel_id: channel.inner.channel_id,
            send: channel.inner.send.clone(),
            recv: channel.inner.recv.clone(),
        });
    }

    /// Stop parking a channel: its stream halves may be dropped (and its send
    /// half finished) again. Called by [`Channel::close`].
    pub(crate) fn unpark_channel(&self, channel_id: u64) {
        self.parked
            .lock()
            .unwrap()
            .retain(|parked| parked.channel_id != channel_id);
    }

    /// Open a `direct-tcp` forwarding channel to `remote` (a socket at reach
    /// of the server), mirroring `OpenTCPForwardingChannel`.
    pub(crate) async fn open_tcp_forwarding_channel(
        self: &Arc<Self>,
        remote: SocketAddr,
    ) -> Result<Channel> {
        self.open_channel(
            "direct-tcp",
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_DATAGRAM_QUEUE_SIZE,
            Some(build_forwarding_additional_bytes(&remote)),
            true,
        )
        .await
    }

    /// Open a `direct-udp` forwarding channel to `remote`, mirroring
    /// `OpenUDPForwardingChannel`.
    pub(crate) async fn open_udp_forwarding_channel(
        self: &Arc<Self>,
        remote: SocketAddr,
    ) -> Result<Channel> {
        self.open_channel(
            "direct-udp",
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_DATAGRAM_QUEUE_SIZE,
            Some(build_forwarding_additional_bytes(&remote)),
            true,
        )
        .await
    }

    /// Request a reverse TCP forwarding: the server listens on `local` and
    /// opens one `open-request-reverse-tcp,<remote>` channel back to this
    /// client per incoming connection (mirrors `RequestTCPReverseChannel`).
    pub(crate) async fn request_tcp_reverse_channel(
        self: &Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Channel> {
        self.open_channel(
            "request-reverse-tcp",
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_DATAGRAM_QUEUE_SIZE,
            Some(build_request_reverse_additional_bytes(&local, &remote)),
            true,
        )
        .await
    }

    /// Request a reverse UDP forwarding (mirrors `RequestUDPReverseChannel`).
    pub(crate) async fn request_udp_reverse_channel(
        self: &Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Channel> {
        self.open_channel(
            "request-reverse-udp",
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_DATAGRAM_QUEUE_SIZE,
            Some(build_request_reverse_additional_bytes(&local, &remote)),
            true,
        )
        .await
    }

    /// Accept the next channel opened by the peer, confirming it (mirrors
    /// `AcceptChannel`).
    ///
    /// Reverse-forwarding channels are served automatically by the stream
    /// dispatcher and never show up here; this returns the remaining channel
    /// types (`agent-connection`, ...). Returns [`Error::Cancelled`] once the
    /// conversation is closed.
    pub(crate) async fn accept_channel(self: &Arc<Self>) -> Result<Channel> {
        let mut rx = self.accept_rx.lock().await;
        if let Ok(channel) = rx.try_recv() {
            channel.confirm(self.max_packet_size).await?;
            return Ok(channel);
        }
        tokio::select! {
            _ = self.closed.cancelled() => {
                Err(Error::Cancelled("the conversation is closed".to_string()))
            }
            channel = rx.recv() => {
                match channel {
                    Some(channel) => {
                        channel.confirm(self.max_packet_size).await?;
                        Ok(channel)
                    }
                    None => Err(Error::Cancelled(
                        "the conversation is closed".to_string(),
                    )),
                }
            }
        }
    }

    /// Register a channel's datagram queue, handing over the datagrams which
    /// arrived before the channel existed (mirrors `channelsManager.addChannel`).
    pub(crate) fn register_channel(&self, channel_id: u64, tx: mpsc::Sender<Bytes>) {
        let mut tables = self.tables.lock().unwrap();
        if let Some(mut queue) = tables.dangling.remove(&channel_id) {
            while let Some(datagram) = queue.pop_front() {
                // a full queue loses the datagram, as it would with a channel
                // whose reader fell behind
                if tx.try_send(datagram).is_err() {
                    break;
                }
            }
        }
        tables.channels.insert(channel_id, tx);
    }

    /// Remove a channel from the routing table (mirrors
    /// `channelsManager.removeChannel`).
    pub(crate) fn remove_channel(&self, channel_id: u64) {
        self.tables.lock().unwrap().channels.remove(&channel_id);
    }

    /// Close the conversation: cancel its background tasks, finish the control
    /// stream and drop the channel routing table (mirrors `Conversation.Close`).
    pub(crate) fn close(&self) {
        if self.closed.is_cancelled() {
            return;
        }
        self.closed.cancel();
        channel::finish_send_stream(self.control_send.clone());
        // release the parked channels: their streams end with the conversation
        self.parked.lock().unwrap().clear();
        let mut tables = self.tables.lock().unwrap();
        tables.channels.clear();
        tables.dangling.clear();
        // wake up a pending accept so it can notice the cancellation
        if let Ok(mut rx) = self.accept_rx.try_lock() {
            while rx.try_recv().is_ok() {}
        }
    }

    /// Route incoming QUIC datagrams to their channels until the conversation
    /// or the connection ends.
    async fn datagram_router(self: &Arc<Self>) {
        loop {
            let datagram = tokio::select! {
                _ = self.closed.cancelled() => break,
                datagram = self.conn.read_datagram() => match datagram {
                    Ok(datagram) => datagram,
                    Err(_) => break, // the connection is gone
                },
            };
            let mut reader = SliceReader::new(&datagram);
            let conv_id = match reader.read_varint() {
                Ok(conv_id) => conv_id,
                Err(_) => {
                    tracing::warn!("discarding a malformed datagram (no conversation ID)");
                    continue;
                }
            };
            if conv_id != self.control_stream_id {
                tracing::warn!(
                    "discarding a datagram with invalid conversation ID {conv_id} (expected {})",
                    self.control_stream_id
                );
                continue;
            }
            let channel_id = match reader.read_varint() {
                Ok(channel_id) => channel_id,
                Err(_) => {
                    tracing::warn!("discarding a malformed datagram (no channel ID)");
                    continue;
                }
            };
            let payload = match reader.read_bytes(reader.remaining()) {
                Ok(payload) => Bytes::copy_from_slice(payload),
                Err(_) => continue,
            };
            self.route_datagram(channel_id, payload).await;
        }
    }

    /// Hand one datagram to its channel, or queue it (bounded) when the channel
    /// does not exist yet (mirrors `Conversation.AddDatagram`).
    async fn route_datagram(self: &Arc<Self>, channel_id: u64, payload: Bytes) {
        let tx = {
            let mut tables = self.tables.lock().unwrap();
            match tables.channels.get(&channel_id) {
                Some(tx) => Some(tx.clone()),
                None => {
                    // The datagram ran ahead of the stream carrying its channel:
                    // keep it for that channel, which picks it up when it is
                    // opened - unless the peer already has too many waiting.
                    if !tables.dangling.contains_key(&channel_id)
                        && tables.dangling.len() >= MAX_DANGLING_QUEUES
                    {
                        tracing::warn!(
                            "dropping datagram for unknown channel {channel_id}: \
                             {MAX_DANGLING_QUEUES} channels already have datagrams waiting"
                        );
                    } else {
                        let queue = tables.dangling.entry(channel_id).or_default();
                        if queue.len() >= DANGLING_QUEUE_LEN {
                            // a queue which is already full loses the datagram, as
                            // it would with a real channel whose reader fell behind
                            tracing::warn!(
                                "dropping datagram for unknown channel {channel_id}: its queue is full"
                            );
                        } else {
                            queue.push_back(payload.clone());
                        }
                    }
                    None
                }
            }
        };
        if let Some(tx) = tx {
            // Blocks until the datagram is added: a channel whose reader fell
            // behind applies backpressure to the whole conversation, like the
            // Go implementation's WaitAdd.
            tokio::select! {
                _ = self.closed.cancelled() => {}
                res = tx.send(payload) => {
                    if res.is_err() {
                        // the channel went away while the datagram was in flight
                        tracing::debug!("dropping datagram for closed channel {channel_id}");
                    }
                }
            }
        }
    }

    /// Accept incoming bidirectional streams and turn them into channels until
    /// the conversation or the connection ends (mirrors the client-side
    /// `StreamHijacker`).
    async fn bidi_dispatcher(self: &Arc<Self>) {
        loop {
            let (send, recv) = tokio::select! {
                _ = self.closed.cancelled() => break,
                stream = self.conn.accept_bi() => match stream {
                    Ok(stream) => stream,
                    Err(_) => break, // the connection is gone
                },
            };
            let conv = self.clone();
            tokio::spawn(async move {
                if let Err(e) = conv.handle_incoming_stream(send, recv).await {
                    tracing::debug!("incoming channel stream failed: {e}");
                }
            });
        }
    }

    /// Parse one incoming channel stream and either serve it (reverse
    /// forwarding channels) or queue it for [`ConversationInner::accept_channel`].
    async fn handle_incoming_stream(
        self: &Arc<Self>,
        mut send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Result<()> {
        let mut reader = WireReader::new(recv, MAX_FIELD_LENGTH);
        let frame_type = reader.read_varint_opt().await?;
        if frame_type != Some(SSH_FRAME_TYPE) {
            // Not an SSH3 channel stream: drain it and give up on the stream.
            let _ = reader.drain().await;
            return Ok(());
        }
        let (control_stream_id, channel_type, max_packet_size) =
            parse_channel_header(&mut reader).await?;
        if control_stream_id != self.control_stream_id {
            // The channel belongs to another conversation of this connection.
            // The Go client tears the whole connection down here; resetting
            // only the stream is safer and loses nothing this client opened.
            tracing::warn!(
                "resetting a channel stream with wrong conversation control stream ID \
                 {control_stream_id} (expected {})",
                self.control_stream_id
            );
            let _ = send.reset(quinn::VarInt::from_u32(CANCEL_READ_ERROR_CODE as u32));
            return Ok(());
        }
        skip_channel_additional_bytes(&mut reader, &channel_type).await?;

        let channel_id = u64::from(send.id());
        let (tx, rx) = mpsc::channel(self.default_datagram_queue_size.max(1) as usize);
        self.register_channel(channel_id, tx);
        let channel = Channel {
            inner: Arc::new(ChannelInner {
                channel_id,
                conversation_stream_id: control_stream_id,
                channel_type: channel_type.clone(),
                max_packet_size,
                send: Arc::new(Mutex::new(send)),
                recv: Arc::new(Mutex::new(reader)),
                datagrams_rx: Mutex::new(rx),
                conversation: self.clone(),
                header: Mutex::new(None),
                usable: AtomicBool::new(false),
                confirmed: AtomicBool::new(true),
                closed: AtomicBool::new(false),
            }),
        };

        // Reverse-forwarding channels are confirmed and served right away
        // (mirrors the accept loop of the Go client's RunSession); every other
        // channel type goes to the accept queue.
        if let Some(dest) = parse_reverse_tcp_dest(&channel_type) {
            channel.confirm(self.max_packet_size).await?;
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(dest).await {
                    Ok(socket) => forwarding::pump_reverse_tcp(channel, socket).await,
                    Err(e) => {
                        tracing::debug!(
                            "could not dial reverse TCP destination {dest}: {e}; closing the channel"
                        );
                        channel.close();
                    }
                }
            });
        } else if let Some((_local, remote)) = parse_reverse_udp_addrs(&channel_type) {
            channel.confirm(self.max_packet_size).await?;
            tokio::spawn(async move {
                let bind_addr: SocketAddr = if remote.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                match tokio::net::UdpSocket::bind(bind_addr).await {
                    Ok(socket) => {
                        if let Err(e) = socket.connect(remote).await {
                            tracing::debug!(
                                "could not connect the reverse UDP socket to {remote}: {e}; closing the channel"
                            );
                            channel.close();
                            return;
                        }
                        forwarding::pump_reverse_udp(channel, socket).await;
                    }
                    Err(e) => {
                        tracing::debug!(
                            "could not bind the reverse UDP socket: {e}; closing the channel"
                        );
                        channel.close();
                    }
                }
            });
        } else {
            let _ = self.accept_tx.send(channel);
        }
        Ok(())
    }
}
