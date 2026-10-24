//! SSH3 channels (mirrors `channel.go` in the Go implementation).
//!
//! A channel is carried by one QUIC bidirectional stream, hijacked from the
//! HTTP/3 layer because it starts with the HTTP/3-unknown frame type
//! `0xaf3627e6`. The stream begins with a channel header:
//!
//! ```text
//! varint(0xaf3627e6) || varint(conversationControlStreamID) ||
//! sshstring(channelType) || varint(maxPacketSize) || [additionalBytes]
//! ```
//!
//! After the header, the stream carries SSH3 messages
//! (`varint(type) || payload`, see [`crate::message`]), and channel payloads
//! can also travel in raw QUIC datagrams
//! (`varint(controlStreamID) || varint(channelID) || payload`).
//!
//! Channel types:
//!
//! | direction     | type                              | additional bytes                        |
//! |---------------|-----------------------------------|-----------------------------------------|
//! | client→server | `session`, `sftp`                 | none                                    |
//! | client→server | `direct-tcp`, `direct-udp`        | `family \|\| ip \|\| u16be(port)` (remote) |
//! | client→server | `request-reverse-tcp/udp`         | the same, twice (local, remote) + the remote port duplicated (interop quirk) |
//! | server→client | `open-request-reverse-tcp,<dest>` | none (the destination is in the type)   |
//! | server→client | `open-request-reverse-udp,<l>,<r>`| none (the addresses are in the type)    |
//! | server→client | `agent-connection`                | none                                    |

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};

use crate::conversation::ConversationInner;
use crate::error::{Error, Result};
use crate::message::{
    self, ChannelOpenConfirmationMessage, ChannelRequestMessage, DataOrExtendedDataMessage,
    Message, SerializableMessage, SshDataType, serialize_message,
};
use crate::wire::{
    self, MAX_NEGOTIATED_MAX_PACKET_SIZE, MIN_MESSAGE_FIELD_LENGTH, SliceReader, WireReader,
    append_ip, append_ssh_string, append_u16_be, append_varint,
};

/// The first varint of an SSH3 channel stream: an (HTTP/3-unknown) frame type
/// that makes the HTTP/3 layer hijack the stream.
pub(crate) const SSH_FRAME_TYPE: u64 = 0xaf3627e6;

/// The stream error code used by the Go implementation for `CancelRead`.
pub(crate) const CANCEL_READ_ERROR_CODE: u64 = 42;

/// An SSH3 channel.
///
/// Channels are cheap to clone (they share the underlying QUIC stream);
/// closing one closes it for every clone.
#[derive(Clone)]
pub struct Channel {
    pub(crate) inner: Arc<ChannelInner>,
}

pub(crate) struct ChannelInner {
    /// The QUIC stream ID carrying the channel.
    pub(crate) channel_id: u64,
    /// The QUIC stream ID of the conversation control stream.
    pub(crate) conversation_stream_id: u64,
    pub(crate) channel_type: String,
    /// The maximum packet size announced to the peer in the channel header.
    pub(crate) max_packet_size: u64,
    pub(crate) send: Arc<Mutex<quinn::SendStream>>,
    pub(crate) recv: Arc<Mutex<WireReader>>,
    pub(crate) datagrams_rx: Mutex<mpsc::Receiver<Bytes>>,
    pub(crate) conversation: Arc<ConversationInner>,
    /// The channel-open header, sent before the first message written on the
    /// stream (`None` once sent).
    pub(crate) header: Mutex<Option<Vec<u8>>>,
    /// Whether the channel may carry messages: true from the start for
    /// channels we open, set once we sent the open confirmation for channels
    /// the peer opened (mirrors the Go `confirmSent`).
    pub(crate) usable: AtomicBool,
    /// Whether the peer's open confirmation was received (mirrors the Go
    /// `confirmReceived`).
    pub(crate) confirmed: AtomicBool,
    pub(crate) closed: AtomicBool,
}

impl Channel {
    /// The QUIC stream ID of the channel.
    pub fn channel_id(&self) -> u64 {
        self.inner.channel_id
    }

    /// The channel type (`session`, `direct-tcp`, `open-request-reverse-tcp,<dest>`, ...).
    pub fn channel_type(&self) -> &str {
        &self.inner.channel_type
    }

    /// The maximum packet size announced for this channel.
    pub fn max_packet_size(&self) -> u64 {
        self.inner.max_packet_size
    }

    /// The QUIC stream ID of the conversation control stream.
    pub fn conversation_stream_id(&self) -> u64 {
        self.inner.conversation_stream_id
    }

    /// Send the channel-open header if it has not been sent yet.
    pub(crate) async fn maybe_send_header(&self) -> Result<()> {
        let mut send = self.inner.send.lock().await;
        let mut header = self.inner.header.lock().await;
        if let Some(h) = header.take() {
            send.write_all(&h).await?;
        }
        Ok(())
    }

    /// Wait until the peer confirms the channel opening.
    ///
    /// Sends the channel-open header if needed, then waits for the
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (mirrors `WaitOpen`).
    pub async fn wait_open(&self) -> Result<()> {
        if self.inner.confirmed.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.maybe_send_header().await?;
        let mut recv = self.inner.recv.lock().await;
        match message::parse_message(&mut recv).await? {
            Some(Message::ChannelOpenConfirmation(_)) => {
                self.inner.confirmed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Some(Message::ChannelOpenFailure(m)) => Err(Error::ChannelOpenFailure {
                reason_code: m.reason_code,
                error_msg: m.error_message_utf8,
            }),
            Some(m) => Err(Error::MessageOnNonConfirmedChannel {
                type_name: m.type_name().to_string(),
            }),
            None => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the channel was closed before its opening was confirmed",
            ))),
        }
    }

    /// Read the next message on the channel.
    ///
    /// Open confirmations are handled internally (looping, like the Go
    /// `NextMessage`); an open failure is returned as
    /// [`Error::ChannelOpenFailure`]. Returns `Ok(None)` when the peer cleanly
    /// closed the stream.
    pub async fn next_message(&self) -> Result<Option<Message>> {
        loop {
            let mut recv = self.inner.recv.lock().await;
            let msg = message::parse_message(&mut recv).await?;
            match msg {
                None => return Ok(None),
                Some(Message::ChannelOpenConfirmation(_)) => {
                    self.inner.confirmed.store(true, Ordering::SeqCst);
                    continue;
                }
                Some(Message::ChannelOpenFailure(m)) => {
                    return Err(Error::ChannelOpenFailure {
                        reason_code: m.reason_code,
                        error_msg: m.error_message_utf8,
                    });
                }
                Some(m) => {
                    if !self.inner.usable.load(Ordering::SeqCst) {
                        return Err(Error::MessageOnNonConfirmedChannel {
                            type_name: m.type_name().to_string(),
                        });
                    }
                    return Ok(Some(m));
                }
            }
        }
    }

    /// Write data on the channel, chunking it into messages of at most
    /// `max_packet_size` bytes (mirrors `WriteData`). Returns the number of
    /// payload bytes written.
    pub async fn write_data(&self, mut data: &[u8], data_type: SshDataType) -> Result<usize> {
        // the encoded length of a message with an empty payload: the framing
        // bytes the chunking must leave room for
        let empty_msg_len = match data_type {
            SshDataType::None => {
                wire::varint_len(message::SSH_MSG_CHANNEL_DATA) + wire::varint_len(0)
            }
            SshDataType::Stderr => {
                wire::varint_len(message::SSH_MSG_CHANNEL_EXTENDED_DATA)
                    + wire::varint_len(SshDataType::Stderr as u64)
                    + wire::varint_len(0)
            }
        };
        let chunk_size = (self.inner.max_packet_size as usize)
            .saturating_sub(empty_msg_len)
            .max(1);
        let mut written = 0;
        while !data.is_empty() {
            let n = data.len().min(chunk_size);
            let msg = DataOrExtendedDataMessage {
                data_type,
                data: Bytes::copy_from_slice(&data[..n]),
            };
            self.send_message(&msg).await?;
            written += n;
            data = &data[n..];
        }
        Ok(written)
    }

    /// Send a channel request (mirrors `SendRequest`).
    pub async fn send_request(&self, request: &ChannelRequestMessage) -> Result<()> {
        self.send_message(request).await
    }

    /// Send a raw QUIC datagram on the channel
    /// (`varint(controlStreamID) || varint(channelID) || payload`).
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        self.maybe_send_header().await?;
        let mut buf = Vec::with_capacity(payload.len() + 16);
        append_varint(&mut buf, self.inner.conversation_stream_id);
        append_varint(&mut buf, self.inner.channel_id);
        buf.extend_from_slice(payload);
        self.inner
            .conversation
            .conn
            .send_datagram(Bytes::from(buf))?;
        Ok(())
    }

    /// Receive the next datagram sent on the channel. Returns `Ok(None)` when
    /// the channel is closed and its datagram queue is drained.
    pub async fn receive_datagram(&self) -> Result<Option<Bytes>> {
        let mut rx = self.inner.datagrams_rx.lock().await;
        tokio::select! {
            d = rx.recv() => Ok(d),
            _ = self.inner.conversation.closed.cancelled() => Ok(None),
        }
    }

    /// Send the open confirmation for a channel opened by the peer (mirrors
    /// `confirmChannel`), announcing the conversation's maximum packet size.
    pub(crate) async fn confirm(&self, max_packet_size: u64) -> Result<()> {
        self.send_message(&ChannelOpenConfirmationMessage { max_packet_size })
            .await?;
        self.inner.usable.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Half-close the channel: finish the send side of the stream (a FIN), so
    /// the peer sees the end of the data written on this channel, and remove
    /// the channel from the conversation's routing table and from its parked
    /// channels (closing a session channel really closes its stream, which
    /// ends the whole conversation server-side).
    ///
    /// On `session` channels the server treats a FIN as the end of the whole
    /// conversation, so prefer [`Channel::close`] there (same effect) and see
    /// the crate documentation.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner
            .conversation
            .unpark_channel(self.inner.channel_id);
        self.inner
            .conversation
            .remove_channel(self.inner.channel_id);
        let send = self.inner.send.clone();
        finish_send_stream(send);
    }

    /// Finish only the send side of the channel stream (a FIN), keeping the
    /// channel registered for incoming data and datagrams.
    pub fn finish_send(&self) {
        finish_send_stream(self.inner.send.clone());
    }

    /// Split the channel into a writer and a reader half.
    pub fn split(self) -> (ChannelWriter, ChannelReader) {
        let writer = ChannelWriter::new(self.inner.clone(), true);
        let reader = ChannelReader::new(self.inner.clone());
        (writer, reader)
    }

    async fn send_message(&self, msg: &impl SerializableMessage) -> Result<()> {
        let buf = serialize_message(msg);
        let mut send = self.inner.send.lock().await;
        let mut header = self.inner.header.lock().await;
        if let Some(h) = header.take() {
            send.write_all(&h).await?;
        }
        drop(header);
        send.write_all(&buf).await?;
        Ok(())
    }
}

/// Finish a send stream from a possibly-sync context.
pub(crate) fn finish_send_stream(send: Arc<Mutex<quinn::SendStream>>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                let mut send = send.lock().await;
                let _ = send.finish();
            });
        }
        Err(_) => {
            if let Ok(mut send) = send.try_lock() {
                let _ = send.finish();
            }
        }
    }
}

/// The write half of a [`Channel`]: implements [`AsyncWrite`] (data is sent as
/// `SSH_MSG_CHANNEL_DATA` messages) and channel requests/datagrams.
///
/// Shutting the writer down half-closes the channel (a FIN on the stream),
/// which for forwarding channels is the TCP-like "no more data from this
/// side" signal.
pub struct ChannelWriter {
    inner: Arc<ChannelInner>,
    /// Raw bytes are buffered here and framed onto the channel by a pump task.
    duplex: tokio::io::DuplexStream,
}

impl ChannelWriter {
    pub(crate) fn new(inner: Arc<ChannelInner>, finish_on_shutdown: bool) -> ChannelWriter {
        let (user_write, pump_read) = tokio::io::duplex(64 * 1024);
        let pump_inner = inner.clone();
        tokio::spawn(async move {
            let mut pump_read = pump_read;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match tokio::io::AsyncReadExt::read(&mut pump_read, &mut buf).await {
                    Ok(0) => break, // the user shut the writer down
                    Ok(n) => {
                        let channel = Channel {
                            inner: pump_inner.clone(),
                        };
                        if channel
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
            if finish_on_shutdown {
                let channel = Channel { inner: pump_inner };
                channel.finish_send();
            }
        });
        ChannelWriter {
            inner,
            duplex: user_write,
        }
    }

    /// The channel this writer writes to.
    pub fn channel(&self) -> Channel {
        Channel {
            inner: self.inner.clone(),
        }
    }

    /// Write data on the channel (stdout direction).
    pub async fn write_data(&self, data: &[u8], data_type: SshDataType) -> Result<usize> {
        Channel {
            inner: self.inner.clone(),
        }
        .write_data(data, data_type)
        .await
    }

    /// Send a channel request.
    pub async fn send_request(&self, request: &ChannelRequestMessage) -> Result<()> {
        Channel {
            inner: self.inner.clone(),
        }
        .send_request(request)
        .await
    }

    /// Send a raw datagram on the channel.
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        Channel {
            inner: self.inner.clone(),
        }
        .send_datagram(payload)
        .await
    }

    /// Close the channel.
    pub fn close(&self) {
        Channel {
            inner: self.inner.clone(),
        }
        .close();
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.duplex).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.duplex).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.duplex).poll_shutdown(cx)
    }
}

/// The read half of a [`Channel`]: a stream of SSH3 [`Message`]s, also
/// readable as raw stdout bytes through [`AsyncRead`].
pub struct ChannelReader {
    inner: Arc<ChannelInner>,
    next: Option<NextMessageFuture>,
    /// Buffered stdout data for `AsyncRead`.
    read_buf: VecDeque<u8>,
}

/// The in-flight `next_message` future of a [`ChannelReader`].
type NextMessageFuture = Pin<Box<dyn Future<Output = Result<Option<Message>>> + Send>>;

impl ChannelReader {
    pub(crate) fn new(inner: Arc<ChannelInner>) -> ChannelReader {
        ChannelReader {
            inner,
            next: None,
            read_buf: VecDeque::new(),
        }
    }

    /// The channel this reader reads from.
    pub fn channel(&self) -> Channel {
        Channel {
            inner: self.inner.clone(),
        }
    }

    /// Read the next message on the channel.
    pub async fn next_message(&self) -> Result<Option<Message>> {
        Channel {
            inner: self.inner.clone(),
        }
        .next_message()
        .await
    }

    /// Receive the next datagram sent on the channel.
    pub async fn receive_datagram(&self) -> Result<Option<Bytes>> {
        Channel {
            inner: self.inner.clone(),
        }
        .receive_datagram()
        .await
    }

    fn start_next(&mut self) {
        if self.next.is_none() {
            let channel = Channel {
                inner: self.inner.clone(),
            };
            self.next = Some(Box::pin(async move { channel.next_message().await }));
        }
    }
}

impl futures_core::Stream for ChannelReader {
    type Item = Result<Message>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.start_next();
        let next = self.next.as_mut().expect("next future just started");
        match next.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(None)) => {
                self.next = None;
                Poll::Ready(None)
            }
            Poll::Ready(Ok(Some(msg))) => {
                self.next = None;
                Poll::Ready(Some(Ok(msg)))
            }
            Poll::Ready(Err(e)) => {
                self.next = None;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

impl AsyncRead for ChannelReader {
    /// Read stdout data. Messages which are not stdout data (stderr, channel
    /// requests, ...) are consumed and skipped.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        use futures_core::Stream;
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                for _ in 0..n {
                    buf.put_slice(&[self.read_buf.pop_front().unwrap()]);
                }
                return Poll::Ready(Ok(()));
            }
            match Stream::poll_next(Pin::new(&mut *self), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(std::io::Error::other(e))),
                Poll::Ready(Some(Ok(Message::Data(m)))) => {
                    if m.data_type == SshDataType::None {
                        self.read_buf.extend(m.data.iter().copied());
                    }
                    // stderr and other data types are skipped
                }
                Poll::Ready(Some(Ok(_))) => {} // requests etc. are skipped
            }
        }
    }
}

/// Build a channel-open header.
pub(crate) fn build_channel_header(
    conversation_stream_id: u64,
    channel_type: &str,
    max_packet_size: u64,
    additional_bytes: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    append_varint(&mut buf, SSH_FRAME_TYPE);
    append_varint(&mut buf, conversation_stream_id);
    append_ssh_string(&mut buf, channel_type.as_bytes());
    append_varint(&mut buf, max_packet_size);
    if let Some(extra) = additional_bytes {
        buf.extend_from_slice(&extra);
    }
    buf
}

/// The additional bytes of a `direct-tcp` / `direct-udp` channel header: the
/// address of the destination at reach of the server.
pub(crate) fn build_forwarding_additional_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    append_ip(&mut buf, &addr.ip());
    append_u16_be(&mut buf, addr.port());
    buf
}

/// The additional bytes of a `request-reverse-tcp` / `request-reverse-udp`
/// channel header: the server-side listen address and the client-side
/// destination, plus the remote port duplicated (a quirk of the Go
/// implementation, kept for interoperability).
pub(crate) fn build_request_reverse_additional_bytes(
    local: &SocketAddr,
    remote: &SocketAddr,
) -> Vec<u8> {
    let mut buf = build_forwarding_additional_bytes(local);
    buf.extend_from_slice(&build_forwarding_additional_bytes(remote));
    append_u16_be(&mut buf, remote.port());
    buf
}

/// Parse a channel-open header from a reader positioned after the
/// `SSH_FRAME_TYPE` varint. Returns the conversation control stream ID, the
/// channel type and the peer's maximum packet size.
pub(crate) async fn parse_channel_header(reader: &mut WireReader) -> Result<(u64, String, u64)> {
    let control_stream_id = reader.read_varint().await?;
    let channel_type = reader.read_ssh_string_utf8().await?;
    let mut max_packet_size = reader.read_varint().await?;
    if max_packet_size > MAX_NEGOTIATED_MAX_PACKET_SIZE {
        max_packet_size = MAX_NEGOTIATED_MAX_PACKET_SIZE;
    }
    Ok((control_stream_id, channel_type, max_packet_size))
}

/// The read limit applied to messages received on a channel (mirrors
/// `maxMessageFieldLength`).
pub(crate) fn channel_read_limit(max_packet_size: u64) -> u64 {
    max_packet_size.clamp(MIN_MESSAGE_FIELD_LENGTH, MAX_NEGOTIATED_MAX_PACKET_SIZE)
}

/// Parse the destination address of an `open-request-reverse-tcp,<dest>`
/// channel type (mirrors `parseReverseTCPDestFromChannelType`).
pub(crate) fn parse_reverse_tcp_dest(channel_type: &str) -> Option<SocketAddr> {
    let dest = channel_type.strip_prefix("open-request-reverse-tcp,")?;
    parse_socket_addr(dest)
}

/// Parse the `(local, remote)` addresses of an
/// `open-request-reverse-udp,<local>,<remote>` channel type (mirrors
/// `parseAddrsFromChannelType`).
pub(crate) fn parse_reverse_udp_addrs(channel_type: &str) -> Option<(SocketAddr, SocketAddr)> {
    let rest = channel_type.strip_prefix("open-request-reverse-udp,")?;
    let mut parts = rest.splitn(2, ',');
    let local = parse_socket_addr(parts.next()?.trim())?;
    let remote = parse_socket_addr(parts.next()?.trim())?;
    Some((local, remote))
}

fn parse_socket_addr(s: &str) -> Option<SocketAddr> {
    // fast path for IP literals (also handles "[v6]:port")
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 0));
    }
    None
}

/// Consume the additional bytes of an incoming channel header, for channel
/// types which carry addresses (mirrors the Go server's header parsing, so
/// the remaining stream stays aligned with the first message).
pub(crate) async fn skip_channel_additional_bytes(
    reader: &mut WireReader,
    channel_type: &str,
) -> Result<()> {
    match channel_type {
        "direct-tcp" | "direct-udp" => {
            skip_forwarding_address(reader).await?;
        }
        "request-reverse-tcp" | "request-reverse-udp" => {
            skip_forwarding_address(reader).await?;
            skip_forwarding_address(reader).await?;
            // the duplicated remote port of the Go implementation
            let _ = reader.read_exact(2).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn skip_forwarding_address(reader: &mut WireReader) -> Result<()> {
    let family = reader.read_varint().await?;
    let len = match family {
        4 => 4,
        6 => 16,
        other => {
            return Err(Error::Protocol(format!(
                "invalid address family in channel header: {other}"
            )));
        }
    };
    let _ = reader.read_exact(len).await?;
    let _ = reader.read_exact(2).await?;
    Ok(())
}

/// A synchronous variant of [`parse_socket_addr`] over a byte slice, for
/// tests and datagram parsing.
#[allow(dead_code)]
pub(crate) fn parse_addr_slice(buf: &[u8]) -> Result<(IpAddr, u16)> {
    let mut r = SliceReader::new(buf);
    let family = r.read_varint()?;
    let ip = r.read_ip(family)?;
    let port = r.read_u16_be()?;
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_header_wire_format() {
        let header = build_channel_header(0, "session", 30000, None);
        let mut expected = Vec::new();
        append_varint(&mut expected, SSH_FRAME_TYPE);
        append_varint(&mut expected, 0);
        append_ssh_string(&mut expected, b"session");
        append_varint(&mut expected, 30000);
        assert_eq!(header, expected);
    }

    #[test]
    fn forwarding_additional_bytes_wire_format() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let bytes = build_forwarding_additional_bytes(&addr);
        // varint(4) || 127.0.0.1 || u16be(8080)
        assert_eq!(bytes, vec![4, 127, 0, 0, 1, 0x1f, 0x90]);

        let v6: SocketAddr = "[::1]:443".parse().unwrap();
        let bytes = build_forwarding_additional_bytes(&v6);
        assert_eq!(bytes.len(), 1 + 16 + 2);
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[17..19], &443u16.to_be_bytes());
    }

    #[test]
    fn request_reverse_additional_bytes_wire_format() {
        let local: SocketAddr = "0.0.0.0:2222".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let bytes = build_request_reverse_additional_bytes(&local, &remote);
        let mut expected = build_forwarding_additional_bytes(&local);
        expected.extend_from_slice(&build_forwarding_additional_bytes(&remote));
        expected.extend_from_slice(&80u16.to_be_bytes()); // duplicated remote port
        assert_eq!(bytes, expected);
    }

    #[test]
    fn parse_reverse_channel_types() {
        assert_eq!(
            parse_reverse_tcp_dest("open-request-reverse-tcp,127.0.0.1:8080"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            parse_reverse_tcp_dest("open-request-reverse-tcp,[::1]:8080"),
            Some("[::1]:8080".parse().unwrap())
        );
        assert_eq!(parse_reverse_tcp_dest("session"), None);
        assert_eq!(parse_reverse_tcp_dest("open-request-reverse-tcp,"), None);

        assert_eq!(
            parse_reverse_udp_addrs("open-request-reverse-udp,0.0.0.0:53,127.0.0.1:5353"),
            Some((
                "0.0.0.0:53".parse().unwrap(),
                "127.0.0.1:5353".parse().unwrap()
            ))
        );
        assert_eq!(
            parse_reverse_udp_addrs("open-request-reverse-udp,onlyone"),
            None
        );
    }

    #[test]
    fn read_limit() {
        assert_eq!(channel_read_limit(30000), 30000);
        assert_eq!(channel_read_limit(0), MIN_MESSAGE_FIELD_LENGTH);
        assert_eq!(channel_read_limit(1 << 21), MAX_NEGOTIATED_MAX_PACKET_SIZE);
    }
}
