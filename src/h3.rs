//! A minimal HTTP/3 client, just enough for SSHOQ's extended CONNECT
//! (RFC 8441) conversation establishment.
//!
//! Only what the protocol needs is implemented:
//!
//! - the client control stream (`varint(0)` + a SETTINGS frame announcing
//!   `H3_DATAGRAM`), exactly like the Go client (`http3.RoundTripper{
//!   EnableDatagrams: true}`);
//! - one extended CONNECT request: a HEADERS frame with a statelessly
//!   QPACK-encoded header block, on a bidirectional stream which is then kept
//!   open as the conversation control stream;
//! - reading the response HEADERS frame (stateless QPACK decode — quic-go's
//!   QPACK encoder never uses the dynamic table) and, for error statuses, the
//!   DATA frames carrying the response body;
//! - draining the unidirectional streams the server opens (its control
//!   stream, QPACK streams, ...), which otherwise just sit there.
//!
//! SSHOQ channels are *not* HTTP/3: once the conversation is established, new
//! bidirectional streams are raw SSH3 channel streams whose first varint is
//! the (HTTP/3-unknown) frame type `0xaf3627e6`, which is what the Go
//! implementation hijacks through `StreamHijacker`.

use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::wire::{MAX_FIELD_LENGTH, WireReader, append_varint};

/// HTTP/3 frame types (RFC 9114 Section 7.2).
pub(crate) const FRAME_TYPE_DATA: u64 = 0x0;
pub(crate) const FRAME_TYPE_HEADERS: u64 = 0x1;
pub(crate) const FRAME_TYPE_SETTINGS: u64 = 0x4;

/// HTTP/3 unidirectional stream types (RFC 9114 Section 6.2).
pub(crate) const STREAM_TYPE_CONTROL: u64 = 0x0;
pub(crate) const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
pub(crate) const STREAM_TYPE_QPACK_DECODER: u64 = 0x3;

/// The HTTP/3 setting `H3_DATAGRAM` (RFC 9297).
const SETTING_H3_DATAGRAM: u64 = 0x33;

/// The result of the extended CONNECT request.
pub(crate) struct ConnectResponse {
    /// The HTTP status code (200 on success).
    pub status: u16,
    /// The `Server` response header (the server's version string).
    pub server_header: Option<String>,
    /// The response body (only meaningful for error statuses).
    pub body: Vec<u8>,
    /// The send half of the request stream: the conversation control stream.
    pub control_send: quinn::SendStream,
    /// The receive half of the request stream.
    pub control_recv: quinn::RecvStream,
}

/// Open the client control stream and announce HTTP/3 datagram support.
///
/// This is exactly what the Go client sends (`http3.RoundTripper{
/// EnableDatagrams: true}`): a SETTINGS frame carrying only `H3_DATAGRAM=1`.
/// The stream is deliberately *not* finished: the HTTP/3 control stream stays
/// open for the whole connection.
pub(crate) async fn open_control_stream(conn: &quinn::Connection) -> Result<()> {
    let mut send = conn.open_uni().await?;
    let mut buf = Vec::with_capacity(16);
    append_varint(&mut buf, STREAM_TYPE_CONTROL);
    // SETTINGS frame: H3_DATAGRAM = 1, and nothing else (like the Go client).
    let mut settings = Vec::with_capacity(4);
    append_varint(&mut settings, SETTING_H3_DATAGRAM);
    append_varint(&mut settings, 1);
    append_varint(&mut buf, FRAME_TYPE_SETTINGS);
    append_varint(&mut buf, settings.len() as u64);
    buf.extend_from_slice(&settings);
    send.write_all(&buf).await?;
    Ok(())
}

/// Send the extended CONNECT request and read the response.
///
/// The request stream is not finished: on success it becomes the conversation
/// control stream, whose QUIC stream ID routes the conversation's datagrams.
pub(crate) async fn extended_connect(
    conn: &quinn::Connection,
    authority: &str,
    path_and_query: &str,
    user_agent: &str,
    authorization: &str,
) -> Result<ConnectResponse> {
    let (mut send, recv) = conn.open_bi().await?;

    let fields = [
        qpack::HeaderField::new(":authority", authority),
        qpack::HeaderField::new(":method", "CONNECT"),
        qpack::HeaderField::new(":path", path_and_query),
        qpack::HeaderField::new(":scheme", "https"),
        qpack::HeaderField::new(":protocol", "ssh3"),
        qpack::HeaderField::new("user-agent", user_agent),
        qpack::HeaderField::new("authorization", authorization),
    ];
    let mut block = Vec::new();
    qpack::encode_stateless(&mut block, fields)
        .map_err(|e| Error::Protocol(format!("could not QPACK-encode the request: {e}")))?;

    let mut frame = Vec::with_capacity(block.len() + 8);
    append_varint(&mut frame, FRAME_TYPE_HEADERS);
    append_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await?;

    let mut reader = WireReader::new(recv, MAX_FIELD_LENGTH);
    let mut status: Option<u16> = None;
    let mut server_header: Option<String> = None;
    let mut body: Vec<u8> = Vec::new();

    loop {
        let Some(frame_type) = reader.read_varint_opt().await? else {
            break; // the peer ended the stream
        };
        let len = reader.read_varint().await?;
        if len > MAX_FIELD_LENGTH {
            return Err(Error::Protocol(format!(
                "the server sent an HTTP/3 frame of {len} bytes"
            )));
        }
        match frame_type {
            FRAME_TYPE_HEADERS => {
                let block = reader.read_exact(len as usize).await?;
                let decoded = qpack::decode_stateless(&mut &block[..], 1 << 16).map_err(|e| {
                    Error::Protocol(format!("could not QPACK-decode the response headers: {e}"))
                })?;
                for field in &decoded.fields {
                    match field.name.as_ref() {
                        b":status" => {
                            let s = std::str::from_utf8(&field.value).map_err(|e| {
                                Error::Protocol(format!("invalid :status header: {e}"))
                            })?;
                            status =
                                Some(s.parse::<u16>().map_err(|_| {
                                    Error::Protocol(format!("invalid :status {s:?}"))
                                })?);
                        }
                        b"server" => {
                            server_header =
                                Some(String::from_utf8(field.value.to_vec()).map_err(|e| {
                                    Error::Protocol(format!("invalid server header: {e}"))
                                })?);
                        }
                        _ => {}
                    }
                }
                if status == Some(200) {
                    // The conversation is established: the request stream stays
                    // open and becomes the conversation control stream.
                    return Ok(ConnectResponse {
                        status: 200,
                        server_header,
                        body,
                        control_send: send,
                        control_recv: reader.into_recv_stream(),
                    });
                }
                // error status: the body follows in DATA frames, read on
            }
            FRAME_TYPE_DATA => {
                let chunk = reader.read_exact(len as usize).await?;
                body.extend_from_slice(&chunk);
            }
            _ => {
                // unknown frame: skip it
                let _ = reader.read_exact(len as usize).await?;
            }
        }
    }

    let status = status.ok_or_else(|| {
        Error::Protocol("the server closed the stream without a HEADERS frame".to_string())
    })?;
    Ok(ConnectResponse {
        status,
        server_header,
        body,
        control_send: send,
        control_recv: reader.into_recv_stream(),
    })
}

/// Accept and drain the unidirectional streams opened by the server (its
/// control stream, QPACK streams, ...), until the conversation is closed.
///
/// The streams are tiny, but draining them keeps the HTTP/3 state machine
/// honest and frees the stream state on the peer.
pub(crate) fn spawn_uni_stream_drainer(conn: quinn::Connection, closed: CancellationToken) {
    tokio::spawn(async move {
        loop {
            let recv = tokio::select! {
                _ = closed.cancelled() => break,
                recv = conn.accept_uni() => match recv {
                    Ok(recv) => recv,
                    Err(_) => break, // the connection is gone
                },
            };
            tokio::spawn(async move {
                let mut reader = WireReader::new(recv, MAX_FIELD_LENGTH);
                // read the stream type (control/QPACK/unknown) then drain
                let stream_type = reader.read_varint_opt().await.ok().flatten();
                match stream_type {
                    Some(STREAM_TYPE_CONTROL)
                    | Some(STREAM_TYPE_QPACK_ENCODER)
                    | Some(STREAM_TYPE_QPACK_DECODER)
                    | None => {}
                    Some(other) => {
                        tracing::trace!(stream_type = other, "draining an unknown uni stream");
                    }
                }
                let _ = reader.drain().await;
            });
        }
    });
}
