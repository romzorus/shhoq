//! Wire format primitives: QUIC varints and SSH strings.
//!
//! SSHOQ encodes all integers as QUIC variable-length integers (RFC 9000
//! Section 16) and length-prefixed byte strings as `varint(len) || bytes`
//! ("SSH strings", cf. RFC 4251 Section 5).

use bytes::{Buf, Bytes, BytesMut};

use crate::error::{Error, Result};

/// The absolute ceiling applied to any length-prefixed field read from a peer
/// (mirrors `util.MaxFieldLength` in the Go implementation).
pub(crate) const MAX_FIELD_LENGTH: u64 = 1 << 24;

/// The largest maximum packet size accepted from a peer (mirrors
/// `maxNegotiatedMaxPacketSize`).
pub(crate) const MAX_NEGOTIATED_MAX_PACKET_SIZE: u64 = 1 << 20;

/// The smallest bound applied when reading a message field (mirrors
/// `minMessageFieldLength`).
pub(crate) const MIN_MESSAGE_FIELD_LENGTH: u64 = 1024;

/// Append `value` as a QUIC varint.
pub(crate) fn append_varint(buf: &mut Vec<u8>, value: u64) {
    // Same encoding as quic-go's quicvarint / the Go util.AppendVarInt.
    if value <= 0x3f {
        buf.push(value as u8);
    } else if value <= 0x3fff {
        buf.push((value >> 8) as u8 | 0x40);
        buf.push(value as u8);
    } else if value <= 0x3fff_ffff {
        buf.push((value >> 24) as u8 | 0x80);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push((value >> 56) as u8 | 0xc0);
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

/// The number of bytes `value` takes as a QUIC varint.
pub(crate) fn varint_len(value: u64) -> usize {
    if value <= 0x3f {
        1
    } else if value <= 0x3fff {
        2
    } else if value <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

/// A byte reader over a QUIC stream with varint and SSH-string decoding.
///
/// `max_field_length` bounds every length-prefixed field read from the peer so
/// that a peer announcing an absurd length cannot trigger a huge allocation
/// (mirrors the Go `lengthLimitedReader`).
pub(crate) struct WireReader {
    recv: quinn::RecvStream,
    max_field_length: u64,
    /// Bytes read from the stream but not yet consumed by a partial read.
    pending: BytesMut,
}

impl WireReader {
    pub(crate) fn new(recv: quinn::RecvStream, max_field_length: u64) -> Self {
        WireReader {
            recv,
            max_field_length: max_field_length.min(MAX_FIELD_LENGTH),
            pending: BytesMut::new(),
        }
    }

    /// Read a chunk of up to `want` bytes. Returns `Ok(false)` when the peer
    /// cleanly ended the stream (no more data will ever arrive).
    async fn read_some_opt(&mut self, want: usize) -> Result<bool> {
        let chunk = self
            .recv
            .read_chunk(want, true)
            .await
            .map_err(|e| match e {
                quinn::ReadError::Reset(code) => {
                    Error::Protocol(format!("stream was reset by the peer with code {code}"))
                }
                other => Error::Read(other),
            })?;
        match chunk {
            Some(chunk) => {
                self.pending.extend_from_slice(&chunk.bytes);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Read a chunk of up to `want` bytes; maps a clean end of stream to an
    /// unexpected-EOF I/O error.
    async fn read_some(&mut self, want: usize) -> Result<()> {
        if !self.read_some_opt(want).await? {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the peer closed the stream in the middle of a message",
            )));
        }
        Ok(())
    }

    /// Read exactly one byte.
    pub(crate) async fn read_byte(&mut self) -> Result<u8> {
        if self.pending.is_empty() {
            self.read_some(1).await?;
        }
        Ok(self.pending.get_u8())
    }

    /// Read a QUIC varint.
    pub(crate) async fn read_varint(&mut self) -> Result<u64> {
        let first = self.read_byte().await?;
        let len = 1usize << ((first & 0xc0) >> 6);
        let mut value = u64::from(first & 0x3f);
        for i in 1..len {
            let b = self.read_byte().await?;
            value |= u64::from(b) << (8 * (len - 1 - i));
        }
        Ok(value)
    }

    /// Read a QUIC varint, returning `Ok(None)` when the peer cleanly ended the
    /// stream exactly at a field boundary (mirrors the Go parser, for which
    /// `ParseMessage` returns `io.EOF` only when no byte was read).
    pub(crate) async fn read_varint_opt(&mut self) -> Result<Option<u64>> {
        if self.pending.is_empty() && !self.read_some_opt(1).await? {
            return Ok(None);
        }
        let len = 1usize << ((self.pending[0] & 0xc0) >> 6);
        while self.pending.len() < len {
            if !self.read_some_opt(1).await? {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the peer closed the stream in the middle of a varint",
                )));
            }
        }
        let first = self.pending.get_u8();
        let mut value = u64::from(first & 0x3f);
        for i in 1..len {
            let b = self.pending.get_u8();
            value |= u64::from(b) << (8 * (len - 1 - i));
        }
        Ok(Some(value))
    }

    /// Read `n` bytes.
    pub(crate) async fn read_exact(&mut self, n: usize) -> Result<Bytes> {
        while self.pending.len() < n {
            let want = (n - self.pending.len()).max(1);
            self.read_some(want).await?;
        }
        Ok(self.pending.split_to(n).freeze())
    }

    /// Read an SSH string (`varint(len) || bytes`), bounded by the negotiated
    /// field length limit.
    pub(crate) async fn read_ssh_string(&mut self) -> Result<Bytes> {
        let len = self.read_varint().await?;
        if len > self.max_field_length {
            return Err(Error::Protocol(format!(
                "peer announced a {len} bytes field, the maximum accepted length is {} bytes",
                self.max_field_length
            )));
        }
        self.read_exact(len as usize).await
    }

    /// Read an SSH string and interpret it as UTF-8.
    pub(crate) async fn read_ssh_string_utf8(&mut self) -> Result<String> {
        let bytes = self.read_ssh_string().await?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::Protocol(format!("invalid UTF-8 in SSH string: {e}")))
    }

    /// Read a single byte as a boolean (0 = false, anything else = true, as
    /// encoded by the Go implementation).
    pub(crate) async fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_byte().await? != 0)
    }

    /// Read and discard everything until the peer ends the stream.
    pub(crate) async fn drain(&mut self) -> Result<()> {
        loop {
            if self.pending.is_empty() && !self.read_some_opt(65536).await? {
                return Ok(());
            }
            self.pending.clear();
        }
    }

    /// Consume the reader and give the underlying stream back.
    pub(crate) fn into_recv_stream(self) -> quinn::RecvStream {
        self.recv
    }
}

/// Append an SSH string (`varint(len) || bytes`).
pub(crate) fn append_ssh_string(buf: &mut Vec<u8>, s: &[u8]) {
    append_varint(buf, s.len() as u64);
    buf.extend_from_slice(s);
}

/// The encoded length of an SSH string.
pub(crate) fn ssh_string_len(s: &[u8]) -> usize {
    varint_len(s.len() as u64) + s.len()
}

/// Append a big-endian u16 (used for ports in forwarding headers).
pub(crate) fn append_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian u16 from a byte slice.
pub(crate) fn read_u16_be(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(Error::Protocol("truncated u16 field".to_string()));
    }
    Ok(u16::from_be_bytes([buf[0], buf[1]]))
}

/// A growable byte buffer helper for serializing messages.
pub(crate) struct MessageWriter {
    pub buf: Vec<u8>,
}

impl MessageWriter {
    pub(crate) fn new() -> Self {
        MessageWriter { buf: Vec::new() }
    }
}

impl Default for MessageWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// A synchronous varint reader over a byte slice (for parsing datagrams and
/// channel headers already fully received).
pub(crate) struct SliceReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        SliceReader { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn read_varint(&mut self) -> Result<u64> {
        if self.pos >= self.buf.len() {
            return Err(Error::Protocol("truncated varint".to_string()));
        }
        let first = self.buf[self.pos];
        let len = 1usize << ((first & 0xc0) >> 6);
        if self.remaining() < len {
            return Err(Error::Protocol("truncated varint".to_string()));
        }
        let mut value = u64::from(first & 0x3f);
        for i in 1..len {
            value |= u64::from(self.buf[self.pos + i]) << (8 * (len - 1 - i));
        }
        self.pos += len;
        Ok(value)
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Protocol("truncated byte field".to_string()));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a string with a big-endian u32 length prefix (the `string` type of
    /// RFC 4251, used by the OpenSSH private key format — unlike SSHOQ
    /// messages, whose strings have a varint length).
    pub(crate) fn read_u32_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32_be()?;
        if u64::from(len) > MAX_FIELD_LENGTH {
            return Err(Error::Protocol(format!(
                "peer announced a {len} bytes field, the maximum accepted length is {MAX_FIELD_LENGTH} bytes"
            )));
        }
        self.read_bytes(len as usize)
    }

    pub(crate) fn read_u16_be(&mut self) -> Result<u16> {
        read_u16_be(self.read_bytes(2)?)
    }

    pub(crate) fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn read_ip(&mut self, family: u64) -> Result<std::net::IpAddr> {
        use std::net::IpAddr;
        match family {
            4 => Ok(IpAddr::from(
                <[u8; 4]>::try_from(self.read_bytes(4)?)
                    .map_err(|_| Error::Protocol("truncated IPv4 address".to_string()))?,
            )),
            6 => Ok(IpAddr::from(
                <[u8; 16]>::try_from(self.read_bytes(16)?)
                    .map_err(|_| Error::Protocol("truncated IPv6 address".to_string()))?,
            )),
            other => Err(Error::Protocol(format!("invalid address family: {other}"))),
        }
    }
}

/// Append a string with a big-endian u32 length prefix (the `string` type of
/// RFC 4251, used by OpenSSH public key blobs and the OpenSSH private key
/// format — unlike SSHOQ messages, whose strings have a varint length).
pub(crate) fn append_u32_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// Encode an IP address as `varint(family) || bytes` (family 4 or 6).
pub(crate) fn append_ip(buf: &mut Vec<u8>, ip: &std::net::IpAddr) {
    match ip {
        std::net::IpAddr::V4(v4) => {
            append_varint(buf, 4);
            buf.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            append_varint(buf, 6);
            buf.extend_from_slice(&v6.octets());
        }
    }
}
