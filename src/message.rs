//! SSH3 messages (mirrors the Go `message` package).
//!
//! Every message on a channel stream is `varint(type) || payload`. Integers
//! are QUIC varints, strings are SSH strings (`varint(len) || bytes`).

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::wire::{MessageWriter, WireReader, append_ssh_string, append_varint};

// SSH message types (RFC 4250 numbering, as used by SSHOQ).
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u64 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u64 = 92;
pub const SSH_MSG_CHANNEL_DATA: u64 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u64 = 95;
pub const SSH_MSG_CHANNEL_REQUEST: u64 = 98;

/// The type of extended data (RFC 4254 Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshDataType {
    /// Regular data (stdout).
    None = 0,
    /// Extended data (stderr).
    Stderr = 1,
}

impl SshDataType {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(SshDataType::None),
            1 => Some(SshDataType::Stderr),
            _ => None,
        }
    }
}

/// `SSH_MSG_CHANNEL_DATA` / `SSH_MSG_CHANNEL_EXTENDED_DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataOrExtendedDataMessage {
    pub data_type: SshDataType,
    pub data: Bytes,
}

impl DataOrExtendedDataMessage {
    /// The encoded length of this message (used to size the write buffer).
    pub fn encoded_len(&self) -> usize {
        let type_len = if self.data_type == SshDataType::None {
            crate::wire::varint_len(SSH_MSG_CHANNEL_DATA)
        } else {
            crate::wire::varint_len(SSH_MSG_CHANNEL_EXTENDED_DATA)
                + crate::wire::varint_len(self.data_type as u64)
        };
        type_len + crate::wire::ssh_string_len(&self.data)
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        if self.data_type == SshDataType::None {
            append_varint(buf, SSH_MSG_CHANNEL_DATA);
        } else {
            append_varint(buf, SSH_MSG_CHANNEL_EXTENDED_DATA);
            append_varint(buf, self.data_type as u64);
        }
        append_ssh_string(buf, &self.data);
    }
}

/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenConfirmationMessage {
    pub max_packet_size: u64,
}

impl ChannelOpenConfirmationMessage {
    pub fn encoded_len(&self) -> usize {
        crate::wire::varint_len(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
            + crate::wire::varint_len(self.max_packet_size)
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        append_varint(buf, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        append_varint(buf, self.max_packet_size);
    }
}

/// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenFailureMessage {
    pub reason_code: u64,
    pub error_message_utf8: String,
    pub language_tag: String,
}

impl ChannelOpenFailureMessage {
    pub fn encoded_len(&self) -> usize {
        crate::wire::varint_len(SSH_MSG_CHANNEL_OPEN_FAILURE)
            + crate::wire::varint_len(self.reason_code)
            + crate::wire::ssh_string_len(self.error_message_utf8.as_bytes())
            + crate::wire::ssh_string_len(self.language_tag.as_bytes())
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        append_varint(buf, SSH_MSG_CHANNEL_OPEN_FAILURE);
        append_varint(buf, self.reason_code);
        append_ssh_string(buf, self.error_message_utf8.as_bytes());
        append_ssh_string(buf, self.language_tag.as_bytes());
    }
}

/// A channel request (the payload of `SSH_MSG_CHANNEL_REQUEST`).
///
/// See RFC 4254 Section 6 for the SSH2 semantics SSHOQ reuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRequest {
    /// `pty-req` (RFC 4254 Section 6.2).
    Pty(PtyRequest),
    /// `x11-req` (RFC 4254 Section 6.3.1).
    X11(X11Request),
    /// `shell` (RFC 4254 Section 6.5).
    Shell,
    /// `exec` (RFC 4254 Section 6.5).
    Exec(ExecRequest),
    /// `subsystem` (RFC 4254 Section 6.6).
    Subsystem(SubsystemRequest),
    /// `window-change` (RFC 4254 Section 6.7).
    WindowChange(WindowChangeRequest),
    /// `signal` (RFC 4254 Section 6.9).
    Signal(SignalRequest),
    /// `exit-status` (RFC 4254 Section 6.10).
    ExitStatus(ExitStatusRequest),
    /// `exit-signal` (RFC 4254 Section 6.10).
    ExitSignal(ExitSignalRequest),
    /// `env` (RFC 4254 Section 6.4).
    Env(EnvRequest),
    /// `sftp` (SSHOQ-specific).
    Sftp(SftpRequest),
}

impl ChannelRequest {
    /// The request type as announced on the wire.
    pub fn request_type_str(&self) -> &'static str {
        match self {
            ChannelRequest::Pty(_) => "pty-req",
            ChannelRequest::X11(_) => "x11-req",
            ChannelRequest::Shell => "shell",
            ChannelRequest::Exec(_) => "exec",
            ChannelRequest::Subsystem(_) => "subsystem",
            ChannelRequest::WindowChange(_) => "window-change",
            ChannelRequest::Signal(_) => "signal",
            ChannelRequest::ExitStatus(_) => "exit-status",
            ChannelRequest::ExitSignal(_) => "exit-signal",
            ChannelRequest::Env(_) => "env",
            ChannelRequest::Sftp(_) => "sftp",
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            ChannelRequest::Pty(r) => r.encoded_len(),
            ChannelRequest::X11(r) => r.encoded_len(),
            ChannelRequest::Shell => 0,
            ChannelRequest::Exec(r) => r.encoded_len(),
            ChannelRequest::Subsystem(r) => r.encoded_len(),
            ChannelRequest::WindowChange(r) => r.encoded_len(),
            ChannelRequest::Signal(r) => r.encoded_len(),
            ChannelRequest::ExitStatus(r) => r.encoded_len(),
            ChannelRequest::ExitSignal(r) => r.encoded_len(),
            ChannelRequest::Env(r) => r.encoded_len(),
            ChannelRequest::Sftp(r) => r.encoded_len(),
        }
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            ChannelRequest::Pty(r) => r.write_to(buf),
            ChannelRequest::X11(r) => r.write_to(buf),
            ChannelRequest::Shell => {}
            ChannelRequest::Exec(r) => r.write_to(buf),
            ChannelRequest::Subsystem(r) => r.write_to(buf),
            ChannelRequest::WindowChange(r) => r.write_to(buf),
            ChannelRequest::Signal(r) => r.write_to(buf),
            ChannelRequest::ExitStatus(r) => r.write_to(buf),
            ChannelRequest::ExitSignal(r) => r.write_to(buf),
            ChannelRequest::Env(r) => r.write_to(buf),
            ChannelRequest::Sftp(r) => r.write_to(buf),
        }
    }
}

/// `SSH_MSG_CHANNEL_REQUEST`: a channel request plus the want-reply flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRequestMessage {
    pub want_reply: bool,
    pub request: ChannelRequest,
}

impl ChannelRequestMessage {
    pub fn encoded_len(&self) -> usize {
        crate::wire::varint_len(SSH_MSG_CHANNEL_REQUEST)
            + crate::wire::ssh_string_len(self.request.request_type_str().as_bytes())
            + 1
            + self.request.encoded_len()
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        append_varint(buf, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_string(buf, self.request.request_type_str().as_bytes());
        buf.push(self.want_reply as u8);
        self.request.write_to(buf);
    }
}

/// `pty-req` (RFC 4254 Section 6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PtyRequest {
    pub term: String,
    pub char_width: u64,
    pub char_height: u64,
    pub pixel_width: u64,
    pub pixel_height: u64,
    pub encoded_terminal_modes: String,
}

impl PtyRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.term.as_bytes())
            + crate::wire::varint_len(self.char_width)
            + crate::wire::varint_len(self.char_height)
            + crate::wire::varint_len(self.pixel_width)
            + crate::wire::varint_len(self.pixel_height)
            + crate::wire::ssh_string_len(self.encoded_terminal_modes.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.term.as_bytes());
        for attr in [
            self.char_width,
            self.char_height,
            self.pixel_width,
            self.pixel_height,
        ] {
            append_varint(buf, attr);
        }
        append_ssh_string(buf, self.encoded_terminal_modes.as_bytes());
    }
}

/// `x11-req` (RFC 4254 Section 6.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct X11Request {
    pub single_connection: bool,
    pub x11_authentication_protocol: String,
    pub x11_authentication_cookie: String,
    pub x11_screen_number: u64,
}

impl X11Request {
    fn encoded_len(&self) -> usize {
        1 + crate::wire::ssh_string_len(self.x11_authentication_protocol.as_bytes())
            + crate::wire::ssh_string_len(self.x11_authentication_cookie.as_bytes())
            + crate::wire::varint_len(self.x11_screen_number)
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.single_connection as u8);
        append_ssh_string(buf, self.x11_authentication_protocol.as_bytes());
        append_ssh_string(buf, self.x11_authentication_cookie.as_bytes());
        append_varint(buf, self.x11_screen_number);
    }
}

/// `exec` (RFC 4254 Section 6.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecRequest {
    pub command: String,
}

impl ExecRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.command.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.command.as_bytes());
    }
}

/// `subsystem` (RFC 4254 Section 6.6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubsystemRequest {
    pub subsystem_name: String,
}

impl SubsystemRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.subsystem_name.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.subsystem_name.as_bytes());
    }
}

/// `window-change` (RFC 4254 Section 6.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowChangeRequest {
    pub char_width: u64,
    pub char_height: u64,
    pub pixel_width: u64,
    pub pixel_height: u64,
}

impl WindowChangeRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::varint_len(self.char_width)
            + crate::wire::varint_len(self.char_height)
            + crate::wire::varint_len(self.pixel_width)
            + crate::wire::varint_len(self.pixel_height)
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        for attr in [
            self.char_width,
            self.char_height,
            self.pixel_width,
            self.pixel_height,
        ] {
            append_varint(buf, attr);
        }
    }
}

/// `signal` (RFC 4254 Section 6.9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignalRequest {
    /// The signal name without the `SIG` prefix (e.g. `TERM`).
    pub signal_name_without_sig: String,
}

impl SignalRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.signal_name_without_sig.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.signal_name_without_sig.as_bytes());
    }
}

/// `exit-status` (RFC 4254 Section 6.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitStatusRequest {
    pub exit_status: u64,
}

impl ExitStatusRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::varint_len(self.exit_status)
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_varint(buf, self.exit_status);
    }
}

/// `exit-signal` (RFC 4254 Section 6.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitSignalRequest {
    pub signal_name_without_sig: String,
    pub core_dumped: bool,
    pub error_message_utf8: String,
    pub language_tag: String,
}

impl ExitSignalRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.signal_name_without_sig.as_bytes())
            + 1
            + crate::wire::ssh_string_len(self.error_message_utf8.as_bytes())
            + crate::wire::ssh_string_len(self.language_tag.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.signal_name_without_sig.as_bytes());
        buf.push(self.core_dumped as u8);
        append_ssh_string(buf, self.error_message_utf8.as_bytes());
        append_ssh_string(buf, self.language_tag.as_bytes());
    }
}

/// `env` (RFC 4254 Section 6.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvRequest {
    pub name: String,
    pub value: String,
}

impl EnvRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::ssh_string_len(self.name.as_bytes())
            + crate::wire::ssh_string_len(self.value.as_bytes())
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_ssh_string(buf, self.name.as_bytes());
        append_ssh_string(buf, self.value.as_bytes());
    }
}

/// SFTP operations (SSHOQ-specific, not conforming to any RFC).
pub mod sftp_op {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const UNLINK: u64 = 2;
    pub const RECURSIVE_UNLINK: u64 = 3;
    pub const STAT: u64 = 4;
    pub const MKDIR: u64 = 5;
    pub const LISTDIR: u64 = 6;
}

/// `sftp` (SSHOQ-specific).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SftpRequest {
    pub operation: u64,
    pub path: String,
    pub payload: Vec<u8>,
}

impl SftpRequest {
    fn encoded_len(&self) -> usize {
        crate::wire::varint_len(self.operation)
            + crate::wire::ssh_string_len(self.path.as_bytes())
            + crate::wire::ssh_string_len(&self.payload)
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        append_varint(buf, self.operation);
        append_ssh_string(buf, self.path.as_bytes());
        append_ssh_string(buf, &self.payload);
    }
}

/// Any SSH3 message received on a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Data(DataOrExtendedDataMessage),
    ChannelRequest(ChannelRequestMessage),
    ChannelOpenConfirmation(ChannelOpenConfirmationMessage),
    ChannelOpenFailure(ChannelOpenFailureMessage),
}

impl Message {
    /// A short type name, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Message::Data(m) => match m.data_type {
                SshDataType::None => "DataOrExtendedDataMessage(stdout)",
                SshDataType::Stderr => "DataOrExtendedDataMessage(stderr)",
            },
            Message::ChannelRequest(_) => "ChannelRequestMessage",
            Message::ChannelOpenConfirmation(_) => "ChannelOpenConfirmationMessage",
            Message::ChannelOpenFailure(_) => "ChannelOpenFailureMessage",
        }
    }
}

/// Parse one message from a channel stream (mirrors `message.ParseMessage`).
///
/// Returns `Ok(None)` when the peer cleanly closed the stream exactly at a
/// message boundary (the Go parser returns `io.EOF` only when no byte at all
/// was read).
pub(crate) async fn parse_message(reader: &mut WireReader) -> Result<Option<Message>> {
    let Some(type_id) = reader.read_varint_opt().await? else {
        return Ok(None);
    };
    match type_id {
        SSH_MSG_CHANNEL_DATA => {
            let data = reader.read_ssh_string().await?;
            Ok(Some(Message::Data(DataOrExtendedDataMessage {
                data_type: SshDataType::None,
                data,
            })))
        }
        SSH_MSG_CHANNEL_EXTENDED_DATA => {
            let data_type = reader.read_varint().await?;
            let data_type = SshDataType::from_u64(data_type).ok_or_else(|| {
                Error::Protocol(format!("unknown extended data type: {data_type}"))
            })?;
            let data = reader.read_ssh_string().await?;
            Ok(Some(Message::Data(DataOrExtendedDataMessage {
                data_type,
                data,
            })))
        }
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            let max_packet_size = reader.read_varint().await?;
            Ok(Some(Message::ChannelOpenConfirmation(
                ChannelOpenConfirmationMessage { max_packet_size },
            )))
        }
        SSH_MSG_CHANNEL_OPEN_FAILURE => {
            let reason_code = reader.read_varint().await?;
            let error_message_utf8 = reader.read_ssh_string_utf8().await?;
            let language_tag = reader.read_ssh_string_utf8().await?;
            Ok(Some(Message::ChannelOpenFailure(
                ChannelOpenFailureMessage {
                    reason_code,
                    error_message_utf8,
                    language_tag,
                },
            )))
        }
        SSH_MSG_CHANNEL_REQUEST => {
            let request_type = reader.read_ssh_string_utf8().await?;
            let want_reply = reader.read_bool().await?;
            let request = parse_channel_request(reader, &request_type).await?;
            Ok(Some(Message::ChannelRequest(ChannelRequestMessage {
                want_reply,
                request,
            })))
        }
        other => Err(Error::UnsupportedMessage(other)),
    }
}

async fn parse_channel_request(
    reader: &mut WireReader,
    request_type: &str,
) -> Result<ChannelRequest> {
    match request_type {
        "pty-req" => {
            let term = reader.read_ssh_string_utf8().await?;
            let char_width = reader.read_varint().await?;
            let char_height = reader.read_varint().await?;
            let pixel_width = reader.read_varint().await?;
            let pixel_height = reader.read_varint().await?;
            // The Go parser tolerates a truncated terminal-modes string.
            let encoded_terminal_modes = reader.read_ssh_string_utf8().await.unwrap_or_default();
            Ok(ChannelRequest::Pty(PtyRequest {
                term,
                char_width,
                char_height,
                pixel_width,
                pixel_height,
                encoded_terminal_modes,
            }))
        }
        "x11-req" => {
            let single_connection = reader.read_bool().await?;
            let x11_authentication_protocol = reader.read_ssh_string_utf8().await?;
            let x11_authentication_cookie = reader.read_ssh_string_utf8().await?;
            let x11_screen_number = reader.read_varint().await?;
            Ok(ChannelRequest::X11(X11Request {
                single_connection,
                x11_authentication_protocol,
                x11_authentication_cookie,
                x11_screen_number,
            }))
        }
        "shell" => Ok(ChannelRequest::Shell),
        "exec" => {
            let command = reader.read_ssh_string_utf8().await?;
            Ok(ChannelRequest::Exec(ExecRequest { command }))
        }
        "subsystem" => {
            let subsystem_name = reader.read_ssh_string_utf8().await?;
            Ok(ChannelRequest::Subsystem(SubsystemRequest {
                subsystem_name,
            }))
        }
        "window-change" => {
            let char_width = reader.read_varint().await?;
            let char_height = reader.read_varint().await?;
            let pixel_width = reader.read_varint().await?;
            let pixel_height = reader.read_varint().await?;
            Ok(ChannelRequest::WindowChange(WindowChangeRequest {
                char_width,
                char_height,
                pixel_width,
                pixel_height,
            }))
        }
        "signal" => {
            let signal_name_without_sig = reader.read_ssh_string_utf8().await?;
            Ok(ChannelRequest::Signal(SignalRequest {
                signal_name_without_sig,
            }))
        }
        "exit-status" => {
            let exit_status = reader.read_varint().await?;
            Ok(ChannelRequest::ExitStatus(ExitStatusRequest {
                exit_status,
            }))
        }
        "exit-signal" => {
            let signal_name_without_sig = reader.read_ssh_string_utf8().await?;
            let core_dumped = reader.read_bool().await?;
            let error_message_utf8 = reader.read_ssh_string_utf8().await?;
            let language_tag = reader.read_ssh_string_utf8().await?;
            Ok(ChannelRequest::ExitSignal(ExitSignalRequest {
                signal_name_without_sig,
                core_dumped,
                error_message_utf8,
                language_tag,
            }))
        }
        "env" => {
            let name = reader.read_ssh_string_utf8().await?;
            let value = reader.read_ssh_string_utf8().await?;
            Ok(ChannelRequest::Env(EnvRequest { name, value }))
        }
        "sftp" => {
            let operation = reader.read_varint().await?;
            let path = reader.read_ssh_string_utf8().await?;
            let payload = reader.read_ssh_string().await?;
            Ok(ChannelRequest::Sftp(SftpRequest {
                operation,
                path,
                payload: payload.to_vec(),
            }))
        }
        other => Err(Error::Protocol(format!(
            "invalid request message type {other}"
        ))),
    }
}

/// Serialize a message into a fresh buffer.
pub(crate) fn serialize_message(msg: &impl SerializableMessage) -> Vec<u8> {
    let mut w = MessageWriter::new();
    msg.serialize(&mut w);
    w.buf
}

/// Helper trait for message serialization.
pub(crate) trait SerializableMessage {
    fn serialize(&self, w: &mut MessageWriter);
}

impl SerializableMessage for DataOrExtendedDataMessage {
    fn serialize(&self, w: &mut MessageWriter) {
        self.write_to(&mut w.buf);
    }
}

impl SerializableMessage for ChannelRequestMessage {
    fn serialize(&self, w: &mut MessageWriter) {
        self.write_to(&mut w.buf);
    }
}

impl SerializableMessage for ChannelOpenConfirmationMessage {
    fn serialize(&self, w: &mut MessageWriter) {
        self.write_to(&mut w.buf);
    }
}

impl SerializableMessage for ChannelOpenFailureMessage {
    fn serialize(&self, w: &mut MessageWriter) {
        self.write_to(&mut w.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message, expected_wire: &[u8]) {
        let buf = match &msg {
            Message::Data(m) => serialize_message(m),
            Message::ChannelRequest(m) => serialize_message(m),
            Message::ChannelOpenConfirmation(m) => serialize_message(m),
            Message::ChannelOpenFailure(m) => serialize_message(m),
        };
        assert_eq!(buf, expected_wire, "serialization mismatch for {msg:?}");
    }

    // Message types are QUIC varints: types >= 64 (91, 92, 94, 95, 98) use the
    // two-byte form, e.g. 94 = 0x40 0x5e, 98 = 0x40 0x62 (same as the Go
    // client's util.AppendVarInt). "sshstring" is a varint length followed by
    // the bytes.

    #[test]
    fn data_message_wire_format() {
        // varint(94) = 0x40 0x5e, sshstring("hi") = 0x02 'h' 'i'
        roundtrip(
            Message::Data(DataOrExtendedDataMessage {
                data_type: SshDataType::None,
                data: Bytes::from_static(b"hi"),
            }),
            &[0x40, 0x5e, 0x02, b'h', b'i'],
        );
    }

    #[test]
    fn extended_data_message_wire_format() {
        // varint(95) = 0x40 0x5f, varint(1) = 0x01, sshstring("err")
        roundtrip(
            Message::Data(DataOrExtendedDataMessage {
                data_type: SshDataType::Stderr,
                data: Bytes::from_static(b"err"),
            }),
            &[0x40, 0x5f, 0x01, 0x03, b'e', b'r', b'r'],
        );
    }

    #[test]
    fn shell_request_wire_format() {
        // varint(98) = 0x40 0x62, sshstring("shell"), want_reply = 1
        roundtrip(
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Shell,
            }),
            &[0x40, 0x62, 0x05, b's', b'h', b'e', b'l', b'l', 0x01],
        );
    }

    #[test]
    fn exec_request_wire_format() {
        roundtrip(
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: "id".to_string(),
                }),
            }),
            &[
                0x40, 0x62, 0x04, b'e', b'x', b'e', b'c', 0x01, 0x02, b'i', b'd',
            ],
        );
    }

    #[test]
    fn env_request_wire_format() {
        roundtrip(
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Env(EnvRequest {
                    name: "A".to_string(),
                    value: "B".to_string(),
                }),
            }),
            &[
                0x40, 0x62, 0x03, b'e', b'n', b'v', 0x01, 0x01, b'A', 0x01, b'B',
            ],
        );
    }

    #[test]
    fn exit_status_wire_format() {
        roundtrip(
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::ExitStatus(ExitStatusRequest { exit_status: 42 }),
            }),
            &[
                0x40, 0x62, 0x0b, b'e', b'x', b'i', b't', b'-', b's', b't', b'a', b't', b'u', b's',
                0x00, 42,
            ],
        );
    }

    #[test]
    fn open_confirmation_wire_format() {
        roundtrip(
            Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                max_packet_size: 30000,
            }),
            &{
                // varint(91) = 0x40 0x5b, varint(30000) = 0x80 00 75 30
                let mut buf = vec![0x40, 91u8];
                crate::wire::append_varint(&mut buf, 30000);
                buf
            },
        );
    }

    #[test]
    fn open_failure_wire_format() {
        roundtrip(
            Message::ChannelOpenFailure(ChannelOpenFailureMessage {
                reason_code: 1,
                error_message_utf8: "nope".to_string(),
                language_tag: "en".to_string(),
            }),
            &[
                0x40, 0x5c, 0x01, 0x04, b'n', b'o', b'p', b'e', 0x02, b'e', b'n',
            ],
        );
    }

    #[test]
    fn pty_request_wire_format() {
        // The four dimensions are varints: 80 = 0x40 0x50, 24/0 = single bytes.
        roundtrip(
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Pty(PtyRequest {
                    term: "xterm".to_string(),
                    char_width: 80,
                    char_height: 24,
                    pixel_width: 0,
                    pixel_height: 0,
                    encoded_terminal_modes: String::new(),
                }),
            }),
            &[
                0x40, 0x62, 0x07, b'p', b't', b'y', b'-', b'r', b'e', b'q', 0x01, 0x05, b'x', b't',
                b'e', b'r', b'm', 0x40, 80, 24, 0, 0, 0,
            ],
        );
    }
}
