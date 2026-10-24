//! Error types for the shhoq client.

use thiserror::Error;

/// Errors returned by the shhoq client.
#[derive(Debug, Error)]
pub enum Error {
    /// The server rejected the authentication (HTTP 401).
    #[error("unauthorized")]
    Unauthorized,

    /// The server answered with an unexpected HTTP status code.
    #[error("HTTP response with {status} status code{}", body.as_ref().map(|b| format!(": {b}")).unwrap_or_default())]
    Http { status: u16, body: Option<String> },

    /// The server runs an SSH3 version this client cannot negotiate.
    #[error("unsupported SSH version: {0}")]
    UnsupportedVersion(String),

    /// No authentication method could be used (e.g. no usable private key).
    #[error("no suitable identity found")]
    NoSuitableIdentity,

    /// The peer refused to open a channel.
    #[error("channel open failure: reason: {reason_code}: {error_msg}")]
    ChannelOpenFailure { reason_code: u64, error_msg: String },

    /// A message was received on a channel that has not been confirmed yet.
    #[error("a message of type {type_name} has been received on a non-confirmed channel")]
    MessageOnNonConfirmedChannel { type_name: String },

    /// The remote command exited with a status code.
    ///
    /// Mirrors the Go client's `ExitStatus`, which is returned as an error from
    /// `RunSession`.
    #[error("exited with status {status_code}")]
    ExitStatus { status_code: u32 },

    /// The remote command was killed by a signal.
    ///
    /// Mirrors the Go client's `ExitSignal`.
    #[error("exited with signal {signal}: {error_message_utf8}")]
    ExitSignal {
        signal: String,
        error_message_utf8: String,
    },

    /// The peer sent an SSH3 message type this implementation does not know.
    #[error("peer sent an unsupported message type: {0}")]
    UnsupportedMessage(u64),

    /// A datagram was received for a channel that does not exist (yet).
    #[error("channel not found: {0}")]
    ChannelNotFound(u64),

    /// The QUIC connection could not be initiated.
    #[error("could not initiate the QUIC connection: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// A QUIC-level error.
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// A QUIC stream read error.
    #[error("QUIC stream read error: {0}")]
    Read(#[from] quinn::ReadError),

    /// A QUIC stream write error.
    #[error("QUIC stream write error: {0}")]
    Write(#[from] quinn::WriteError),

    /// A QUIC stream was closed.
    #[error("QUIC stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),

    /// A QUIC datagram could not be sent.
    #[error("could not send QUIC datagram: {0}")]
    SendDatagram(#[from] quinn::SendDatagramError),

    /// A TLS-level error.
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    /// The TLS keying material could not be exported.
    #[error("could not export TLS keying material: {0}")]
    ExportKeyingMaterial(String),

    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol violation by the peer.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A key could not be parsed or used.
    #[error("private key error: {0}")]
    Key(String),

    /// JSON (de)serialization failure (JWT claims).
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The operation was cancelled (the client or conversation was closed).
    #[error("cancelled: {0}")]
    Cancelled(String),
}

/// The result of running a command to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Data written by the command to stdout.
    pub stdout: Vec<u8>,
    /// Data written by the command to stderr.
    pub stderr: Vec<u8>,
    /// The exit status reported by the server.
    pub exit_status: u32,
}

impl From<ExitStatus> for Error {
    fn from(e: ExitStatus) -> Self {
        Error::ExitStatus {
            status_code: e.status_code,
        }
    }
}

impl From<ExitSignal> for Error {
    fn from(e: ExitSignal) -> Self {
        Error::ExitSignal {
            signal: e.signal,
            error_message_utf8: e.error_message_utf8,
        }
    }
}

/// The remote process exited with a status code (mirrors Go's `ExitStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub status_code: u32,
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exited with status {}", self.status_code)
    }
}

impl std::error::Error for ExitStatus {}

/// The remote process was killed by a signal (mirrors Go's `ExitSignal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignal {
    pub signal: String,
    pub error_message_utf8: String,
}

impl std::fmt::Display for ExitSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exited with signal {}: {}",
            self.signal, self.error_message_utf8
        )
    }
}

impl std::error::Error for ExitSignal {}

/// A terminal window size, for `pty-req` and `window-change` requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowSize {
    pub char_width: u64,
    pub char_height: u64,
    pub pixel_width: u64,
    pub pixel_height: u64,
}

pub type Result<T> = std::result::Result<T, Error>;
