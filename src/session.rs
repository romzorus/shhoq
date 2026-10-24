//! Interactive sessions on `session` channels (mirrors the session handling of
//! the Go client's `RunSession`).
//!
//! A [`Session`] wraps a `session` channel: it sends the usual SSH2-style
//! channel requests (`exec`, `shell`, `pty-req`, `env`, `signal`,
//! `window-change`, ...) and yields [`SessionEvent`]s (stdout/stderr data, the
//! command's exit status or signal, unexpected requests).
//!
//! # A warning about closing the session channel
//!
//! The SSHOQ server treats the end of the *session* channel as the end of the
//! whole conversation: it closes the conversation when the channel's stream
//! ends. For that reason [`SessionWriter`]'s shutdown does *not* finish the
//! channel stream (unlike forwarding channels, where a FIN is the TCP-like
//! half-close), and the Go CLI client never propagates stdin EOF either.
//! Dropping a [`Session`] does not close the channel either: the conversation
//! parks the channel's stream halves (see [`crate::Client::run_command`]), so
//! a finished session never ends the conversation by accident.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use crate::channel::{Channel, ChannelReader, ChannelWriter};
use crate::error::{Error, ExitSignal, ExitStatus, Result, WindowSize};
use crate::message::{
    ChannelRequest, ChannelRequestMessage, EnvRequest, ExecRequest, Message, PtyRequest,
    SignalRequest, SshDataType, SubsystemRequest, WindowChangeRequest,
};

/// A session on a `session` channel.
pub struct Session {
    channel: Channel,
}

/// One event of a [`Session`]: data written by the remote process, or the way
/// it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Data written by the remote process to stdout.
    Data(Vec<u8>),
    /// Data written by the remote process to stderr.
    Stderr(Vec<u8>),
    /// The remote process exited with a status code.
    ExitStatus(ExitStatus),
    /// The remote process was killed by a signal.
    ExitSignal(ExitSignal),
    /// A channel request the server sent on the session channel (the exit
    /// status and exit signal requests are reported as their own variants).
    Request(ChannelRequestMessage),
}

/// Map one channel message to a session event.
pub(crate) fn map_message(msg: Message) -> Result<SessionEvent> {
    match msg {
        Message::Data(m) => match m.data_type {
            SshDataType::None => Ok(SessionEvent::Data(m.data.to_vec())),
            SshDataType::Stderr => Ok(SessionEvent::Stderr(m.data.to_vec())),
        },
        Message::ChannelRequest(req) => match req.request {
            ChannelRequest::ExitStatus(e) => Ok(SessionEvent::ExitStatus(ExitStatus {
                status_code: e.exit_status as u32,
            })),
            ChannelRequest::ExitSignal(e) => Ok(SessionEvent::ExitSignal(ExitSignal {
                signal: e.signal_name_without_sig,
                error_message_utf8: e.error_message_utf8,
            })),
            request => Ok(SessionEvent::Request(ChannelRequestMessage {
                want_reply: req.want_reply,
                request,
            })),
        },
        other => Err(Error::Protocol(format!(
            "unexpected message on a session channel: {}",
            other.type_name()
        ))),
    }
}

impl Session {
    pub(crate) fn new(channel: Channel) -> Session {
        Session { channel }
    }

    /// The channel this session runs on.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Consume the session and return its channel.
    pub fn into_channel(self) -> Channel {
        self.channel
    }

    /// Run a command (`exec` request). The command's output and exit status are
    /// read with [`Session::next_event`] or [`Session::wait`].
    pub async fn exec(&self, command: &str) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: command.to_string(),
                }),
            })
            .await
    }

    /// Start a shell (`shell` request).
    pub async fn start_shell(&self) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Shell,
            })
            .await
    }

    /// Start a subsystem (`subsystem` request, e.g. `sftp`).
    pub async fn start_subsystem(&self, name: &str) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Subsystem(SubsystemRequest {
                    subsystem_name: name.to_string(),
                }),
            })
            .await
    }

    /// Request a pseudo-terminal (`pty-req` request).
    pub async fn request_pty(&self, term: &str, size: WindowSize) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Pty(PtyRequest {
                    term: term.to_string(),
                    char_width: size.char_width,
                    char_height: size.char_height,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                    encoded_terminal_modes: String::new(),
                }),
            })
            .await
    }

    /// Set an environment variable on the remote process (`env` request). Must
    /// be called before the shell or command is started.
    pub async fn send_env(&self, name: &str, value: &str) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Env(EnvRequest {
                    name: name.to_string(),
                    value: value.to_string(),
                }),
            })
            .await
    }

    /// Send a signal to the remote process (`signal` request). The signal name
    /// is given without the `SIG` prefix (e.g. `TERM`).
    pub async fn signal(&self, signal_name_without_sig: &str) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Signal(SignalRequest {
                    signal_name_without_sig: signal_name_without_sig.to_string(),
                }),
            })
            .await
    }

    /// Notify the remote process of a terminal size change (`window-change`
    /// request).
    pub async fn window_change(&self, size: WindowSize) -> Result<()> {
        self.channel
            .send_request(&ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::WindowChange(WindowChangeRequest {
                    char_width: size.char_width,
                    char_height: size.char_height,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                }),
            })
            .await
    }

    /// Ask the server to expose its user's SSH agent to the processes it starts
    /// on this session (the Go client's `-A`): the request is sent as the
    /// first data of the still-larval session channel, and the server opens
    /// `agent-connection` channels which [`crate::Client::forward_agent`]
    /// pipes to the local agent.
    pub async fn request_agent_forwarding(&self) -> Result<usize> {
        self.channel
            .write_data(b"forward-agent", SshDataType::None)
            .await
    }

    /// Write data to the remote process's stdin.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<usize> {
        self.channel.write_data(data, SshDataType::None).await
    }

    /// Read the next session event. Returns `Ok(None)` when the session
    /// channel is closed by the peer.
    pub async fn next_event(&self) -> Result<Option<SessionEvent>> {
        match self.channel.next_message().await? {
            Some(msg) => Ok(Some(map_message(msg)?)),
            None => Ok(None),
        }
    }

    /// Wait for the remote process to exit.
    ///
    /// Returns the exit status when the process exited with status 0;
    /// a non-zero exit status is returned as [`Error::ExitStatus`] and a
    /// signal as [`Error::ExitSignal`] (mirrors the Go client, which returns
    /// the exit status as an error from `RunSession`). Data written meanwhile
    /// is discarded. An EOF on the session channel before the exit status is a
    /// protocol error.
    pub async fn wait(&self) -> Result<ExitStatus> {
        loop {
            match self.next_event().await? {
                Some(SessionEvent::ExitStatus(status)) => {
                    if status.status_code == 0 {
                        return Ok(status);
                    }
                    return Err(Error::ExitStatus {
                        status_code: status.status_code,
                    });
                }
                Some(SessionEvent::ExitSignal(signal)) => {
                    return Err(Error::ExitSignal {
                        signal: signal.signal,
                        error_message_utf8: signal.error_message_utf8,
                    });
                }
                Some(_) => {} // data, stderr and requests are discarded
                None => {
                    return Err(Error::Protocol(
                        "the session channel closed before the command's exit status".to_string(),
                    ));
                }
            }
        }
    }

    /// Split the session into a writer (stdin) and a reader (events).
    pub fn split(self) -> (SessionWriter, SessionReader) {
        let writer = SessionWriter {
            writer: ChannelWriter::new(self.channel.inner.clone(), false),
        };
        let reader = SessionReader {
            reader: ChannelReader::new(self.channel.inner.clone()),
        };
        (writer, reader)
    }
}

/// The write half of a [`Session`]: stdin of the remote process.
///
/// Implements [`AsyncWrite`]. Shutting the writer down only stops the write
/// pump: it does *not* finish the channel stream, because the SSHOQ server
/// treats the end of a session channel as the end of the whole conversation
/// (see the [module documentation](self)).
pub struct SessionWriter {
    writer: ChannelWriter,
}

impl SessionWriter {
    /// The channel this writer writes to.
    pub fn channel(&self) -> Channel {
        self.writer.channel()
    }

    /// Write data to the remote process's stdin.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<usize> {
        self.writer.write_data(data, SshDataType::None).await
    }

    /// Close the session channel (a FIN on the stream, which ends the whole
    /// conversation server-side: prefer letting the command exit instead).
    pub fn close(&self) {
        self.writer.close();
    }
}

impl AsyncWrite for SessionWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// The read half of a [`Session`]: a stream of [`SessionEvent`]s.
pub struct SessionReader {
    reader: ChannelReader,
}

impl SessionReader {
    /// The channel this reader reads from.
    pub fn channel(&self) -> Channel {
        self.reader.channel()
    }

    /// Read the next session event. Returns `Ok(None)` when the session
    /// channel is closed by the peer.
    pub async fn next_event(&self) -> Result<Option<SessionEvent>> {
        match self.reader.next_message().await? {
            Some(msg) => Ok(Some(map_message(msg)?)),
            None => Ok(None),
        }
    }
}

impl futures_core::Stream for SessionReader {
    type Item = Result<SessionEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use futures_core::Stream;
        match Stream::poll_next(Pin::new(&mut self.reader), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(msg))) => match map_message(msg) {
                Ok(event) => Poll::Ready(Some(Ok(event))),
                Err(e) => Poll::Ready(Some(Err(e))),
            },
        }
    }
}
