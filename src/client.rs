//! The SSHOQ client (mirrors `client/client.go` in the Go implementation).
//!
//! [`Client::connect`] dials the server over QUIC, establishes a conversation
//! with an extended CONNECT request (see the `h3` module), trying the given
//! authentication methods in order like OpenSSH, and returns a client ready to
//! open sessions and forwarding channels.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::AuthMethod;
use crate::channel::Channel;
use crate::config::Config;
use crate::conversation::{ConversationInner, DEFAULT_MAX_PACKET_SIZE};
use crate::error::{CommandOutput, Error, Result};
use crate::session::{Session, SessionEvent};
use crate::tls::ClientTlsConfig;
use crate::version::{self, Version};
use crate::{forwarding, h3};

/// The number of bidirectional streams the peer may open concurrently
/// (mirrors `MaxIncomingStreams`).
const MAX_INCOMING_BIDI_STREAMS: u32 = 2048;

/// The number of unidirectional streams the peer may open concurrently
/// (mirrors `MaxIncomingUniStreams`).
const MAX_INCOMING_UNI_STREAMS: u32 = 128;

/// An SSHOQ client: one QUIC connection to a server, carrying one conversation
/// (many SSH3 channels).
pub struct Client {
    conversation: Arc<ConversationInner>,
    config: Config,
    /// Kept alive for the lifetime of the connection (dropping the endpoint
    /// would close it).
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    server_version: Version,
}

/// The outcome of one conversation-establishment attempt.
enum AttemptOutcome {
    /// The conversation is established (HTTP 200).
    Established(Box<h3::ConnectResponse>, Version),
    /// The server rejected the authentication (HTTP 401): try the next method.
    Unauthorized,
}

impl Client {
    /// Connect to an SSHOQ server and establish a conversation.
    ///
    /// The QUIC connection is dialed with the given TLS configuration, then the
    /// given authentication methods are tried in order: when the server answers
    /// 401 (unauthorized) the next method is tried; any other HTTP error aborts
    /// the connection attempt. A 403 triggers SSH3 version negotiation: the
    /// request is retried once with a compatible client version (mirrors the
    /// Go client's `Dial` + `EstablishClientConversation`).
    pub async fn connect(
        config: &Config,
        auth_methods: &[AuthMethod],
        tls: &ClientTlsConfig,
    ) -> Result<Client> {
        if auth_methods.is_empty() {
            return Err(Error::NoSuitableIdentity);
        }

        // Resolve the server address.
        let host_port = config.url_hostname_port();
        let addrs: Vec<_> = tokio::net::lookup_host(host_port.as_str()).await?.collect();
        if addrs.is_empty() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("could not resolve {host_port}"),
            )));
        }

        // Build the QUIC client configuration.
        let rustls_config = tls.build_rustls_config(&config.canonical_host_format())?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
            .map_err(|e| Error::Protocol(format!("could not build the QUIC client config: {e}")))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(1)));
        // Bound the total connection attempt time (handshake + idle) to 10
        // seconds, so a single unreachable address cannot stall the
        // connection for quinn's 30-second default idle timeout.
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(10))
                .expect("10 seconds fits in a QUIC varint"),
        ));
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_INCOMING_BIDI_STREAMS));
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_INCOMING_UNI_STREAMS));
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = match quinn::Endpoint::client("[::]:0".parse().unwrap()) {
            Ok(endpoint) => endpoint,
            Err(_) => quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?,
        };
        endpoint.set_default_client_config(client_config);

        // Try all resolved addresses concurrently, using the first one that
        // connects. A hostname like `localhost` may resolve to both ::1 and
        // 127.0.0.1, but the server may only listen on one of them (e.g.
        // bound to 127.0.0.1 only): connecting to the wrong family would
        // hang until the QUIC idle timeout. Racing the addresses avoids
        // waiting for an unreachable one to time out.
        // The hostname is used as the TLS server name (SNI); it may be a DNS
        // name or an IP literal.
        let mut last_err = None;
        let mut set = tokio::task::JoinSet::new();
        for addr in addrs {
            match endpoint.connect(addr, config.hostname()) {
                Ok(connecting) => {
                    set.spawn(async move {
                        let result = connecting.await;
                        (addr, result)
                    });
                }
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "could not initiate QUIC connection");
                    last_err = Some(Error::Connect(e));
                }
            }
        }
        let conn = wait_for_connection(&mut set, last_err, &host_port).await?;

        // The conversation ID is exported from the TLS keying material
        // (mirrors GenerateConversationID).
        let mut conversation_id = [0u8; 32];
        conn.export_keying_material(&mut conversation_id, b"EXPORTER-SSH3", b"")
            .map_err(|_| {
                Error::ExportKeyingMaterial(
                    "the TLS session does not support exporting keying material".to_string(),
                )
            })?;

        // Open the HTTP/3 control stream, announcing datagram support.
        h3::open_control_stream(&conn).await?;

        // Try each authentication method in sequence, like OpenSSH.
        let authority = config.url_hostname_port();
        let path = config.request_path();
        let mut last_err = None;
        for method in auth_methods {
            let authorization =
                match method.authorization_header(config.username(), &conversation_id) {
                    Ok(authorization) => authorization,
                    Err(e) => {
                        tracing::warn!("could not prepare an auth method: {e}");
                        last_err = Some(e);
                        continue;
                    }
                };
            match Self::attempt(&conn, &authority, &path, &authorization).await {
                Ok(AttemptOutcome::Established(response, server_version)) => {
                    let conversation = ConversationInner::new(
                        conn.clone(),
                        response.control_send,
                        response.control_recv,
                        conversation_id,
                        server_version.clone(),
                    );
                    return Ok(Client {
                        conversation,
                        config: config.clone(),
                        endpoint,
                        server_version,
                    });
                }
                Ok(AttemptOutcome::Unauthorized) => {
                    tracing::debug!("the server rejected an auth method, trying the next one");
                    last_err = Some(Error::Unauthorized);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(Error::NoSuitableIdentity))
    }

    /// One conversation-establishment attempt: the extended CONNECT request,
    /// including SSH3 version negotiation on HTTP 403 (mirrors
    /// `EstablishClientConversation`).
    async fn attempt(
        conn: &quinn::Connection,
        authority: &str,
        path: &str,
        authorization: &str,
    ) -> Result<AttemptOutcome> {
        let mut response = h3::extended_connect(
            conn,
            authority,
            path,
            &version::this_version().version_string(),
            authorization,
        )
        .await?;

        // Version negotiation: older servers strictly check the exact protocol
        // version and answer 403; retry once with a compatible client version.
        if response.status == 403 {
            let this_protocol_version = version::this_version().protocol_version;
            if let Some(server_header) = &response.server_header
                && let Ok(server_version) = version::parse_version_string(server_header)
                && server_version.protocol_version != this_protocol_version
            {
                // an exact version match first (including the software
                // version, for old versions without protocol-version
                // negotiation), else any version with the same protocol
                // version
                let supported = version::available_client_versions();
                let index = supported
                    .iter()
                    .position(|v| *v == server_version)
                    .or_else(|| {
                        supported
                            .iter()
                            .position(|v| v.protocol_version == server_version.protocol_version)
                    });
                if let Some(index) = index {
                    tracing::warn!(
                        "the server runs an old version of the protocol ({server_header}); \
                         retrying with a compatible client version"
                    );
                    response = h3::extended_connect(
                        conn,
                        authority,
                        path,
                        &supported[index].version_string(),
                        authorization,
                    )
                    .await?;
                }
            }
        }

        match response.status {
            200 => {
                let server_header = response.server_header.clone().unwrap_or_default();
                let server_version = version::parse_version_string(&server_header)
                    .map_err(|_| Error::UnsupportedVersion(server_header.clone()))?;
                if !version::is_version_supported(&server_version) {
                    tracing::warn!(
                        "the server runs an unsupported SSH version ({server_header}), continuing anyway"
                    );
                }
                Ok(AttemptOutcome::Established(
                    Box::new(response),
                    server_version,
                ))
            }
            401 => Ok(AttemptOutcome::Unauthorized),
            status => Err(Error::Http {
                status,
                body: if response.body.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&response.body).into_owned())
                },
            }),
        }
    }

    /// The conversation ID, exported from the TLS keying material.
    pub fn conversation_id(&self) -> [u8; 32] {
        self.conversation.conversation_id
    }

    /// The version the server announced during the conversation establishment.
    pub fn server_version(&self) -> &Version {
        &self.server_version
    }

    /// The peer's version as announced in the conversation.
    pub fn peer_version(&self) -> &Version {
        &self.conversation.peer_version
    }

    /// The configuration this client connected with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Open a channel of the given type (`session`, `sftp`, ...).
    ///
    /// The channel-open header is sent lazily, before the first message written
    /// on the channel, and the channel's datagram queue is unbuffered (like
    /// the Go client's `OpenChannel` for session channels).
    pub async fn open_channel(&self, channel_type: &str, max_packet_size: u64) -> Result<Channel> {
        self.conversation
            .open_channel(channel_type, max_packet_size, 0, None, false)
            .await
    }

    /// Open a `direct-tcp` forwarding channel to `remote` (a socket at reach
    /// of the server).
    pub async fn open_tcp_forwarding_channel(&self, remote: SocketAddr) -> Result<Channel> {
        self.conversation.open_tcp_forwarding_channel(remote).await
    }

    /// Open a `direct-udp` forwarding channel to `remote`.
    pub async fn open_udp_forwarding_channel(&self, remote: SocketAddr) -> Result<Channel> {
        self.conversation.open_udp_forwarding_channel(remote).await
    }

    /// Accept the next channel opened by the server, confirming it.
    ///
    /// Reverse-forwarding channels are served automatically and never show up
    /// here; this returns the remaining channel types (`agent-connection`, ...).
    pub async fn accept_channel(&self) -> Result<Channel> {
        self.conversation.accept_channel().await
    }

    /// Open a `session` channel and set the configured environment variables on
    /// it (mirrors the beginning of the Go client's `RunSession`).
    pub async fn open_session(&self) -> Result<Session> {
        let channel = self
            .conversation
            .open_channel("session", DEFAULT_MAX_PACKET_SIZE, 0, None, false)
            .await?;
        let session = Session::new(channel);
        // Environment variables must be requested before the shell or command
        // is started, as they define the environment of the remote process.
        // Malformed entries (empty name, no '=') are skipped.
        for kv in self.config.env_vars() {
            let Some((name, value)) = kv.split_once('=') else {
                tracing::warn!(
                    "skipping invalid environment variable {kv:?}: expected a NAME=VALUE pair"
                );
                continue;
            };
            if name.is_empty() {
                tracing::warn!(
                    "skipping invalid environment variable {kv:?}: expected a NAME=VALUE pair"
                );
                continue;
            }
            session.send_env(name, value).await?;
        }
        Ok(session)
    }

    /// Run a command on the server to completion and collect its output
    /// (mirrors running `sshoq user@host -- command`).
    ///
    /// The command's exit status is returned as data, not as an error: a
    /// non-zero exit status is reported in [`CommandOutput::exit_status`]. The
    /// command being killed by a signal is reported as [`Error::ExitSignal`].
    ///
    /// The session channel is not closed when the command exits: the
    /// conversation parks it (keeps its stream open) until the client is
    /// closed, because the server ends the whole conversation when the stream
    /// of a session channel ends, and dropping a channel would finish its
    /// stream. Stdin is not finished either, for the same reason.
    pub async fn run_command(&self, command: &str) -> Result<CommandOutput> {
        let session = self.open_session().await?;
        session.exec(command).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match session.next_event().await? {
                Some(SessionEvent::Data(data)) => stdout.extend_from_slice(&data),
                Some(SessionEvent::Stderr(data)) => stderr.extend_from_slice(&data),
                Some(SessionEvent::ExitStatus(status)) => {
                    return Ok(CommandOutput {
                        stdout,
                        stderr,
                        exit_status: status.status_code,
                    });
                }
                Some(SessionEvent::ExitSignal(signal)) => {
                    return Err(Error::ExitSignal {
                        signal: signal.signal,
                        error_message_utf8: signal.error_message_utf8,
                    });
                }
                Some(SessionEvent::Request(_)) => {} // unexpected requests are ignored
                None => {
                    return Err(Error::Protocol(
                        "the session channel closed before the command's exit status".to_string(),
                    ));
                }
            }
        }
    }

    /// Forward TCP connections arriving on `local` to `remote` (a socket at
    /// reach of the server), like `sshoq -L` (mirrors `ForwardTCP`).
    ///
    /// Returns the address the local listener is bound to. The forwarding runs
    /// in the background until the conversation is closed.
    pub async fn forward_tcp(&self, local: SocketAddr, remote: SocketAddr) -> Result<SocketAddr> {
        forwarding::forward_tcp(&self.conversation, local, remote).await
    }

    /// Forward UDP datagrams arriving on `local` to `remote`, like `sshoq -L`
    /// with a UDP destination (mirrors `ForwardUDP`).
    ///
    /// Returns the address the local socket is bound to. The forwarding runs in
    /// the background until the conversation is closed.
    pub async fn forward_udp(&self, local: SocketAddr, remote: SocketAddr) -> Result<SocketAddr> {
        forwarding::forward_udp(&self.conversation, local, remote).await
    }

    /// Request a reverse TCP forwarding: the server listens on `local` and
    /// forwards the connections it receives to `remote` (a socket at reach of
    /// this client), like `sshoq -R` (mirrors `ReverseTCP`).
    ///
    /// Returns the address the server listens on (i.e. `local`). The channels
    /// the server opens for the incoming connections are served automatically
    /// by the client, until the conversation is closed.
    pub async fn reverse_tcp(&self, local: SocketAddr, remote: SocketAddr) -> Result<SocketAddr> {
        // The channel is only used to carry the request: it is closed
        // afterwards, and the server opens one open-request-reverse-tcp
        // channel per incoming connection.
        let channel = self
            .conversation
            .request_tcp_reverse_channel(local, remote)
            .await?;
        channel.close();
        Ok(local)
    }

    /// Request a reverse UDP forwarding, like `sshoq -R` with UDP addresses
    /// (mirrors `ReverseUDP`).
    pub async fn reverse_udp(&self, local: SocketAddr, remote: SocketAddr) -> Result<SocketAddr> {
        let channel = self
            .conversation
            .request_udp_reverse_channel(local, remote)
            .await?;
        channel.close();
        Ok(local)
    }

    /// Bind a local SOCKS5 proxy and tunnel the connections asked for by
    /// SOCKS5 clients through the conversation, like `sshoq -D` (mirrors
    /// `DynamicForward`).
    ///
    /// Only SOCKS5 CONNECT requests with "no authentication" are supported.
    /// Returns the address the local listener is bound to.
    pub async fn dynamic_forward(&self, local: SocketAddr) -> Result<SocketAddr> {
        forwarding::dynamic_forward(&self.conversation, local).await
    }

    /// Forward SSH agent connections to the local agent socket at
    /// `socket_path`: accept `agent-connection` channels opened by the server
    /// (after [`Session::request_agent_forwarding`] was called on a session)
    /// and pipe them to the agent (mirrors the Go client's `forwardAgent`).
    ///
    /// This loops until the conversation is closed; channels of other types
    /// are closed. It competes with [`Client::accept_channel`] for the incoming
    /// channels: only one of them may run at a time.
    pub async fn forward_agent(&self, socket_path: impl AsRef<Path>) -> Result<()> {
        let socket_path = socket_path.as_ref().to_path_buf();
        loop {
            let channel = match self.conversation.accept_channel().await {
                Ok(channel) => channel,
                Err(e) => return Err(e),
            };
            if channel.channel_type() == "agent-connection" {
                let socket_path = socket_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_agent_connection(channel, &socket_path).await {
                        tracing::debug!("agent forwarding ended: {e}");
                    }
                });
            } else {
                channel.close();
            }
        }
    }

    /// Close the client: close the conversation and the QUIC connection
    /// (mirrors the Go client's `Close`).
    pub fn close(&self) {
        self.conversation.close();
        self.conversation
            .conn
            .close(quinn::VarInt::from_u32(0), b"session finished");
    }

    /// Wait until the QUIC connection is closed, returning the reason.
    pub async fn wait_closed(&self) -> quinn::ConnectionError {
        self.conversation.conn.closed().await
    }
}

/// One raced connection attempt: the address it targeted and the outcome of
/// awaiting the QUIC handshake.
type ConnectionAttempt = (
    SocketAddr,
    std::result::Result<quinn::Connection, quinn::ConnectionError>,
);

/// Wait for the first successful connection attempt in `set`.
///
/// A definitive error (e.g. a TLS certificate validation failure) aborts all
/// remaining attempts and is returned immediately: retrying on another
/// address cannot succeed. Non-definitive errors (e.g. a timeout on an
/// unreachable address) are only remembered, and the remaining attempts keep
/// running.
async fn wait_for_connection(
    set: &mut tokio::task::JoinSet<ConnectionAttempt>,
    mut last_err: Option<Error>,
    host_port: &str,
) -> Result<quinn::Connection> {
    loop {
        match set.join_next().await {
            Some(Ok((addr, Ok(conn)))) => {
                tracing::debug!(%addr, "QUIC connection established");
                return Ok(conn);
            }
            Some(Ok((addr, Err(e)))) => {
                tracing::debug!(%addr, error = %e, "QUIC connection failed");
                // A definitive error means retrying on another address cannot
                // succeed: abort the remaining attempts and return now,
                // instead of waiting for them to time out.
                if is_definitive_connection_error(&e) {
                    tracing::debug!(%addr, error = %e, "definitive connection error, aborting remaining attempts");
                    set.abort_all();
                    return Err(Error::Connection(e));
                }
                last_err = Some(Error::Connection(e));
            }
            Some(Err(e)) => {
                last_err = Some(Error::Protocol(format!("connection task failed: {e}")));
            }
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("could not resolve {host_port}"),
                    ))
                }));
            }
        }
    }
}

/// Returns true if the error is definitive — retrying on a different address
/// cannot succeed (e.g. TLS certificate validation failure).
fn is_definitive_connection_error(err: &quinn::ConnectionError) -> bool {
    use quinn::ConnectionError;
    match err {
        // TLS/crypto errors have codes in the 0x100..0x200 range.
        ConnectionError::TransportError(transport_err) => {
            let code: u64 = transport_err.code.into();
            (0x100..0x200).contains(&code)
        }
        ConnectionError::VersionMismatch
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_)
        | ConnectionError::Reset => true,
        ConnectionError::TimedOut
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted => false,
    }
}

/// Pipe one `agent-connection` channel to the local SSH agent socket (mirrors
/// the Go client's `forwardAgent`).
async fn forward_agent_connection(channel: Channel, socket_path: &Path) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let socket = tokio::net::UnixStream::connect(socket_path).await?;
    let (mut socket_read, mut socket_write) = socket.into_split();
    let channel2 = channel.clone();
    // channel -> agent socket
    let to_socket = tokio::spawn(async move {
        loop {
            match channel2.next_message().await {
                Ok(Some(crate::message::Message::Data(m))) => {
                    if socket_write.write_all(&m.data).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {} // other messages are ignored
                Ok(None) => break,
                Err(_) => break,
            }
        }
    });
    // agent socket -> channel
    let mut buf = vec![0u8; channel.max_packet_size() as usize];
    let result = loop {
        match socket_read.read(&mut buf).await {
            Ok(0) => break Ok(()), // the agent socket closed
            Ok(n) => {
                if let Err(e) = channel
                    .write_data(&buf[..n], crate::message::SshDataType::None)
                    .await
                {
                    break Err(e);
                }
            }
            Err(e) => break Err(Error::Io(e)),
        }
    };
    to_socket.abort();
    channel.close();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// A TLS/crypto handshake failure, as produced by a certificate
    /// validation error (transport error codes in the 0x100..0x200 range).
    fn crypto_connection_error(alert: u8) -> quinn::ConnectionError {
        quinn::ConnectionError::TransportError(quinn::TransportErrorCode::crypto(alert).into())
    }

    #[test]
    fn definitive_connection_error_classification() {
        // TLS/crypto handshake failures are definitive.
        assert!(is_definitive_connection_error(&crypto_connection_error(46)));
        assert!(is_definitive_connection_error(&crypto_connection_error(0)));
        // Other transport errors are not: another address may behave
        // differently.
        assert!(!is_definitive_connection_error(
            &quinn::ConnectionError::TransportError(
                quinn::TransportErrorCode::APPLICATION_ERROR.into()
            )
        ));
        assert!(is_definitive_connection_error(
            &quinn::ConnectionError::VersionMismatch
        ));
        assert!(is_definitive_connection_error(
            &quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::NO_ERROR,
                frame_type: None,
                reason: bytes::Bytes::new(),
            })
        ));
        assert!(is_definitive_connection_error(
            &quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: bytes::Bytes::new(),
            })
        ));
        assert!(is_definitive_connection_error(
            &quinn::ConnectionError::Reset
        ));
        // Timeouts and resource issues may succeed on another address.
        assert!(!is_definitive_connection_error(
            &quinn::ConnectionError::TimedOut
        ));
        assert!(!is_definitive_connection_error(
            &quinn::ConnectionError::LocallyClosed
        ));
        assert!(!is_definitive_connection_error(
            &quinn::ConnectionError::CidsExhausted
        ));
    }

    #[tokio::test]
    async fn definitive_error_aborts_hanging_attempts() {
        let mut set: tokio::task::JoinSet<ConnectionAttempt> = tokio::task::JoinSet::new();
        // One attempt fails immediately with a definitive error (e.g. the
        // server's self-signed certificate is rejected)...
        set.spawn(async move { (test_addr(4433), Err(crypto_connection_error(46))) });
        // ...while another one hangs forever (e.g. IPv6 when the server only
        // listens on IPv4).
        set.spawn(async move { std::future::pending::<ConnectionAttempt>().await });

        // The error must be returned immediately, not after the hanging
        // attempt times out (30 seconds with quinn's default idle timeout).
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_connection(&mut set, None, "localhost:4433"),
        )
        .await
        .expect("a definitive error must abort the hanging attempts");
        match result {
            Err(Error::Connection(quinn::ConnectionError::TransportError(e))) => {
                let code: u64 = e.code.into();
                assert!((0x100..0x200).contains(&code));
            }
            other => panic!("expected a crypto transport error, got {other:?}"),
        }
        // The hanging attempt was aborted.
        match set.join_next().await {
            Some(Err(e)) => assert!(e.is_cancelled()),
            other => panic!("expected the hanging attempt to be aborted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_definitive_error_waits_for_other_attempts() {
        let mut set: tokio::task::JoinSet<ConnectionAttempt> = tokio::task::JoinSet::new();
        // One attempt fails immediately with a non-definitive error (a
        // timeout on an unreachable address)...
        set.spawn(async move { (test_addr(4433), Err(quinn::ConnectionError::TimedOut)) });
        // ...and another one fails later with a definitive error.
        set.spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            (test_addr(4434), Err(quinn::ConnectionError::Reset))
        });

        // The loop must keep waiting for the second attempt: the error
        // returned is the second attempt's, not the first attempt's timeout.
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_connection(&mut set, None, "localhost:4433"),
        )
        .await
        .expect("the loop must wait for the remaining attempts");
        assert!(start.elapsed() >= Duration::from_millis(100));
        match result {
            Err(Error::Connection(quinn::ConnectionError::Reset)) => {}
            other => panic!("expected the second attempt's error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn all_attempts_failing_returns_an_error() {
        let mut set: tokio::task::JoinSet<ConnectionAttempt> = tokio::task::JoinSet::new();
        set.spawn(async move { (test_addr(4433), Err(quinn::ConnectionError::TimedOut)) });
        set.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            (test_addr(4434), Err(quinn::ConnectionError::TimedOut))
        });
        let result = wait_for_connection(&mut set, None, "localhost:4433").await;
        assert!(matches!(
            result,
            Err(Error::Connection(quinn::ConnectionError::TimedOut))
        ));
    }

    #[tokio::test]
    async fn empty_set_returns_the_previous_error() {
        // When no connection could even be initiated (the errors collected
        // while spawning), that error is returned as-is.
        let mut set: tokio::task::JoinSet<ConnectionAttempt> = tokio::task::JoinSet::new();
        let result =
            wait_for_connection(&mut set, Some(Error::Unauthorized), "localhost:4433").await;
        assert!(matches!(result, Err(Error::Unauthorized)));
    }
}
