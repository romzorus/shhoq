//! # shhoq — an SSHOQ client library for Rust
//!
//! [SSHOQ](https://github.com/h4sh5/sshoq) is an SSH2-like client/server
//! system running commands remotely over the QUIC protocol (SSH over HTTP/3,
//! cf. the SSH3 Internet-Draft). This crate is a client library for it,
//! written in Rust on top of the Rust ecosystem pillars: [`quinn`] (QUIC),
//! [`rustls`] (TLS) and [`tokio`].
//!
//! It mirrors the API of the Go client (`go-version/client`): connect to a
//! server, authenticate (password, private key, bearer token), run commands,
//! open interactive sessions, and set up local/reverse/dynamic port
//! forwarding.
//!
//! # Example
//!
//! ```no_run
//! use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};
//!
//! # async fn example() -> shhoq::Result<()> {
//! let config = Config::new("alice", "example.org", 443, "/sshoq-server")?;
//! let tls = ClientTlsConfig::with_system_roots();
//! let client = Client::connect(
//!     &config,
//!     &[AuthMethod::private_key_file("~/.ssh/id_ed25519")],
//!     &tls,
//! )
//! .await?;
//!
//! let output = client.run_command("echo hello").await?;
//! assert_eq!(output.stdout, b"hello\n");
//! assert_eq!(output.exit_status, 0);
//!
//! client.close();
//! # Ok(())
//! # }
//! ```
//!
//! # A warning about session channels
//!
//! The SSHOQ server treats the end of a *session* channel as the end of the
//! whole conversation. For that reason, shutting down a [`SessionWriter`]
//! does not finish the channel stream (unlike forwarding channels, where a FIN
//! is the TCP-like half-close). See [`session`] for details.
//!
//! [`quinn`]: https://docs.rs/quinn
//! [`rustls`]: https://docs.rs/rustls
//! [`tokio`]: https://docs.rs/tokio

pub mod auth;
pub mod channel;
pub mod client;
pub mod config;
pub mod error;
pub mod key;
pub mod known_hosts;
pub mod message;
pub mod session;
pub mod tls;
pub mod version;

pub(crate) mod conversation;
pub(crate) mod forwarding;
pub(crate) mod h3;
pub(crate) mod wire;

pub use auth::AuthMethod;
pub use channel::{Channel, ChannelReader, ChannelWriter};
pub use client::Client;
pub use config::{Config, ConfigBuilder, DEFAULT_PORT, DEFAULT_URL_PATH};
pub use error::{CommandOutput, Error, ExitSignal, ExitStatus, Result, WindowSize};
pub use key::PrivateKey;
pub use known_hosts::{KnownHosts, default_known_hosts_path};
pub use message::{
    ChannelOpenConfirmationMessage, ChannelOpenFailureMessage, ChannelRequest,
    ChannelRequestMessage, DataOrExtendedDataMessage, EnvRequest, ExecRequest, ExitSignalRequest,
    ExitStatusRequest, Message, PtyRequest, SftpRequest, SignalRequest, SshDataType,
    SubsystemRequest, WindowChangeRequest, X11Request, sftp_op,
};
pub use session::{Session, SessionEvent, SessionReader, SessionWriter};
pub use tls::ClientTlsConfig;
pub use version::{ProtocolVersion, SoftwareVersion, Version};
