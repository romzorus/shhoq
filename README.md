# shhoq

A Rust client library for [SSHOQ](https://github.com/h4sh5/sshoq) — an SSH2-like
client/server system that runs commands remotely over QUIC (SSH over HTTP/3, per
the [SSH3 Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh3/)).

`shhoq` lets you connect to an SSHOQ server, authenticate (password, private key,
or bearer token), run commands, open interactive sessions, and set up local,
reverse, and dynamic (SOCKS5) port forwarding — all from Rust, with an API that
mirrors the Go client (`go-version/`).

Built on [`quinn`](https://docs.rs/quinn) (QUIC), [`rustls`](https://docs.rs/rustls)
(TLS 1.3), and [`tokio`](https://docs.rs/tokio).

## Installation

Add `shhoq` to your `Cargo.toml`:

```toml
[dependencies]
shhoq = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick start

```rust,no_run
use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};

#[tokio::main]
async fn main() -> shhoq::Result<()> {
    // Where the server is and who to log in as.
    let config = Config::new("alice", "example.org", 443, "/sshoq-server")?;

    // Trust the system root certificates.
    let tls = ClientTlsConfig::with_system_roots();

    // Connect, trying the given authentication methods in order (like OpenSSH).
    let client = Client::connect(
        &config,
        &[AuthMethod::private_key_file("~/.ssh/id_ed25519")],
        &tls,
    )
    .await?;

    // Run a command to completion and collect its output.
    let output = client.run_command("echo hello").await?;
    assert_eq!(output.stdout, b"hello\n");
    assert_eq!(output.exit_status, 0);

    client.close();
    Ok(())
}
```

A runnable version of this example lives in
[`examples/run_command.rs`](examples/run_command.rs).

## Concepts

```
Config ──┐
         ├──> Client::connect() ──> Client
AuthMethod ─┘         │
ClientTlsConfig ──────┘
                       │
                       ├── run_command() ──> CommandOutput
                       ├── open_session() ──> Session (exec, shell, pty, env, signals)
                       ├── open_channel() ──> Channel (raw SSH3 channel)
                       ├── forward_tcp / forward_udp   (local forwarding,  like ssh -L)
                       ├── reverse_tcp / reverse_udp   (reverse forwarding, like ssh -R)
                       ├── dynamic_forward             (SOCKS5 proxy, like ssh -D)
                       └── forward_agent               (SSH agent forwarding, like ssh -A)
```

A [`Client`] is one QUIC connection to a server carrying one SSH3 conversation.
A conversation multiplexes many SSH3 **channels** over QUIC streams and datagrams.

## API overview

### Connecting

```rust,no_run
use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};

# async fn connect() -> shhoq::Result<()> {
// Server location and login user.
let config = Config::builder()
    .username("alice")
    .hostname("example.org")
    .port(443)                        // default: 443
    .url_path("/sshoq-server")        // default: "/sshoq-server"
    .env_var("LANG", "en_US.UTF-8")   // sent as `env` requests before exec/shell
    .build()?;

// TLS: system roots, a known_hosts file, extra roots, or insecure (testing only).
let tls = ClientTlsConfig::with_system_roots()
    .with_known_hosts_file("~/.ssh/sshoq_known_hosts");

// Authentication methods are tried in order, like OpenSSH.
let auth = [
    AuthMethod::private_key_file("~/.ssh/id_ed25519"),
    AuthMethod::private_key_file_with_passphrase("~/.ssh/id_rsa", "secret"),
    AuthMethod::password("hunter2"),
    AuthMethod::bearer_token("eyJhbGciOi..."),  // e.g. an OIDC ID token
];

let client = Client::connect(&config, &auth, &tls).await?;
# Ok(())
# }
```

`AuthMethod` variants:

| Variant | Description |
|---|---|
| `Password` | HTTP Basic auth (`user:password`) |
| `PrivateKeyFile` | Public-key auth from a PEM key file (OpenSSH, PKCS#8, PKCS#1, SEC1; optionally encrypted) |
| `PrivateKey` | Public-key auth from an already-parsed [`PrivateKey`] |
| `BearerToken` | Raw bearer token (e.g. OIDC), sent as `Authorization: Bearer` |

Public-key auth signs a short-lived JWT (RS256 / EdDSA / ES256 depending on the
key type) bound to the conversation ID exported from the TLS keying material.

`ClientTlsConfig` options:

| Method | Description |
|---|---|
| `with_system_roots()` | Trust the operating system's root certificates |
| `with_known_hosts_file(path)` | Additionally trust certificates pinned in a `known_hosts` file for the host |
| `with_root_certificate(der)` / `with_root_certificates(ders)` | Trust additional root CA certificates |
| `insecure()` | Disable certificate verification entirely (testing only, mirrors `sshoq -insecure`) |

### Running commands

```rust,no_run
# use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};
# async fn run(client: &Client) -> shhoq::Result<()> {
let output = client.run_command("uname -a").await?;
println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
println!("exit status: {}", output.exit_status);
# Ok(())
# }
```

`run_command` returns a [`CommandOutput`] with `stdout`, `stderr`, and
`exit_status`. A non-zero exit status is **data**, not an error. If the remote
process is killed by a signal, `run_command` returns `Err(Error::ExitSignal)`.

### Interactive sessions

For full control (stdin, PTY, signals, streaming output), open a [`Session`]:

```rust,no_run
# use shhoq::{Client, SessionEvent, WindowSize};
# async fn session(client: &Client) -> shhoq::Result<()> {
let session = client.open_session().await?;

// Set environment variables (must be done before exec/shell).
session.send_env("MY_VAR", "42").await?;

// Request a pseudo-terminal, then start a shell.
session.request_pty("xterm-256color", WindowSize {
    char_width: 120,
    char_height: 40,
    pixel_width: 0,
    pixel_height: 0,
}).await?;
session.start_shell().await?;

// Write to stdin and read events as they arrive.
session.write_stdin(b"ls -la\n").await?;
while let Some(event) = session.next_event().await? {
    match event {
        SessionEvent::Data(data)       => print!("{}", String::from_utf8_lossy(&data)),
        SessionEvent::Stderr(data)     => eprint!("{}", String::from_utf8_lossy(&data)),
        SessionEvent::ExitStatus(s)    => { println!("exit: {}", s.status_code); break; }
        SessionEvent::ExitSignal(sig)  => { println!("killed by {}", sig.signal); break; }
        SessionEvent::Request(_)       => {} // unexpected requests are surfaced here
    }
}
# Ok(())
# }
```

A `Session` can also:

- `exec(command)` — run a command (instead of `start_shell`).
- `start_subsystem("sftp")` — start a subsystem.
- `signal("TERM")` — send a signal (name without the `SIG` prefix).
- `window_change(size)` — notify of a terminal resize.
- `request_agent_forwarding()` — ask the server to expose its SSH agent
  (serve the resulting channels with `Client::forward_agent`).
- `wait()` — block until the remote process exits, returning its `ExitStatus`
  (non-zero status and signals are returned as `Err`).
- `split()` — split into a `SessionWriter` (implements `tokio::io::AsyncWrite`,
  for stdin) and a `SessionReader` (implements `futures_core::Stream`, yields
  `SessionEvent`s).

> **Note on closing sessions.** The SSHOQ server treats the end of a *session*
> channel as the end of the whole conversation. Shutting down a `SessionWriter`
> therefore does **not** finish the channel stream, and dropping a `Session`
> parks the channel instead of closing it. Let the remote command exit on its
> own, or call `Client::close()` to end everything.

### Raw channels

For lower-level access (e.g. implementing SFTP), open a raw [`Channel`]:

```rust,no_run
# use shhoq::{Client, SshDataType};
# async fn raw(client: &Client) -> shhoq::Result<()> {
let channel = client.open_channel("sftp", 32768).await?;

// Write data and SSH3 messages.
channel.write_data(b"payload", SshDataType::None).await?;

// Read the next SSH3 message.
while let Some(msg) = channel.next_message().await? {
    // msg is a shhoq::Message (Data, ChannelRequest, ...)
}

// Channels can also be split into a ChannelWriter (AsyncWrite) and
// a ChannelReader (AsyncRead + Stream), and carry raw QUIC datagrams
// via send_datagram / receive_datagram.
# Ok(())
# }
```

### Port forwarding

```rust,no_run
# use shhoq::Client;
# use std::net::SocketAddr;
# async fn fwd(client: &Client) -> shhoq::Result<()> {
let local: SocketAddr  = "127.0.0.1:8080".parse().unwrap();
let remote: SocketAddr = "10.0.0.5:80".parse().unwrap();

// Local forwarding (like ssh -L): connections to `local` are forwarded
// to `remote` through the server.
let bound = client.forward_tcp(local, remote).await?;

// Reverse forwarding (like ssh -R): the server listens on `local` and
// forwards incoming connections back to `remote` on this machine.
client.reverse_tcp("0.0.0.0:2222".parse().unwrap(), "127.0.0.1:22".parse().unwrap()).await?;

// Dynamic forwarding (like ssh -D): a local SOCKS5 proxy (no-auth CONNECT).
client.dynamic_forward("127.0.0.1:1080".parse().unwrap()).await?;

// UDP variants exist too: forward_udp / reverse_udp.
# Ok(())
# }
```

Forwarding runs in the background until the conversation is closed.

### SSH agent forwarding

```rust,no_run
# use shhoq::Client;
# async fn agent(client: &Client) -> shhoq::Result<()> {
// On a session, request agent forwarding (like ssh -A) ...
let session = client.open_session().await?;
session.request_agent_forwarding().await?;
session.exec("ssh-add -l").await?;

// ... then pipe the server's agent-connection channels to the local agent.
client.forward_agent("/run/user/1000/ssh-agent").await?;
# Ok(())
# }
```

### Key and host management

```rust,no_run
# use shhoq::{KnownHosts, PrivateKey};
# fn keys() -> shhoq::Result<()> {
// Parse a private key from PEM bytes or a file (OpenSSH, PKCS#8, PKCS#1, SEC1).
let key = PrivateKey::from_pem_file("~/.ssh/id_ed25519", Some("passphrase"))?;

// Generate a new Ed25519 key.
let mut rng = rand::rngs::OsRng;
let key = PrivateKey::generate_ed25519(&mut rng);

// Read the public key in OpenSSH authorized_keys format.
let pubkey = key.public_key_openssh();

// Parse a known_hosts file (canonical host -> pinned certificates).
let known = KnownHosts::parse_file("~/.ssh/sshoq_known_hosts")?;
if let Some(certs) = known.certificates("example.org:443/sshoq-server") {
    // certs: &[CertificateDer] — pass them to ClientTlsConfig::with_root_certificates
}
# Ok(())
# }
```

### Error handling

All fallible operations return `shhoq::Result<T>` (`Result<T, shhoq::Error>`).
Notable `Error` variants:

| Variant | Meaning |
|---|---|
| `Unauthorized` | The server rejected all authentication methods (HTTP 401) |
| `Http { status, body }` | Unexpected HTTP status during conversation setup |
| `UnsupportedVersion` | The server runs an incompatible SSH3 version |
| `ExitStatus { status_code }` | A remote process exited non-zero (from `Session::wait`) |
| `ExitSignal { signal, .. }` | A remote process was killed by a signal |
| `NoSuitableIdentity` | No usable authentication method was provided |
| `Connection` / `Read` / `Write` / ... | QUIC-level errors |
| `Io` / `Tls` / `Key` / `Protocol` / ... | I/O, TLS, key parsing, protocol errors |

## Protocol notes

- Transport: QUIC over UDP, TLS 1.3 via rustls. The conversation ID is derived
  from the TLS exporter (`EXPORTER-SSH3`).
- The conversation is established with an HTTP/3 extended CONNECT request;
  channels are HTTP/3 streams hijacked by the frame type `0xaf3627e6` and may
  also carry raw QUIC datagrams.
- SSH3 messages reuse the RFC 4250/4254 numbering and wire format
  (`varint(type) || payload`, SSH strings as `varint(len) || bytes`).
- SSH3 version negotiation: on HTTP 403 the client retries once with a
  compatible version announced by the server.

## License

Apache-2.0. See the [Go project's LICENSE](go-version/LICENSE) for the upstream license.
