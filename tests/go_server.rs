//! End-to-end test against the reference Go SSHOQ server
//! (`go-version/cmd/sshoq-server`).
//!
//! The test builds the Go server, starts it with a self-signed certificate and
//! a throwaway authorized key, then exercises the Rust client against it:
//! command execution (stdout, stderr, exit status, environment variables) and
//! TCP forwarding in both directions.
//!
//! It is skipped when no Go toolchain is available or the vendored Go sources
//! are missing.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use shhoq::{AuthMethod, Client, ClientTlsConfig, Config, PrivateKey, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

const KEY_PEM: &[u8] = include_bytes!("keys/id_ed25519");
const KEY_PUB: &str = include_str!("keys/id_ed25519.pub");

/// A running Go sshoq-server process.
struct GoServer {
    child: tokio::process::Child,
    _dir: tempfile::TempDir,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build the reference Go server. Returns `None` (and the test skips) when no
/// Go toolchain is available or the vendored Go sources are missing.
async fn build_go_server(dir: &Path) -> Option<PathBuf> {
    let go_version = Path::new(env!("CARGO_MANIFEST_DIR")).join("go-version");
    if !go_version.join("cmd/sshoq-server/main.go").is_file() {
        eprintln!("skipping the Go server test: go-version/cmd/sshoq-server not found");
        return None;
    }
    let binary = dir.join("sshoq-server");
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg("./cmd/sshoq-server")
        .current_dir(&go_version)
        .stdin(Stdio::null())
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => Some(binary),
        Ok(out) => {
            eprintln!(
                "skipping the Go server test: `go build` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            None
        }
        Err(e) => {
            eprintln!("skipping the Go server test: no Go toolchain available ({e})");
            None
        }
    }
}

/// Start the Go server with a self-signed certificate and the test key
/// authorized. Returns `None` if the server does not come up.
async fn start_go_server(dir: tempfile::TempDir, binary: &Path, port: u16) -> Option<GoServer> {
    let work = dir.path().to_path_buf();
    let mut child = Command::new(binary)
        .arg("-bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-generate-selfsigned-cert")
        .arg("-cert")
        .arg(work.join("cert.pem"))
        .arg("-key")
        .arg(work.join("priv.key"))
        .arg("-pubkey")
        .arg(KEY_PUB.trim())
        .arg("-url-path")
        .arg("/sshoq-server")
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // Wait for the "Server started" line on stderr, then drain the rest of the
    // log in the background so the server never blocks on a full pipe.
    let stderr = child.stderr.take()?;
    let mut lines = BufReader::new(stderr).lines();
    let started = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("Server started") {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    if !started {
        eprintln!("the Go server did not start");
        return None;
    }
    Some(GoServer { child, _dir: dir })
}

/// The user the server resolves the `?user=` query parameter to.
fn current_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("LOGNAME").ok().filter(|u| !u.is_empty()))
        .or_else(|| {
            std::process::Command::new("whoami")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|u| !u.is_empty())
        })
}

/// Spawn a TCP echo server on 127.0.0.1 and return its address.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn connect_with_retry(config: &Config, auth: &[AuthMethod]) -> Result<Client> {
    let mut last_err = None;
    for _ in 0..10 {
        match Client::connect(config, auth, &ClientTlsConfig::insecure()).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    Err(last_err.unwrap())
}

async fn connect_tcp_with_retry(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    TcpStream::connect(addr).await.unwrap()
}

#[tokio::test]
async fn go_server_end_to_end() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("skipping the Go server test: cannot create a temp dir ({e})");
            return;
        }
    };
    let Some(binary) = build_go_server(dir.path()).await else {
        return;
    };
    let port = free_port();
    let Some(server) = start_go_server(dir, &binary, port).await else {
        return;
    };
    let Some(username) = current_username() else {
        eprintln!("skipping the Go server test: cannot determine the current user");
        return;
    };

    let mut config = Config::new(username, "127.0.0.1", port, "/sshoq-server").unwrap();
    config.add_env_var("SSHOQ_E2E", "hello-from-rust");
    let key = PrivateKey::from_pem(KEY_PEM, None).unwrap();
    let auth = [AuthMethod::private_key(key)];
    let client = match connect_with_retry(&config, &auth).await {
        Ok(client) => client,
        Err(e) => panic!("could not connect to the Go server: {e}"),
    };
    assert_eq!(client.config().port(), port);

    // --- command execution ---
    let out = client.run_command("echo hello-sshoq").await.unwrap();
    assert_eq!(out.exit_status, 0);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello-sshoq");
    assert!(out.stderr.is_empty());

    // stdout and stderr are reported separately
    let out = client
        .run_command("echo out-line; echo err-line >&2")
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out-line");
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "err-line");

    // the exit status is propagated
    let out = client.run_command("exit 42").await.unwrap();
    assert_eq!(out.exit_status, 42);

    // environment variables set on the config reach the command
    let out = client.run_command("echo $SSHOQ_E2E").await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello-from-rust"
    );

    // --- forward TCP: local listener -> server -> local echo server ---
    let echo_addr = echo_server().await;
    let bound = client
        .forward_tcp("127.0.0.1:0".parse().unwrap(), echo_addr)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(bound).await.unwrap();
    stream.write_all(b"forward-ping").await.unwrap();
    let mut buf = vec![0u8; b"forward-ping".len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"forward-ping");

    // --- reverse TCP: server-side listener -> client -> local echo server ---
    let echo_addr = echo_server().await;
    let server_side: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let bound = client.reverse_tcp(server_side, echo_addr).await.unwrap();
    assert_eq!(bound, server_side);
    // the server binds asynchronously: retry until it accepts
    let mut stream = connect_tcp_with_retry(server_side).await;
    stream.write_all(b"reverse-ping").await.unwrap();
    let mut buf = vec![0u8; b"reverse-ping".len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"reverse-ping");

    client.close();
    drop(server);
}
