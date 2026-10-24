//! Connect to an SSHOQ server and run a command remotely.
//!
//! The server certificate is not verified (`ClientTlsConfig::insecure`): this
//! example is meant for testing against a server with a self-signed
//! certificate. The command's stdout and stderr are printed, and the process
//! exits with the command's exit status.

use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};

#[tokio::main]
async fn main() -> shhoq::Result<()> {
    let config = Config::new("alice", "example.com", 4433, "/secret-path")?;
    let auth = [AuthMethod::private_key_file("~/.ssh/id_ed25519")];
    let client = Client::connect(&config, &auth, &ClientTlsConfig::insecure()).await?;
    let output = client.run_command("echo hello world !").await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    client.close();
    std::process::exit(output.exit_status as i32);
}
