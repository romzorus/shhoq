//! Client configuration (mirrors `client/config.Config` in the Go client).

use std::net::IpAddr;

use crate::error::{Error, Result};

/// The default URL path of an SSHOQ server.
pub const DEFAULT_URL_PATH: &str = "/sshoq-server";
/// The default SSHOQ port.
pub const DEFAULT_PORT: u16 = 443;

/// Connection configuration: which user to log in as, where the server is,
/// and which environment variables to set on the remote session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    username: String,
    hostname: String,
    port: u16,
    /// The URL path the server serves the conversation endpoint on. Always
    /// starts with `/`.
    url_path: String,
    /// Environment variables as `NAME=VALUE` pairs, sent as `env` channel
    /// requests before the shell/exec request (mirrors `SetEnv`/`SendEnv` in
    /// an OpenSSH config).
    env_vars: Vec<String>,
}

impl Config {
    /// Create a configuration. `url_path` is normalized to start with `/`.
    pub fn new(
        username: impl Into<String>,
        hostname: impl Into<String>,
        port: u16,
        url_path: impl Into<String>,
    ) -> Result<Self> {
        let mut url_path = url_path.into();
        if !url_path.starts_with('/') {
            url_path = format!("/{url_path}");
        }
        Ok(Config {
            username: username.into(),
            hostname: hostname.into(),
            port,
            url_path,
            env_vars: Vec::new(),
        })
    }

    /// A builder for `Config`.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn url_path(&self) -> &str {
        &self.url_path
    }

    /// The environment variables (`NAME=VALUE` pairs) to set on the remote
    /// session.
    pub fn env_vars(&self) -> &[String] {
        &self.env_vars
    }

    /// Set the environment variables (`NAME=VALUE` pairs) to set on the
    /// remote session.
    pub fn set_env_vars(&mut self, env_vars: Vec<String>) -> &mut Self {
        self.env_vars = env_vars;
        self
    }

    /// Add one environment variable (`NAME=VALUE`).
    pub fn add_env_var(&mut self, name: &str, value: &str) -> &mut Self {
        self.env_vars.push(format!("{name}={value}"));
        self
    }

    /// The `host:port` pair in URL format: IPv6 addresses are written inside
    /// square brackets (`[::1]:443`) (mirrors `URLHostnamePort`).
    pub fn url_hostname_port(&self) -> String {
        match self.hostname.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{}]:{}", self.hostname, self.port),
            _ => format!("{}:{}", self.hostname, self.port),
        }
    }

    /// The canonical host representation used as the known_hosts key:
    /// `hostname:port/urlpath` (mirrors `CanonicalHostFormat`).
    pub fn canonical_host_format(&self) -> String {
        format!("{}:{}{}", self.hostname, self.port, self.url_path)
    }

    /// The `:path` of the CONNECT request: the URL path plus the `user` query
    /// parameter, percent-encoded like Go's `url.Values.Encode`.
    pub(crate) fn request_path(&self) -> String {
        format!("{}?user={}", self.url_path, query_escape(&self.username))
    }
}

/// Percent-encode `s` the way Go's `url.QueryEscape` does: everything except
/// `A-Z a-z 0-9 - _ . ~` is escaped, and spaces become `+`.
pub(crate) fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Builder for [`Config`].
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    username: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    url_path: Option<String>,
    env_vars: Vec<String>,
}

impl ConfigBuilder {
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// The server port (default: 443).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// The URL path of the conversation endpoint (default: `/sshoq-server`).
    pub fn url_path(mut self, url_path: impl Into<String>) -> Self {
        self.url_path = Some(url_path.into());
        self
    }

    /// Environment variables (`NAME=VALUE` pairs) to set on the remote session.
    pub fn env_vars(mut self, env_vars: Vec<String>) -> Self {
        self.env_vars = env_vars;
        self
    }

    /// Add one environment variable (`NAME=VALUE`).
    pub fn env_var(mut self, name: &str, value: &str) -> Self {
        self.env_vars.push(format!("{name}={value}"));
        self
    }

    pub fn build(self) -> Result<Config> {
        let username = self
            .username
            .ok_or_else(|| Error::Protocol("config: username is required".to_string()))?;
        let hostname = self
            .hostname
            .ok_or_else(|| Error::Protocol("config: hostname is required".to_string()))?;
        if username.is_empty() {
            return Err(Error::Protocol("config: username is empty".to_string()));
        }
        if hostname.is_empty() {
            return Err(Error::Protocol("config: hostname is empty".to_string()));
        }
        Config::new(
            username,
            hostname,
            self.port.unwrap_or(DEFAULT_PORT),
            self.url_path
                .unwrap_or_else(|| DEFAULT_URL_PATH.to_string()),
        )
        .map(|mut c| {
            c.env_vars = self.env_vars;
            c
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_formatting() {
        let c = Config::new("alice", "example.org", 443, "sshoq-server").unwrap();
        assert_eq!(c.url_path(), "/sshoq-server");
        assert_eq!(c.url_hostname_port(), "example.org:443");
        assert_eq!(c.canonical_host_format(), "example.org:443/sshoq-server");
        assert_eq!(c.request_path(), "/sshoq-server?user=alice");

        let v6 = Config::new("alice", "::1", 22, "/").unwrap();
        assert_eq!(v6.url_hostname_port(), "[::1]:22");
        assert_eq!(v6.canonical_host_format(), "::1:22/");

        let ip = Config::new("bob", "127.0.0.1", 8443, "/x").unwrap();
        assert_eq!(ip.url_hostname_port(), "127.0.0.1:8443");
        assert_eq!(ip.request_path(), "/x?user=bob");
    }

    #[test]
    fn query_escape_matches_go() {
        // Go's url.QueryEscape: unreserved chars stay, space becomes '+',
        // everything else is %XX uppercase.
        assert_eq!(query_escape("alice"), "alice");
        assert_eq!(query_escape("a b+c/d?e=f&g"), "a+b%2Bc%2Fd%3Fe%3Df%26g");
        assert_eq!(query_escape("héllo"), "h%C3%A9llo");
        assert_eq!(query_escape("-_.~"), "-_.~");
    }

    #[test]
    fn builder_defaults() {
        let c = Config::builder()
            .username("alice")
            .hostname("example.org")
            .env_var("FOO", "bar")
            .build()
            .unwrap();
        assert_eq!(c.port(), 443);
        assert_eq!(c.url_path(), "/sshoq-server");
        assert_eq!(c.env_vars(), &["FOO=bar".to_string()]);
        assert!(Config::builder().hostname("x").build().is_err());
        assert!(Config::builder().username("x").build().is_err());
    }
}
