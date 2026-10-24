//! The `known_hosts` file (mirrors `known_hosts.go` in the Go implementation).
//!
//! The file holds one line per known host:
//!
//! ```text
//! <canonicalHost> x509-certificate <base64(DER certificate)>
//! ```
//!
//! where `<canonicalHost>` is [`crate::Config::canonical_host_format`]
//! (`hostname:port/urlpath`). The pinned certificates are added to the TLS
//! trust roots when connecting to that host.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use rustls_pki_types::CertificateDer;

use crate::error::{Error, Result};

/// A parsed known_hosts file: canonical host to pinned certificates.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    hosts: HashMap<String, Vec<CertificateDer<'static>>>,
}

impl KnownHosts {
    /// Parse a known_hosts file. A missing file yields an empty `KnownHosts`
    /// (mirrors the Go behavior). Invalid lines are skipped.
    pub fn parse_file(path: impl AsRef<Path>) -> Result<KnownHosts> {
        let contents = match std::fs::read_to_string(path.as_ref()) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KnownHosts::default()),
            Err(e) => {
                return Err(Error::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "could not read known_hosts file {}: {e}",
                        path.as_ref().display()
                    ),
                )));
            }
        };
        Ok(KnownHosts::parse_str(&contents))
    }

    /// Parse known_hosts content.
    pub fn parse_str(contents: &str) -> KnownHosts {
        let mut hosts: HashMap<String, Vec<CertificateDer<'static>>> = HashMap::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 3 || fields[1] != "x509-certificate" {
                continue;
            }
            let Ok(der) = base64::engine::general_purpose::STANDARD.decode(fields[2]) else {
                continue;
            };
            hosts
                .entry(fields[0].to_string())
                .or_default()
                .push(CertificateDer::from(der));
        }
        KnownHosts { hosts }
    }

    /// Whether the file knows `host` (a canonical host format string).
    pub fn knows(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }

    /// The certificates pinned for `host`, if any.
    pub fn certificates(&self, host: &str) -> Option<&[CertificateDer<'static>]> {
        self.hosts.get(host).map(Vec::as_slice)
    }

    /// All pinned (host, certificates) pairs.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &[CertificateDer<'static>])> {
        self.hosts.iter().map(|(h, c)| (h.as_str(), c.as_slice()))
    }

    /// Append a pinned certificate for `host` to the known_hosts file at
    /// `path` (mirrors `AppendKnownHost`). The file is created with mode 0600.
    pub fn append(path: impl AsRef<Path>, host: &str, cert_der: &[u8]) -> Result<()> {
        use std::io::Write;
        let path = path.as_ref();
        let encoded = base64::engine::general_purpose::STANDARD.encode(cert_der);
        let mut options = std::fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("could not open known_hosts file {}: {e}", path.display()),
            ))
        })?;
        // tighten the permissions of a file which already existed with looser ones
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        writeln!(file, "{host} x509-certificate {encoded}")?;
        Ok(())
    }
}

/// The default known_hosts path: `~/.ssh3/known_hosts` (mirrors the Go CLI).
pub fn default_known_hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| Path::new(&home).join(".ssh3").join("known_hosts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let cert = [0x30u8, 0x01, 0x02, 0x03]; // not a real cert, only the encoding matters
        let line = format!(
            "example.org:443/sshoq-server x509-certificate {}",
            base64::engine::general_purpose::STANDARD.encode(cert)
        );
        let kh = KnownHosts::parse_str(&format!(
            "# comment\n\n{line}\ninvalid line\nexample.org:443/sshoq-server x509-certificate !!!\n"
        ));
        assert!(kh.knows("example.org:443/sshoq-server"));
        assert!(!kh.knows("other.org:443/sshoq-server"));
        assert_eq!(
            kh.certificates("example.org:443/sshoq-server")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            kh.certificates("example.org:443/sshoq-server").unwrap()[0].as_ref(),
            &cert
        );
    }

    #[test]
    fn missing_file_is_empty() {
        let kh = KnownHosts::parse_file("/nonexistent/known_hosts").unwrap();
        assert!(!kh.knows("anything"));
    }

    #[test]
    fn append_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        KnownHosts::append(&path, "h:1/", &[1, 2, 3]).unwrap();
        KnownHosts::append(&path, "h:1/", &[4, 5, 6]).unwrap();
        let kh = KnownHosts::parse_file(&path).unwrap();
        assert_eq!(kh.certificates("h:1/").unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
