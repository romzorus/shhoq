//! SSH3 version negotiation (mirrors `version.go` in the Go implementation).
//!
//! The version string exchanged in the `User-Agent` request header and the
//! `Server` response header has the format:
//!
//! ```text
//! <protocolName> <major>.<minor> <implementationName> <major>.<minor>.<patch>[ experimental_spec_version=<spec>]
//! ```

use std::fmt;

use crate::error::{Error, Result};

pub const PROTOCOL_MAJOR: u32 = 3;
pub const PROTOCOL_MINOR: u32 = 0;
pub const PROTOCOL_EXPERIMENTAL_SPEC_VERSION: &str = "alpha-00";

pub const SOFTWARE_IMPLEMENTATION_NAME: &str = "shhoq-rust";
pub const SOFTWARE_MAJOR: u32 = 0;
pub const SOFTWARE_MINOR: u32 = 1;
pub const SOFTWARE_PATCH: u32 = 0;

/// The protocol version (e.g. `3.0_alpha-00`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub experimental_spec_version: String,
}

impl ProtocolVersion {
    pub fn new(major: u32, minor: u32, experimental_spec_version: &str) -> Self {
        ProtocolVersion {
            major,
            minor,
            experimental_spec_version: experimental_spec_version.to_string(),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.experimental_spec_version.is_empty() {
            write!(f, "{}.{}", self.major, self.minor)
        } else {
            write!(
                f,
                "{}.{}_{}",
                self.major, self.minor, self.experimental_spec_version
            )
        }
    }
}

/// The software version (e.g. `shhoq-rust 0.1.0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftwareVersion {
    pub implementation_name: String,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SoftwareVersion {
    pub fn new(major: u32, minor: u32, patch: u32, implementation_name: &str) -> Self {
        SoftwareVersion {
            implementation_name: implementation_name.to_string(),
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for SoftwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}.{}.{}",
            self.implementation_name, self.major, self.minor, self.patch
        )
    }
}

/// A full SSH3 version: protocol name + protocol version + software version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub protocol_name: String,
    pub protocol_version: ProtocolVersion,
    pub software_version: SoftwareVersion,
}

impl Version {
    pub fn new(
        protocol_name: &str,
        protocol_version: ProtocolVersion,
        software_version: SoftwareVersion,
    ) -> Self {
        Version {
            protocol_name: protocol_name.to_string(),
            protocol_version,
            software_version,
        }
    }

    /// The version string exchanged during version negotiation.
    pub fn version_string(&self) -> String {
        let mut ret = format!(
            "{} {}.{} {} {}.{}.{}",
            self.protocol_name,
            self.protocol_version.major,
            self.protocol_version.minor,
            self.software_version.implementation_name,
            self.software_version.major,
            self.software_version.minor,
            self.software_version.patch
        );
        if !self.protocol_version.experimental_spec_version.is_empty() {
            ret = format!(
                "{} experimental_spec_version={}",
                ret, self.protocol_version.experimental_spec_version
            );
        }
        ret
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.version_string())
    }
}

/// This implementation's version.
pub fn this_version() -> Version {
    Version::new(
        "SSH",
        ProtocolVersion::new(
            PROTOCOL_MAJOR,
            PROTOCOL_MINOR,
            PROTOCOL_EXPERIMENTAL_SPEC_VERSION,
        ),
        SoftwareVersion::new(
            SOFTWARE_MAJOR,
            SOFTWARE_MINOR,
            SOFTWARE_PATCH,
            SOFTWARE_IMPLEMENTATION_NAME,
        ),
    )
}

/// The versions this client can fall back to when negotiating with an older
/// server (mirrors `AVAILABLE_CLIENT_VERSIONS`). The legacy entries speak the
/// pre-spec-version protocol (protocol version 3.0 without an experimental
/// spec version) understood by sshoq 0.1.3 through 0.1.5 servers.
pub fn available_client_versions() -> Vec<Version> {
    vec![
        this_version(),
        Version::new(
            "SSH",
            ProtocolVersion::new(3, 0, ""),
            SoftwareVersion::new(0, 1, 5, "h4sh5/sshoq"),
        ),
        Version::new(
            "SSH",
            ProtocolVersion::new(3, 0, ""),
            SoftwareVersion::new(0, 1, 4, "h4sh5/sshoq"),
        ),
        Version::new(
            "SSH",
            ProtocolVersion::new(3, 0, ""),
            SoftwareVersion::new(0, 1, 3, "h4sh5/sshoq"),
        ),
    ]
}

/// Tells whether `other` is compatible with this implementation (mirrors
/// `IsVersionSupported`).
pub fn is_version_supported(other: &Version) -> bool {
    let this = this_version();
    if other.protocol_version.major != this.protocol_version.major
        || other.protocol_version.minor != this.protocol_version.minor
    {
        return false;
    }
    // Legacy servers (sshoq 0.1.3 - 0.1.5) only accept protocol version 3.0
    // without an experimental spec version.
    if other.protocol_version.experimental_spec_version.is_empty()
        && other.software_version.implementation_name == "h4sh5/sshoq"
        && other.software_version.major == 0
        && other.software_version.minor == 1
        && other.software_version.patch <= 5
    {
        return other.software_version.patch >= 3;
    }
    other.protocol_version.experimental_spec_version == PROTOCOL_EXPERIMENTAL_SPEC_VERSION
}

/// Parse a version string (mirrors `ParseVersionString`).
pub fn parse_version_string(version_string: &str) -> Result<Version> {
    let fields: Vec<&str> = version_string.split_whitespace().collect();
    if fields.len() < 4 {
        return Err(Error::UnsupportedVersion(format!(
            "invalid ssh version string: {version_string:?}"
        )));
    }
    let protocol_name = fields[0];

    let protocol_fields: Vec<&str> = fields[1].split('_').collect();
    if protocol_fields.is_empty() || protocol_fields.len() > 2 {
        return Err(Error::UnsupportedVersion(format!(
            "invalid protocol version string: {:?}",
            fields[1]
        )));
    }
    let major_minor: Vec<&str> = protocol_fields[0].split('.').collect();
    if major_minor.len() != 2 {
        return Err(Error::UnsupportedVersion(format!(
            "protocol version should be in format x.y, got: {:?}",
            fields[1]
        )));
    }
    let major: u32 = major_minor[0].parse().map_err(|_| {
        Error::UnsupportedVersion(format!("bad protocol major: {:?}", major_minor[0]))
    })?;
    let minor: u32 = major_minor[1].parse().map_err(|_| {
        Error::UnsupportedVersion(format!("bad protocol minor: {:?}", major_minor[1]))
    })?;
    let experimental_spec_version = if protocol_fields.len() == 2 {
        protocol_fields[1].to_string()
    } else {
        String::new()
    };

    let sw_fields: Vec<&str> = fields[3].split('.').collect();
    if sw_fields.len() != 3 {
        return Err(Error::UnsupportedVersion(format!(
            "bad SSH version major.minor.patch field: {:?}",
            fields[3]
        )));
    }
    let sw_major: u32 = sw_fields[0].parse().map_err(|_| {
        Error::UnsupportedVersion(format!("bad software major: {:?}", sw_fields[0]))
    })?;
    let sw_minor: u32 = sw_fields[1].parse().map_err(|_| {
        Error::UnsupportedVersion(format!("bad software minor: {:?}", sw_fields[1]))
    })?;
    let sw_patch: u32 = sw_fields[2].parse().map_err(|_| {
        Error::UnsupportedVersion(format!("bad software patch: {:?}", sw_fields[2]))
    })?;

    let mut protocol_version = ProtocolVersion::new(major, minor, &experimental_spec_version);

    // Custom `key=value` fields; only `experimental_spec_version` is understood.
    for field in &fields[4..] {
        if let Some((key, value)) = field.split_once('=')
            && key == "experimental_spec_version"
        {
            protocol_version.experimental_spec_version = value.to_string();
        }
    }

    Ok(Version::new(
        protocol_name,
        protocol_version,
        SoftwareVersion::new(sw_major, sw_minor, sw_patch, fields[2]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_roundtrip() {
        let v = this_version();
        let s = v.version_string();
        assert_eq!(
            s,
            "SSH 3.0 shhoq-rust 0.1.0 experimental_spec_version=alpha-00"
        );
        let parsed = parse_version_string(&s).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn parse_go_version_string() {
        let v =
            parse_version_string("SSH 3.0 h4sh5/sshoq 0.2.1 experimental_spec_version=alpha-00")
                .unwrap();
        assert_eq!(v.protocol_version.major, 3);
        assert_eq!(v.protocol_version.minor, 0);
        assert_eq!(v.protocol_version.experimental_spec_version, "alpha-00");
        assert_eq!(v.software_version.implementation_name, "h4sh5/sshoq");
        assert!(is_version_supported(&v));
    }

    #[test]
    fn parse_legacy_version_string() {
        // Legacy servers announce no experimental spec version.
        let v = parse_version_string("SSH 3.0 h4sh5/sshoq 0.1.5").unwrap();
        assert_eq!(v.protocol_version.experimental_spec_version, "");
        assert!(is_version_supported(&v));
        // Too old to be supported.
        let old = parse_version_string("SSH 3.0 h4sh5/sshoq 0.1.2").unwrap();
        assert!(!is_version_supported(&old));
    }

    #[test]
    fn unsupported_versions() {
        let v = parse_version_string("SSH 2.0 foo 1.0.0").unwrap();
        assert!(!is_version_supported(&v));
        assert!(parse_version_string("SSH 3.0").is_err());
        assert!(parse_version_string("").is_err());
    }
}
