//! Authentication methods (mirrors the Go client's auth methods and
//! `Identity.SetAuthorizationHeader`).
//!
//! Methods are tried in order, like OpenSSH: when the server answers 401
//! (unauthorized) the next method is tried; any other HTTP error aborts the
//! connection attempt.

use std::path::{Path, PathBuf};

use base64::Engine;

use crate::error::Result;
use crate::key::PrivateKey;

/// An authentication method to try when connecting.
///
/// The variants map to the Go client's auth methods:
///
/// | Go                              | Rust                                  |
/// |---------------------------------|---------------------------------------|
/// | `PasswordAuthMethod`            | [`AuthMethod::Password`]              |
/// | `PrivkeyFileAuthMethod`         | [`AuthMethod::PrivateKeyFile`]        |
/// | (parsed identity)               | [`AuthMethod::PrivateKey`]            |
/// | `OidcAuthMethod` / raw identity | [`AuthMethod::BearerToken`]           |
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Password authentication: sent as HTTP Basic auth
    /// (`Authorization: Basic base64(user:password)`).
    Password(String),
    /// Public-key authentication from a PEM private key file (OpenSSH, PKCS#8,
    /// PKCS#1 or SEC1 format). `passphrase` decrypts encrypted OpenSSH keys.
    PrivateKeyFile {
        path: PathBuf,
        passphrase: Option<String>,
    },
    /// Public-key authentication from an already-parsed private key.
    PrivateKey(Box<PrivateKey>),
    /// A raw bearer token (e.g. an OIDC ID token), sent as
    /// `Authorization: Bearer <token>`.
    BearerToken(String),
}

impl AuthMethod {
    /// Password authentication.
    pub fn password(password: impl Into<String>) -> Self {
        AuthMethod::Password(password.into())
    }

    /// Public-key authentication from a private key file.
    pub fn private_key_file(path: impl Into<PathBuf>) -> Self {
        AuthMethod::PrivateKeyFile {
            path: path.into(),
            passphrase: None,
        }
    }

    /// Public-key authentication from a private key file, with a passphrase for
    /// encrypted keys.
    pub fn private_key_file_with_passphrase(
        path: impl Into<PathBuf>,
        passphrase: impl Into<String>,
    ) -> Self {
        AuthMethod::PrivateKeyFile {
            path: path.into(),
            passphrase: Some(passphrase.into()),
        }
    }

    /// Public-key authentication from an already-parsed private key.
    pub fn private_key(key: PrivateKey) -> Self {
        AuthMethod::PrivateKey(Box::new(key))
    }

    /// A raw bearer token.
    pub fn bearer_token(token: impl Into<String>) -> Self {
        AuthMethod::BearerToken(token.into())
    }

    /// The default private key files OpenSSH tries (`~/.ssh/id_*`), mirroring
    /// `NewDefaultPrivkeyFileAuthMethods`.
    pub fn default_private_key_files() -> Vec<AuthMethod> {
        let mut methods = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            let home = Path::new(&home).join(".ssh");
            for name in [
                "id_ed25519",
                "id_ecdsa",
                "id_rsa",
                "id_dsa",
                "id_xmss",
                "id_ecdsa_sk",
                "id_ed25519_sk",
            ] {
                let path = home.join(name);
                if path.is_file() {
                    methods.push(AuthMethod::private_key_file(path));
                }
            }
        }
        methods
    }

    /// Build the value of the `Authorization` header for one connection
    /// attempt on the given conversation.
    ///
    /// The conversation ID is needed to build the `jti` claim of the JWT used
    /// by public-key authentication.
    pub(crate) fn authorization_header(
        &self,
        username: &str,
        conversation_id: &[u8; 32],
    ) -> Result<String> {
        match self {
            AuthMethod::Password(password) => Ok(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
            )),
            AuthMethod::PrivateKeyFile { path, passphrase } => {
                let key = PrivateKey::from_pem_file(path, passphrase.as_deref())?;
                let token = key.jwt_bearer_token(username, conversation_id)?;
                Ok(format!("Bearer {token}"))
            }
            AuthMethod::PrivateKey(key) => {
                let token = key.jwt_bearer_token(username, conversation_id)?;
                Ok(format!("Bearer {token}"))
            }
            AuthMethod::BearerToken(token) => Ok(format!("Bearer {token}")),
        }
    }
}
