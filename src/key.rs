//! Private key parsing and JWT bearer-token construction for public-key
//! authentication.
//!
//! SSHOQ authenticates public keys with a JWT sent as
//! `Authorization: Bearer <jwt>` (mirrors `BuildJWTBearerToken` in the Go
//! client). The token is signed with RS256 (RSA PKCS#1 v1.5 + SHA-256),
//! EdDSA (Ed25519) or ES256 (ECDSA P-256 + SHA-256), depending on the key
//! type, and carries the claims:
//!
//! ```text
//! iss       = username
//! iat       = now (unix seconds)
//! exp       = now + 10s
//! sub       = "ssh3"
//! aud       = "unused"
//! client_id = "ssh3-<username>"
//! jti       = base64-std(conversation ID)
//! ```
//!
//! Supported private key formats: OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`,
//! optionally encrypted with bcrypt + AES-256-CTR), PKCS#8 (`PRIVATE KEY`),
//! PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`).

use base64::Engine;
use rsa::signature::{SignatureEncoding, Signer as _};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::wire::{SliceReader, append_u32_string};

/// A private key usable for SSHOQ public-key authentication.
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA key, signed with RS256 (PKCS#1 v1.5 + SHA-256).
    Rsa(rsa::pkcs1v15::SigningKey<Sha256>),
    /// Ed25519 key, signed with EdDSA.
    Ed25519(ed25519_dalek::SigningKey),
    /// ECDSA P-256 key, signed with ES256 (raw R || S signature).
    EcdsaP256(p256::ecdsa::SigningKey),
}

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NISTP256: &str = "1.2.840.10045.3.1.7";

impl PrivateKey {
    /// Parse a PEM-encoded private key.
    ///
    /// `passphrase` decrypts OpenSSH-encrypted keys; it is ignored (and may be
    /// `None`) for unencrypted keys.
    pub fn from_pem(pem: &[u8], passphrase: Option<&str>) -> Result<Self> {
        // ssh-keygen wraps OpenSSH keys at 70 base64 characters per line while
        // other tools use 64, so detect the line width instead of assuming it.
        let mut decoder = pem_rfc7468::Decoder::new_detect_wrap(pem)
            .map_err(|e| Error::Key(format!("invalid PEM document: {e}")))?;
        let label = decoder.type_label();
        let mut der = Vec::new();
        decoder
            .decode_to_end(&mut der)
            .map_err(|e| Error::Key(format!("invalid PEM document: {e}")))?;
        match label {
            "OPENSSH PRIVATE KEY" => Self::from_openssh_der(&der, passphrase),
            "PRIVATE KEY" => Self::from_pkcs8_der(&der),
            "RSA PRIVATE KEY" => Self::from_pkcs1_der(&der),
            "EC PRIVATE KEY" => Self::from_sec1_der(&der),
            "ENCRYPTED PRIVATE KEY" => Err(Error::Key(
                "PKCS#8 encrypted private keys (ENCRYPTED PRIVATE KEY) are not supported, \
                 use an OpenSSH or unencrypted PKCS#8 key instead"
                    .to_string(),
            )),
            other => Err(Error::Key(format!(
                "unsupported PEM label {other:?}, expected OPENSSH PRIVATE KEY, PRIVATE KEY, \
                 RSA PRIVATE KEY or EC PRIVATE KEY"
            ))),
        }
    }

    /// Read and parse a PEM-encoded private key file.
    pub fn from_pem_file(
        path: impl AsRef<std::path::Path>,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let pem = std::fs::read(path.as_ref()).map_err(|e| {
            Error::Key(format!(
                "could not read key file {}: {e}",
                path.as_ref().display()
            ))
        })?;
        Self::from_pem(&pem, passphrase)
    }

    /// Generate a fresh Ed25519 key with the given random number generator.
    pub fn generate_ed25519(rng: &mut impl rsa::rand_core::CryptoRngCore) -> Self {
        PrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(rng))
    }

    fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        use pkcs8::der::Decode;
        let info = pkcs8::PrivateKeyInfo::from_der(der)
            .map_err(|e| Error::Key(format!("invalid PKCS#8 private key: {e}")))?;
        let oid = info.algorithm.oid;
        if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_RSA_ENCRYPTION) {
            let key = rsa::RsaPrivateKey::try_from(info)
                .map_err(|e| Error::Key(format!("invalid RSA private key: {e}")))?;
            Ok(PrivateKey::Rsa(rsa::pkcs1v15::SigningKey::new(key)))
        } else if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_ED25519) {
            use pkcs8::der::asn1::OctetStringRef;
            // RFC 8410: the private key is an OCTET STRING wrapping the seed.
            let octets = OctetStringRef::from_der(info.private_key)
                .map_err(|e| Error::Key(format!("invalid Ed25519 private key: {e}")))?;
            let seed: &[u8; 32] = octets.as_bytes().try_into().map_err(|_| {
                Error::Key("invalid Ed25519 private key: expected 32 bytes".to_string())
            })?;
            Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                seed,
            )))
        } else if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_EC_PUBLIC_KEY) {
            // The curve may be named by the algorithm identifier parameters
            // when the inner SEC1 structure omits them.
            let curve = info
                .algorithm
                .parameters
                .map(|params| pkcs8::der::asn1::ObjectIdentifier::from_bytes(params.value()))
                .transpose()
                .map_err(|e| Error::Key(format!("invalid EC curve OID: {e}")))?;
            Self::ec_from_sec1(info.private_key, curve)
        } else {
            Err(Error::Key(format!(
                "unsupported PKCS#8 key algorithm OID {oid}"
            )))
        }
    }

    fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let key = pkcs1::RsaPrivateKey::try_from(der)
            .map_err(|e| Error::Key(format!("invalid PKCS#1 RSA private key: {e}")))?;
        Self::rsa_from_pkcs1(&key)
    }

    fn from_sec1_der(der: &[u8]) -> Result<Self> {
        Self::ec_from_sec1(der, None)
    }

    fn rsa_from_pkcs1(key: &pkcs1::RsaPrivateKey) -> Result<Self> {
        use rsa::BigUint;
        let n = BigUint::from_bytes_be(key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(key.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(key.private_exponent.as_bytes());
        let primes = vec![
            BigUint::from_bytes_be(key.prime1.as_bytes()),
            BigUint::from_bytes_be(key.prime2.as_bytes()),
        ];
        let key = rsa::RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|e| Error::Key(format!("invalid RSA private key: {e}")))?;
        Ok(PrivateKey::Rsa(rsa::pkcs1v15::SigningKey::new(key)))
    }

    /// Parse a SEC1 EC private key. The curve is named either inside the SEC1
    /// structure or, for PKCS#8 keys whose inner SEC1 omits it, by the
    /// algorithm identifier (`curve_from_alg`).
    fn ec_from_sec1(der: &[u8], curve_from_alg: Option<pkcs8::ObjectIdentifier>) -> Result<Self> {
        let key = sec1::EcPrivateKey::try_from(der)
            .map_err(|e| Error::Key(format!("invalid SEC1 EC private key: {e}")))?;
        let curve = match &key.parameters {
            Some(sec1::EcParameters::NamedCurve(oid)) => Some(*oid),
            None => curve_from_alg,
        };
        match curve {
            Some(oid) if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_NISTP256) => {}
            Some(oid) => {
                return Err(Error::Key(format!(
                    "unsupported EC curve {oid}, only nistp256 (P-256) is supported"
                )));
            }
            None => {
                return Err(Error::Key(
                    "unsupported SEC1 EC parameters: expected a named curve".to_string(),
                ));
            }
        }
        let secret = p256_secret_from_scalar(key.private_key)?;
        Ok(PrivateKey::EcdsaP256(p256::ecdsa::SigningKey::from(
            &secret,
        )))
    }

    /// Parse an OpenSSH-format private key (`openssh-key-v1`).
    fn from_openssh_der(der: &[u8], passphrase: Option<&str>) -> Result<Self> {
        let mut r = SliceReader::new(der);
        let magic = r.read_bytes(15)?;
        if magic != b"openssh-key-v1\0" {
            return Err(Error::Key("invalid OpenSSH private key magic".to_string()));
        }
        let ciphername = read_ssh_string_utf8(&mut r)?;
        let kdfname = read_ssh_string_utf8(&mut r)?;
        let kdfoptions = r.read_u32_string()?;
        let nkeys = r.read_u32_be()?;
        if nkeys != 1 {
            return Err(Error::Key(format!(
                "OpenSSH private keys with {nkeys} keys are not supported"
            )));
        }
        let _pubkey_blob = r.read_u32_string()?;
        let mut section = r.read_u32_string()?.to_vec();

        if ciphername != "none" {
            let passphrase = passphrase.ok_or_else(|| {
                Error::Key(format!(
                    "the OpenSSH private key is encrypted ({ciphername}/{kdfname}) but no passphrase was provided"
                ))
            })?;
            if kdfname != "bcrypt" {
                return Err(Error::Key(format!(
                    "unsupported OpenSSH key KDF {kdfname:?}, only bcrypt is supported"
                )));
            }
            let mut kdf = SliceReader::new(kdfoptions);
            let salt = kdf.read_u32_string()?;
            let rounds = kdf.read_u32_be()?;
            let mut key_material = [0u8; 48]; // 32 bytes key + 16 bytes IV
            bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut key_material)
                .map_err(|e| Error::Key(format!("bcrypt key derivation failed: {e}")))?;
            let key: &[u8; 32] = key_material[..32].try_into().expect("32 bytes");
            let iv: &[u8; 16] = key_material[32..].try_into().expect("16 bytes");
            aes256_ctr_crypt(key, iv, &mut section);
        }

        let mut r = SliceReader::new(&section);
        let check1 = r.read_u32_be()?;
        let check2 = r.read_u32_be()?;
        if check1 != check2 {
            return Err(Error::Key(
                "invalid OpenSSH private key: decryption failed (bad passphrase?)".to_string(),
            ));
        }
        let keytype = read_ssh_string_utf8(&mut r)?;
        match keytype.as_str() {
            "ssh-rsa" => {
                // OpenSSH order: modulus, public exponent, private exponent,
                // iqmp, p, q (all mpints).
                let n = r.read_u32_string()?;
                let e = r.read_u32_string()?;
                let d = r.read_u32_string()?;
                let _iqmp = r.read_u32_string()?;
                let p = r.read_u32_string()?;
                let q = r.read_u32_string()?;
                use rsa::BigUint;
                let key = rsa::RsaPrivateKey::from_components(
                    BigUint::from_bytes_be(n),
                    BigUint::from_bytes_be(e),
                    BigUint::from_bytes_be(d),
                    vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
                )
                .map_err(|e| Error::Key(format!("invalid RSA private key: {e}")))?;
                Ok(PrivateKey::Rsa(rsa::pkcs1v15::SigningKey::new(key)))
            }
            "ssh-ed25519" => {
                let _pk = r.read_u32_string()?;
                let sk = r.read_u32_string()?;
                let seed: &[u8; 32] =
                    sk.get(..32)
                        .and_then(|s| s.try_into().ok())
                        .ok_or_else(|| {
                            Error::Key(
                                "invalid OpenSSH ed25519 private key: bad secret key".to_string(),
                            )
                        })?;
                Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                    seed,
                )))
            }
            "ecdsa-sha2-nistp256" => {
                let curve = read_ssh_string_utf8(&mut r)?;
                if curve != "nistp256" {
                    return Err(Error::Key(format!(
                        "unsupported OpenSSH EC curve {curve:?}, only nistp256 is supported"
                    )));
                }
                let _q = r.read_u32_string()?;
                let d = r.read_u32_string()?;
                let secret = p256_secret_from_scalar(d)?;
                Ok(PrivateKey::EcdsaP256(p256::ecdsa::SigningKey::from(
                    &secret,
                )))
            }
            other => Err(Error::Key(format!(
                "unsupported OpenSSH key type {other:?}"
            ))),
        }
    }

    /// The JWT signing algorithm used with this key (`RS256`, `EdDSA` or
    /// `ES256`).
    pub fn algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Rsa(_) => "RS256",
            PrivateKey::Ed25519(_) => "EdDSA",
            PrivateKey::EcdsaP256(_) => "ES256",
        }
    }

    /// Sign `data` with this key; returns the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Rsa(key) => {
                let sig: rsa::pkcs1v15::Signature = key.sign(data);
                Ok(sig.to_bytes().to_vec())
            }
            PrivateKey::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                let sig: ed25519_dalek::Signature = key.sign(data);
                Ok(sig.to_bytes().to_vec())
            }
            PrivateKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = key.sign(data);
                // ES256 signatures are the raw 64-byte R || S concatenation.
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// Build the JWT bearer token for authenticating as `username` on the
    /// conversation identified by `conversation_id` (mirrors
    /// `BuildJWTBearerToken`).
    pub fn jwt_bearer_token(&self, username: &str, conversation_id: &[u8; 32]) -> Result<String> {
        let header = serde_json::json!({"alg": self.algorithm(), "typ": "JWT"});
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Key(format!("system clock error: {e}")))?
            .as_secs();
        let claims = serde_json::json!({
            "iss": username,
            "iat": now,
            "exp": now + 10,
            "sub": "ssh3",
            "aud": "unused",
            "client_id": format!("ssh3-{username}"),
            "jti": base64::engine::general_purpose::STANDARD.encode(conversation_id),
        });
        let signing_input = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let signature = self.sign(signing_input.as_bytes())?;
        Ok(format!(
            "{}.{}",
            signing_input,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    /// The public key in OpenSSH `authorized_keys` format
    /// (`<key-type> <base64> <comment>`), e.g. for building a server's
    /// authorized identities.
    pub fn public_key_openssh(&self) -> String {
        let (key_type, blob) = match self {
            PrivateKey::Rsa(key) => {
                let pubkey: &rsa::RsaPrivateKey = key.as_ref();
                let mut blob = Vec::new();
                append_u32_string(&mut blob, b"ssh-rsa");
                append_mpint(&mut blob, pubkey.e().to_bytes_be().as_slice());
                append_mpint(&mut blob, pubkey.n().to_bytes_be().as_slice());
                ("ssh-rsa", blob)
            }
            PrivateKey::Ed25519(key) => {
                let mut blob = Vec::new();
                append_u32_string(&mut blob, b"ssh-ed25519");
                append_u32_string(&mut blob, &key.verifying_key().to_bytes());
                ("ssh-ed25519", blob)
            }
            PrivateKey::EcdsaP256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let mut blob = Vec::new();
                append_u32_string(&mut blob, b"ecdsa-sha2-nistp256");
                append_u32_string(&mut blob, b"nistp256");
                append_u32_string(&mut blob, point.as_bytes());
                ("ecdsa-sha2-nistp256", blob)
            }
        };
        format!(
            "{} {}",
            key_type,
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }
}

/// Apply AES-256-CTR with a full 128-bit big-endian counter (the semantics of
/// Go's `crypto/cipher.NewCTR`, which the OpenSSH key format uses).
fn aes256_ctr_crypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    use aes::Block;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes256::new_from_slice(key).expect("AES-256 key is 32 bytes");
    let mut counter = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = Block::default();
        block.copy_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= k;
        }
        // Increment the counter block itself (Go's crypto/cipher NewCTR does
        // the same); the keystream block must not replace it.
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

/// Encode an integer as an SSH `mpint` (`sshstring` of the big-endian minimal
/// representation, with a leading zero byte when the high bit is set).
fn append_mpint(buf: &mut Vec<u8>, big_endian: &[u8]) {
    let mut v = big_endian;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let mut value = Vec::with_capacity(v.len() + 1);
    if v[0] & 0x80 != 0 {
        value.push(0);
    }
    value.extend_from_slice(v);
    append_u32_string(buf, &value);
}

fn read_ssh_string_utf8(r: &mut SliceReader) -> Result<String> {
    let bytes = r.read_u32_string()?;
    String::from_utf8(bytes.to_vec())
        .map_err(|e| Error::Key(format!("invalid UTF-8 in OpenSSH key: {e}")))
}

/// Parse a P-256 private scalar from an mpint/octet string: mpints strip
/// leading zeros and add one when the high bit is set, so normalize to the
/// fixed 32-byte big-endian encoding `SecretKey::from_slice` expects.
fn p256_secret_from_scalar(bytes: &[u8]) -> Result<p256::SecretKey> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    if v.is_empty() || v.len() > 32 {
        return Err(Error::Key(format!(
            "invalid P-256 private key scalar: {} bytes",
            bytes.len()
        )));
    }
    let mut padded = [0u8; 32];
    padded[32 - v.len()..].copy_from_slice(v);
    p256::SecretKey::from_slice(&padded)
        .map_err(|e| Error::Key(format!("invalid P-256 private key scalar: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_OPENSSH: &str = include_str!("../tests/keys/id_ed25519");
    const ED25519_ENCRYPTED: &str = include_str!("../tests/keys/id_ed25519_enc");
    const ED25519_PKCS8: &str = include_str!("../tests/keys/id_ed25519_pkcs8");
    const ED25519_PUB: &str = include_str!("../tests/keys/id_ed25519.pub");
    const RSA_OPENSSH: &str = include_str!("../tests/keys/id_rsa");
    const RSA_PKCS1: &str = include_str!("../tests/keys/id_rsa_pkcs1");
    const RSA_PKCS8: &str = include_str!("../tests/keys/id_rsa_pkcs8");
    const ECDSA_OPENSSH: &str = include_str!("../tests/keys/id_ecdsa");
    const ECDSA_SEC1: &str = include_str!("../tests/keys/id_ecdsa_sec1");
    const ECDSA_PKCS8: &str = include_str!("../tests/keys/id_ecdsa_pkcs8");

    fn conv_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        id
    }

    /// Verify a JWT produced by `key`: signature with the public key, plus the
    /// claims the SSHOQ server checks.
    fn verify_jwt(key: &PrivateKey, token: &str, username: &str) {
        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap();
        let claims_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();
        assert!(parts.next().is_none());
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header_b64)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], key.algorithm());
        assert_eq!(header["typ"], "JWT");
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims_b64)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["iss"], username);
        assert_eq!(claims["sub"], "ssh3");
        assert_eq!(claims["aud"], "unused");
        assert_eq!(claims["client_id"], format!("ssh3-{username}"));
        assert_eq!(
            claims["jti"],
            base64::engine::general_purpose::STANDARD.encode(conv_id())
        );
        let exp = claims["exp"].as_u64().unwrap();
        let iat = claims["iat"].as_u64().unwrap();
        assert!(exp > iat && exp - iat <= 10);

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .unwrap();
        match key {
            PrivateKey::Rsa(key) => {
                use rsa::signature::{Keypair as _, Verifier as _};
                let verifying = key.verifying_key();
                let sig = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
                verifying.verify(signing_input.as_bytes(), &sig).unwrap();
            }
            PrivateKey::Ed25519(key) => {
                use ed25519_dalek::Verifier as _;
                let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
                key.verifying_key()
                    .verify(signing_input.as_bytes(), &sig)
                    .unwrap();
            }
            PrivateKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::Verifier as _;
                let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
                key.verifying_key()
                    .verify(signing_input.as_bytes(), &sig)
                    .unwrap();
            }
        }
    }

    #[test]
    fn parse_openssh_ed25519() {
        let key = PrivateKey::from_pem(ED25519_OPENSSH.as_bytes(), None).unwrap();
        assert_eq!(key.algorithm(), "EdDSA");
        // the generated authorized_keys line matches ssh-keygen's .pub file
        let expected = ED25519_PUB
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(key.public_key_openssh(), expected);
    }

    #[test]
    fn parse_all_ed25519_formats_agree() {
        let a = PrivateKey::from_pem(ED25519_OPENSSH.as_bytes(), None).unwrap();
        let b = PrivateKey::from_pem(ED25519_PKCS8.as_bytes(), None).unwrap();
        assert_eq!(a.public_key_openssh(), b.public_key_openssh());
    }

    #[test]
    fn parse_encrypted_openssh_ed25519() {
        // no passphrase -> error
        assert!(PrivateKey::from_pem(ED25519_ENCRYPTED.as_bytes(), None).is_err());
        // wrong passphrase -> error
        assert!(PrivateKey::from_pem(ED25519_ENCRYPTED.as_bytes(), Some("wrong")).is_err());
        // right passphrase -> the key ssh-keygen derives for this file
        let enc = PrivateKey::from_pem(ED25519_ENCRYPTED.as_bytes(), Some("testpass")).unwrap();
        assert_eq!(enc.algorithm(), "EdDSA");
        assert_eq!(
            enc.public_key_openssh(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyH1QOum1I5LcbGuZwkE1N//pCtqz2KCCV6QmrzMi33"
        );
    }

    #[test]
    fn parse_rsa_all_formats() {
        let a = PrivateKey::from_pem(RSA_OPENSSH.as_bytes(), None).unwrap();
        let b = PrivateKey::from_pem(RSA_PKCS1.as_bytes(), None).unwrap();
        let c = PrivateKey::from_pem(RSA_PKCS8.as_bytes(), None).unwrap();
        assert_eq!(a.algorithm(), "RS256");
        assert_eq!(a.public_key_openssh(), b.public_key_openssh());
        assert_eq!(a.public_key_openssh(), c.public_key_openssh());
        assert!(a.public_key_openssh().starts_with("ssh-rsa "));
    }

    #[test]
    fn parse_ecdsa_all_formats() {
        let a = PrivateKey::from_pem(ECDSA_OPENSSH.as_bytes(), None).unwrap();
        let b = PrivateKey::from_pem(ECDSA_SEC1.as_bytes(), None).unwrap();
        let c = PrivateKey::from_pem(ECDSA_PKCS8.as_bytes(), None).unwrap();
        assert_eq!(a.algorithm(), "ES256");
        assert_eq!(a.public_key_openssh(), b.public_key_openssh());
        assert_eq!(a.public_key_openssh(), c.public_key_openssh());
        assert!(a.public_key_openssh().starts_with("ecdsa-sha2-nistp256 "));
    }

    #[test]
    fn jwt_roundtrip_all_key_types() {
        for pem in [ED25519_OPENSSH, RSA_OPENSSH, ECDSA_OPENSSH] {
            let key = PrivateKey::from_pem(pem.as_bytes(), None).unwrap();
            let token = key.jwt_bearer_token("alice", &conv_id()).unwrap();
            verify_jwt(&key, &token, "alice");
        }
    }

    #[test]
    fn mpint_encoding() {
        // mpints are u32be-length-prefixed (RFC 4251 `string`/`mpint`).
        // e = 65537 = 0x010001, high bit not set, no padding byte
        let mut buf = Vec::new();
        append_mpint(&mut buf, &[0x01, 0x00, 0x01]);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01]);
        // high bit set -> leading zero byte
        let mut buf = Vec::new();
        append_mpint(&mut buf, &[0xff, 0x01]);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x03, 0x00, 0xff, 0x01]);
        // leading zeros are stripped
        let mut buf = Vec::new();
        append_mpint(&mut buf, &[0x00, 0x00, 0x2a]);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x01, 0x2a]);
    }

    #[test]
    fn aes256_ctr_matches_reference_vector() {
        // NIST F.5.5 CTR-AES256: key/IV/counter from the standard example.
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let mut buf = plaintext;
        aes256_ctr_crypt(&key, &iv, &mut buf);
        let expected = [
            0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3,
            0xd2, 0x28,
        ];
        assert_eq!(buf, expected);
    }
}
