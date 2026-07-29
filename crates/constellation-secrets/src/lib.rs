//! OS-keyring-backed content encryption for local private state.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Encrypted value stored outside the OS credential store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedContent {
    /// Envelope format version.
    pub version: u8,
    /// Unique `XChaCha20` nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Credential or encryption failure with no secret-bearing diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// OS credential backend failed.
    #[error("OS credential storage is unavailable")]
    Credential,
    /// Stored key material is malformed.
    #[error("stored content key is invalid")]
    InvalidKey,
    /// Encryption failed.
    #[error("content encryption failed")]
    Encrypt,
    /// Authentication or decryption failed.
    #[error("content authentication failed")]
    Decrypt,
}

/// OS-native credential handle for the wrapped local content key.
#[derive(Debug, Clone)]
pub struct OsKeyring {
    service: String,
    account: String,
}

/// Cloneable content-key source selecting production OS storage or an isolated test key.
#[derive(Clone)]
pub struct ContentKeySource {
    source: Arc<ContentKeySourceInner>,
}

enum ContentKeySourceInner {
    Os(OsKeyring),
    Ephemeral(Zeroizing<[u8; 32]>),
}

impl ContentKeySource {
    /// Creates a production source backed by OS-native credential storage.
    #[must_use]
    pub fn os(keyring: OsKeyring) -> Self {
        Self {
            source: Arc::new(ContentKeySourceInner::Os(keyring)),
        }
    }

    /// Creates a process-local random source for loopback integration tests.
    #[must_use]
    pub fn ephemeral() -> Self {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(key.as_slice());
        Self {
            source: Arc::new(ContentKeySourceInner::Ephemeral(Zeroizing::new(bytes))),
        }
    }

    /// Loads the production key or copies the process-local test key into a short-lived cipher.
    ///
    /// # Errors
    ///
    /// Returns an error when the production credential backend is unavailable.
    pub fn load_cipher(&self) -> Result<ContentCipher, SecretError> {
        match self.source.as_ref() {
            ContentKeySourceInner::Os(keyring) => keyring.load_or_create_cipher(),
            ContentKeySourceInner::Ephemeral(key) => Ok(ContentCipher::from_key(**key)),
        }
    }
}

impl OsKeyring {
    /// Creates a credential handle without reading a secret.
    #[must_use]
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// Loads the existing 256-bit content key or creates it atomically enough for a
    /// single-controller local installation.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform credential store is unavailable or contains
    /// malformed key material.
    pub fn load_or_create_cipher(&self) -> Result<ContentCipher, SecretError> {
        let secret = self.load_or_create_secret_32()?;
        Ok(ContentCipher::from_key(*secret))
    }

    /// Loads or creates a generic 256-bit secret in OS-native credential storage.
    ///
    /// The returned memory is cleared when dropped. Callers should retain it only in a
    /// secret-owning type and must never serialize or log it.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential backend is unavailable or contains malformed data.
    pub fn load_or_create_secret_32(&self) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let entry = keyring::Entry::new(&self.service, &self.account)
            .map_err(|_| SecretError::Credential)?;
        match entry.get_password() {
            Ok(encoded) => {
                let decoded = STANDARD_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| SecretError::InvalidKey)?;
                let key: [u8; 32] = decoded.try_into().map_err(|_| SecretError::InvalidKey)?;
                Ok(Zeroizing::new(key))
            }
            Err(keyring::Error::NoEntry) => {
                let key = XChaCha20Poly1305::generate_key(&mut OsRng);
                let encoded = STANDARD_NO_PAD.encode(key.as_slice());
                entry
                    .set_password(&encoded)
                    .map_err(|_| SecretError::Credential)?;
                let mut bytes = [0_u8; 32];
                bytes.copy_from_slice(key.as_slice());
                Ok(Zeroizing::new(bytes))
            }
            Err(_) => Err(SecretError::Credential),
        }
    }

    /// Stores an externally issued provider secret in OS-native credential storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential backend is unavailable or the secret is empty or
    /// larger than 16 KiB.
    pub fn store_secret_string(&self, secret: &str) -> Result<(), SecretError> {
        if secret.is_empty() || secret.len() > 16 * 1024 {
            return Err(SecretError::InvalidKey);
        }
        keyring::Entry::new(&self.service, &self.account)
            .and_then(|entry| entry.set_password(secret))
            .map_err(|_| SecretError::Credential)
    }

    /// Loads an existing provider secret without creating a replacement.
    ///
    /// The returned string is cleared when dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret is absent, malformed, or unavailable.
    pub fn load_secret_string(&self) -> Result<Zeroizing<String>, SecretError> {
        let secret = keyring::Entry::new(&self.service, &self.account)
            .and_then(|entry| entry.get_password())
            .map_err(|_| SecretError::Credential)?;
        if secret.is_empty() || secret.len() > 16 * 1024 {
            return Err(SecretError::InvalidKey);
        }
        Ok(Zeroizing::new(secret))
    }
}

/// Authenticated content cipher whose key is loaded from native credential storage.
pub struct ContentCipher {
    key: [u8; 32],
}

impl ContentCipher {
    /// Constructs a cipher from an already protected 256-bit key.
    #[must_use]
    pub const fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypts one value with caller-provided associated metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if authenticated encryption fails.
    pub fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedContent, SecretError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecretError::Encrypt)?;
        Ok(EncryptedContent {
            version: 1,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Authenticates and decrypts one value.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported envelopes, invalid nonces, altered associated
    /// metadata, or corrupted ciphertext.
    pub fn open(
        &self,
        associated_data: &[u8],
        encrypted: &EncryptedContent,
    ) -> Result<Vec<u8>, SecretError> {
        if encrypted.version != 1 || encrypted.nonce.len() != 24 {
            return Err(SecretError::Decrypt);
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                XNonce::from_slice(&encrypted.nonce),
                Payload {
                    msg: &encrypted.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecretError::Decrypt)
    }
}

impl Drop for ContentCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_requires_matching_associated_data() {
        let cipher = ContentCipher::from_key([7_u8; 32]);
        let sealed_result = cipher.seal(b"conversation/message", b"private content");
        assert!(sealed_result.is_ok());
        let sealed = sealed_result.unwrap_or_else(|error| panic!("seal: {error}"));
        let opened = cipher.open(b"conversation/message", &sealed);
        assert_eq!(opened.unwrap_or_default(), b"private content");
        assert!(cipher.open(b"different/message", &sealed).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let cipher = ContentCipher::from_key([9_u8; 32]);
        let sealed_result = cipher.seal(b"message", b"private content");
        assert!(sealed_result.is_ok());
        let mut sealed = sealed_result.unwrap_or_else(|error| panic!("seal: {error}"));
        if let Some(byte) = sealed.ciphertext.first_mut() {
            *byte ^= 1;
        }
        assert!(cipher.open(b"message", &sealed).is_err());
    }
}
