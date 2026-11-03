//! Secrets the server stores, such as the GitHub App's private key
//! (ADR-0024): encrypted with AES-256-GCM under SONDA_SECRET_KEY, which is
//! never stored, so the database and its dumps hold no plaintext. Each is
//! sealed with its purpose as associated data: a ciphertext copied to
//! another purpose doesn't open.

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::PgExecutor;

/// The GitHub App's private key, PEM.
pub const GITHUB_APP_KEY: &str = "github_app_key";

/// SONDA_SECRET_KEY: 32 random bytes, base64.
pub struct SecretKey(LessSafeKey);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    pub fn new(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded.trim())
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| {
                anyhow!(
                    "SONDA_SECRET_KEY must be 32 random bytes, base64 \
                     (generate it with `openssl rand -base64 32`)"
                )
            })?;
        let key = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| anyhow!("not a key"))?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// `(nonce, ciphertext)`, with a random nonce each time.
    fn seal(&self, purpose: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow!("no randomness for a nonce"))?;
        let mut data = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.as_bytes()),
                &mut data,
            )
            .map_err(|_| anyhow!("encrypting failed"))?;
        Ok((nonce.to_vec(), data))
    }

    /// `None` under another key, for another purpose, or tampered with.
    fn open(&self, purpose: &str, nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut data = ciphertext.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(purpose.as_bytes()), &mut data)
            .ok()?;
        Some(plain.to_vec())
    }
}

/// A stored secret, as read back.
#[derive(Debug, PartialEq)]
pub enum Stored {
    Missing,
    /// Stored, but SONDA_SECRET_KEY is unset or isn't the one it was
    /// stored with.
    Unreadable,
    Value(Vec<u8>),
}

/// Stores `value` for `purpose`, replacing any.
pub async fn store<'e, E: PgExecutor<'e>>(
    db: E,
    key: &SecretKey,
    purpose: &str,
    value: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = key.seal(purpose, value)?;
    sqlx::query(
        "INSERT INTO encrypted_secrets (purpose, nonce, ciphertext) VALUES ($1, $2, $3)
         ON CONFLICT (purpose) DO UPDATE
         SET nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext, updated_at = now()",
    )
    .bind(purpose)
    .bind(nonce)
    .bind(ciphertext)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn load<'e, E: PgExecutor<'e>>(
    db: E,
    key: Option<&SecretKey>,
    purpose: &str,
) -> sqlx::Result<Stored> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT nonce, ciphertext FROM encrypted_secrets WHERE purpose = $1")
            .bind(purpose)
            .fetch_optional(db)
            .await?;
    Ok(match (row, key) {
        (None, _) => Stored::Missing,
        (Some(_), None) => Stored::Unreadable,
        (Some((nonce, ciphertext)), Some(key)) => key
            .open(purpose, &nonce, &ciphertext)
            .map_or(Stored::Unreadable, Stored::Value),
    })
}

pub async fn delete<'e, E: PgExecutor<'e>>(db: E, purpose: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM encrypted_secrets WHERE purpose = $1")
        .bind(purpose)
        .execute(db)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn a_secret_key_is_32_bytes_of_base64() {
        assert!(SecretKey::new(KEY).is_ok());
        assert!(SecretKey::new(&format!("{KEY}\n")).is_ok());
        for bad in [
            "",
            "not base64!",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
        ] {
            let e = SecretKey::new(bad).unwrap_err().to_string();
            assert!(e.contains("openssl rand -base64 32"), "{bad:?}: {e}");
        }
        assert_eq!(
            format!("{:?}", SecretKey::new(KEY).unwrap()),
            "SecretKey(..)"
        );
    }

    #[test]
    fn sealed_secrets_open_only_with_their_key_and_purpose() {
        let key = SecretKey::new(KEY).unwrap();
        let (nonce, ciphertext) = key.seal(GITHUB_APP_KEY, b"-----BEGIN").unwrap();
        assert!(!ciphertext.windows(5).any(|w| w == b"BEGIN"));
        assert_eq!(
            key.open(GITHUB_APP_KEY, &nonce, &ciphertext).as_deref(),
            Some(&b"-----BEGIN"[..])
        );
        assert_eq!(key.open("other", &nonce, &ciphertext), None);
        let other = SecretKey::new(&STANDARD.encode([7u8; 32])).unwrap();
        assert_eq!(other.open(GITHUB_APP_KEY, &nonce, &ciphertext), None);
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert_eq!(key.open(GITHUB_APP_KEY, &nonce, &tampered), None);
        // A fresh nonce each time.
        assert_ne!(
            key.seal(GITHUB_APP_KEY, b"x").unwrap().0,
            key.seal(GITHUB_APP_KEY, b"x").unwrap().0
        );
    }
}
