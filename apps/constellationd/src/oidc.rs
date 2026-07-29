//! `OpenID` Connect authorization-code flow with PKCE and server-held ceremony state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use constellation_secrets::OsKeyring;
use constellation_teams::{AuthProvider, AuthProviderKind};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

const CEREMONY_TTL: Duration = Duration::from_mins(5);
const MAX_PENDING_CEREMONIES: usize = 1_024;

/// Process-shared, bounded OIDC authorization state.
#[derive(Clone, Default)]
pub struct OidcState {
    pending: Arc<Mutex<HashMap<String, PendingAuthorization>>>,
}

struct PendingAuthorization {
    provider_id: Uuid,
    pkce_verifier: String,
    nonce: String,
    created_at: Instant,
}

/// Authorization information returned to the browser dashboard.
pub struct AuthorizationStart {
    /// Provider authorization URL.
    pub authorization_url: String,
    /// Expiration relative to the response.
    pub expires_in_seconds: u64,
}

/// Verified, policy-admitted external identity. The raw subject is never persisted.
pub struct VerifiedIdentity {
    /// Configured provider identity.
    pub provider_id: Uuid,
    /// Domain-separated digest of the provider subject.
    pub subject_sha256: String,
}

impl OidcState {
    /// Performs discovery and verifies that an enabled provider has usable credentials.
    pub async fn probe(provider: &AuthProvider) -> Result<()> {
        require_oidc(provider)?;
        let secret = provider_secret(provider)?;
        let http_client = oidc_http_client()?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider.issuer.to_string()).context("invalid OIDC issuer")?,
            &http_client,
        )
        .await
        .context("OIDC discovery failed")?;
        let _client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(provider.redirect_uri.to_string()).context("invalid OIDC redirect")?,
        );
        Ok(())
    }

    /// Begins a single-use authorization-code ceremony with PKCE, CSRF state, and nonce.
    pub async fn begin(&self, provider: &AuthProvider) -> Result<AuthorizationStart> {
        require_oidc(provider)?;
        let secret = provider_secret(provider)?;
        let http_client = oidc_http_client()?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider.issuer.to_string()).context("invalid OIDC issuer")?,
            &http_client,
        )
        .await
        .context("OIDC discovery failed")?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(provider.redirect_uri.to_string()).context("invalid OIDC redirect")?,
        );
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization_url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        let state_secret = state.secret().to_owned();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, ceremony| ceremony.created_at.elapsed() < CEREMONY_TTL);
        if pending.len() >= MAX_PENDING_CEREMONIES {
            bail!("too many pending OIDC ceremonies");
        }
        pending.insert(
            state_secret,
            PendingAuthorization {
                provider_id: provider.id,
                pkce_verifier: pkce_verifier.secret().to_owned(),
                nonce: nonce.secret().to_owned(),
                created_at: Instant::now(),
            },
        );
        Ok(AuthorizationStart {
            authorization_url: authorization_url.to_string(),
            expires_in_seconds: CEREMONY_TTL.as_secs(),
        })
    }

    /// Consumes a ceremony and verifies the returned ID token, nonce, token hash, and group policy.
    pub async fn finish(
        &self,
        provider: &AuthProvider,
        state: &str,
        code: &str,
    ) -> Result<VerifiedIdentity> {
        if state.len() > 512 || code.is_empty() || code.len() > 8_192 {
            bail!("invalid OIDC callback bounds");
        }
        let ceremony = self
            .pending
            .lock()
            .await
            .remove(state)
            .context("OIDC ceremony is absent or already used")?;
        if ceremony.created_at.elapsed() >= CEREMONY_TTL || ceremony.provider_id != provider.id {
            bail!("OIDC ceremony expired or mismatched");
        }
        require_oidc(provider)?;
        let secret = provider_secret(provider)?;
        let http_client = oidc_http_client()?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider.issuer.to_string()).context("invalid OIDC issuer")?,
            &http_client,
        )
        .await
        .context("OIDC discovery failed")?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(provider.redirect_uri.to_string()).context("invalid OIDC redirect")?,
        );
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .context("OIDC token endpoint is unavailable")?
            .set_pkce_verifier(PkceCodeVerifier::new(ceremony.pkce_verifier))
            .request_async(&http_client)
            .await
            .context("OIDC code exchange failed")?;
        let id_token = response
            .id_token()
            .context("OIDC response omitted an ID token")?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(ceremony.nonce))
            .context("OIDC ID token verification failed")?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                id_token
                    .signing_alg()
                    .context("OIDC signing algorithm unavailable")?,
                id_token
                    .signing_key(&verifier)
                    .context("OIDC signing key unavailable")?,
            )
            .context("OIDC access-token hash failed")?;
            if actual != *expected {
                bail!("OIDC access-token hash mismatch");
            }
        }
        enforce_groups(provider, &id_token.to_string())?;
        Ok(VerifiedIdentity {
            provider_id: provider.id,
            subject_sha256: external_subject_digest(provider.id, claims.subject().as_str()),
        })
    }
}

/// Produces a domain-separated digest for a provider subject.
#[must_use]
pub fn external_subject_digest(provider_id: Uuid, subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"constellation.external-identity.v1\0");
    digest.update(provider_id.as_bytes());
    digest.update(b"\0");
    digest.update(subject.as_bytes());
    format!("{:x}", digest.finalize())
}

fn require_oidc(provider: &AuthProvider) -> Result<()> {
    if !provider.enabled || provider.kind != AuthProviderKind::Oidc {
        bail!("OIDC provider is disabled or has an unsupported protocol");
    }
    Ok(())
}

fn provider_secret(provider: &AuthProvider) -> Result<zeroize::Zeroizing<String>> {
    OsKeyring::new("com.constellation.provider", &provider.credential_reference)
        .load_secret_string()
        .context("OIDC credential reference is unavailable")
}

fn oidc_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent("Constellation/0.1 OIDC")
        .build()
        .context("build OIDC HTTP client")
}

fn enforce_groups(provider: &AuthProvider, encoded_id_token: &str) -> Result<()> {
    if provider.allowed_groups.is_empty() {
        return Ok(());
    }
    let payload = encoded_id_token
        .split('.')
        .nth(1)
        .context("OIDC ID token payload is absent")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .context("OIDC ID token payload is malformed")?;
    let value: Value = serde_json::from_slice(&decoded).context("OIDC claims are malformed")?;
    let groups = value
        .get("groups")
        .and_then(Value::as_array)
        .context("OIDC provider did not return required groups")?;
    if !groups.iter().filter_map(Value::as_str).any(|group| {
        provider
            .allowed_groups
            .iter()
            .any(|allowed| allowed == group)
    }) {
        bail!("OIDC group policy rejected the identity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::external_subject_digest;
    use uuid::Uuid;

    #[test]
    fn external_subjects_are_provider_scoped() {
        let first = external_subject_digest(Uuid::nil(), "subject");
        let second = external_subject_digest(Uuid::max(), "subject");
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert_ne!(first, external_subject_digest(Uuid::nil(), "other"));
    }
}
