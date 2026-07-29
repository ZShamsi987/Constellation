//! Team identities, RBAC, provider policy, and fenced controller-leader contracts.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// Team policy validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TeamError {
    /// Identity or provider configuration is invalid.
    #[error("invalid team configuration: {0}")]
    Invalid(String),
    /// Role does not authorize an operation.
    #[error("permission denied")]
    PermissionDenied,
    /// Controller lease is stale or fenced by a later term.
    #[error("controller lease is stale")]
    StaleLease,
}

/// Built-in identity roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full cluster authority and recovery ownership.
    Owner,
    /// Team, policy, plugin, and provider administration.
    Admin,
    /// Workload, model, benchmark, and workflow operations.
    Operator,
    /// Read-only inventory, reports, plans, and audits.
    Viewer,
    /// Machine identity limited to node-local control paths.
    Node,
    /// API identity further constrained by explicit scopes.
    Service,
}

/// Stable authorization capability checked at native API boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// View cluster state and reports.
    ClusterRead,
    /// Change cluster-wide settings.
    ClusterAdmin,
    /// Submit and cancel workloads.
    WorkloadExecute,
    /// Create and operate workflows.
    WorkflowOperate,
    /// Approve human workflow gates.
    WorkflowApprove,
    /// Install and grant plugins.
    PluginAdmin,
    /// Configure identity and cloud providers.
    ProviderAdmin,
    /// Create principals and team memberships.
    TeamAdmin,
    /// Read audit history.
    AuditRead,
    /// Node heartbeat, lease, event, and inventory operations.
    NodeOperate,
    /// Emergency kill switches and credential revocation.
    EmergencyControl,
}

/// Returns whether a role authorizes a permission before service-scope narrowing.
#[must_use]
pub fn role_allows(role: Role, permission: Permission) -> bool {
    match role {
        Role::Owner => true,
        Role::Admin => !matches!(permission, Permission::NodeOperate),
        Role::Operator => matches!(
            permission,
            Permission::ClusterRead
                | Permission::WorkloadExecute
                | Permission::WorkflowOperate
                | Permission::WorkflowApprove
                | Permission::AuditRead
        ),
        Role::Viewer => matches!(permission, Permission::ClusterRead | Permission::AuditRead),
        Role::Node => permission == Permission::NodeOperate,
        Role::Service => false,
    }
}

/// Human or service principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Principal identity.
    pub id: Uuid,
    /// Stable display name.
    pub name: String,
    /// Base role.
    pub role: Role,
    /// Explicit service scopes; ignored for non-service identities.
    pub scopes: Vec<Permission>,
    /// Revoked principals cannot authenticate.
    pub active: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

impl Principal {
    /// Checks role and service-scope authorization.
    #[must_use]
    pub fn allows(&self, permission: Permission) -> bool {
        self.active
            && if self.role == Role::Service {
                self.scopes.contains(&permission)
            } else {
                role_allows(self.role, permission)
            }
    }
}

/// Team membership binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamMembership {
    /// Team identity.
    pub team_id: Uuid,
    /// Principal identity.
    pub principal_id: Uuid,
    /// Team-local role, never more privileged than cluster role.
    pub role: Role,
}

/// Supported external authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProviderKind {
    /// `OpenID` Connect discovery and authorization code flow with `PKCE`.
    Oidc,
    /// SAML 2.0 service-provider flow.
    Saml,
}

/// External authentication provider with secrets held by opaque credential reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProvider {
    /// Provider identity.
    pub id: Uuid,
    /// Protocol.
    pub kind: AuthProviderKind,
    /// HTTPS issuer/entity identifier.
    pub issuer: Url,
    /// Public client/entity identifier.
    pub client_id: String,
    /// OS/native-secret-store reference, never the secret itself.
    pub credential_reference: String,
    /// Exact callback URL.
    pub redirect_uri: Url,
    /// Optional identity groups accepted by policy.
    pub allowed_groups: Vec<String>,
    /// Disabled providers cannot begin new sessions.
    pub enabled: bool,
}

/// Validates an identity provider without performing discovery.
///
/// # Errors
///
/// Returns invalid for non-HTTPS endpoints, fragments, broad groups, or secret-like fields.
pub fn validate_auth_provider(provider: &AuthProvider) -> Result<(), TeamError> {
    if provider.issuer.scheme() != "https"
        || provider.redirect_uri.scheme() != "https"
        || provider.issuer.host_str().is_none()
        || provider.redirect_uri.host_str().is_none()
        || !provider.issuer.username().is_empty()
        || provider.issuer.password().is_some()
        || provider.issuer.query().is_some()
        || !provider.redirect_uri.username().is_empty()
        || provider.redirect_uri.password().is_some()
        || provider.issuer.fragment().is_some()
        || provider.redirect_uri.fragment().is_some()
        || provider.client_id.trim().is_empty()
        || provider.client_id.len() > 256
        || !valid_identifier(&provider.credential_reference)
        || provider.allowed_groups.len() > 64
        || provider
            .allowed_groups
            .iter()
            .any(|group| group.trim().is_empty() || group.len() > 256 || group == "*")
    {
        return Err(TeamError::Invalid(
            "authentication provider violates endpoint or allowlist policy".to_owned(),
        ));
    }
    Ok(())
}

/// Explicit opt-in policy for a cloud compute adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudAdapterPolicy {
    /// Adapter identity.
    pub id: Uuid,
    /// Provider plugin identifier.
    pub provider_plugin: String,
    /// Cloud use remains false by default.
    pub enabled: bool,
    /// Explicit region allowlist.
    pub regions: Vec<String>,
    /// Explicit model allowlist.
    pub models: Vec<String>,
    /// Monthly hard spend ceiling in millionths of deployment currency.
    pub monthly_cost_limit_micros: u64,
    /// Monthly hard egress ceiling.
    pub monthly_network_limit_bytes: u64,
    /// Opaque credential reference.
    pub credential_reference: String,
    /// Exact HTTPS OpenAI-compatible API base; the credential is never embedded in it.
    #[serde(default)]
    pub endpoint: Option<Url>,
    /// Maximum provider charge per million input tokens in deployment-currency millionths.
    #[serde(default)]
    pub input_cost_per_million_tokens_micros: u64,
    /// Maximum provider charge per million output tokens in deployment-currency millionths.
    #[serde(default)]
    pub output_cost_per_million_tokens_micros: u64,
}

impl Default for CloudAdapterPolicy {
    fn default() -> Self {
        Self {
            id: Uuid::now_v7(),
            provider_plugin: String::new(),
            enabled: false,
            regions: Vec::new(),
            models: Vec::new(),
            monthly_cost_limit_micros: 0,
            monthly_network_limit_bytes: 0,
            credential_reference: String::new(),
            endpoint: None,
            input_cost_per_million_tokens_micros: 0,
            output_cost_per_million_tokens_micros: 0,
        }
    }
}

/// Validates explicit cloud limits and allowlists.
///
/// # Errors
///
/// Returns invalid when enabled cloud access lacks any hard bound.
pub fn validate_cloud_policy(policy: &CloudAdapterPolicy) -> Result<(), TeamError> {
    if !valid_reverse_dns(&policy.provider_plugin)
        || !valid_identifier(&policy.credential_reference)
        || policy.regions.len() > 32
        || policy.models.len() > 128
        || policy
            .regions
            .iter()
            .any(|region| !valid_identifier(region))
        || policy
            .models
            .iter()
            .any(|model| model.trim().is_empty() || model.len() > 256 || model == "*")
        || policy.endpoint.as_ref().is_some_and(|endpoint| {
            endpoint.scheme() != "https"
                || endpoint.host_str().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
        })
        || (policy.enabled
            && (policy.regions.is_empty()
                || policy.models.is_empty()
                || policy.monthly_cost_limit_micros == 0
                || policy.monthly_network_limit_bytes == 0
                || policy.endpoint.is_none()
                || policy.input_cost_per_million_tokens_micros == 0
                || policy.output_cost_per_million_tokens_micros == 0))
    {
        return Err(TeamError::Invalid(
            "cloud adapter requires explicit regions, models, spend, egress, and credentials"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Single-leader control-plane lease with fencing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerLease {
    /// Controller device identity.
    pub controller_id: Uuid,
    /// Monotonically increasing election term.
    pub term: u64,
    /// Monotonically increasing write fencing token.
    pub fencing_token: u64,
    /// Lease expiry evaluated against controller time.
    pub expires_at: DateTime<Utc>,
}

impl ControllerLease {
    /// Issues a later fenced lease.
    ///
    /// # Errors
    ///
    /// Returns invalid for lease durations outside 10 through 60 seconds.
    pub fn next(
        previous: Option<&Self>,
        controller_id: Uuid,
        now: DateTime<Utc>,
        duration_seconds: u8,
    ) -> Result<Self, TeamError> {
        if !(10..=60).contains(&duration_seconds) {
            return Err(TeamError::Invalid(
                "controller lease duration must be 10 through 60 seconds".to_owned(),
            ));
        }
        Ok(Self {
            controller_id,
            term: previous.map_or(1, |lease| lease.term.saturating_add(1)),
            fencing_token: previous.map_or(1, |lease| lease.fencing_token.saturating_add(1)),
            expires_at: now + Duration::seconds(i64::from(duration_seconds)),
        })
    }

    /// Checks whether a write is authorized by the current term and fencing token.
    ///
    /// # Errors
    ///
    /// Returns stale lease after expiry or when any identity/token differs.
    pub fn authorize_write(
        &self,
        controller_id: Uuid,
        term: u64,
        fencing_token: u64,
        now: DateTime<Utc>,
    ) -> Result<(), TeamError> {
        if self.controller_id != controller_id
            || self.term != term
            || self.fencing_token != fencing_token
            || now >= self.expires_at
        {
            return Err(TeamError::StaleLease);
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_reverse_dns(value: &str) -> bool {
    value.split('.').count() >= 3 && valid_identifier(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_scopes_and_roles_fail_closed() {
        let service = Principal {
            id: Uuid::now_v7(),
            name: "reporter".to_owned(),
            role: Role::Service,
            scopes: vec![Permission::ClusterRead],
            active: true,
            created_at: Utc::now(),
        };
        assert!(service.allows(Permission::ClusterRead));
        assert!(!service.allows(Permission::WorkloadExecute));
        assert!(!role_allows(Role::Viewer, Permission::ClusterAdmin));
    }

    #[test]
    fn enabled_cloud_policy_requires_every_hard_limit() {
        let policy = CloudAdapterPolicy {
            enabled: true,
            provider_plugin: "com.constellation.cloud.test".to_owned(),
            credential_reference: "cloud-test".to_owned(),
            ..CloudAdapterPolicy::default()
        };
        assert!(validate_cloud_policy(&policy).is_err());
    }

    #[test]
    fn controller_fencing_rejects_prior_term() {
        let now = Utc::now();
        let first = ControllerLease::next(None, Uuid::now_v7(), now, 15)
            .unwrap_or_else(|error| panic!("first lease: {error}"));
        let second = ControllerLease::next(Some(&first), Uuid::now_v7(), now, 15)
            .unwrap_or_else(|error| panic!("second lease: {error}"));
        assert!(
            second
                .authorize_write(first.controller_id, first.term, first.fencing_token, now)
                .is_err()
        );
    }
}
