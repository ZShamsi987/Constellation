//! Policy-first transport selection for LAN and explicitly enabled remote nodes.

use std::collections::HashMap;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// Transport implementations ordered by privacy preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Same-process or loopback traffic.
    Loopback,
    /// Authenticated direct QUIC inside the trusted LAN.
    LanQuic,
    /// Authenticated direct QUIC after NAT traversal.
    DirectQuic,
    /// Encrypted traffic through an operator-controlled relay.
    SelfHostedRelay,
    /// Encrypted traffic through an explicitly opted-in managed relay.
    ManagedRelay,
}

/// Local network controls. Remote and managed paths default off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Permit traffic outside the local network.
    pub remote_enabled: bool,
    /// Permit a managed relay after remote networking is enabled.
    pub managed_relay_enabled: bool,
    /// Optional self-hosted relay origin.
    pub self_hosted_relay: Option<Url>,
    /// Maximum remote bytes per UTC month; zero denies remote bytes.
    pub monthly_remote_byte_quota: u64,
}

/// One observed transport possibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCandidate {
    /// Transport implementation.
    pub kind: TransportKind,
    /// Both peers were cryptographically authenticated.
    pub authenticated: bool,
    /// Payload is protected end to end or hop-to-hop with cluster mTLS.
    pub encrypted: bool,
    /// Path leaves the local network.
    pub remote: bool,
    /// Relay origin for relay paths.
    pub relay: Option<Url>,
    /// Estimated bytes for this operation.
    pub estimated_bytes: u64,
}

/// User-visible privacy report for a selected transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPrivacyReport {
    /// Selected path.
    pub transport: TransportKind,
    /// Whether traffic leaves the LAN.
    pub leaves_local_network: bool,
    /// Whether a relay can observe encrypted traffic metadata.
    pub uses_relay: bool,
    /// Relay origin when applicable.
    pub relay: Option<Url>,
    /// Relay sees ciphertext but not model chunks or inference content in plaintext.
    pub relay_sees_plaintext: bool,
    /// Planned byte budget.
    pub estimated_bytes: u64,
}

/// Deterministic transport decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDecision {
    /// Chosen candidate.
    pub candidate: TransportCandidate,
    /// Pre-execution privacy disclosure.
    pub privacy: TransportPrivacyReport,
}

/// Stable transport policy failures.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// No encrypted authenticated path remained.
    #[error("no authenticated encrypted transport is available")]
    NoTrustedTransport,
    /// Local owner has disabled all remote networking.
    #[error("remote networking is disabled by local policy")]
    RemoteDisabled,
    /// Managed relay requires a separate explicit opt-in.
    #[error("managed relay is disabled by local policy")]
    ManagedRelayDisabled,
    /// Remote byte budget would be exceeded.
    #[error("remote bandwidth quota would be exceeded")]
    BandwidthQuotaExceeded,
    /// Emergency remote kill switch is engaged.
    #[error("remote networking kill switch is engaged")]
    KillSwitchEngaged,
}

/// Per-cluster UTC-month remote byte accounting.
#[derive(Debug, Default, Clone)]
pub struct BandwidthLedger {
    bytes: HashMap<(Uuid, i32, u32), u64>,
}

impl BandwidthLedger {
    /// Bytes recorded for a cluster in the current UTC month.
    #[must_use]
    pub fn used(&self, cluster_id: Uuid, now: DateTime<Utc>) -> u64 {
        self.bytes
            .get(&(cluster_id, now.year(), now.month()))
            .copied()
            .unwrap_or(0)
    }

    /// Commits observed remote bytes using saturating accounting.
    pub fn record(&mut self, cluster_id: Uuid, now: DateTime<Utc>, bytes: u64) {
        let used = self
            .bytes
            .entry((cluster_id, now.year(), now.month()))
            .or_default();
        *used = used.saturating_add(bytes);
    }
}

/// Selects the narrowest allowed transport without performing network I/O.
///
/// # Errors
///
/// Returns a stable policy failure when every candidate violates trust, privacy, quota, or
/// emergency controls.
pub fn select_transport(
    cluster_id: Uuid,
    candidates: &[TransportCandidate],
    policy: &NetworkPolicy,
    ledger: &BandwidthLedger,
    now: DateTime<Utc>,
    kill_switch: bool,
) -> Result<TransportDecision, NetworkError> {
    let mut trusted = candidates
        .iter()
        .filter(|candidate| candidate.authenticated && candidate.encrypted)
        .cloned()
        .collect::<Vec<_>>();
    if trusted.is_empty() {
        return Err(NetworkError::NoTrustedTransport);
    }
    trusted.sort_by_key(|candidate| transport_rank(candidate.kind));
    let used = ledger.used(cluster_id, now);
    let mut last_error = NetworkError::NoTrustedTransport;
    for candidate in trusted {
        if candidate.remote && kill_switch {
            last_error = NetworkError::KillSwitchEngaged;
            continue;
        }
        if candidate.remote && !policy.remote_enabled {
            last_error = NetworkError::RemoteDisabled;
            continue;
        }
        if candidate.kind == TransportKind::ManagedRelay && !policy.managed_relay_enabled {
            last_error = NetworkError::ManagedRelayDisabled;
            continue;
        }
        if candidate.remote
            && used.saturating_add(candidate.estimated_bytes) > policy.monthly_remote_byte_quota
        {
            last_error = NetworkError::BandwidthQuotaExceeded;
            continue;
        }
        if candidate.kind == TransportKind::SelfHostedRelay
            && candidate.relay != policy.self_hosted_relay
        {
            continue;
        }
        let uses_relay = matches!(
            candidate.kind,
            TransportKind::SelfHostedRelay | TransportKind::ManagedRelay
        );
        return Ok(TransportDecision {
            privacy: TransportPrivacyReport {
                transport: candidate.kind,
                leaves_local_network: candidate.remote,
                uses_relay,
                relay: candidate.relay.clone(),
                relay_sees_plaintext: false,
                estimated_bytes: candidate.estimated_bytes,
            },
            candidate,
        });
    }
    Err(last_error)
}

const fn transport_rank(kind: TransportKind) -> u8 {
    match kind {
        TransportKind::Loopback => 0,
        TransportKind::LanQuic => 1,
        TransportKind::DirectQuic => 2,
        TransportKind::SelfHostedRelay => 3,
        TransportKind::ManagedRelay => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(kind: TransportKind, relay: Option<Url>) -> TransportCandidate {
        TransportCandidate {
            kind,
            authenticated: true,
            encrypted: true,
            remote: true,
            relay,
            estimated_bytes: 1024,
        }
    }

    #[test]
    fn remote_and_managed_relay_are_separate_opt_ins() {
        let cluster = Uuid::now_v7();
        let now = Utc::now();
        let candidates = [remote(
            TransportKind::ManagedRelay,
            Url::parse("https://relay.example").ok(),
        )];
        assert_eq!(
            select_transport(
                cluster,
                &candidates,
                &NetworkPolicy::default(),
                &BandwidthLedger::default(),
                now,
                false,
            ),
            Err(NetworkError::RemoteDisabled)
        );
        let policy = NetworkPolicy {
            remote_enabled: true,
            monthly_remote_byte_quota: 4096,
            ..NetworkPolicy::default()
        };
        assert_eq!(
            select_transport(
                cluster,
                &candidates,
                &policy,
                &BandwidthLedger::default(),
                now,
                false,
            ),
            Err(NetworkError::ManagedRelayDisabled)
        );
    }

    #[test]
    fn direct_path_wins_and_kill_switch_blocks_remote() {
        let cluster = Uuid::now_v7();
        let now = Utc::now();
        let candidates = [
            remote(
                TransportKind::SelfHostedRelay,
                Url::parse("https://relay.internal").ok(),
            ),
            remote(TransportKind::DirectQuic, None),
        ];
        let policy = NetworkPolicy {
            remote_enabled: true,
            self_hosted_relay: Url::parse("https://relay.internal").ok(),
            monthly_remote_byte_quota: 4096,
            ..NetworkPolicy::default()
        };
        let selected = select_transport(
            cluster,
            &candidates,
            &policy,
            &BandwidthLedger::default(),
            now,
            false,
        );
        assert!(selected.is_ok_and(|value| value.candidate.kind == TransportKind::DirectQuic));
        assert_eq!(
            select_transport(
                cluster,
                &candidates,
                &policy,
                &BandwidthLedger::default(),
                now,
                true,
            ),
            Err(NetworkError::KillSwitchEngaged)
        );
    }

    #[test]
    fn quota_uses_observed_monthly_bytes() {
        let cluster = Uuid::now_v7();
        let now = Utc::now();
        let mut ledger = BandwidthLedger::default();
        ledger.record(cluster, now, 3500);
        let policy = NetworkPolicy {
            remote_enabled: true,
            monthly_remote_byte_quota: 4096,
            ..NetworkPolicy::default()
        };
        assert_eq!(
            select_transport(
                cluster,
                &[remote(TransportKind::DirectQuic, None)],
                &policy,
                &ledger,
                now,
                false,
            ),
            Err(NetworkError::BandwidthQuotaExceeded)
        );
    }
}
