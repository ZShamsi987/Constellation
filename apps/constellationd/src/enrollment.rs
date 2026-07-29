//! Secret-bearing enrollment state kept outside durable storage.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use constellation_core::Node;
use constellation_identity::{
    DeviceCertificate, DeviceIdentity, EnrollmentKey, IdentityError, InvitationMethod,
    InvitationPresentation, InvitationRegistry, InvitationStatus, MembershipCredential,
    PeerTransferTicket, ServerCertificateMaterial,
};
use tokio::sync::Mutex;
use uuid::Uuid;

/// A proved device waiting for explicit administrator approval.
pub struct PendingEnrollment {
    /// Device inventory supplied over the authenticated SPAKE2 session.
    pub node: Node,
    /// Long-lived Ed25519 public key for membership issuance.
    pub public_key: [u8; 32],
    key: EnrollmentKey,
    credential: Option<MembershipCredential>,
    certificate: Option<DeviceCertificate>,
}

/// Controller-owned enrollment coordinator.
#[derive(Clone)]
pub struct EnrollmentCoordinator {
    authority: Arc<DeviceIdentity>,
    invitations: Arc<Mutex<InvitationRegistry>>,
    handshakes: Arc<Mutex<HashMap<Uuid, EnrollmentKey>>>,
    pending: Arc<Mutex<HashMap<Uuid, PendingEnrollment>>>,
}

impl EnrollmentCoordinator {
    /// Creates a coordinator backed by one cluster authority.
    #[must_use]
    pub fn new(authority: DeviceIdentity) -> Self {
        Self {
            authority: Arc::new(authority),
            invitations: Arc::new(Mutex::new(InvitationRegistry::default())),
            handshakes: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Public authority key advertised with approved membership credentials.
    #[must_use]
    pub fn authority_public_key(&self) -> [u8; 32] {
        self.authority.public_key_bytes()
    }

    /// Opaque discovery identifier derived from the public cluster authority.
    #[must_use]
    pub fn cluster_id(&self) -> String {
        self.authority.fingerprint()
    }

    /// Creates a 24-hour server leaf signed by the stable cluster authority.
    pub fn issue_server_certificate(
        &self,
        bind_ip: std::net::IpAddr,
        now: DateTime<Utc>,
    ) -> Result<ServerCertificateMaterial, IdentityError> {
        self.authority.issue_server_certificate(bind_ip, now)
    }

    /// Rotates a node's signed membership and key-bound client certificate for 24 hours.
    pub fn rotate_device_credentials(
        &self,
        device_id: Uuid,
        public_key: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<(MembershipCredential, DeviceCertificate), IdentityError> {
        let credential = MembershipCredential::issue(
            &self.authority,
            device_id,
            public_key,
            vec!["node".to_owned()],
            now,
            1,
            1,
        );
        let certificate = self
            .authority
            .issue_device_certificate(device_id, public_key, now)?;
        Ok((credential, certificate))
    }

    /// Issues a short-lived, single-chunk peer transfer authorization.
    #[must_use]
    pub fn issue_transfer_ticket(
        &self,
        source_node: Uuid,
        destination_node: Uuid,
        model_sha256: String,
        chunk_sha256: String,
        now: DateTime<Utc>,
    ) -> PeerTransferTicket {
        PeerTransferTicket::issue(
            &self.authority,
            source_node,
            destination_node,
            model_sha256,
            chunk_sha256,
            now,
        )
    }

    /// Creates a bounded single-use invitation.
    pub async fn create_invitation(
        &self,
        cluster_id: &str,
        now: DateTime<Utc>,
    ) -> Result<InvitationPresentation, IdentityError> {
        let mut invitation = self.invitations.lock().await.create(cluster_id, now);
        invitation.certificate_authority_pem = Some(self.authority.certificate_authority_pem()?);
        Ok(invitation)
    }

    /// Returns redacted status without exposing invitation material.
    pub async fn status(&self, invitation_id: Uuid) -> Option<InvitationStatus> {
        self.invitations.lock().await.status(invitation_id)
    }

    /// Finishes the controller side of SPAKE2 and retains only the derived confirmation key.
    pub async fn begin(
        &self,
        invitation_id: Uuid,
        method: InvitationMethod,
        client_message: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(Vec<u8>, [u8; 32]), IdentityError> {
        let (controller, controller_message) =
            self.invitations
                .lock()
                .await
                .begin_controller(invitation_id, method, now)?;
        let Ok(key) = controller.finish(client_message) else {
            let error = self
                .invitations
                .lock()
                .await
                .record_failure(invitation_id, now);
            return Err(error);
        };
        let proof = key.proof("controller", invitation_id);
        self.handshakes.lock().await.insert(invitation_id, key);
        Ok((controller_message, proof))
    }

    /// Confirms a matching SPAKE2 transcript and records a joining device for approval.
    pub async fn confirm(
        &self,
        invitation_id: Uuid,
        client_proof: &[u8; 32],
        node: Node,
        public_key: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<InvitationStatus, IdentityError> {
        let mut handshakes = self.handshakes.lock().await;
        let key = handshakes
            .get(&invitation_id)
            .ok_or(IdentityError::InvalidHandshake)?;
        self.invitations
            .lock()
            .await
            .confirm_client(invitation_id, key, client_proof, now)?;
        let Some(key) = handshakes.remove(&invitation_id) else {
            return Err(IdentityError::InvalidHandshake);
        };
        self.pending.lock().await.insert(
            invitation_id,
            PendingEnrollment {
                node,
                public_key,
                key,
                credential: None,
                certificate: None,
            },
        );
        self.status(invitation_id)
            .await
            .ok_or(IdentityError::InvitationUnavailable)
    }

    /// Applies administrator approval and issues a protocol-bounded 24-hour credential.
    pub async fn approve(
        &self,
        invitation_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<
        (
            Node,
            MembershipCredential,
            DeviceCertificate,
            InvitationStatus,
        ),
        IdentityError,
    > {
        if let Some(status) = self.status(invitation_id).await
            && status.approved
        {
            let pending = self.pending.lock().await;
            let enrollment = pending
                .get(&invitation_id)
                .ok_or(IdentityError::InvitationUnavailable)?;
            let credential = enrollment
                .credential
                .clone()
                .ok_or(IdentityError::InvitationUnavailable)?;
            let certificate = enrollment
                .certificate
                .clone()
                .ok_or(IdentityError::InvitationUnavailable)?;
            return Ok((enrollment.node.clone(), credential, certificate, status));
        }
        let status = self.invitations.lock().await.approve(invitation_id, now)?;
        let mut pending = self.pending.lock().await;
        let enrollment = pending
            .get_mut(&invitation_id)
            .ok_or(IdentityError::InvitationUnavailable)?;
        let credential = MembershipCredential::issue(
            &self.authority,
            enrollment.node.id.0,
            enrollment.public_key,
            vec!["node".to_owned()],
            now,
            1,
            1,
        );
        let certificate = self.authority.issue_device_certificate(
            enrollment.node.id.0,
            enrollment.public_key,
            now,
        )?;
        enrollment.credential = Some(credential.clone());
        enrollment.certificate = Some(certificate.clone());
        Ok((enrollment.node.clone(), credential, certificate, status))
    }

    /// Returns an approved credential only to a client proving the enrollment key.
    pub async fn credential(
        &self,
        invitation_id: Uuid,
        status_proof: &[u8; 32],
    ) -> Result<Option<(MembershipCredential, DeviceCertificate)>, IdentityError> {
        let pending = self.pending.lock().await;
        let enrollment = pending
            .get(&invitation_id)
            .ok_or(IdentityError::InvitationUnavailable)?;
        if !enrollment
            .key
            .verify_proof("status", invitation_id, status_proof)
        {
            return Err(IdentityError::InvalidProof);
        }
        Ok(enrollment
            .credential
            .clone()
            .zip(enrollment.certificate.clone()))
    }
}

#[cfg(test)]
mod tests {
    use constellation_core::{NodeCapabilities, NodeId, NodeStatus, OperatingSystem};
    use constellation_identity::ClientEnrollment;

    use super::*;

    #[tokio::test]
    async fn enrollment_requires_proof_then_explicit_approval() {
        let now = Utc::now();
        let coordinator = EnrollmentCoordinator::new(DeviceIdentity::generate());
        let invitation = coordinator
            .create_invitation("opaque-cluster", now)
            .await
            .unwrap_or_else(|error| panic!("create invitation: {error}"));
        let (client, client_message) =
            ClientEnrollment::begin(invitation.id, invitation.short_code.as_bytes());
        let begin = coordinator
            .begin(
                invitation.id,
                InvitationMethod::ShortCode,
                &client_message,
                now,
            )
            .await;
        assert!(begin.is_ok());
        let (controller_message, controller_proof) =
            begin.unwrap_or_else(|error| panic!("begin enrollment: {error}"));
        let client_key = client
            .finish(&controller_message)
            .unwrap_or_else(|error| panic!("finish enrollment: {error}"));
        assert!(client_key.verify_proof("controller", invitation.id, &controller_proof));
        let node = Node {
            id: NodeId::new(),
            name: "Joining node".to_owned(),
            os: OperatingSystem::Linux,
            architecture: "x86_64".to_owned(),
            status: NodeStatus::Joining,
            capabilities: NodeCapabilities {
                cpu_model: "simulated".to_owned(),
                logical_cores: 8,
                memory_total_bytes: 16 * 1024 * 1024 * 1024,
                memory_available_bytes: 12 * 1024 * 1024 * 1024,
                accelerator: None,
                runtimes: vec!["mock".to_owned()],
                on_battery: false,
                user_active: false,
                temperature_celsius: None,
                thermal_throttling: None,
            },
            last_seen_at: now,
        };
        let device = DeviceIdentity::generate();
        let confirmed = coordinator
            .confirm(
                invitation.id,
                &client_key.proof("client", invitation.id),
                node,
                device.public_key_bytes(),
                now,
            )
            .await;
        assert!(confirmed.is_ok_and(|status| status.consumed && !status.approved));
        let status_proof = client_key.proof("status", invitation.id);
        assert!(
            coordinator
                .credential(invitation.id, &status_proof)
                .await
                .is_ok_and(|credential| credential.is_none())
        );
        let approved = coordinator.approve(invitation.id, now).await;
        assert!(approved.is_ok());
        let credential = coordinator
            .credential(invitation.id, &status_proof)
            .await
            .unwrap_or_default();
        assert!(credential.is_some_and(|(value, certificate)| {
            value.verify(&coordinator.authority_public_key(), now, 1)
                && certificate.expires_at == now + constellation_identity::CERTIFICATE_LIFETIME
        }));
    }
}
