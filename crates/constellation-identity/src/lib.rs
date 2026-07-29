//! Device identity, bounded enrollment invitations, and membership credentials.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519, SubjectPublicKeyInfo,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Maximum age of any enrollment invitation.
pub const INVITATION_LIFETIME: Duration = Duration::minutes(10);
/// Failed confirmations allowed before invalidation.
pub const MAX_INVITATION_FAILURES: u8 = 5;
/// Maximum membership credential lifetime.
pub const CERTIFICATE_LIFETIME: Duration = Duration::hours(24);

/// X.509 device certificate issued by the cluster authority after administrator approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    /// PEM leaf certificate whose Ed25519 public key is the enrolled device identity.
    pub certificate_pem: String,
    /// Stable self-signed cluster CA certificate used to validate controller and peer traffic.
    pub certificate_authority_pem: String,
    /// Certificate issue time.
    pub issued_at: DateTime<Utc>,
    /// Hard 24-hour certificate expiration.
    pub expires_at: DateTime<Utc>,
}

/// Ephemeral server certificate material signed by the stable cluster authority.
pub struct ServerCertificateMaterial {
    /// Leaf certificate followed by its issuing CA, both DER encoded.
    pub certificate_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 DER private key for the ephemeral server leaf.
    pub private_key_der: Vec<u8>,
    /// Cluster CA DER used as the mTLS client trust root.
    pub certificate_authority_der: Vec<u8>,
}

/// Long-lived Ed25519 device or cluster-authority identity.
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Generates a fresh identity with the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstructs an identity from a 32-byte secret loaded from OS-native storage.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    /// Returns secret bytes for immediate placement in OS-native credential storage.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the public verification key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns a short human-comparable Base32 fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.public_key_bytes());
        BASE32_NOPAD.encode(&digest[..10])
    }

    /// Signs protocol-domain-separated bytes.
    #[must_use]
    pub fn sign(&self, domain: &str, payload: &[u8]) -> [u8; 64] {
        self.signing_key
            .sign(&signature_payload(domain, payload))
            .to_bytes()
    }

    /// Verifies protocol-domain-separated bytes against a public key.
    #[must_use]
    pub fn verify(
        public_key: &[u8; 32],
        domain: &str,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        verifying_key
            .verify(
                &signature_payload(domain, payload),
                &Signature::from_bytes(signature),
            )
            .is_ok()
    }

    /// Serializes the device identity as PKCS#8 PEM for a TLS client without changing its key.
    ///
    /// Callers must keep the returned value in OS-native credential storage or short-lived memory.
    ///
    /// # Errors
    ///
    /// Returns an error only when the validated Ed25519 seed cannot be encoded by the X.509 backend.
    pub fn private_key_pem(&self) -> Result<String, IdentityError> {
        identity_key_pair(self).map(|key| key.serialize_pem())
    }

    /// Returns the stable cluster certificate authority in PEM form for invitation pinning.
    ///
    /// # Errors
    ///
    /// Returns an error if the authority certificate cannot be encoded.
    pub fn certificate_authority_pem(&self) -> Result<String, IdentityError> {
        certificate_issuer(self).map(|issuer| issuer.pem())
    }

    /// Issues a 24-hour client-auth certificate bound to one enrolled device public key.
    ///
    /// # Errors
    ///
    /// Returns an error if X.509 parameters or key encodings cannot be constructed.
    pub fn issue_device_certificate(
        &self,
        device_id: Uuid,
        device_public_key: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<DeviceCertificate, IdentityError> {
        let issuer = certificate_issuer(self)?;
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(IdentityError::certificate)?;
        params.distinguished_name = distinguished_name(&device_id.to_string());
        params.not_before = offset_time(now - Duration::minutes(5))?;
        params.not_after = offset_time(now + CERTIFICATE_LIFETIME)?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let public_key = SubjectPublicKeyInfo::from_der(&ed25519_spki(device_public_key))
            .map_err(IdentityError::certificate)?;
        let certificate = params
            .signed_by(&public_key, &issuer)
            .map_err(IdentityError::certificate)?;
        Ok(DeviceCertificate {
            certificate_pem: certificate.pem(),
            certificate_authority_pem: issuer.pem(),
            issued_at: now,
            expires_at: now + CERTIFICATE_LIFETIME,
        })
    }

    /// Creates a short-lived TLS 1.3 server leaf for the requested bind IP.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation fails.
    pub fn issue_server_certificate(
        &self,
        bind_ip: std::net::IpAddr,
        now: DateTime<Utc>,
    ) -> Result<ServerCertificateMaterial, IdentityError> {
        let issuer = certificate_issuer(self)?;
        let server_key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(IdentityError::certificate)?;
        let mut params = CertificateParams::new(vec![bind_ip.to_string(), "localhost".to_owned()])
            .map_err(IdentityError::certificate)?;
        params.distinguished_name = distinguished_name("Constellation controller");
        params.not_before = offset_time(now - Duration::minutes(5))?;
        params.not_after = offset_time(now + CERTIFICATE_LIFETIME)?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&server_key, &issuer)
            .map_err(IdentityError::certificate)?;
        Ok(ServerCertificateMaterial {
            certificate_chain_der: vec![certificate.der().to_vec(), issuer.der().to_vec()],
            private_key_der: server_key.serialize_der(),
            certificate_authority_der: issuer.der().to_vec(),
        })
    }
}

fn certificate_issuer(
    identity: &DeviceIdentity,
) -> Result<CertifiedIssuer<'static, KeyPair>, IdentityError> {
    let signing_key = identity_key_pair(identity)?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(IdentityError::certificate)?;
    params.distinguished_name = distinguished_name("Constellation cluster authority");
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    CertifiedIssuer::self_signed(params, signing_key).map_err(IdentityError::certificate)
}

fn identity_key_pair(identity: &DeviceIdentity) -> Result<KeyPair, IdentityError> {
    let mut pkcs8 = Zeroizing::new(Vec::with_capacity(48));
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(&identity.secret_bytes());
    KeyPair::try_from(pkcs8.to_vec()).map_err(IdentityError::certificate)
}

fn ed25519_spki(public_key: [u8; 32]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    spki.extend_from_slice(&public_key);
    spki
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Constellation");
    name.push(DnType::CommonName, common_name);
    name
}

fn offset_time(value: DateTime<Utc>) -> Result<time::OffsetDateTime, IdentityError> {
    time::OffsetDateTime::from_unix_timestamp(value.timestamp()).map_err(|error| {
        IdentityError::Certificate(format!("certificate time is invalid: {error}"))
    })
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::generate()
    }
}

/// Secret path selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationMethod {
    /// Eight-character Base32 code used with SPAKE2.
    ShortCode,
    /// 128-bit link or QR secret used with SPAKE2.
    LinkSecret,
}

/// User-visible invitation material. It must never enter logs or durable events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvitationPresentation {
    /// Invitation identity safe to persist.
    pub id: Uuid,
    /// Opaque cluster discovery identifier.
    pub cluster_id: String,
    /// Eight Base32 characters with 40 bits of entropy.
    pub short_code: String,
    /// URL-safe 128-bit secret for QR/deep-link enrollment.
    pub link_secret: String,
    /// Stable cluster CA to pin before using a non-loopback HTTPS enrollment endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_authority_pem: Option<String>,
    /// Hard expiration time.
    pub expires_at: DateTime<Utc>,
}

/// Durable invitation status containing no enrollment secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationStatus {
    /// Invitation identity.
    pub id: Uuid,
    /// Hard expiration time.
    pub expires_at: DateTime<Utc>,
    /// Failed key confirmations.
    pub failed_attempts: u8,
    /// A joining device proved possession of the secret.
    pub consumed: bool,
    /// An administrator approved membership after secret proof.
    pub approved: bool,
    /// Administrator approval time.
    pub approved_at: Option<DateTime<Utc>>,
}

struct ActiveInvitation {
    status: InvitationStatus,
    short_code: Zeroizing<Vec<u8>>,
    link_secret: Zeroizing<Vec<u8>>,
}

/// In-memory secret-bearing invitation registry. Durable persistence stores only `InvitationStatus`.
#[derive(Default)]
pub struct InvitationRegistry {
    invitations: HashMap<Uuid, ActiveInvitation>,
}

impl InvitationRegistry {
    /// Creates a single-use invitation with both human and link presentations.
    #[must_use]
    pub fn create(&mut self, cluster_id: &str, now: DateTime<Utc>) -> InvitationPresentation {
        let id = Uuid::now_v7();
        let mut code_bytes = [0_u8; 5];
        let mut link_bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut code_bytes);
        OsRng.fill_bytes(&mut link_bytes);
        let short_code = BASE32_NOPAD.encode(&code_bytes);
        let link_secret = BASE64URL_NOPAD.encode(&link_bytes);
        let expires_at = now + INVITATION_LIFETIME;
        self.invitations.insert(
            id,
            ActiveInvitation {
                status: InvitationStatus {
                    id,
                    expires_at,
                    failed_attempts: 0,
                    consumed: false,
                    approved: false,
                    approved_at: None,
                },
                short_code: Zeroizing::new(short_code.as_bytes().to_vec()),
                link_secret: Zeroizing::new(link_secret.as_bytes().to_vec()),
            },
        );
        InvitationPresentation {
            id,
            cluster_id: cluster_id.to_owned(),
            short_code,
            link_secret,
            certificate_authority_pem: None,
            expires_at,
        }
    }

    /// Begins the controller half of SPAKE2 for an active invitation.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, expired, consumed, approved, or invalidated invitations.
    pub fn begin_controller(
        &self,
        invitation_id: Uuid,
        method: InvitationMethod,
        now: DateTime<Utc>,
    ) -> Result<(ControllerEnrollment, Vec<u8>), IdentityError> {
        let invitation = self.usable(invitation_id, now)?;
        let secret = invitation.secret(method);
        let identities = enrollment_identities(invitation_id);
        let (state, outbound) = Spake2::<Ed25519Group>::start_b(
            &Password::new(secret),
            &Identity::new(&identities.0),
            &Identity::new(&identities.1),
        );
        Ok((
            ControllerEnrollment {
                invitation_id,
                state: Some(state),
            },
            outbound,
        ))
    }

    /// Records a client proof, consuming the invitation on success.
    ///
    /// # Errors
    ///
    /// Returns an error and increments the failure count when proof is invalid. The fifth
    /// failure permanently invalidates the invitation.
    pub fn confirm_client(
        &mut self,
        invitation_id: Uuid,
        key: &EnrollmentKey,
        client_proof: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        let invitation = self
            .invitations
            .get_mut(&invitation_id)
            .ok_or(IdentityError::InvitationUnavailable)?;
        validate_status(&invitation.status, now)?;
        let expected = key.proof("client", invitation_id);
        if !bool::from(expected.ct_eq(client_proof)) {
            invitation.status.failed_attempts = invitation.status.failed_attempts.saturating_add(1);
            return Err(
                if invitation.status.failed_attempts >= MAX_INVITATION_FAILURES {
                    IdentityError::InvitationInvalidated
                } else {
                    IdentityError::InvalidProof
                },
            );
        }
        invitation.status.consumed = true;
        invitation.short_code.zeroize();
        invitation.link_secret.zeroize();
        Ok(())
    }

    /// Applies the mandatory administrator approval after key confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error unless secret proof succeeded and the invitation remains current.
    pub fn approve(
        &mut self,
        invitation_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<InvitationStatus, IdentityError> {
        let invitation = self
            .invitations
            .get_mut(&invitation_id)
            .ok_or(IdentityError::InvitationUnavailable)?;
        if now >= invitation.status.expires_at {
            return Err(IdentityError::InvitationExpired);
        }
        if !invitation.status.consumed {
            return Err(IdentityError::ApprovalRequired);
        }
        invitation.status.approved = true;
        invitation.status.approved_at = Some(now);
        Ok(invitation.status.clone())
    }

    /// Returns a redacted durable status.
    #[must_use]
    pub fn status(&self, invitation_id: Uuid) -> Option<InvitationStatus> {
        self.invitations
            .get(&invitation_id)
            .map(|invitation| invitation.status.clone())
    }

    /// Records a failed enrollment attempt and invalidates the invitation at the limit.
    ///
    /// # Errors
    ///
    /// Returns the resulting stable failure state.
    pub fn record_failure(&mut self, invitation_id: Uuid, now: DateTime<Utc>) -> IdentityError {
        let Some(invitation) = self.invitations.get_mut(&invitation_id) else {
            return IdentityError::InvitationUnavailable;
        };
        if let Err(error) = validate_status(&invitation.status, now) {
            return error;
        }
        invitation.status.failed_attempts = invitation.status.failed_attempts.saturating_add(1);
        if invitation.status.failed_attempts >= MAX_INVITATION_FAILURES {
            IdentityError::InvitationInvalidated
        } else {
            IdentityError::InvalidHandshake
        }
    }

    fn usable(
        &self,
        invitation_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<&ActiveInvitation, IdentityError> {
        let invitation = self
            .invitations
            .get(&invitation_id)
            .ok_or(IdentityError::InvitationUnavailable)?;
        validate_status(&invitation.status, now)?;
        Ok(invitation)
    }
}

impl ActiveInvitation {
    fn secret(&self, method: InvitationMethod) -> &[u8] {
        match method {
            InvitationMethod::ShortCode => &self.short_code,
            InvitationMethod::LinkSecret => &self.link_secret,
        }
    }
}

/// Joining-device half of one SPAKE2 exchange.
pub struct ClientEnrollment {
    invitation_id: Uuid,
    state: Option<Spake2<Ed25519Group>>,
}

impl ClientEnrollment {
    /// Begins the joining half from user-entered or QR-provided secret material.
    #[must_use]
    pub fn begin(invitation_id: Uuid, secret: &[u8]) -> (Self, Vec<u8>) {
        let identities = enrollment_identities(invitation_id);
        let (state, outbound) = Spake2::<Ed25519Group>::start_a(
            &Password::new(secret),
            &Identity::new(&identities.0),
            &Identity::new(&identities.1),
        );
        (
            Self {
                invitation_id,
                state: Some(state),
            },
            outbound,
        )
    }

    /// Finishes the exchange and derives a confirmation key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or reflected peer messages or session reuse.
    pub fn finish(mut self, controller_message: &[u8]) -> Result<EnrollmentKey, IdentityError> {
        let state = self.state.take().ok_or(IdentityError::SessionConsumed)?;
        let shared = state
            .finish(controller_message)
            .map_err(|_| IdentityError::InvalidHandshake)?;
        Ok(EnrollmentKey::derive(self.invitation_id, &shared))
    }
}

/// Controller half of one SPAKE2 exchange.
pub struct ControllerEnrollment {
    invitation_id: Uuid,
    state: Option<Spake2<Ed25519Group>>,
}

impl ControllerEnrollment {
    /// Finishes the exchange and derives a confirmation key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or reflected peer messages or session reuse.
    pub fn finish(mut self, client_message: &[u8]) -> Result<EnrollmentKey, IdentityError> {
        let state = self.state.take().ok_or(IdentityError::SessionConsumed)?;
        let shared = state
            .finish(client_message)
            .map_err(|_| IdentityError::InvalidHandshake)?;
        Ok(EnrollmentKey::derive(self.invitation_id, &shared))
    }
}

/// Derived SPAKE2 key used only for transcript confirmation and subsequent enrollment wrapping.
pub struct EnrollmentKey(Zeroizing<[u8; 32]>);

impl EnrollmentKey {
    fn derive(invitation_id: Uuid, shared: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"constellation enrollment key v1\0");
        digest.update(invitation_id.as_bytes());
        digest.update(shared);
        Self(Zeroizing::new(digest.finalize().into()))
    }

    /// Produces a role-specific confirmation proof.
    #[must_use]
    pub fn proof(&self, role: &str, invitation_id: Uuid) -> [u8; 32] {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.0.as_ref()) else {
            return [0_u8; 32];
        };
        mac.update(b"constellation enrollment proof v1\0");
        mac.update(role.as_bytes());
        mac.update(invitation_id.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Verifies a role-specific confirmation proof in constant time.
    #[must_use]
    pub fn verify_proof(&self, role: &str, invitation_id: Uuid, proof: &[u8; 32]) -> bool {
        bool::from(self.proof(role, invitation_id).ct_eq(proof))
    }
}

/// Authority-signed membership credential used before X.509 transport encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCredential {
    /// Credential serial number.
    pub serial: Uuid,
    /// Device identifier.
    pub device_id: Uuid,
    /// Device Ed25519 key.
    pub device_public_key: [u8; 32],
    /// Granted cluster roles.
    pub roles: Vec<String>,
    /// Issue time.
    pub issued_at: DateTime<Utc>,
    /// Hard expiration no more than 24 hours later.
    pub expires_at: DateTime<Utc>,
    /// Minimum supported protocol version.
    pub protocol_min: u32,
    /// Maximum supported protocol version.
    pub protocol_max: u32,
    /// Cluster authority signature.
    pub signature: Vec<u8>,
}

/// Authority-signed authorization for one peer model-chunk transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerTransferTicket {
    /// Unique ticket identity.
    pub id: Uuid,
    /// Node serving the verified chunk.
    pub source_node: Uuid,
    /// Node permitted to receive the chunk.
    pub destination_node: Uuid,
    /// Full model digest containing the chunk.
    pub model_sha256: String,
    /// Authorized 4 MiB-or-smaller chunk digest.
    pub chunk_sha256: String,
    /// Issue time.
    pub issued_at: DateTime<Utc>,
    /// Short expiry, never longer than ten minutes.
    pub expires_at: DateTime<Utc>,
    /// Cluster authority signature.
    pub signature: Vec<u8>,
}

impl PeerTransferTicket {
    /// Issues a ten-minute ticket scoped to one source, destination, model, and chunk.
    #[must_use]
    pub fn issue(
        authority: &DeviceIdentity,
        source_node: Uuid,
        destination_node: Uuid,
        model_sha256: String,
        chunk_sha256: String,
        now: DateTime<Utc>,
    ) -> Self {
        let mut ticket = Self {
            id: Uuid::now_v7(),
            source_node,
            destination_node,
            model_sha256,
            chunk_sha256,
            issued_at: now,
            expires_at: now + INVITATION_LIFETIME,
            signature: Vec::new(),
        };
        ticket.signature = authority
            .sign("peer transfer ticket v1", &ticket.signing_bytes())
            .to_vec();
        ticket
    }

    /// Verifies scope, lifetime, digest shape, and authority signature.
    #[must_use]
    pub fn verify(
        &self,
        authority_public_key: &[u8; 32],
        now: DateTime<Utc>,
        source_node: Uuid,
        destination_node: Uuid,
        chunk_sha256: &str,
    ) -> bool {
        if self.source_node != source_node
            || self.destination_node != destination_node
            || self.chunk_sha256 != chunk_sha256
            || self.model_sha256.len() != 64
            || self.chunk_sha256.len() != 64
            || now < self.issued_at
            || now >= self.expires_at
            || self.expires_at - self.issued_at > INVITATION_LIFETIME
            || !self
                .model_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !self
                .chunk_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return false;
        }
        let Ok(signature) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        DeviceIdentity::verify(
            authority_public_key,
            "peer transfer ticket v1",
            &self.signing_bytes(),
            &signature,
        )
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(self.id.as_bytes());
        encoded.extend_from_slice(self.source_node.as_bytes());
        encoded.extend_from_slice(self.destination_node.as_bytes());
        encoded.extend_from_slice(self.model_sha256.as_bytes());
        encoded.extend_from_slice(self.chunk_sha256.as_bytes());
        encoded.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        encoded.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        encoded
    }
}

impl MembershipCredential {
    /// Issues a 24-hour authority-signed credential.
    #[must_use]
    pub fn issue(
        authority: &DeviceIdentity,
        device_id: Uuid,
        device_public_key: [u8; 32],
        roles: Vec<String>,
        now: DateTime<Utc>,
        protocol_min: u32,
        protocol_max: u32,
    ) -> Self {
        let mut credential = Self {
            serial: Uuid::now_v7(),
            device_id,
            device_public_key,
            roles,
            issued_at: now,
            expires_at: now + CERTIFICATE_LIFETIME,
            protocol_min,
            protocol_max,
            signature: Vec::new(),
        };
        credential.signature = authority
            .sign("membership credential v1", &credential.signing_bytes())
            .to_vec();
        credential
    }

    /// Verifies authority signature, validity interval, and protocol negotiation.
    #[must_use]
    pub fn verify(
        &self,
        authority_public_key: &[u8; 32],
        now: DateTime<Utc>,
        protocol_version: u32,
    ) -> bool {
        if now < self.issued_at
            || now >= self.expires_at
            || self.expires_at - self.issued_at > CERTIFICATE_LIFETIME
            || protocol_version < self.protocol_min
            || protocol_version > self.protocol_max
        {
            return false;
        }
        let Ok(signature) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        DeviceIdentity::verify(
            authority_public_key,
            "membership credential v1",
            &self.signing_bytes(),
            &signature,
        )
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(self.serial.as_bytes());
        encoded.extend_from_slice(self.device_id.as_bytes());
        encoded.extend_from_slice(&self.device_public_key);
        for role in &self.roles {
            encoded.extend_from_slice(&u64::try_from(role.len()).unwrap_or(u64::MAX).to_be_bytes());
            encoded.extend_from_slice(role.as_bytes());
        }
        encoded.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        encoded.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        encoded.extend_from_slice(&self.protocol_min.to_be_bytes());
        encoded.extend_from_slice(&self.protocol_max.to_be_bytes());
        encoded
    }
}

/// Stable identity and enrollment failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// Invitation is missing or no longer usable.
    #[error("invitation is unavailable")]
    InvitationUnavailable,
    /// Invitation expired.
    #[error("invitation expired")]
    InvitationExpired,
    /// Five confirmation failures invalidated the invitation.
    #[error("invitation was invalidated")]
    InvitationInvalidated,
    /// Key confirmation failed.
    #[error("enrollment proof is invalid")]
    InvalidProof,
    /// Administrator approval has not occurred.
    #[error("administrator approval is required")]
    ApprovalRequired,
    /// SPAKE2 peer message was malformed or reflected.
    #[error("enrollment handshake is invalid")]
    InvalidHandshake,
    /// One-shot session was reused.
    #[error("enrollment session was already consumed")]
    SessionConsumed,
    /// X.509 material could not be created from a validated device identity.
    #[error("certificate operation failed: {0}")]
    Certificate(String),
}

impl IdentityError {
    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err at X.509 boundaries.
    fn certificate(error: rcgen::Error) -> Self {
        Self::Certificate(error.to_string())
    }
}

fn validate_status(status: &InvitationStatus, now: DateTime<Utc>) -> Result<(), IdentityError> {
    if now >= status.expires_at {
        Err(IdentityError::InvitationExpired)
    } else if status.failed_attempts >= MAX_INVITATION_FAILURES {
        Err(IdentityError::InvitationInvalidated)
    } else if status.consumed || status.approved {
        Err(IdentityError::InvitationUnavailable)
    } else {
        Ok(())
    }
}

fn enrollment_identities(invitation_id: Uuid) -> (Vec<u8>, Vec<u8>) {
    (
        format!("joining-device:{invitation_id}").into_bytes(),
        format!("cluster-controller:{invitation_id}").into_bytes(),
    )
}

fn signature_payload(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + payload.len() + 32);
    message.extend_from_slice(b"constellation signature v1\0");
    message.extend_from_slice(
        &u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(payload);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_signatures_are_domain_separated() {
        let identity = DeviceIdentity::generate();
        let public = identity.public_key_bytes();
        let signature = identity.sign("inventory", b"payload");
        assert!(DeviceIdentity::verify(
            &public,
            "inventory",
            b"payload",
            &signature
        ));
        assert!(!DeviceIdentity::verify(
            &public,
            "heartbeat",
            b"payload",
            &signature
        ));
    }

    #[test]
    fn stable_ca_issues_key_bound_twenty_four_hour_certificates() {
        let identity = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_secret_bytes(&identity.secret_bytes());
        assert_eq!(
            identity.certificate_authority_pem().unwrap_or_default(),
            restored.certificate_authority_pem().unwrap_or_default()
        );
        let device = DeviceIdentity::generate();
        let now = Utc::now();
        let certificate =
            identity.issue_device_certificate(Uuid::now_v7(), device.public_key_bytes(), now);
        assert!(certificate.is_ok_and(|value| {
            value
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
                && value.certificate_authority_pem
                    == identity.certificate_authority_pem().unwrap_or_default()
                && value.expires_at == now + CERTIFICATE_LIFETIME
        }));
        assert!(
            device
                .private_key_pem()
                .is_ok_and(|pem| pem.starts_with("-----BEGIN PRIVATE KEY-----"))
        );
    }

    #[test]
    fn invitation_uses_exact_entropy_presentations_and_expires() {
        let now = Utc::now();
        let mut registry = InvitationRegistry::default();
        let invitation = registry.create("opaque-cluster", now);
        assert_eq!(invitation.short_code.len(), 8);
        assert_eq!(
            BASE32_NOPAD
                .decode(invitation.short_code.as_bytes())
                .map_or(0, |v| v.len()),
            5
        );
        assert_eq!(
            BASE64URL_NOPAD
                .decode(invitation.link_secret.as_bytes())
                .map_or(0, |v| v.len()),
            16
        );
        assert_eq!(invitation.expires_at, now + INVITATION_LIFETIME);
        assert_eq!(
            registry
                .begin_controller(
                    invitation.id,
                    InvitationMethod::ShortCode,
                    invitation.expires_at
                )
                .err(),
            Some(IdentityError::InvitationExpired)
        );
    }

    #[test]
    fn spake2_requires_matching_secret_and_admin_approval() {
        let now = Utc::now();
        let mut registry = InvitationRegistry::default();
        let invitation = registry.create("opaque-cluster", now);
        let (client, client_message) =
            ClientEnrollment::begin(invitation.id, invitation.short_code.as_bytes());
        let controller_result =
            registry.begin_controller(invitation.id, InvitationMethod::ShortCode, now);
        assert!(controller_result.is_ok());
        let (controller, controller_message) =
            controller_result.unwrap_or_else(|error| panic!("begin: {error}"));
        let client_key = client
            .finish(&controller_message)
            .unwrap_or_else(|error| panic!("client finish: {error}"));
        let controller_key = controller
            .finish(&client_message)
            .unwrap_or_else(|error| panic!("controller finish: {error}"));
        let client_proof = client_key.proof("client", invitation.id);
        assert_eq!(client_proof, controller_key.proof("client", invitation.id));
        assert_eq!(
            registry.approve(invitation.id, now),
            Err(IdentityError::ApprovalRequired)
        );
        assert!(
            registry
                .confirm_client(invitation.id, &controller_key, &client_proof, now)
                .is_ok()
        );
        let approved = registry.approve(invitation.id, now);
        assert!(approved.is_ok_and(|status| status.approved));
    }

    #[test]
    fn invitation_invalidates_after_five_bad_confirmations() {
        let now = Utc::now();
        let mut registry = InvitationRegistry::default();
        let invitation = registry.create("opaque-cluster", now);
        let fake_key = EnrollmentKey::derive(invitation.id, b"fake shared key");
        for attempt in 1..=MAX_INVITATION_FAILURES {
            let result = registry.confirm_client(invitation.id, &fake_key, &[0_u8; 32], now);
            if attempt < MAX_INVITATION_FAILURES {
                assert_eq!(result, Err(IdentityError::InvalidProof));
            } else {
                assert_eq!(result, Err(IdentityError::InvitationInvalidated));
            }
        }
        assert_eq!(
            registry
                .begin_controller(invitation.id, InvitationMethod::ShortCode, now)
                .err(),
            Some(IdentityError::InvitationInvalidated)
        );
    }

    #[test]
    fn membership_credentials_expire_and_negotiate_protocol() {
        let now = Utc::now();
        let authority = DeviceIdentity::generate();
        let device = DeviceIdentity::generate();
        let credential = MembershipCredential::issue(
            &authority,
            Uuid::now_v7(),
            device.public_key_bytes(),
            vec!["node".to_owned()],
            now,
            1,
            2,
        );
        assert!(credential.verify(&authority.public_key_bytes(), now, 1));
        assert!(!credential.verify(&authority.public_key_bytes(), now, 3));
        assert!(!credential.verify(&authority.public_key_bytes(), now + CERTIFICATE_LIFETIME, 1));
    }

    #[test]
    fn peer_transfer_ticket_is_bound_to_every_transfer_dimension() {
        let now = Utc::now();
        let authority = DeviceIdentity::generate();
        let source = Uuid::now_v7();
        let destination = Uuid::now_v7();
        let model = "a".repeat(64);
        let chunk = "b".repeat(64);
        let ticket =
            PeerTransferTicket::issue(&authority, source, destination, model, chunk.clone(), now);
        assert!(ticket.verify(
            &authority.public_key_bytes(),
            now,
            source,
            destination,
            &chunk,
        ));
        assert!(!ticket.verify(
            &authority.public_key_bytes(),
            now,
            source,
            Uuid::now_v7(),
            &chunk,
        ));
        assert!(!ticket.verify(
            &authority.public_key_bytes(),
            now + INVITATION_LIFETIME,
            source,
            destination,
            &chunk,
        ));
    }
}
