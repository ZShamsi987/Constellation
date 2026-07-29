//! Deny-by-default WASI Component Model plugin contracts and host.

use std::collections::BTreeSet;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker, ResourceTable, Val};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_IO_BYTES: usize = 1024 * 1024;

/// Plugin validation, authorization, or sandbox execution error.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// Manifest does not satisfy the versioned contract.
    #[error("invalid plugin manifest: {0}")]
    InvalidManifest(String),
    /// Component digest does not match the manifest.
    #[error("plugin component integrity verification failed")]
    Integrity,
    /// A permission was not declared and granted.
    #[error("plugin permission denied: {0}")]
    PermissionDenied(String),
    /// Component cannot be compiled or linked within the sandbox.
    #[error("plugin component is incompatible: {0}")]
    Incompatible(String),
    /// Guest execution trapped or violated a resource bound.
    #[error("plugin execution failed: {0}")]
    Execution(String),
}

/// Plugin category and extension boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    /// Sandboxed workflow tool.
    Tool,
    /// Runtime adapter implemented through the stable host interface.
    Runtime,
    /// Authentication or cloud provider.
    Provider,
    /// Declarative UI panel; arbitrary browser scripts are forbidden.
    Ui,
}

/// Fine-grained permission. Missing permissions are denied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "permission", rename_all = "snake_case", deny_unknown_fields)]
pub enum PluginPermission {
    /// Read content-free cluster inventory.
    ClusterInventoryRead,
    /// Submit model inference for an explicit alias allowlist.
    ModelInference {
        /// Allowed model aliases.
        models: Vec<String>,
    },
    /// Read a host-mounted directory under an opaque mount identifier.
    FilesystemRead {
        /// Administrator-configured mount name, never a host path.
        mount: String,
    },
    /// Write encrypted workflow artifacts.
    ArtifactWrite,
    /// Read explicitly named credentials through opaque handles.
    CredentialRead {
        /// Allowed credential names.
        names: Vec<String>,
    },
    /// Make outbound HTTPS calls to an exact hostname allowlist.
    NetworkHttps {
        /// DNS hostnames; IP literals and wildcards are forbidden.
        hosts: Vec<String>,
    },
    /// Register bounded workflow schedules.
    ScheduleWrite,
    /// Contribute a declarative UI panel definition.
    UiPanel,
}

/// Versioned plugin manifest distributed beside one component binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Manifest schema version. The current version is one.
    pub schema_version: u16,
    /// Reverse-DNS plugin identifier.
    pub id: String,
    /// Semantic plugin version.
    pub version: Version,
    /// Extension category.
    pub kind: PluginKind,
    /// Relative component file path.
    pub component: String,
    /// Lowercase component SHA-256.
    pub sha256: String,
    /// Compatible Constellation host protocol versions.
    pub host_protocol: VersionReq,
    /// Requested capabilities; installation grants remain separate.
    #[serde(default)]
    pub permissions: Vec<PluginPermission>,
    /// Declarative marketplace metadata.
    pub metadata: PluginMetadata,
}

/// Marketplace and UI metadata with no executable content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginMetadata {
    /// Display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// SPDX license expression supplied by the publisher.
    pub license: String,
    /// Publisher identity shown before installation.
    pub publisher: String,
    /// HTTPS source repository.
    pub repository: String,
    /// Optional declarative panel schema for UI plugins.
    pub ui: Option<DeclarativeUiPanel>,
}

/// Safe UI extension rendered by host-owned components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarativeUiPanel {
    /// Navigation label.
    pub title: String,
    /// Host-owned icon name.
    pub icon: String,
    /// Read-only data endpoints used by host widgets.
    pub data_sources: Vec<String>,
    /// Declarative widget tree; script and raw HTML fields are rejected.
    pub layout: Value,
}

/// Administrator-approved permission set for one exact plugin digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginGrant {
    /// Plugin identifier.
    pub plugin_id: String,
    /// Exact component digest.
    pub component_sha256: String,
    /// Granted subset of manifest permissions.
    pub permissions: Vec<PluginPermission>,
    /// Local administrator who approved the grants.
    pub approved_by: String,
}

/// Validates a manifest before component bytes are accepted.
///
/// # Errors
///
/// Returns the first deterministic schema, permission, or metadata violation.
#[allow(clippy::too_many_lines)] // Stable validation order is part of the security contract.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginError> {
    if manifest.schema_version != 1 {
        return Err(PluginError::InvalidManifest(
            "only schema version 1 is supported".to_owned(),
        ));
    }
    if !valid_reverse_dns(&manifest.id) {
        return Err(PluginError::InvalidManifest(
            "id must be a bounded reverse-DNS name".to_owned(),
        ));
    }
    if manifest.component.is_empty()
        || manifest.component.len() > 256
        || manifest.component.starts_with('/')
        || manifest.component.split('/').any(|part| part == "..")
        || !std::path::Path::new(&manifest.component)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
    {
        return Err(PluginError::InvalidManifest(
            "component must be a relative .wasm path without traversal".to_owned(),
        ));
    }
    if !is_sha256(&manifest.sha256) {
        return Err(PluginError::InvalidManifest(
            "component SHA-256 is invalid".to_owned(),
        ));
    }
    if manifest.metadata.name.trim().is_empty()
        || manifest.metadata.name.len() > 128
        || manifest.metadata.description.len() > 1024
        || manifest.metadata.license.trim().is_empty()
        || manifest.metadata.license.len() > 128
        || manifest.metadata.publisher.trim().is_empty()
        || manifest.metadata.publisher.len() > 128
        || !manifest.metadata.repository.starts_with("https://")
        || manifest.metadata.repository.len() > 512
    {
        return Err(PluginError::InvalidManifest(
            "marketplace metadata is invalid".to_owned(),
        ));
    }
    let unique = manifest
        .permissions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if unique.len() != manifest.permissions.len() || unique.len() > 32 {
        return Err(PluginError::InvalidManifest(
            "permissions are duplicated or exceed the limit".to_owned(),
        ));
    }
    for permission in &manifest.permissions {
        match permission {
            PluginPermission::ModelInference { models } => {
                validate_string_allowlist(models, "model")?;
            }
            PluginPermission::FilesystemRead { mount } if !valid_identifier(mount) => {
                return Err(PluginError::InvalidManifest(
                    "filesystem mount identifier is invalid".to_owned(),
                ));
            }
            PluginPermission::CredentialRead { names } => {
                validate_string_allowlist(names, "credential")?;
            }
            PluginPermission::NetworkHttps { hosts } => validate_hosts(hosts)?,
            PluginPermission::ClusterInventoryRead
            | PluginPermission::ArtifactWrite
            | PluginPermission::ScheduleWrite
            | PluginPermission::UiPanel
            | PluginPermission::FilesystemRead { .. } => {}
        }
    }
    match (manifest.kind, &manifest.metadata.ui) {
        (PluginKind::Ui, Some(panel)) => validate_ui_panel(panel)?,
        (PluginKind::Ui, None) => {
            return Err(PluginError::InvalidManifest(
                "UI plugins require a declarative panel".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(PluginError::InvalidManifest(
                "only UI plugins may define a panel".to_owned(),
            ));
        }
        (_, None) => {}
    }
    Ok(())
}

fn validate_string_allowlist(values: &[String], kind: &str) -> Result<(), PluginError> {
    if values.is_empty()
        || values.len() > 64
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 256 || value == "*")
    {
        return Err(PluginError::InvalidManifest(format!(
            "{kind} allowlist is invalid"
        )));
    }
    Ok(())
}

fn validate_hosts(hosts: &[String]) -> Result<(), PluginError> {
    if hosts.is_empty()
        || hosts.len() > 64
        || hosts.iter().any(|host| {
            host.is_empty()
                || host.len() > 253
                || host.contains('*')
                || host.parse::<std::net::IpAddr>().is_ok()
                || host.starts_with('.')
                || !host.contains('.')
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
    {
        return Err(PluginError::InvalidManifest(
            "HTTPS hostname allowlist is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ui_panel(panel: &DeclarativeUiPanel) -> Result<(), PluginError> {
    let encoded = serde_json::to_vec(&panel.layout)
        .map_err(|error| PluginError::InvalidManifest(error.to_string()))?;
    let lower = String::from_utf8_lossy(&encoded).to_ascii_lowercase();
    if panel.title.trim().is_empty()
        || panel.title.len() > 64
        || !valid_identifier(&panel.icon)
        || panel.data_sources.len() > 32
        || encoded.len() > 256 * 1024
        || lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("dangerouslysetinnerhtml")
        || panel
            .data_sources
            .iter()
            .any(|source| !source.starts_with("/constellation/v1/plugins/self/"))
    {
        return Err(PluginError::InvalidManifest(
            "declarative UI panel is invalid or contains executable content".to_owned(),
        ));
    }
    Ok(())
}

fn valid_reverse_dns(value: &str) -> bool {
    value.len() <= 128 && value.split('.').count() >= 3 && value.split('.').all(valid_identifier)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Ensures every grant was declared and is bound to the exact component digest.
///
/// # Errors
///
/// Returns permission denied for digest drift, wrong plugin identity, or grant expansion.
pub fn validate_grant(manifest: &PluginManifest, grant: &PluginGrant) -> Result<(), PluginError> {
    if grant.plugin_id != manifest.id
        || grant.component_sha256 != manifest.sha256
        || grant.approved_by.trim().is_empty()
        || grant.approved_by.len() > 128
    {
        return Err(PluginError::PermissionDenied(
            "grant is not bound to this exact plugin".to_owned(),
        ));
    }
    if grant
        .permissions
        .iter()
        .any(|permission| !manifest.permissions.contains(permission))
    {
        return Err(PluginError::PermissionDenied(
            "grant contains a permission absent from the manifest".to_owned(),
        ));
    }
    Ok(())
}

/// Wasmtime component host with fuel limits and a non-inheriting WASI context.
#[derive(Clone)]
pub struct PluginHost {
    engine: Engine,
    host_protocol: Version,
    fuel: u64,
}

impl PluginHost {
    /// Creates the sandbox host for one protocol version.
    ///
    /// # Errors
    ///
    /// Returns an incompatible error when Wasmtime cannot initialize.
    pub fn new(host_protocol: Version, fuel: u64) -> Result<Self, PluginError> {
        if fuel == 0 {
            return Err(PluginError::InvalidManifest(
                "plugin fuel limit must be nonzero".to_owned(),
            ));
        }
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|error| PluginError::Incompatible(error.to_string()))?;
        Ok(Self {
            engine,
            host_protocol,
            fuel,
        })
    }

    /// Compiles and integrity-checks one component without executing it.
    ///
    /// # Errors
    ///
    /// Returns manifest, integrity, compatibility, or size failures.
    pub fn compile(
        &self,
        manifest: &PluginManifest,
        component_bytes: &[u8],
    ) -> Result<Component, PluginError> {
        validate_manifest(manifest)?;
        if !manifest.host_protocol.matches(&self.host_protocol) {
            return Err(PluginError::Incompatible(format!(
                "host protocol {} is outside {}",
                self.host_protocol, manifest.host_protocol
            )));
        }
        if component_bytes.is_empty() || component_bytes.len() > MAX_COMPONENT_BYTES {
            return Err(PluginError::Incompatible(
                "component must contain at most 64 MiB".to_owned(),
            ));
        }
        if format!("{:x}", Sha256::digest(component_bytes)) != manifest.sha256 {
            return Err(PluginError::Integrity);
        }
        Component::new(&self.engine, component_bytes)
            .map_err(|error| PluginError::Incompatible(error.to_string()))
    }

    /// Executes a component's canonical `run(string) -> string` export.
    ///
    /// The WASI context inherits no arguments, environment, standard streams, filesystem mounts,
    /// sockets, or host credentials. Higher-level capabilities are provided only by separately
    /// authorized Constellation host interfaces.
    ///
    /// # Errors
    ///
    /// Returns permission, compatibility, fuel, trap, or I/O-bound failures.
    pub fn execute(
        &self,
        manifest: &PluginManifest,
        grant: &PluginGrant,
        component_bytes: &[u8],
        input: &str,
    ) -> Result<String, PluginError> {
        validate_grant(manifest, grant)?;
        if input.len() > MAX_IO_BYTES {
            return Err(PluginError::Execution(
                "plugin input exceeds the 1 MiB limit".to_owned(),
            ));
        }
        let component = self.compile(manifest, component_bytes)?;
        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|error| PluginError::Incompatible(error.to_string()))?;
        let mut store = Store::new(
            &self.engine,
            HostState {
                table: ResourceTable::new(),
                wasi: WasiCtx::builder().build(),
            },
        );
        store
            .set_fuel(self.fuel)
            .map_err(|error| PluginError::Execution(error.to_string()))?;
        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|error| PluginError::Incompatible(error.to_string()))?;
        let function = instance
            .get_func(&mut store, "run")
            .ok_or_else(|| PluginError::Incompatible("run export is missing".to_owned()))?;
        let mut results = [Val::String(String::new())];
        function
            .call(&mut store, &[Val::String(input.to_owned())], &mut results)
            .map_err(|error| PluginError::Execution(error.to_string()))?;
        let Val::String(output) = &results[0] else {
            return Err(PluginError::Incompatible(
                "run export did not return a string".to_owned(),
            ));
        };
        if output.len() > MAX_IO_BYTES {
            return Err(PluginError::Execution(
                "plugin output exceeds the 1 MiB limit".to_owned(),
            ));
        }
        Ok(output.clone())
    }
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> PluginManifest {
        PluginManifest {
            schema_version: 1,
            id: "com.constellation.example".to_owned(),
            version: Version::new(1, 0, 0),
            kind: PluginKind::Tool,
            component: "plugin.wasm".to_owned(),
            sha256: "0".repeat(64),
            host_protocol: VersionReq::parse("^1.0").unwrap_or(VersionReq::STAR),
            permissions: vec![PluginPermission::ArtifactWrite],
            metadata: PluginMetadata {
                name: "Example".to_owned(),
                description: "Test plugin".to_owned(),
                license: "Apache-2.0".to_owned(),
                publisher: "Constellation".to_owned(),
                repository: "https://example.test/plugin".to_owned(),
                ui: None,
            },
        }
    }

    #[test]
    fn grants_cannot_expand_manifest_permissions() {
        let manifest = manifest();
        assert!(validate_manifest(&manifest).is_ok());
        let grant = PluginGrant {
            plugin_id: manifest.id.clone(),
            component_sha256: manifest.sha256.clone(),
            permissions: vec![PluginPermission::ScheduleWrite],
            approved_by: "owner".to_owned(),
        };
        assert!(validate_grant(&manifest, &grant).is_err());
    }

    #[test]
    fn network_permissions_reject_wildcards_and_ip_literals() {
        let mut manifest = manifest();
        manifest.permissions = vec![PluginPermission::NetworkHttps {
            hosts: vec!["*.example.test".to_owned()],
        }];
        assert!(validate_manifest(&manifest).is_err());
        manifest.permissions = vec![PluginPermission::NetworkHttps {
            hosts: vec!["api.example.test".to_owned()],
        }];
        assert!(validate_manifest(&manifest).is_ok());
    }
}
