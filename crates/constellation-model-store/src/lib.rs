//! Verified, content-addressed local model storage.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Model chunks are always four mebibytes except for the final chunk.
pub const CHUNK_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Accepted license evidence stored beside a model manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseAcceptance {
    /// SPDX identifier or upstream license label.
    pub license_id: String,
    /// When the local operator accepted the terms.
    pub accepted_at: DateTime<Utc>,
    /// Redacted source from which the terms were presented.
    pub source: String,
}

/// One immutable content-addressed model chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelChunk {
    /// Zero-based ordering within the model file.
    pub index: u32,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Exact chunk length.
    pub size_bytes: u32,
}

/// Durable model metadata. Secrets and repository credentials are never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// User-facing model alias.
    pub alias: String,
    /// SHA-256 of the complete source file.
    pub sha256: String,
    /// Exact complete file size.
    pub size_bytes: u64,
    /// Fixed nominal chunk size.
    pub chunk_size_bytes: u32,
    /// Ordered verified chunks.
    pub chunks: Vec<ModelChunk>,
    /// Runtime format, currently `gguf` for real local inference.
    pub format: String,
    /// Quantization label when known.
    pub quantization: Option<String>,
    /// Redacted provenance such as a filename or repository identifier.
    pub source: String,
    /// License acceptance evidence.
    pub license: LicenseAcceptance,
    /// Pinned models are protected from eviction.
    pub pinned: bool,
    /// Import completion time.
    pub created_at: DateTime<Utc>,
    /// Last full verification time.
    pub verified_at: DateTime<Utc>,
}

/// Options required before a model is promoted into the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOptions {
    /// User-facing model alias.
    pub alias: String,
    /// Runtime format.
    pub format: String,
    /// Quantization label when known.
    pub quantization: Option<String>,
    /// Redacted source identifier.
    pub source: String,
    /// Accepted license evidence. Import is denied when absent.
    pub license: Option<LicenseAcceptance>,
    /// Protect the imported model from eviction.
    pub pinned: bool,
}

/// Content store failure.
#[derive(Debug, thiserror::Error)]
pub enum ModelStoreError {
    /// The requested alias is unsafe or malformed.
    #[error("invalid model alias")]
    InvalidAlias,
    /// Import requires explicit license acceptance.
    #[error("model license must be accepted before import")]
    LicenseNotAccepted,
    /// The requested model does not exist.
    #[error("model is not present: {0}")]
    NotFound(String),
    /// A digest or size check failed.
    #[error("model verification failed: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("model store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Manifest encoding failed.
    #[error("model manifest encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// SHA-256-addressed model cache rooted in a caller-selected data directory.
#[derive(Debug, Clone)]
pub struct ModelStore {
    root: PathBuf,
}

impl ModelStore {
    /// Opens or initializes a model cache.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the cache directories cannot be created.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, ModelStoreError> {
        let store = Self { root: root.into() };
        for directory in [
            store.chunk_root(),
            store.manifest_root(),
            store.staging_root(),
            store.materialized_root(),
        ] {
            fs::create_dir_all(directory).await?;
        }
        Ok(store)
    }

    /// Returns the storage root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Imports a file, verifies every chunk, and atomically promotes its manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe metadata, missing license acceptance, unreadable input,
    /// failed verification, or a cache write failure.
    pub async fn import_file(
        &self,
        path: impl AsRef<Path>,
        options: ImportOptions,
    ) -> Result<ModelManifest, ModelStoreError> {
        validate_alias(&options.alias)?;
        let license = options
            .license
            .filter(|value| !value.license_id.trim().is_empty())
            .ok_or(ModelStoreError::LicenseNotAccepted)?;
        validate_source_format(path.as_ref(), &options.format).await?;
        let mut source = fs::File::open(path.as_ref()).await?;
        let import_id = Uuid::now_v7().to_string();
        let mut full_digest = Sha256::new();
        let mut chunks = Vec::new();
        let mut total_size = 0_u64;
        let mut index = 0_u32;

        loop {
            let mut buffer = vec![0_u8; CHUNK_SIZE_BYTES];
            let mut read = 0_usize;
            while read < buffer.len() {
                let count = source.read(&mut buffer[read..]).await?;
                if count == 0 {
                    break;
                }
                read += count;
            }
            if read == 0 {
                break;
            }
            buffer.truncate(read);
            full_digest.update(&buffer);
            let chunk_sha = sha256_hex(&buffer);
            self.promote_chunk(&import_id, &chunk_sha, &buffer).await?;
            chunks.push(ModelChunk {
                index,
                sha256: chunk_sha,
                size_bytes: u32::try_from(read).unwrap_or(u32::MAX),
            });
            total_size = total_size.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            index = index.saturating_add(1);
        }

        if chunks.is_empty() {
            return Err(ModelStoreError::Verification(
                "empty model files are not accepted".to_owned(),
            ));
        }
        let now = Utc::now();
        let complete_sha256 = format!("{:x}", full_digest.finalize());
        let manifest = ModelManifest {
            schema_version: 1,
            alias: options.alias,
            sha256: complete_sha256,
            size_bytes: total_size,
            chunk_size_bytes: u32::try_from(CHUNK_SIZE_BYTES).unwrap_or(u32::MAX),
            chunks,
            format: options.format,
            quantization: options.quantization,
            source: options.source,
            license,
            pinned: options.pinned,
            created_at: now,
            verified_at: now,
        };
        self.verify(&manifest).await?;
        self.write_manifest(&manifest).await?;
        Ok(manifest)
    }

    /// Lists manifests in stable alias order.
    ///
    /// # Errors
    ///
    /// Returns an error when a manifest cannot be read or decoded.
    pub async fn list(&self) -> Result<Vec<ModelManifest>, ModelStoreError> {
        let mut directory = fs::read_dir(self.manifest_root()).await?;
        let mut manifests = Vec::new();
        while let Some(entry) = directory.next_entry().await? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let encoded = fs::read(entry.path()).await?;
            manifests.push(serde_json::from_slice(&encoded)?);
        }
        manifests
            .sort_by(|left: &ModelManifest, right: &ModelManifest| left.alias.cmp(&right.alias));
        Ok(manifests)
    }

    /// Loads a manifest by exact alias.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid alias, missing manifest, or malformed stored data.
    pub async fn get(&self, alias: &str) -> Result<ModelManifest, ModelStoreError> {
        validate_alias(alias)?;
        let path = self.manifest_path(alias);
        match fs::read(path).await {
            Ok(encoded) => Ok(serde_json::from_slice(&encoded)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(ModelStoreError::NotFound(alias.to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Reads one verified content-addressed chunk for an authorized peer transfer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed digests, missing content, oversized content, or a
    /// digest mismatch. Unverified bytes are never returned.
    pub async fn read_verified_chunk(&self, sha256: &str) -> Result<Vec<u8>, ModelStoreError> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelStoreError::Verification(
                "chunk digest is malformed".to_owned(),
            ));
        }
        let bytes = match fs::read(self.chunk_path(sha256)).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ModelStoreError::NotFound(sha256.to_owned()));
            }
            Err(error) => return Err(error.into()),
        };
        if bytes.is_empty() || bytes.len() > CHUNK_SIZE_BYTES || sha256_hex(&bytes) != sha256 {
            return Err(ModelStoreError::Verification(
                "stored chunk did not pass size and digest checks".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Recomputes all chunk and whole-file digests without materializing content.
    ///
    /// # Errors
    ///
    /// Returns an error when content is missing, unreadable, or fails a digest or size check.
    pub async fn verify(&self, manifest: &ModelManifest) -> Result<(), ModelStoreError> {
        let mut full_digest = Sha256::new();
        let mut total_size = 0_u64;
        for (expected_index, chunk) in manifest.chunks.iter().enumerate() {
            if usize::try_from(chunk.index).unwrap_or(usize::MAX) != expected_index {
                return Err(ModelStoreError::Verification(
                    "chunk ordering is invalid".to_owned(),
                ));
            }
            let bytes = fs::read(self.chunk_path(&chunk.sha256)).await?;
            if bytes.len() != usize::try_from(chunk.size_bytes).unwrap_or(usize::MAX)
                || sha256_hex(&bytes) != chunk.sha256
            {
                return Err(ModelStoreError::Verification(format!(
                    "chunk {} does not match its manifest",
                    chunk.index
                )));
            }
            total_size = total_size.saturating_add(u64::from(chunk.size_bytes));
            full_digest.update(&bytes);
        }
        let complete_sha256 = format!("{:x}", full_digest.finalize());
        if total_size != manifest.size_bytes || complete_sha256 != manifest.sha256 {
            return Err(ModelStoreError::Verification(
                "complete model digest or size does not match".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies an alias and persists the refreshed verification timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the alias is absent, corrupt, unreadable, or cannot be updated.
    pub async fn verify_alias(&self, alias: &str) -> Result<ModelManifest, ModelStoreError> {
        let mut manifest = self.get(alias).await?;
        self.verify(&manifest).await?;
        manifest.verified_at = Utc::now();
        self.write_manifest(&manifest).await?;
        Ok(manifest)
    }

    /// Materializes a verified cache entry for runtimes that require one contiguous file.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is absent, corrupt, or cannot be materialized.
    pub async fn materialize(&self, alias: &str) -> Result<PathBuf, ModelStoreError> {
        let manifest = self.get(alias).await?;
        self.verify(&manifest).await?;
        let extension = if manifest.format.eq_ignore_ascii_case("gguf") {
            "gguf"
        } else {
            "bin"
        };
        let destination = self
            .materialized_root()
            .join(format!("{}.{}", manifest.sha256, extension));
        if fs::metadata(&destination)
            .await
            .is_ok_and(|metadata| metadata.len() == manifest.size_bytes)
        {
            return Ok(destination);
        }
        let temporary = self
            .staging_root()
            .join(format!("materialize-{}.tmp", Uuid::now_v7()));
        let mut output = fs::File::create(&temporary).await?;
        for chunk in &manifest.chunks {
            let bytes = fs::read(self.chunk_path(&chunk.sha256)).await?;
            output.write_all(&bytes).await?;
        }
        output.sync_all().await?;
        drop(output);
        if fs::metadata(&destination).await.is_ok() {
            fs::remove_file(&destination).await?;
        }
        fs::rename(&temporary, &destination).await?;
        Ok(destination)
    }

    /// Updates eviction protection for a model.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is absent or its manifest cannot be replaced.
    pub async fn set_pinned(
        &self,
        alias: &str,
        pinned: bool,
    ) -> Result<ModelManifest, ModelStoreError> {
        let mut manifest = self.get(alias).await?;
        manifest.pinned = pinned;
        self.write_manifest(&manifest).await?;
        Ok(manifest)
    }

    /// Removes a manifest and then deletes chunks no longer referenced by any model.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is absent or cache cleanup fails.
    pub async fn remove(&self, alias: &str) -> Result<(), ModelStoreError> {
        let _existing = self.get(alias).await?;
        fs::remove_file(self.manifest_path(alias)).await?;
        self.garbage_collect().await
    }

    /// Deletes content chunks unreachable from any manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when manifests or cache directories cannot be read or updated.
    pub async fn garbage_collect(&self) -> Result<(), ModelStoreError> {
        let reachable = self
            .list()
            .await?
            .into_iter()
            .flat_map(|manifest| manifest.chunks.into_iter().map(|chunk| chunk.sha256))
            .collect::<BTreeSet<_>>();
        let mut prefixes = fs::read_dir(self.chunk_root()).await?;
        while let Some(prefix) = prefixes.next_entry().await? {
            if !prefix.file_type().await?.is_dir() {
                continue;
            }
            let mut chunks = fs::read_dir(prefix.path()).await?;
            while let Some(chunk) = chunks.next_entry().await? {
                let name = chunk.file_name().to_string_lossy().into_owned();
                if !reachable.contains(&name) && chunk.file_type().await?.is_file() {
                    fs::remove_file(chunk.path()).await?;
                }
            }
        }
        Ok(())
    }

    async fn promote_chunk(
        &self,
        import_id: &str,
        sha256: &str,
        bytes: &[u8],
    ) -> Result<(), ModelStoreError> {
        let destination = self.chunk_path(sha256);
        if fs::metadata(&destination).await.is_ok() {
            return Ok(());
        }
        let parent = destination
            .parent()
            .ok_or_else(|| ModelStoreError::Verification("chunk path has no parent".to_owned()))?;
        fs::create_dir_all(parent).await?;
        let temporary = self
            .staging_root()
            .join(format!("{import_id}-{sha256}.tmp"));
        let mut output = fs::File::create(&temporary).await?;
        output.write_all(bytes).await?;
        output.sync_all().await?;
        drop(output);
        match fs::rename(&temporary, &destination).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(temporary).await?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn write_manifest(&self, manifest: &ModelManifest) -> Result<(), ModelStoreError> {
        let destination = self.manifest_path(&manifest.alias);
        let temporary = self
            .staging_root()
            .join(format!("manifest-{}.tmp", Uuid::now_v7()));
        let encoded = serde_json::to_vec_pretty(manifest)?;
        let mut output = fs::File::create(&temporary).await?;
        output.write_all(&encoded).await?;
        output.sync_all().await?;
        drop(output);
        if fs::metadata(&destination).await.is_ok() {
            fs::remove_file(&destination).await?;
        }
        fs::rename(&temporary, destination).await?;
        Ok(())
    }

    fn chunk_root(&self) -> PathBuf {
        self.root.join("chunks")
    }

    fn manifest_root(&self) -> PathBuf {
        self.root.join("manifests")
    }

    fn staging_root(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn materialized_root(&self) -> PathBuf {
        self.root.join("materialized")
    }

    fn chunk_path(&self, sha256: &str) -> PathBuf {
        let prefix = sha256.get(..2).unwrap_or("00");
        self.chunk_root().join(prefix).join(sha256)
    }

    fn manifest_path(&self, alias: &str) -> PathBuf {
        self.manifest_root()
            .join(format!("{}.json", sha256_hex(alias.as_bytes())))
    }
}

fn validate_alias(alias: &str) -> Result<(), ModelStoreError> {
    if alias.is_empty()
        || alias.len() > 200
        || alias.trim() != alias
        || alias.chars().any(char::is_control)
    {
        Err(ModelStoreError::InvalidAlias)
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn validate_source_format(path: &Path, format: &str) -> Result<(), ModelStoreError> {
    if !format.eq_ignore_ascii_case("gguf") {
        return Err(ModelStoreError::Verification(
            "only GGUF model import is currently supported".to_owned(),
        ));
    }
    let mut source = fs::File::open(path).await?;
    let mut magic = [0_u8; 4];
    source
        .read_exact(&mut magic)
        .await
        .map_err(ModelStoreError::Io)?;
    if &magic != b"GGUF" {
        return Err(ModelStoreError::Verification(
            "file does not contain a GGUF header".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("constellation-model-store-{}", Uuid::now_v7()))
    }

    fn options(alias: &str) -> ImportOptions {
        ImportOptions {
            alias: alias.to_owned(),
            format: "gguf".to_owned(),
            quantization: Some("Q4_K_M".to_owned()),
            source: "test-model.gguf".to_owned(),
            license: Some(LicenseAcceptance {
                license_id: "Apache-2.0".to_owned(),
                accepted_at: Utc::now(),
                source: "test fixture".to_owned(),
            }),
            pinned: false,
        }
    }

    #[tokio::test]
    async fn imports_verifies_and_materializes_multiple_chunks() {
        let root = test_root();
        let source = root.with_extension("source.gguf");
        let mut bytes = b"GGUF".to_vec();
        bytes.resize(CHUNK_SIZE_BYTES, 7_u8);
        bytes.extend_from_slice(b"final chunk");
        let write_result = fs::write(&source, &bytes).await;
        assert!(write_result.is_ok());
        let store_result = ModelStore::open(&root).await;
        assert!(store_result.is_ok());
        let store = store_result.unwrap_or_else(|error| panic!("open store: {error}"));
        let import_result = store.import_file(&source, options("example/model")).await;
        assert!(import_result.is_ok());
        let manifest = import_result.unwrap_or_else(|error| panic!("import: {error}"));
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.size_bytes, u64::try_from(bytes.len()).unwrap_or(0));
        assert!(store.verify(&manifest).await.is_ok());
        let output_result = store.materialize("example/model").await;
        assert!(output_result.is_ok());
        let output = output_result.unwrap_or_else(|error| panic!("materialize: {error}"));
        let restored_result = fs::read(output).await;
        assert!(restored_result.is_ok());
        assert_eq!(restored_result.unwrap_or_default(), bytes);
        let _cleanup_store = fs::remove_dir_all(&root).await;
        let _cleanup_source = fs::remove_file(&source).await;
    }

    #[tokio::test]
    async fn rejects_import_without_license_acceptance() {
        let root = test_root();
        let source = root.with_extension("source.gguf");
        assert!(fs::write(&source, b"model").await.is_ok());
        let store_result = ModelStore::open(&root).await;
        assert!(store_result.is_ok());
        let store = store_result.unwrap_or_else(|error| panic!("open store: {error}"));
        let mut import_options = options("unlicensed");
        import_options.license = None;
        let result = store.import_file(&source, import_options).await;
        assert!(matches!(result, Err(ModelStoreError::LicenseNotAccepted)));
        let _cleanup_store = fs::remove_dir_all(&root).await;
        let _cleanup_source = fs::remove_file(&source).await;
    }
}
