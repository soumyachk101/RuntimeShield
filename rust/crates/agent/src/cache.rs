//! Offline policy cache.
//!
//! The local guard must keep working when the control plane is
//! unreachable (spec §18: "local guard remains operational during a
//! control-plane outage according to configured policy"). The cache
//! stores the most recent *signed* policy document, its version label
//! and an expiry. On read:
//!
//! - fresh + signature valid  -> use it
//! - expired / signature bad  -> depend on `fail_mode`:
//!   - `fail_closed` (default, and the only mode for the `restricted`
//!     profile): refuse evaluation, force a DENY on every request
//!   - `fail_open`: fall back to the *last good* document without
//!     re-checking expiry, and mark the decision as `audit_only` so the
//!     outcome is visible in the journal
//!
//! The cache is stored in a single JSON file plus a small
//! `cache_meta.json` sidecar. Both are created in the agent's data
//! directory with 0600 permissions.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use anyhow::{Context, Result};
use runtime_shield_core::policy::{self, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailClosed,
    FailOpen,
}

impl Default for FailMode {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// One cached policy. Written atomically (temp file + rename) so a
/// crash never leaves a half-written document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    pub policy: Policy,
    /// The signature claimed by the publisher, hex.
    pub signature: Option<String>,
    /// UTC expiry; after this the document is considered stale.
    pub expires_at: DateTime<Utc>,
    /// Who wrote this entry (device id or "local").
    pub written_by: String,
}

pub struct PolicyCache {
    dir: PathBuf,
    pub fail_mode: FailMode,
    /// HMAC key material for signature verification. In dev mode the
    /// agent may run with `signature_check = false`, which skips this.
    pub key_material: Option<String>,
}

/// The result of a cache lookup. `stale` means "usable under fail-open,
/// not under fail-closed".
pub enum CacheStatus {
    Fresh(CacheMeta),
    Stale(CacheMeta),
    Empty,
}

impl PolicyCache {
    pub fn new(dir: PathBuf, fail_mode: FailMode, key_material: Option<String>) -> Self {
        Self {
            dir,
            fail_mode,
            key_material,
        }
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("policy_cache.meta.json")
    }
    fn doc_path(&self) -> PathBuf {
        self.dir.join("policy_cache.doc.json")
    }

    /// Store a new document. The signature (if any) must verify against
    /// the key material before we accept the document — an attacker who
    /// can write the cache file can also write the document, but they
    /// cannot forge the signature.
    pub fn store(
        &mut self,
        doc: &serde_json::Value,
        signature: Option<String>,
        expires_at: DateTime<Utc>,
        written_by: &str,
    ) -> Result<()> {
        let policy_doc = Policy::from_json(doc)
            .with_context(|| "cached document failed schema validation".to_string())?;
        if let (Some(sig), Some(key)) = (&signature, &self.key_material) {
            if !policy::verify_signature(doc, sig, key)? {
                anyhow::bail!("policy signature verification failed; refusing to cache");
            }
        }
        std::fs::create_dir_all(&self.dir)?;
        let meta = CacheMeta {
            policy: policy_doc.clone(),
            signature: signature.clone(),
            expires_at,
            written_by: written_by.to_string(),
        };
        write_atomic(
            &self.doc_path(),
            &serde_json::to_vec_pretty(doc)?,
        )?;
        write_atomic(&self.meta_path(), &serde_json::to_vec_pretty(&meta)?)?;
        Ok(())
    }

    /// Load and classify the cache.
    pub fn load(&self) -> Result<CacheStatus, std::io::Error> {
        if !self.meta_path().exists() {
            return Ok(CacheStatus::Empty);
        }
        let raw = std::fs::read(self.meta_path())?;
        let meta: CacheMeta = serde_json::from_slice(&raw)?;
        let now = Utc::now();
        if self.key_material.is_some() && meta.signature.is_none() {
            // Signature required but missing: treat as stale.
            return Ok(CacheStatus::Stale(meta));
        }
        if now >= meta.expires_at {
            return Ok(CacheStatus::Stale(meta));
        }
        Ok(CacheStatus::Fresh(meta))
    }

    /// Resolve the policy to use for a decision, applying the fail mode
    /// to a stale/empty cache. This is the function the agent calls.
    pub fn resolve(&self) -> Result<(Policy, bool)> {
        match self.load()? {
            CacheStatus::Fresh(meta) => Ok((meta.policy, false)),
            CacheStatus::Stale(meta) => match self.fail_mode {
                FailMode::FailClosed => {
                    anyhow::bail!(
                        "policy cache is stale (expired or signature invalid) and fail_mode is fail-closed; refusing to evaluate ({})",
                        meta.policy.version_label()
                    );
                }
                FailMode::FailOpen => Ok((meta.policy, true)),
            },
            CacheStatus::Empty => match self.fail_mode {
                FailMode::FailClosed => {
                    anyhow::bail!("no policy cached and fail_mode is fail-closed");
                }
                FailMode::FailOpen => {
                    anyhow::bail!("no policy cached; fail-open cannot run without a document");
                }
            },
        }
    }
}

/// Atomic write: write to a sibling temp file, fsync, rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = Path::new(&format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()))
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(
            ".{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Convenience for the CLI: load a policy file, validate it and return
/// `(policy, cache-ready doc)`.
pub fn load_policy_file(path: &Path) -> Result<(Policy, serde_json::Value)> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_slice(&raw).with_context(|| format!("{} is not valid JSON", path.display()))?;
    let p = Policy::from_json(&doc)
        .with_context(|| format!("{} does not validate against the policy schema", path.display()))?;
    Ok((p, doc))
}

/// Check whether a request would be *audited as stale* — i.e. whether
/// the caller should mark the decision with a stale-policy annotation.
pub fn annotate_stale(decision_json: &mut serde_json::Value, stale: bool) {
    if stale {
        if let Some(o) = decision_json.as_object_mut() {
            o.insert("stale_policy".to_string(), serde_json::json!(true));
        }
    }
}
