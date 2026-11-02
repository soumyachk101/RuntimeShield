use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// JSON-Schema for the execution request protocol. Adapters (agent runtimes,
/// CI runners, the Go control plane) must produce these documents; the
/// embedded schema is the offline validator.
pub const REQUEST_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://runshield.dev/schemas/execution-request.v1.json",
  "title": "RuntimeShield Execution Request v1",
  "type": "object",
  "required": ["request_id", "principal", "principal_id", "executable", "argv", "cwd", "workspace", "capabilities"],
  "properties": {
    "request_id": { "type": "string", "minLength": 1 },
    "principal": {
      "type": "string",
      "enum": ["user", "agent", "ci", "internal_service"],
      "description": "Execution origin. Adapters identify their own origin; the engine never infers it."
    },
    "principal_id": { "type": "string", "minLength": 1 },
    "principal_display": { "type": "string" },
    "executable": { "type": "string", "minLength": 1 },
    "argv": {
      "type": "array",
      "maxItems": 512,
      "items": { "type": "string" },
      "description": "Argument array. Adapters must never send a shell string; reconstruction from unsafe concatenation is a protocol violation."
    },
    "cwd": { "type": "string", "minLength": 1 },
    "workspace": { "type": "string" },
    "parent_pid": { "type": "integer", "minimum": 0 },
    "user": { "type": "string" },
    "repo_ref": { "type": "string" },
    "capabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["kind"],
        "properties": {
          "kind": { "enum": ["fs_read", "fs_write", "network", "process", "secret"] },
          "path": { "type": "string" },
          "host": { "type": "string" },
          "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
          "executable": { "type": "string" },
          "env_keys": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "env_keys_requested": { "type": "array", "items": { "type": "string" } }
  }
}"#;

/// Where the execution request originates. Adapters identify their own
/// origin; the engine never infers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
    User,
    Agent,
    Ci,
    InternalService,
}

impl Principal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Principal::User => "user",
            Principal::Agent => "agent",
            Principal::Ci => "ci",
            Principal::InternalService => "internal_service",
        }
    }
}

/// The structured request after schema validation. `argv` is kept as an
/// array end-to-end; no shell parsing anywhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub principal_id: String,
    pub principal: Principal,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub workspace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_ref: Option<String>,
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys_requested: Vec<String>,
}

/// What the caller says it needs. The engine validates this against
/// policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    pub kind: CapabilityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    FsRead,
    FsWrite,
    Network,
    Process,
    Secret,
}

impl CapabilityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityKind::FsRead => "fs_read",
            CapabilityKind::FsWrite => "fs_write",
            CapabilityKind::Network => "network",
            CapabilityKind::Process => "process",
            CapabilityKind::Secret => "secret",
        }
    }
}

impl ExecutionRequest {
    /// Deterministic content digest of the request. Used to correlate
    /// audit events with requests without storing the raw document
    /// twice (spec data model: `argv_digest`, `cwd_digest`).
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.executable.as_bytes());
        for a in &self.argv {
            hasher.update(a.as_bytes());
            hasher.update([0u8]);
        }
        hasher.update(self.cwd.as_bytes());
        if let Ok(cap_json) = serde_json::to_string(&self.capabilities) {
            hasher.update(cap_json.as_bytes());
        }
        hasher.update(self.workspace.as_bytes());
        let bytes = hasher.finalize();
        hex::encode(&bytes[..8])
    }

    /// Validate structural invariants beyond JSON Schema (argv length,
    /// no NUL bytes, non-empty argv, per-kind required fields).
    pub fn validate(&self) -> Result<()> {
        if self.request_id.is_empty() {
            return Err(Error::InvalidRequest("request_id must be non-empty".into()));
        }
        if self.argv.is_empty() {
            return Err(Error::InvalidRequest("argv must have at least one element".into()));
        }
        if self.argv.len() > 512 {
            return Err(Error::InvalidRequest(format!(
                "argv exceeds 512 elements ({} given)",
                self.argv.len()
            )));
        }
        for a in &self.argv {
            if a.contains('\0') {
                return Err(Error::InvalidRequest(
                    "argv elements must not contain NUL bytes".into(),
                ));
            }
        }
        if self.cwd.is_empty() {
            return Err(Error::InvalidRequest("cwd must be non-empty".into()));
        }
        for c in &self.capabilities {
            match c.kind {
                CapabilityKind::FsRead | CapabilityKind::FsWrite => {
                    if c.path.is_none() {
                        return Err(Error::InvalidRequest(format!(
                            "capability kind {} requires a path",
                            c.kind.as_str()
                        )));
                    }
                }
                CapabilityKind::Network => {
                    if c.host.is_none() {
                        return Err(Error::InvalidRequest(
                            "capability kind network requires a host".into(),
                        ));
                    }
                }
                CapabilityKind::Process => {
                    if c.executable.is_none() {
                        return Err(Error::InvalidRequest(
                            "capability kind process requires an executable".into(),
                        ));
                    }
                }
                CapabilityKind::Secret => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ExecutionRequest {
        ExecutionRequest {
            request_id: "r-001".into(),
            principal_id: "agent-x".into(),
            principal: Principal::Agent,
            executable: "git".into(),
            argv: vec!["git".into(), "status".into()],
            cwd: "/home/dev/repo".into(),
            workspace: "w-1".into(),
            parent_pid: None,
            user: Some("dev".into()),
            repo_ref: None,
            capabilities: vec![],
            env_keys_requested: vec![],
        }
    }

    #[test]
    fn a_valid_request_validates() {
        base().validate().expect("base request is valid");
    }

    #[test]
    fn rejects_empty_argv() {
        let mut r = base();
        r.argv = vec![];
        assert!(matches!(r.validate(), Err(Error::InvalidRequest(_))));
    }

    #[test]
    fn rejects_nul_byte_in_argv() {
        let mut r = base();
        r.argv = vec!["a".into(), "b\0".into()];
        assert!(matches!(r.validate(), Err(Error::InvalidRequest(_))));
    }

    #[test]
    fn rejects_overlong_argv() {
        let mut r = base();
        r.argv = vec!["x".to_string(); 513];
        assert!(matches!(r.validate(), Err(Error::InvalidRequest(_))));
    }

    #[test]
    fn fs_capability_requires_path() {
        let mut r = base();
        r.capabilities.push(Capability {
            kind: CapabilityKind::FsRead,
            path: None,
            host: None,
            port: None,
            executable: None,
            env_keys: vec![],
        });
        assert!(matches!(r.validate(), Err(Error::InvalidRequest(_))));
    }

    #[test]
    fn digest_is_stable() {
        let a = base();
        let b = base();
        assert_eq!(a.digest(), b.digest());
        let mut c = base();
        c.argv.push("--all".into());
        assert_ne!(a.digest(), c.digest());
    }
}
