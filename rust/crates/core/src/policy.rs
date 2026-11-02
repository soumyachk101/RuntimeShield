use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{Error, Result};

/// Schema version of the policy document accepted by this engine.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Draft 2020-12 JSON Schema for policy documents.
///
/// Keep in sync with `policies/schema/policy.schema.json` (the file is the
/// canonical artifact distributed to the web editor and the Go control
/// plane; this constant is the embedded validator used offline).
pub const POLICY_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://runshield.dev/schemas/policy.v1.json",
  "title": "RuntimeShield Policy v1",
  "type": "object",
  "required": ["version", "profile", "default_action"],
  "properties": {
    "version": { "const": 1 },
    "policy_version": { "type": "string", "minLength": 1 },
    "profile": { "type": "string", "minLength": 1, "maxLength": 64 },
    "description": { "type": "string" },
    "default_action": { "$ref": "#/$defs/decision" },
    "filesystem": {
      "type": "object",
      "properties": {
        "workspace": {
          "type": "object",
          "required": ["access", "roots"],
          "properties": {
            "access": { "$ref": "#/$defs/fsAccess" },
            "roots": {
              "type": "array",
              "minItems": 1,
              "items": { "type": "string", "minLength": 1 }
            }
          }
        },
        "temp": {
          "type": "object",
          "required": ["access"],
          "properties": { "access": { "$ref": "#/$defs/fsAccess" } }
        },
        "sensitive_paths": { "type": "array", "items": { "type": "string" } },
        "deny_paths": { "type": "array", "items": { "type": "string" } },
        "allow_paths": { "type": "array", "items": { "type": "string" } }
      }
    },
    "network": {
      "type": "object",
      "properties": {
        "default": { "enum": ["allow", "deny"] },
        "allow": { "type": "array", "items": { "$ref": "#/$defs/destination" } },
        "deny": { "type": "array", "items": { "$ref": "#/$defs/destination" } }
      }
    },
    "process": {
      "type": "object",
      "properties": {
        "allow": { "type": "array", "items": { "$ref": "#/$defs/procRule" } },
        "deny": { "type": "array", "items": { "$ref": "#/$defs/procRule" } },
        "require_approval": { "type": "array", "items": { "$ref": "#/$defs/procRule" } }
      }
    },
    "secrets": {
      "type": "object",
      "properties": {
        "deny_env_keys": { "type": "array", "items": { "type": "string" } },
        "patterns": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["id", "regex"],
            "properties": {
              "id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9._-]*$" },
              "regex": { "type": "string" },
              "description": { "type": "string" }
            }
          }
        }
      }
    },
    "rules": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "effect", "capability"],
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9._:-]*$" },
          "effect": { "$ref": "#/$defs/decision" },
          "capability": { "enum": ["filesystem", "network", "process", "secret"] },
          "priority": { "type": "integer", "default": 0 },
          "path": { "type": "string" },
          "host": { "type": "string" },
          "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
          "executable": { "type": "string" },
          "actions": { "type": "array", "items": { "type": "string" } },
          "note": { "type": "string" }
        }
      }
    }
  },
  "$defs": {
    "decision": { "enum": ["allow", "deny", "require_approval", "audit_only"] },
    "fsAccess": { "enum": ["read-write", "read-only", "deny"] },
    "destination": {
      "type": "object",
      "required": ["host"],
      "properties": {
        "host": { "type": "string", "minLength": 1 },
        "ports": {
          "type": "array",
          "minItems": 1,
          "items": { "type": "integer", "minimum": 1, "maximum": 65535 },
          "uniqueItems": true
        }
      }
    },
    "procRule": {
      "type": "object",
      "required": ["executable"],
      "properties": {
        "executable": { "type": "string", "minLength": 1 },
        "actions": { "type": "array", "items": { "type": "string" } },
        "note": { "type": "string" }
      }
    }
  }
}"##;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
    AuditOnly,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::RequireApproval => "require_approval",
            Decision::AuditOnly => "audit_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsAccess {
    ReadWrite,
    ReadOnly,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkDefault {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub access: FsAccess,
    pub roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempConfig {
    pub access: FsAccess,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp: Option<TempConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl Destination {
    /// A destination with an empty port list applies to every port.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_ok = crate::netmatch::host_matches(&self.host, host);
        if !host_ok {
            return false;
        }
        // An entry with an empty port list applies to every port;
        // otherwise the exact port must be listed.
        self.ports.is_empty() || self.ports.contains(&port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSection {
    #[serde(default = "default_network_default")]
    pub default: NetworkDefault,
    #[serde(default)]
    pub allow: Vec<Destination>,
    #[serde(default)]
    pub deny: Vec<Destination>,
}

fn default_network_default() -> NetworkDefault {
    NetworkDefault::Deny
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            default: default_network_default(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcRule {
    pub executable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<ProcRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<ProcRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_approval: Vec<ProcRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPattern {
    pub id: String,
    pub regex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<SecretPattern>,
}

/// Effect of an explicit rule; mirrors [`Decision`].
type RuleEffect = Decision;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(rename = "effect")]
    pub effect: RuleEffect,
    pub capability: CapabilityKind,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Filesystem,
    Network,
    Process,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "version")]
    pub schema_version: u32,
    /// Operator-facing version label (semver string) recorded in audit.
    #[serde(default)]
    pub policy_version: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub default_action: Decision,
    #[serde(default)]
    pub filesystem: FilesystemSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub process: ProcessSection,
    #[serde(default)]
    pub secrets: SecretsSection,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Parse and validate a JSON policy document.
    pub fn from_json(doc: &Value) -> Result<Self> {
        validate_json(doc)?;
        let policy: Policy = serde_json::from_value(doc.clone())
            .map_err(|e| Error::InvalidPolicy(format!("field mismatch: {e}")))?;
        if policy.schema_version != POLICY_SCHEMA_VERSION {
            return Err(Error::InvalidPolicy(format!(
                "unsupported schema version {} (this engine supports v{POLICY_SCHEMA_VERSION})",
                policy.schema_version
            )));
        }
        if policy.default_action == Decision::Allow {
            // Accepted, but callers are expected to surface a warning;
            // a default-allow policy inverts the product's core promise.
        }
        Ok(policy)
    }

    /// Deterministic content digest used for caching and signature checks.
    pub fn digest(&self) -> std::result::Result<String, serde_json::Error> {
        let canonical = serde_json::to_vec(self)?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(canonical);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Stable identifier for audit lines: "policy_version@schema_version"
    /// falling back to the schema version when unlabeled.
    pub fn version_label(&self) -> String {
        if self.policy_version.is_empty() {
            format!("v{}", self.schema_version)
        } else {
            self.policy_version.clone()
        }
    }
}

/// Validate a policy document against the embedded JSON Schema.
pub fn validate_json(doc: &Value) -> Result<()> {
    let schema: Value =
        serde_json::from_str(POLICY_SCHEMA).map_err(|e| Error::InvalidPolicy(e.to_string()))?;
    if !jsonschema::is_valid(&schema, doc) {
        return Err(Error::InvalidPolicy(
            "document does not match policy JSON schema".into(),
        ));
    }
    Ok(())
}

/// Validate a signed policy bundle: the signature is HMAC-SHA256 over the
/// canonical document with a shared org key. Any failure fails closed.
pub fn verify_signature(doc: &Value, signature: &str, key_material: &str) -> Result<bool> {
    use crate::secret::hmac_sha256_hex;
    let canonical = serde_json::to_vec(doc).map_err(|e| Error::InvalidPolicy(e.to_string()))?;
    let expected = hmac_sha256_hex(key_material, &canonical);
    Ok(constant_time_eq(&expected, signature))
}

/// Constant-time string compare; avoids a timing side channel on keys.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A fresh audit event id for the decision result.
pub fn new_audit_event_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(extra: Value) -> Value {
        let mut base = json!({
            "version": 1,
            "profile": "repository-development",
            "default_action": "deny"
        });
        if let (Some(m), Some(o)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in o {
                m.insert(k.clone(), v.clone());
            }
        }
        base
    }

    #[test]
    fn minimal_policy_is_valid() {
        Policy::from_json(&doc(json!({}))).expect("minimal policy must validate");
    }

    #[test]
    fn full_example_policy_is_valid() {
        let d = doc(json!({
            "policy_version": "0.1.0",
            "filesystem": {
                "workspace": { "access": "read-write", "roots": ["~/repo"] },
                "temp": { "access": "read-write" },
                "sensitive_paths": ["~/.ssh", "~/.aws"]
            },
            "network": {
                "default": "deny",
                "allow": [{ "host": "registry.npmjs.org", "ports": [443] }]
            },
            "process": {
                "allow": [{ "executable": "git", "actions": ["status", "diff", "log"] }],
                "require_approval": [{ "executable": "sudo" }, { "executable": "curl" }]
            }
        }));
        let p = Policy::from_json(&d).unwrap();
        assert_eq!(p.version_label(), "0.1.0");
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let d = doc(json!({ "version": 2 }));
        assert!(matches!(Policy::from_json(&d), Err(Error::InvalidPolicy(_))));
    }

    #[test]
    fn structurally_bad_policy_is_rejected() {
        let d = doc(json!({ "filesystem": { "workspace": { "access": "read-write" } } }));
        // workspace requires "roots"
        assert!(matches!(Policy::from_json(&d), Err(Error::InvalidPolicy(_))));
    }

    #[test]
    fn signature_verification_roundtrips() {
        let d = doc(json!({}));
        let key = "test-key-0123456789";
        let canonical = serde_json::to_vec(&d).unwrap();
        let sig = crate::secret::hmac_sha256_hex(key, &canonical);
        assert!(verify_signature(&d, &sig, key).unwrap());
        assert!(!verify_signature(&d, "deadbeef", key).unwrap());
    }
}
