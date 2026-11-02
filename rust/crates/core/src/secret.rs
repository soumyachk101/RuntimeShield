//! Secret redaction for audit lines and telemetry.
//!
//! The detection layer is *heuristic*: high-regex patterns for common
//! key shapes, plus org-configured patterns. It is documented as
//! best-effort — regex scanning alone cannot guarantee detection of
//! every secret (see ENFORCEMENT-LIMITS.md). Redaction is the
//! deterministic part: whatever is detected is never written in the
//! clear into the journal.

use serde::{Deserialize, Serialize};

/// Built-in high-confidence patterns. Each carries a `redact_to` token
/// describing what replaces the value (never the value itself).
pub const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    (
        "pem-private-key",
        r"-----BEGIN (RSA|EC|OPENSSH|DSA|ENCRYPTED) PRIVATE KEY-----",
    ),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),
    ("pg-connection-url", r"postgres(?:ql)?://[^\s:]+:[^\s@]+@"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("openai-key", r"sk-[A-Za-z0-9]{20,}"),
    ("generic-long-token", r"(?:api[_-]?key|token|secret)\s*[:=]\s*\S{24,}"),
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretHit {
    pub pattern_id: String,
    /// A stable, non-sensitive fingerprint (first 4 hex chars of the
    /// SHA-256 of the matched value) so auditors can correlate without
    /// seeing the value.
    pub fingerprint: String,
    /// What replaces the value in redacted output.
    pub redacted: String,
}

/// Scan `text` for likely secret values and return hits with redacted
/// replacements. Empty text returns no hits.
pub fn detect(text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for &(id, regex) in BUILTIN_PATTERNS {
        let Ok(re) = regex::Regex::new(regex) else {
            continue; // a broken builtin must never take the engine down
        };
        for m in re.find_iter(text) {
            let val = m.as_str();
            let fp = value_fingerprint(val);
            hits.push(SecretHit {
                pattern_id: id.into(),
                fingerprint: fp.clone(),
                redacted: format!("[redacted:{id}:{fp}]"),
            });
        }
    }
    hits
}

/// Redact all builtin hits in `text`, replacing each match in place.
/// Overlapping matches keep the earliest; order is preserved.
pub fn redact(text: &str) -> String {
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    for &(id, regex) in BUILTIN_PATTERNS {
        let Ok(re) = regex::Regex::new(regex) else {
            continue;
        };
        for m in re.find_iter(text) {
            let fp = value_fingerprint(m.as_str());
            spans.push((m.start(), m.end(), format!("[redacted:{id}:{fp}]")));
        }
    }
    spans.sort_by_key(|s| (s.0, s.1));
    let mut out = String::with_capacity(text.len());
    let mut last_end = 0usize;
    for (start, end, replacement) in spans {
        if start < last_end {
            continue; // overlaps an earlier hit: keep the earlier one
        }
        out.push_str(&text[last_end..start]);
        out.push_str(&replacement);
        last_end = end;
    }
    out.push_str(&text[last_end..]);
    out
}

/// SHA-256 based stable fingerprint (first 8 hex chars) so two
/// occurrences of the same value can be correlated in audit logs
/// without exposing the value.
pub fn value_fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    hex::encode(&h.finalize()[..4])
}

/// HMAC-SHA256 used for signed policy bundles.
pub fn hmac_sha256_hex(key: &str, msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    // HMAC accepts keys of any length, so new_from_slice cannot fail
    // for this key type; unwrap is safe here.
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_redacts_aws_key() {
        let text = "AKIAABCDEFGHIJKLMNOP";
        let hits = detect(text);
        assert!(hits.iter().any(|h| h.pattern_id == "aws-access-key"));
        let red = redact(text);
        assert!(!red.contains("AKIA"));
        assert!(red.contains("[redacted:aws-access-key:"));
    }

    #[test]
    fn redaction_preserves_non_secret_text() {
        let text = "value=AKIAABCDEFGHIJKLMNOP tail";
        let red = redact(text);
        assert!(red.ends_with(" tail"));
        assert_eq!(value_fingerprint("abc"), value_fingerprint("abc"));
        assert_ne!(value_fingerprint("abc"), value_fingerprint("abd"));
    }
}
