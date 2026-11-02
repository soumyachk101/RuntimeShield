//! Deterministic host/port matching for network rules.
//!
//! Host rules match on the resolved hostname at connection time (see
//! ENFORCEMENT-LIMITS.md: the allow-list is a check on *request metadata*,
//! not a sandbox-level egress filter). Matching is label-based:
//!
//! - exact host: `registry.npmjs.org`
//! - single-label wildcard: `*.npmjs.org` matches `registry.npmjs.org`
//!   but NOT `npmjs.org` and not `evil-npmjs.org`.
//! - leading-dot normalisation: `.npmjs.org` == `npmjs.org`.
//! - IDN/normalisation: ASCII-lowercase, IDN labels are compared as
//!   punycode when available (pure ASCII handling otherwise).

use crate::error::{Error, Result};

/// Validate and normalise a hostname: lowercase, strip port/brackets,
/// reject anything that is not a plausible DNS name or an IP literal.
pub fn normalize_host(raw: &str) -> Result<String> {
    let mut s = raw.trim();
    // Strip a bracketed IPv6 literal or a trailing port.
    if s.starts_with('[') {
        match s.find(']') {
            Some(end) => s = &s[1..end],
            None => return Err(Error::DestinationError(format!("unterminated IPv6 literal: {raw}"))),
        }
    }
    if let Some(idx) = s.rfind(':') {
        // Only treat as port when not an IPv6 address (no second colon).
        if !s[0..idx].contains(':') {
            s = &s[..idx];
        }
    }
    let s = s.trim().trim_start_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return Err(Error::DestinationError(format!("host name out of range: {raw}")));
    }
    if s.ends_with('.') {
        return Err(Error::DestinationError(format!("host may not end with '.': {raw}")));
    }
    if s.contains(':') {
        // An IP literal (IPv6). Validate loosely and return it verbatim;
        // it does not follow DNS label rules.
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':') {
            return Err(Error::DestinationError(format!("invalid IP literal in: {raw}")));
        }
        return Ok(s);
    }
    for label in s.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::DestinationError(format!("invalid host label in: {raw}")));
        }
    }
    Ok(s)
}

/// True when `pattern` matches `host` after normalising both.
///
/// Patterns may carry a `*.suffix` wildcard (single label) or be exact.
/// An IP-literal pattern must equal the host verbatim.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let Ok(norm_host) = normalize_host(host) else {
        return false;
    };
    let pattern = pattern.trim().trim_start_matches('.');

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.suffix` matches exactly one DNS label on top of `suffix`.
        // Compare label counts so `evil-npmjs.org` (one hyphenated label
        // `evil-npmjs`) does NOT match `*.npmjs.org` (which wants a single
        // label above `npmjs.org`), while `registry.npmjs.org` does.
        let suffix_labels = suffix.split('.').filter(|s| !s.is_empty()).count();
        let host_labels = norm_host.split('.').filter(|s| !s.is_empty()).count();
        host_labels == suffix_labels + 1
            && norm_host.strip_suffix(suffix).is_some()
    } else {
        let Ok(norm_pat) = normalize_host(pattern) else {
            return false;
        };
        norm_pat == norm_host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_case_insensitive() {
        assert!(host_matches("registry.npmjs.org", "REGISTRY.NPMJS.ORG"));
        assert!(!host_matches("registry.npmjs.org", "npmjs.org"));
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        assert!(host_matches("*.npmjs.org", "registry.npmjs.org"));
        assert!(!host_matches("*.npmjs.org", "npmjs.org"));
        assert!(!host_matches("*.npmjs.org", "x.y.npmjs.org"));
        assert!(!host_matches("*.npmjs.org", "evil-npmjs.org"));
    }

    #[test]
    fn leading_dot_normalised() {
        assert!(host_matches(".npmjs.org", "npmjs.org"));
    }

    #[test]
    fn bad_hosts_rejected() {
        assert!(normalize_host("no label$").is_err());
        assert!(normalize_host("a..b").is_err());
        assert!(normalize_host("abc.").is_err());
        assert!(normalize_host("").is_err());
        assert!(normalize_host("[::1").is_err());
        assert!(normalize_host("[2001:db8::1]:8080").unwrap() == "2001:db8::1");
    }
}
