//! The deterministic policy evaluator.
//!
//! Precedence (highest wins):
//!
//! 1. A matching `deny` explicit rule (any capability) — deny can
//!    never be bypassed by a broader allow.
//! 2. A matching `deny` section rule (sensitive paths, network deny
//!    list, process deny list).
//! 3. A matching `require_approval` rule (process section).
//! 4. A matching `allow` rule or section allowlist entry.
//! 5. `audit_only` — allow with logging.
//! 6. The profile's `default_action` (default-deny is the product's
//!    core promise; a policy that sets `default_action: allow` is
//!    legal but the agent refuses to run a `restricted` profile with
//!    it).
//!
//! Every DENY carries the rule id, a human explanation and a safe
//! remediation string — the engine produces them, not the UI.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::netmatch;
use crate::paths::{self, ResolvedPath};
use crate::policy::{
    CapabilityKind, Decision, FsAccess, NetworkDefault, Policy,
};
use crate::request::{Capability, CapabilityKind as Cap, ExecutionRequest};

/// A resolved context for one evaluation. The agent builds it; it is
/// pure data so the engine stays unit-testable.
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub home: std::path::PathBuf,
    pub temp_dir: std::path::PathBuf,
}

impl EvalContext {
    /// Canonicalise `home` and `temp_dir` when they exist so that
    /// symlinked roots (macOS `/tmp` → `/private/tmp`) resolve to the
    /// same physical tree as target paths. When they do not exist
    /// (tests, fresh containers) the input is used verbatim and the
    /// ancestor walk in `paths::resolve` keeps containment consistent.
    pub fn new(home: std::path::PathBuf, temp_dir: std::path::PathBuf) -> Self {
        Self {
            home: canonicalize_or(home),
            temp_dir: canonicalize_or(temp_dir),
        }
    }
}

fn canonicalize_or(p: PathBuf) -> PathBuf {
    std::fs::canonicalize(&p).unwrap_or(p)
}

/// The result of a full evaluation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvalResult {
    pub decision: Decision,
    /// Every rule/section that contributed to the decision (so the UI
    /// can show the full chain, not just the winner).
    pub matched_rule_ids: Vec<String>,
    /// Present whenever decision is DENY — and ideally whenever
    /// REQUIRE_APPROVAL. Never empty for a deny.
    pub explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// A human-safe "scope" string describing what would be permitted
    /// if this were allowed; recorded on REQUIRE_APPROVAL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permitted_scope: Option<String>,
}

impl EvalResult {
    fn allow(rule: &str, explanation: String) -> Self {
        Self {
            decision: Decision::Allow,
            matched_rule_ids: vec![rule.to_string()],
            explanation,
            remediation: None,
            permitted_scope: None,
        }
    }
    fn audit_only(rule: &str, explanation: String) -> Self {
        Self {
            decision: Decision::AuditOnly,
            matched_rule_ids: vec![rule.to_string()],
            explanation,
            remediation: None,
            permitted_scope: None,
        }
    }
    fn require_approval(
        rule: &str,
        explanation: String,
        scope: String,
        remediation: String,
    ) -> Self {
        Self {
            decision: Decision::RequireApproval,
            matched_rule_ids: vec![rule.to_string()],
            explanation,
            remediation: Some(remediation),
            permitted_scope: Some(scope),
        }
    }
    fn deny(rule: &str, explanation: String, remediation: String) -> Self {
        Self {
            decision: Decision::Deny,
            matched_rule_ids: vec![rule.to_string()],
            explanation,
            remediation: Some(remediation),
            permitted_scope: None,
        }
    }
}

/// Canonicalise a capability path against the context.
fn resolve_cap_path(raw: &str, cwd: &Path, ctx: &EvalContext) -> Result<ResolvedPath> {
    paths::resolve(raw, cwd, &ctx.home)
}

/// Evaluate one request against a policy. This is the core decision
/// function; it is pure and fully deterministic.
pub fn evaluate(
    policy: &Policy,
    request: &ExecutionRequest,
    ctx: &EvalContext,
) -> Result<EvalResult> {
    request.validate()?;
    let cwd = Path::new(&request.cwd);
    let mut hits: Vec<EvalResult> = Vec::new();

    // --- capability checks ---------------------------------------------------
    for cap in &request.capabilities {
        hits.push(cap_check(policy, request, cap, cwd, ctx)?);
    }

    // The process check applies to the *main* executable only when the
    // request carries no capabilities at all. When capabilities are
    // present they are evaluated on their own dimension; process
    // allow-listing is opt-in via an explicit `process` capability, and
    // an unlisted main executable does not override an explicit
    // capability allow. (See KNOWN-LIMITATIONS.md.)
    if request.capabilities.is_empty() {
        let main_exec_cap = Capability {
            kind: Cap::Process,
            path: None,
            host: None,
            port: None,
            executable: Some(request.executable.clone()),
            env_keys: Vec::new(),
        };
        hits.push(cap_check(policy, request, &main_exec_cap, cwd, ctx)?);
    }

    // Secret checks: requested env keys that the policy denies.
    if !request.env_keys_requested.is_empty()
        || request.capabilities.iter().any(|c| c.kind == Cap::Secret)
    {
        let denied_keys: Vec<String> = request
            .env_keys_requested
            .iter()
            .filter(|k| {
                policy.secrets.deny_env_keys.iter().any(|dk| {
                    k.to_lowercase().contains(&dk.to_lowercase())
                })
            })
            .cloned()
            .collect();
        if !denied_keys.is_empty() {
            return Ok(EvalResult::deny(
                "secret-deny-env",
                format!(
                    "environment key(s) {denied_keys:?} are denied by the secrets section"
                ),
                "Remove the denied keys from the request's env_keys_requested or grant them explicitly in a policy rule. Do not request secret env keys when the request does not need them.".into(),
            ));
        }
    }

    // Merge: deny > require_approval > allow/audit_only (last wins within same level)
    let outcome = merge(&hits, policy);
    Ok(outcome)
}

fn merge(hits: &[EvalResult], policy: &Policy) -> EvalResult {
    // Each check already resolves its own "default" fallback when no rule
    // matches, so an empty `hits` list is the only case where the profile
    // default decides on its own.
    if hits.is_empty() {
        return default_outcome(policy);
    }
    // Precedence: deny (4) > require_approval (3) > allow (2) > audit_only (1).
    // On a tie at the winning level, deny-class wins over allow-class, and
    // all rule ids at the winning level are accumulated so the UI shows the
    // full chain.
    let strength = |d: &Decision| -> i32 {
        match d {
            Decision::Deny => 4,
            Decision::RequireApproval => 3,
            Decision::Allow => 2,
            Decision::AuditOnly => 1,
        }
    };
    let mut best = hits[0].clone();
    for h in hits.iter().skip(1) {
        let (hs, bs) = (strength(&h.decision), strength(&best.decision));
        match (hs, bs) {
            (a, b) if a > b => best = h.clone(),
            (a, b) if a == b => {
                // tie: deny/require-approval beats allow/audit-only
                if matches!(h.decision, Decision::Deny | Decision::RequireApproval)
                    && !matches!(best.decision, Decision::Deny | Decision::RequireApproval)
                {
                    best = h.clone();
                }
                for id in &h.matched_rule_ids {
                    if !best.matched_rule_ids.iter().any(|x| x == id) {
                        best.matched_rule_ids.push(id.clone());
                    }
                }
            }
            _ => {}
        }
    }
    best
}

fn default_outcome(policy: &Policy) -> EvalResult {
    if policy.default_action == Decision::Deny {
        EvalResult::deny(
            "default-action-deny",
            format!(
                "no matching rule permitted this request; profile default is deny ({})",
                policy.profile
            ),
            format!(
                "Add an explicit allow rule, request an approval, or switch to a broader profile. Rule: default-action-deny of profile '{}'.",
                policy.profile
            ),
        )
    } else {
        EvalResult::audit_only(
            "default-action",
            format!(
                "no matching rule; profile default is {}, so this request is recorded without blocking",
                policy.default_action.as_str()
            ),
        )
    }
}

/// Evaluate one capability.
fn cap_check(
    policy: &Policy,
    request: &ExecutionRequest,
    cap: &Capability,
    cwd: &Path,
    ctx: &EvalContext,
) -> Result<EvalResult> {
    let explicit = explicit_rule_hit(policy, request, cap);
    if let Some(hit) = explicit {
        return Ok(hit);
    }
    match cap.kind {
        Cap::FsRead | Cap::FsWrite => fs_check(policy, request, cap, cwd, ctx),
        Cap::Network => net_check(policy, request, cap),
        Cap::Process => proc_check(policy, request, cap),
        Cap::Secret => {
            // Secret access is denied unless explicitly allowed; the
            // engine does not model "secret capability granted" as a
            // first-class thing because it is always high-risk.
            Ok(EvalResult::deny(
                "secret-default-deny",
                "access to secrets is denied by default; the policy must grant it explicitly and narrowly, and any approval is recorded".into(),
                "Scope the secret grant to a specific key and a short-lived approval. Never make a default-allow on secrets.".into(),
            ))
        }
    }
}

/// An explicit `rules` entry that covers this capability.
fn explicit_rule_hit(
    policy: &Policy,
    request: &ExecutionRequest,
    cap: &Capability,
) -> Option<EvalResult> {
    for rule in &policy.rules {
        let matches = match rule.capability {
            CapabilityKind::Filesystem => {
                if cap.kind == Cap::FsRead || cap.kind == Cap::FsWrite {
                    rule
                        .path
                        .as_deref()
                        .is_some_and(|p| paths::glob_match(p, cap.path.as_deref().unwrap_or("")))
                } else {
                    false
                }
            }
            CapabilityKind::Network => {
                rule.host.as_deref().is_some_and(|h| {
                    cap.host.as_deref().is_some_and(|ch| {
                        netmatch::host_matches(h, ch)
                            && rule.port.map_or(true, |rp| cap.port == Some(rp))
                    })
                })
            }
            CapabilityKind::Process => {
                rule.executable
                    .as_deref()
                    .is_some_and(|ex| {
                        let target = cap
                            .executable
                            .as_deref()
                            .unwrap_or(&request.executable);
                        ex == target
                            && rule
                                .actions
                                .as_deref()
                                .map_or(true, |acts| {
                                    acts.iter().any(|a| {
                                        request.argv.get(1).as_deref() == Some(a)
                                    })
                                })
                    })
            }
            CapabilityKind::Secret => {
                cap.kind == Cap::Secret
            }
        };
        if !matches {
            continue;
        }
        let rule_id = &rule.id;
        let note = rule.note.as_deref().unwrap_or("");
        return Some(match rule.effect {
            Decision::Allow => EvalResult::allow(
                rule_id,
                format!("explicit rule {rule_id} permits this capability ({note})"),
            ),
            Decision::Deny => EvalResult::deny(
                rule_id,
                format!("explicit rule {rule_id} denies this capability ({note})"),
                format!(
                    "Rule {rule_id} is an explicit deny. To override it, remove or narrow that rule and re-publish the policy. Approval cannot override an explicit deny."
                ),
            ),
            Decision::RequireApproval => EvalResult::require_approval(
                rule_id,
                format!("explicit rule {rule_id} requires approval for this capability ({note})"),
                format!(
                    "capabilities: {} (note: {note})",
                    cap.kind.as_str()
                ),
                "An operator must approve this request in the approval workspace. The scope is limited to the exact capability requested.".into(),
            ),
            Decision::AuditOnly => EvalResult::audit_only(
                rule_id,
                format!("explicit rule {rule_id} records this capability without blocking ({note})"),
            ),
        });
    }
    None
}

fn fs_check(
    policy: &Policy,
    _request: &ExecutionRequest,
    cap: &Capability,
    cwd: &Path,
    ctx: &EvalContext,
) -> Result<EvalResult> {
    let raw = cap.path.as_deref().ok_or_else(|| {
        Error::InvalidRequest("fs capability missing path".into())
    })?;
    let resolved = resolve_cap_path(raw, cwd, ctx)?;
    let write = cap.kind == Cap::FsWrite;

    // 1. Sensitive / deny paths win over everything else.
    for pat in policy.filesystem.sensitive_paths.iter().chain(policy.filesystem.deny_paths.iter()) {
        let Ok(rp) = paths::resolve(pat, cwd, &ctx.home) else {
            continue;
        };
        if inside_or_equal(&resolved.path, &rp.path, pat) {

            let label = if policy.filesystem.sensitive_paths.contains(pat) {
                "sensitive"
            } else {
                "denied"
            };
            return Ok(EvalResult::deny(
                "sensitive-or-deny-path",
                format!(
                    "path {raw} resolves to {} which is a {label} path (matched {pat})",
                    resolved.path.display()
                ),
                format!(
                    "The {label} path {pat} is protected by policy. Access it through a narrow, time-boxed approval, or use a different location within your workspace."
                ),
            ));
        }
    }

    // 2. Explicit allow paths (exact canonical path or glob).
    for pat in &policy.filesystem.allow_paths {
        if paths::glob_match(pat, &resolved.path.to_string_lossy()) {
            return Ok(EvalResult::allow(
                "fs-allow-path",
                format!("path {raw} is explicitly permitted via allow_paths entry {pat}"),
            ));
        }
    }

    // 3. Workspace boundary.
    if let Some(ws) = &policy.filesystem.workspace {
        for root in &ws.roots {
            let Ok(rp) = paths::resolve(root, cwd, &ctx.home) else {
                continue;
            };
            if paths::inside(&resolved.path, &rp.path) { // component-boundary containment

                match ws.access {
                    FsAccess::ReadWrite => {
                        return Ok(EvalResult::allow(
                            "fs-workspace",
                            format!(
                                "path {raw} is inside workspace root {root} (access: read-write)"
                            ),
                        ));
                    }
                    FsAccess::ReadOnly => {
                        if write {
                            return Ok(EvalResult::deny(
                                "fs-workspace-readonly",
                                format!(
                                    "path {raw} is inside read-only workspace root {root}; write is not permitted by profile"
                                ),
                                format!(
                                    "Switch the workspace access to read-write for this profile or move the write target outside the read-only root. Profile '{}' uses read-only workspace access.",
                                    policy.profile
                                ),
                            ));
                        }
                        return Ok(EvalResult::allow(
                            "fs-workspace",
                            format!("path {raw} is inside read-only workspace root {root}"),
                        ));
                    }
                    FsAccess::Deny => {
                        return Ok(EvalResult::deny(
                            "fs-workside-deny",
                            format!("workspace access is denied by the profile for path {raw}"),
                            "Edit the profile's filesystem.workspace.access to at least read-only and re-publish.".into(),
                        ));
                    }
                }
            }
        }
        // Not inside any workspace root: check the temp area next.
        if let Some(temp) = &policy.filesystem.temp {
            if paths::inside(&resolved.path, &ctx.temp_dir) {
                match temp.access {
                    FsAccess::ReadWrite => {
                        return Ok(EvalResult::allow(
                            "fs-temp",
                            format!("path {raw} is inside the system temp directory"),
                        ));
                    }
                    FsAccess::ReadOnly => {
                        if write {
                            return Ok(EvalResult::deny(
                                "fs-temp-readonly",
                                format!(
                                    "path {raw} is inside the system temp directory, which the profile marks read-only"
                                ),
                                "The profile grants temp read-only. Move the write to a workspace root or relax the profile temp access.".into(),
                            ));
                        }
                        return Ok(EvalResult::allow(
                            "fs-temp",
                            format!("path {raw} is inside the system temp directory (read-only)"),
                        ));
                    }
                    FsAccess::Deny => {
                        return Ok(EvalResult::deny(
                            "fs-temp-deny",
                            format!("path {raw} targets the system temp directory, which the profile denies"),
                            "The profile denies all temp access. Use a workspace root instead.".into(),
                        ));
                    }
                }
            }
        }
        return Ok(EvalResult::deny(
            "fs-outside-scope",
            format!(
                "path {raw} is not inside any workspace root and not in the permitted temp area"
            ),
            "Add the path to filesystem.workspace.roots or filesystem.allow_paths and re-publish. A one-off exception is also possible via the approval workflow.".into(),
        ));
    }

    // No workspace section at all.
    Ok(EvalResult::deny(
        "fs-no-scope",
        "no workspace roots or allow_paths are configured; filesystem access has no scope to match against".into(),
        "Configure filesystem.workspace.roots in the profile, or add filesystem.allow_paths entries, before running agent workloads against this policy.".into(),
    ))
}

/// A canonical path is "inside" a pattern when it is a component-prefix
/// match (or exact match, when the pattern carries no glob metachars), or
/// when the pattern is a glob and the path matches it.
fn inside_or_equal(target: &Path, root: &Path, pattern: &str) -> bool {
    if target == root {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        return paths::glob_match(pattern, target.to_string_lossy().as_ref());
    }
    paths::inside(target, root)
}

fn net_check(
    policy: &Policy,
    _request: &ExecutionRequest,
    cap: &Capability,
) -> Result<EvalResult> {
    let host = cap
        .host
        .clone()
        .ok_or_else(|| Error::InvalidRequest("network capability missing host".into()))?;
    let port = cap.port.unwrap_or(443);

    // Normalise both sides so `Foo.example.com` and `foo.example.com`
    // hit the same check.
    let Ok(norm_host) = netmatch::normalize_host(&host) else {
        return Ok(EvalResult::deny(
            "net-bad-host",
            format!("host {host} is not a valid destination for policy evaluation"),
            "Check the host spelling. Wildcards are `*.suffix` and IP literals must be verbatim.".into(),
        ));
    };

    // Deny list wins over allow list (never bypass a deny).
    for d in &policy.network.deny {
        if d.matches(&norm_host, port) {
            return Ok(EvalResult::deny(
                "net-explicit-deny",
                format!("destination {norm_host}:{port} is explicitly denied by policy"),
                "Remove the entry from network.deny or request a time-boxed exception via the approval workflow. Explicit denies cannot be overridden by allow rules.".into(),
            ));
        }
    }
    for a in &policy.network.allow {
        if a.matches(&norm_host, port) {
            return Ok(EvalResult::allow(
                "net-allow",
                format!("destination {norm_host}:{port} is explicitly permitted by policy"),
            ));
        }
    }
    match policy.network.default {
        NetworkDefault::Deny => Ok(EvalResult::deny(
            "net-default-deny",
            format!(
                "destination {norm_host}:{port} is not in the allow list and the profile default is deny"
            ),
            format!(
                "Add the destination to network.allow in profile '{profile}' (host {norm_host}, port {port}) or switch the profile default. Outbound traffic to unlisted hosts is denied by default.",
                profile = ""
            ),
        )),
        NetworkDefault::Allow => Ok(EvalResult::audit_only(
            "net-default-allow",
            format!(
                "destination {norm_host}:{port} is not in any list; profile default is allow, so this is recorded without blocking"
            ),
        )),
    }
}

fn proc_check(
    policy: &Policy,
    request: &ExecutionRequest,
    cap: &Capability,
) -> Result<EvalResult> {
    let target = cap
        .executable
        .as_deref()
        .unwrap_or(&request.executable)
        .to_string();
    // argv[0] is the executable, argv[1] (if any) is the action.
    let action = request.argv.get(1).map(|s| s.as_str());

    // Deny list.
    if let Some(rule) = policy.process.deny.iter().find(|r| r.executable == target) {
        if actions_match(&rule.actions, action) {
            return Ok(EvalResult::deny(
                "proc-explicit-deny",
                format!(
                    "executable '{target}' with action {action:?} is explicitly denied by policy"
                ),
                format!(
                    "The policy's process.deny section blocks this command. Remove the entry or request a narrow approval. Deny rules cannot be bypassed by allow rules."
                ),
            ));
        }
    }
    // Require-approval.
    if let Some(rule) = policy
        .process
        .require_approval
        .iter()
        .find(|r| r.executable == target)
    {
        if actions_match(&rule.actions, action) {
            let scope = format!(
                "exec:{target}{}",
                action.map_or(String::new(), |a| format!(" action:{a}"))
            );
            return Ok(EvalResult::require_approval(
                "proc-require-approval",
                format!(
                    "executable '{target}' with action {action:?} requires approval before it can run"
                ),
                scope,
                "An operator must approve this in the approval workspace. The scope is limited to the exact executable and action requested. Approvals expire by default; do not grant blanket approvals.".into(),
            ));
        }
    }
    // Allow list.
    if let Some(rule) = policy.process.allow.iter().find(|r| r.executable == target) {
        if actions_match(&rule.actions, action) {
            return Ok(EvalResult::allow(
                "proc-allow",
                format!(
                    "executable '{target}' with action {action:?} is explicitly permitted by policy"
                ),
            ));
        }
        // Executable is in allow but action is not listed → fall through
        // to default (deny by product principle).
    }
    // No rule matched the executable at all.
    match policy.default_action {
        Decision::Deny => Ok(EvalResult::deny(
            "proc-default-deny",
            format!(
                "executable '{target}' is not in any process list; profile default is deny"
            ),
            format!(
                "Add a process.allow entry for '{target}' (with the specific actions) or use a broader profile. Running unlisted executables is denied by default."
            ),
        )),
        _ => Ok(EvalResult::audit_only(
            "proc-default-open",
            format!(
                "executable '{target}' has no process rule; profile default is '{}', so this is recorded without blocking",
                policy.default_action.as_str()
            ),
        )),
    }
}

fn actions_match(actions: &Option<Vec<String>>, actual: Option<&str>) -> bool {
    match actions {
        None => true, // no action constraint
        Some(list) => {
            if list.is_empty() {
                true
            } else {
                actual.map_or(false, |a| list.iter().any(|x| x == a))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx() -> EvalContext {
        // Use a real temp dir so the ancestor walk in paths::resolve
        // has a fully-resolved anchor; home stays synthetic for
        // tilde expansion.
        EvalContext::new(
            PathBuf::from("/home/dev"),
            std::env::temp_dir(),
        )
    }

    fn policy() -> Policy {
        Policy::from_json(&serde_json::json!({
            "version": 1,
            "profile": "repository-development",
            "default_action": "deny",
            "filesystem": {
                "workspace": { "access": "read-write", "roots": ["/home/dev/repo"] },
                "temp": { "access": "read-write" },
                "sensitive_paths": ["/home/dev/.ssh"]
            },
            "network": {
                "default": "deny",
                "allow": [{ "host": "registry.npmjs.org", "ports": [443] }]
            },
            "process": {
                "allow": [{ "executable": "git", "actions": ["status", "diff", "log"] }],
                "require_approval": [{ "executable": "curl" }]
            }
        }))
        .expect("policy must validate")
    }

    fn req(executable: &str, argv: Vec<&str>, caps: Vec<Capability>) -> ExecutionRequest {
        ExecutionRequest {
            request_id: "r-test".into(),
            principal_id: "agent-t".into(),
            principal: crate::request::Principal::Agent,
            executable: executable.into(),
            argv: argv.into_iter().map(|s| s.to_string()).collect(),
            cwd: "/home/dev/repo".into(),
            workspace: "w-1".into(),
            parent_pid: None,
            user: None,
            repo_ref: None,
            capabilities: caps,
            env_keys_requested: vec![],
        }
    }

    fn fs_cap(kind: Cap, path: &str) -> Capability {
        Capability {
            kind,
            path: Some(path.into()),
            host: None,
            port: None,
            executable: None,
            env_keys: vec![],
        }
    }
    fn net_cap(host: &str, port: u16) -> Capability {
        Capability {
            kind: Cap::Network,
            path: None,
            host: Some(host.into()),
            port: Some(port),
            executable: None,
            env_keys: vec![],
        }
    }
    fn proc_cap(executable: &str) -> Capability {
        Capability {
            kind: Cap::Process,
            path: None,
            host: None,
            port: None,
            executable: Some(executable.into()),
            env_keys: vec![],
        }
    }

    #[test]
    fn git_status_is_allowed() {
        let p = policy();
        let r = req("git", vec!["git", "status"], vec![proc_cap("git")]);
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.matched_rule_ids, vec!["proc-allow"]);
    }

    #[test]
    fn git_push_falls_to_default_deny() {
        let p = policy();
        let r = req("git", vec!["git", "push"], vec![proc_cap("git")]);
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Deny);
        assert!(out.matched_rule_ids.iter().any(|i| i == "proc-default-deny"));
        assert!(out.remediation.is_some());
    }

    #[test]
    fn curl_requires_approval() {
        let p = policy();
        let r = req("curl", vec!["curl", "-s", "https://x"], vec![proc_cap("curl")]);
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::RequireApproval);
        assert!(out.permitted_scope.as_deref().unwrap_or("").starts_with("exec:curl"));
    }

    #[test]
    fn npm_registry_is_allowed_other_hosts_deny() {
        let p = policy();
        let ok = evaluate(
            &p,
            &req("npm", vec!["npm", "install"], vec![net_cap("registry.npmjs.org", 443)]),
            &ctx(),
        )
        .unwrap();
        assert_eq!(ok.decision, Decision::Allow);

        let bad = evaluate(
            &p,
            &req("npm", vec!["npm", "install"], vec![net_cap("evil.example", 443)]),
            &ctx(),
        )
        .unwrap();
        assert_eq!(bad.decision, Decision::Deny);
        assert!(bad.matched_rule_ids.iter().any(|i| i == "net-default-deny"));
    }

    #[test]
    fn sensitive_path_write_is_denied() {
        let p = policy();
        let r = req(
            "cp",
            vec!["cp", "a", "b"],
            vec![fs_cap(Cap::FsWrite, "/home/dev/.ssh/id_rsa")],
        );
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Deny);
    }

    #[test]
    fn path_traversal_into_sensitive_still_denied() {
        let p = policy();
        // `../.ssh/id_rsa` from /home/dev/repo lands on /home/dev/.ssh/id_rsa
        let r = req(
            "cp",
            vec!["cp", "a", "b"],
            vec![fs_cap(Cap::FsWrite, "../.ssh/id_rsa")],
        );
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Deny);
    }

    #[test]
    fn workspace_write_inside_root_is_allowed() {
        let p = policy();
        let r = req(
            "touch",
            vec!["touch", "file.rs"],
            vec![fs_cap(Cap::FsWrite, "file.rs")],
        );
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Allow);
        assert!(out.matched_rule_ids.iter().any(|i| i == "fs-workspace"));
    }

    #[test]
    fn temp_write_inside_system_temp_is_allowed() {
        let p = policy();
        let tmp = std::env::temp_dir();
        let target = tmp.join("rs-eval-test-file").to_string_lossy().into_owned();
        let r = req("touch", vec!["touch", "f"], vec![fs_cap(Cap::FsWrite, &target)]);
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Allow);
        assert!(out.matched_rule_ids.iter().any(|i| i == "fs-temp"));
    }

    #[test]
    fn outside_scope_is_default_denied() {
        let p = policy();
        let r = req(
            "rm",
            vec!["rm", "x"],
            vec![fs_cap(Cap::FsWrite, "/etc/hosts")],
        );
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Deny);
    }

    #[test]
    fn explicit_deny_rule_overrides_allow_section() {
        let doc = serde_json::json!({
            "version": 1,
            "profile": "restricted",
            "default_action": "deny",
            "network": { "default": "deny", "allow": [{ "host": "api.example.com", "ports": [443] }] },
            "rules": [
                { "id": "no-api-example", "effect": "deny", "capability": "network", "host": "api.example.com" }
            ]
        });
        let p = Policy::from_json(&doc).unwrap();
        let r = req("curl", vec!["curl", "https://api.example.com"], vec![net_cap("api.example.com", 443)]);
        let out = evaluate(&p, &r, &ctx()).unwrap();
        assert_eq!(out.decision, Decision::Deny);
        assert!(out.matched_rule_ids.iter().any(|i| i == "no-api-example"));
    }
}
