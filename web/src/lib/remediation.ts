// Safe remediation text for rule IDs the Rust engine emits on denials
// (rust/crates/core/src/eval.rs). The console surfaces the rule IDs on every
// denial; for the well-known section rules we can also show the remediation
// the engine produced, so the timeline stays actionable without re-running
// the agent. Explicit rule ids (`rules[].id`) are product-defined, so they
// carry no generic text — the explanation is the source of truth there.
//
// Deliberately conservative: this map only fills in text for the engine's
// built-in section-rule ids. Anything not listed shows the raw rule id and
// the generic guidance — never invented remediation.

export const RULE_REMEDIATION: Record<string, string> = {
  "default-action-deny":
    "No matching rule permitted this request and the profile default is deny. Add an explicit allow rule, request an approval, or switch to a broader profile.",
  "default-action": "No matching rule; the profile default is non-blocking, so the request was recorded without blocking.",
  "sensitive-or-deny-path":
    "The target is inside a sensitive or denied path. Access it through a narrow, time-boxed approval or use a location within the workspace.",
  "fs-allow-path": "The path is explicitly permitted via an allow_paths entry.",
  "fs-workspace": "The path is inside a permitted workspace root.",
  "fs-workspace-readonly":
    "The path is inside a read-only workspace root. Switch the workspace access to read-write for this profile, or move the write target elsewhere.",
  "fs-temp": "The path is inside the system temp directory.",
  "fs-temp-readonly": "The profile grants the temp directory read-only; move the write to a workspace root.",
  "fs-temp-deny": "The profile denies all temp access. Use a workspace root instead.",
  "fs-outside-scope":
    "The path is not inside any workspace root and not in the permitted temp area. Add it to filesystem.workspace.roots or filesystem.allow_paths and re-publish, or use a one-off approval.",
  "fs-no-scope":
    "No workspace roots or allow_paths are configured, so filesystem access has nothing to match. Configure filesystem.workspace.roots or add allow_paths before running workloads against this policy.",
  "fs-workside-deny":
    "Workspace access is denied by the profile for this path. Edit the profile's filesystem.workspace.access to at least read-only and re-publish.",
  "net-bad-host": "The destination host is not valid for policy evaluation. Check the host spelling; wildcards are *.suffix.",
  "net-explicit-deny":
    "The destination is explicitly denied. Remove it from network.deny or request a time-boxed exception; explicit denies cannot be overridden by allow rules.",
  "net-allow": "The destination is explicitly permitted by the network allow list.",
  "net-default-deny":
    "The destination is not in the allow list and the profile default is deny. Add the host and port to network.allow or request an approval.",
  "net-default-allow": "The destination is unlisted but the profile default is allow, so it is recorded without blocking.",
  "proc-explicit-deny":
    "The executable/action is in the process deny list. Remove the entry or request a narrow approval; deny rules cannot be bypassed by allow rules.",
  "proc-require-approval":
    "The executable/action requires approval. An operator approves it in the approval workspace; the scope is limited to the exact executable and action requested.",
  "proc-allow": "The executable/action is explicitly permitted by the process allow list.",
  "proc-default-deny":
    "The executable is not in any process list and the profile default is deny. Add a process.allow entry with the specific actions, or use a broader profile.",
  "proc-default-open": "The executable has no process rule; the profile default is non-blocking, so it is recorded without blocking.",
  "secret-deny-env":
    "An environment key is denied by the secrets section. Remove the denied key from the request or grant it explicitly and narrowly in a policy rule.",
  "secret-default-deny":
    "Access to secrets is denied by default. Grant it explicitly and narrowly with a short-lived approval; never make secrets default-allow.",
};

export const GENERIC_REMEDIATION =
  "Rule ids shown are the engine's matched rules. Check the rule's note in the policy document; explicit denies cannot be overridden by approvals — remove or narrow the rule and re-publish.";

export function remediationFor(ruleIds: string[]): string {
  const known = ruleIds
    .map((id) => RULE_REMEDIATION[id])
    .filter((t): t is string => Boolean(t));
  return known.length > 0 ? known.join(" ") : GENERIC_REMEDIATION;
}

// Decision kinds that warrant a remediation callout in the timeline:
// denials and approval-required requests are the actionable ones.
export function isActionable(decision: string): boolean {
  return decision === "deny" || decision === "require_approval";
}
