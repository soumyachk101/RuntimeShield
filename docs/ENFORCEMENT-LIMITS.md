# RuntimeShield — Enforcement Limits

This file states, honestly, what the local `runshield` agent **guarantees**
on this operating system versus what is **advisory**. The framing is copied
from the Rust source's own doc comments so the docs and the code can never
diverge. The short version: **RuntimeShield is a deterministic, auditable
policy *gate* on structured execution requests — not a kernel sandbox, not an
EDR, and not a shell wrapper.** No user-space wrapper can promise complete
host protection against a privileged adversary (spec §11 security disclaimer).

The agent's own scope statement (`rust/crates/agent/src/main.rs`):

> "this agent *evaluates* structured execution requests deterministically,
> journals every decision locally and uploads asynchronously. It does NOT wrap
> your shell, intercept a kernel process table or pin memory. What it
> verifiably does on this machine: schema validation of requests,
> deterministic policy evaluation (default-deny, rule ids, safe remediation),
> canonicalised filesystem checks, host/port network checks against the
> request metadata, secret redaction of anything it journals, and a file
> spool for offline control-plane outages."

## What is guaranteed (deterministic, test-covered)

These hold on any host the Rust binary runs on (macOS / Linux today), and are
backed by unit tests in `rust/crates/core/src/eval.rs`:

- **Structured argv, no shell reconstruction.** The agent receives argv as an
  array and launches via `std::process::Command` with that array — it never
  joins arguments into a shell string, so shell metacharacter injection
  (`;`, `&&`, backticks, quoting tricks) cannot smuggle a second command past
  the policy check. *Guaranteed for requests that arrive as structured argv.*
- **Default-deny evaluation with explicit precedence.** deny >
  require-approval > allow > audit-only > profile default. A broad allow
  cannot bypass a deny. Test `explicit_deny_rule_overrides_allow_section`.
- **Canonicalised filesystem *decisions*.** Every fs decision runs on a
  canonical, absolute path (tilde expand → resolve against cwd →
  `canonicalize`, with an ancestor walk for not-yet-existing write targets).
  Traversal like `../../.ssh/id_rsa` and `..` collapsing are resolved before
  the allow/deny check, so `path_traversal_into_sensitive_still_denied` holds.
  What is guaranteed is that **the decision is correct about which real
  location the request targets** — it is a decision-time guard, *not* a
  confinement boundary on the running process.
- **Host/port *decision* matching.** Network rules match the declared
  destination (normalized hostname + port). Test
  `npm_registry_is_allowed_other_hosts_deny`.
- **Secret redaction of everything it journals.** Detected secret values are
  replaced by a fingerprint + redacted token before they reach the SQLite
  journal or the spool. This part is deterministic: what is detected is never
  written in the clear.
- **Offline continuity.** The agent keeps deciding from its cached signed
  policy and keeps spooling events through a control-plane outage
  (`cache.rs`, `spool.rs`).

## What is advisory (a check on declared metadata, not a kernel boundary)

- **Filesystem writes/reads are gated by the decision, not confined.** After
  `exec` allows a command, the launched child process inherits the host's
  filesystem. RuntimeShield does not mount a sandbox, apply a capability set
  or a seccomp/landlock policy around the child in this reference build. A
  process that is *allowed to start* can therefore still do what the
  underlying OS permits it. The guarantee is "we decided the request was
  in-scope and recorded it," not "the process was incapable of escaping."
- **Network is an allow-list on request metadata, not egress filtering.**
  `netmatch.rs` says it plainly: "the allow-list is a check on *request
  metadata*, not a sandbox-level egress filter." DNS rebinding (a host name
  resolving to a different IP at connect time than at decision time) is not
  prevented by pinning the resolved IP, because the agent does not resolve and
  pin at connect time — it checks the declared host/port. Stronger
  network-enforced profiles need the OS/gVisor/Firecracker layer the spec
  calls out as a later phase.
- **Process spawn is advisory on the process tree.** The agent evaluates the
  requested `executable` + action. It does not pin or monitor the spawned
  child's descendants, so a child that forks a non-listed process is not
  re-evaluated. Structured argv reduces but does not eliminate interpreter /
  child-process escapes (spec §11 threat "child process escapes the expected
  execution tree").
- **Secret detection is best-effort.** `secret.rs`: "regex scanning alone
  cannot guarantee detection of every secret." The built-in patterns cover
  common key shapes; an org-specific or novel format may be missed. Redaction
  of what *is* detected is guaranteed; detection completeness is not.
- **The web console and the control plane are not enforcement.** The control
  plane distributes signed policy and ingests audit; it never decides. The
  UI presents decisions. Neither is a security boundary — a compromised
  control plane or UI must not be able to weaken local enforcement (spec §6
  trust boundaries 4–5 and §5 "important architecture decision").

## What a shell wrapper / prompt-level check would be (and isn't claimed)

RuntimeShield deliberately is **not** a shell wrapper that intercepts raw
command strings, and it is **not** an "ask the LLM whether this is safe"
prompt-level check. Those are the two weak layers this product is designed to
replace. Because the decision is made on structured, schema-validated argv
with canonicalised paths and deterministic precedence — before anything runs,
and recorded to an append-only journal — it is *auditable* in a way a shell
string or an LLM judgment is not. The gap (documented above) is that the
decision is advisory at the OS boundary until the isolation layer lands.

## Supported platform and bypass classes to test (spec §11)

Documented bypass classes to cover in the adversarial suite (later phase):
prompt-injection exfiltration, repo-script path traversal / symlink escape,
shell metacharacter hiding, child-process escape, DNS rebinding /
allowlist bypass, local audit or policy-cache tampering, stolen
control-plane token, malicious install-script exfiltration, and a policy
update that weakens default-deny. The current test suite covers the
traversal/symlink, default-deny and explicit-deny-override cases; the rest are
planned.
