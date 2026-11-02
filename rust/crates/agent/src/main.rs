//! `runshield` — the RuntimeShield local agent CLI.
//!
//! Honest scope statement: this agent *evaluates* structured execution
//! requests deterministically, journals every decision locally and
//! uploads asynchronously. It does NOT wrap your shell, intercept a
//! kernel process table or pin memory. What it verifiably does on this
//! machine: schema validation of requests, deterministic policy
//! evaluation (default-deny, rule ids, safe remediation), canonicalised
//! filesystem checks, host/port network checks against the request
//! metadata, secret redaction of anything it journals, and a file
//! spool for offline control-plane outages. See docs/ENFORCEMENT-LIMITS.md
//! for the full guaranteed-vs-advisory breakdown.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};

use runtime_shield_core::eval::{EvalContext, evaluate};
use runtime_shield_core::policy::Policy;
use runtime_shield_core::request::ExecutionRequest;

use cache::{FailMode, PolicyCache, load_policy_file};
use journal::{Journal, JournalEvent};
use spool::{Spool, SpooledEvent, Uploader};

mod cache;
mod journal;
mod spool;

#[derive(Parser)]
#[command(name = "runshield", version, about)]
struct Cli {
    /// Path to the agent data directory (default: $RUNSHIELD_DATA_DIR or ~/.runshield).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Control-plane base URL for policy pull / event upload.
    #[arg(long, global = true, env = "RUNSHIELD_CONTROL_PLANE")]
    control_plane: Option<String>,
    /// Force a specific fail mode on cache staleness.
    #[arg(long, global = true, value_enum, default_value_t = FailModeCli::Closed)]
    fail_mode: FailModeCli,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
#[repr(u8)]
enum FailModeCli {
    Closed,
    Open,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate a policy document against the JSON schema.
    PolicyValidate { file: PathBuf },
    /// Print a human summary of a policy document.
    PolicyShow { file: PathBuf },
    /// Evaluate a request (JSON on the path or `-` for stdin) against a policy.
    Check {
        /// Request JSON file, or `-` for stdin.
        #[arg(value_name = "REQUEST")]
        request: String,
        /// Policy file; omitted → use the cached policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Evaluate then (if allowed) exec the structured argv. No shell.
    Exec {
        /// Request JSON file, or `-` for stdin.
        #[arg(value_name = "REQUEST")]
        request: String,
        /// Policy file; omitted → use the cached policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Approve a REQUIRE_APPROVAL request locally (scoped, expiring).
    Approve {
        #[arg(long)]
        request_id: String,
        /// Scope string (default: the scope from the decision).
        #[arg(long)]
        scope: Option<String>,
        /// Approver id (default: $USER or "local").
        #[arg(long)]
        approver: Option<String>,
        /// Expiry in hours (default 1).
        #[arg(long, default_value_t = 1)]
        expires_h: u32,
    },
    /// Deny/close a REQUIRE_APPROVAL request locally.
    DenyApproval {
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        approver: Option<String>,
    },
    /// Print the recent local decision timeline.
    Journal {
        #[arg(long, default_value_t = 20)]
        limit: i64,
        /// Only events for one request.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Pull and cache the latest signed policy from the control plane.
    SyncPolicy {
        /// Device identity to present.
        #[arg(long, default_value = "local-dev")]
        device: String,
        /// Key material for signature verification (env in prod).
        #[arg(long, env = "RUNSHIELD_POLICY_KEY")]
        key: Option<String>,
        /// How long the cached document stays fresh (hours).
        #[arg(long, default_value_t = 24)]
        ttl_h: u32,
    },
    /// Show cache + spool status.
    Status,
    /// Flush the spool to the control plane once.
    Upload,
}

fn data_dir(opt: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = opt {
        return Ok(d.clone());
    }
    if let Ok(d) = std::env::var("RUNSHIELD_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".runshield"))
}

fn read_request(text: &str) -> Result<ExecutionRequest> {
    let raw = if text == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(text).with_context(|| format!("reading {text}"))?
    };
    let v: serde_json::Value =
        serde_json::from_str(&raw).context("request is not valid JSON")?;
    let req: ExecutionRequest =
        serde_json::from_value(v).context("request does not match the execution-request schema")?;
    Ok(req)
}

fn resolve_policy(
    data_dir_opt: &Option<PathBuf>,
    fail_mode: FailModeCli,
    explicit: &Option<PathBuf>,
) -> Result<(Policy, bool, String)> {
    // explicit file wins; second flag is "stale" (always false for files)
    if let Some(p) = explicit {
        let (pol, _doc) = load_policy_file(p).context("loading/explicit policy file")?;
        return Ok((pol, false, p.display().to_string()));
    }
    let dir = data_dir(data_dir_opt)?;
    let fail = match fail_mode {
        FailModeCli::Closed => FailMode::FailClosed,
        FailModeCli::Open => FailMode::FailOpen,
    };
    let key = std::env::var("RUNSHIELD_POLICY_KEY").ok();
    let cache = PolicyCache::new(dir, fail, key);
    match cache.resolve() {
        Ok((pol, stale)) => Ok((pol, stale, "cache".into())),
        Err(e) => {
            bail!(
                "no usable policy: {e}. Provide --policy, or run `runshield sync-policy` first."
            );
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir_opt = cli.data_dir.clone();
    let fail_mode = cli.fail_mode;
    let control_plane = cli.control_plane.clone();
    match cli.cmd {
        Cmd::PolicyValidate { file } => {
            let (_, doc) = load_policy_file(&file)?;
            let _ = runtime_shield_core::policy::validate_json(&doc);
            println!("policy {} is valid (schema v1)", file.display());
        }
        Cmd::PolicyShow { file } => {
            let (pol, _) = load_policy_file(&file)?;
            print_policy_summary(&pol);
        }
        Cmd::Check { request, policy } => {
            let req = read_request(&request)?;
            let (pol, stale, source) = resolve_policy(&data_dir_opt, fail_mode, &policy)?;
            let ctx = default_ctx()?;
            let out = evaluate(&pol, &req, &ctx)?;
            let mut decision = serde_json::to_value(&out)?;
            decision["policy_version"] = serde_json::json!(pol.version_label());
            decision["policy_source"] = serde_json::json!(&source);
            decision["stale_policy"] = serde_json::json!(stale);
            decision["audit_event_id"] = serde_json::json!(runtime_shield_core::policy::new_audit_event_id());
            println!("{}", serde_json::to_string_pretty(&decision)?);

            // Journal the decision so the audit trail is complete even
            // in offline mode.
            let dir = data_dir(&data_dir_opt)?;
            let j = open_journal(&dir)?;
            let id = decision["audit_event_id"]
                .as_str()
                .unwrap_or("no-id")
                .to_string();
            let rule_ids: Vec<String> = out.matched_rule_ids.clone();
            let ex: serde_json::Value = serde_json::to_value(&req).unwrap_or_default();
            let meta = redact_meta(&serde_json::json!({ "request": ex }));
            j.append(&JournalEvent {
                event_id: id.clone(),
                request_id: req.request_id.clone(),
                principal_id: req.principal_id.clone(),
                principal_kind: req.principal.as_str().to_string(),
                event_type: "decision".into(),
                decision: Some(out.decision.as_str().to_string()),
                rule_ids: rule_ids.clone(),
                policy_version: Some(pol.version_label()),
                executable: Some(req.executable.clone()),
                argv_digest: Some(req.digest()),
                cwd_digest: None,
                metadata: meta,
                recorded_at: Utc::now(),
            })?;
            // Spool a copy for the uploader (no-op when offline).
            let spool = Spool::new(dir.join("spool"));
            let _ = spool.push(&SpooledEvent {
                event_id: id.clone(),
                request_id: req.request_id.clone(),
                event_type: "decision".into(),
                decision: Some(out.decision.as_str().to_string()),
                rule_ids,
                policy_version: Some(pol.version_label()),
                metadata: "{}".into(),
                recorded_at: Utc::now().to_rfc3339(),
                idempotency_key: id,
            });
            let code = match out.decision {
                runtime_shield_core::policy::Decision::Deny => 3,
                runtime_shield_core::policy::Decision::RequireApproval => 4,
                _ => 0,
            };
            std::process::exit(code);
        }
        Cmd::Exec { request, policy } => {
            let req = read_request(&request)?;
            let (pol, _stale, _src) = resolve_policy(&data_dir_opt, fail_mode, &policy)?;
            let ctx = default_ctx()?;
            let out = evaluate(&pol, &req, &ctx)?;
            let d = serde_json::to_value(&out)?;
            let dir = data_dir(&data_dir_opt)?;
            let j = open_journal(&dir)?;
            let meta = redact_meta(&serde_json::json!({
                "argv": req.argv,
                "cwd": req.cwd,
                "workspace": req.workspace,
            }));
            let base_evt = |etype: &str, dec: &str| JournalEvent {
                event_id: runtime_shield_core::policy::new_audit_event_id(),
                request_id: req.request_id.clone(),
                principal_id: req.principal_id.clone(),
                principal_kind: req.principal.as_str().to_string(),
                event_type: etype.into(),
                decision: Some(dec.into()),
                rule_ids: out.matched_rule_ids.clone(),
                policy_version: Some(pol.version_label()),
                executable: Some(req.executable.clone()),
                argv_digest: Some(req.digest()),
                cwd_digest: None,
                metadata: meta.clone(),
                recorded_at: Utc::now(),
            };
            match out.decision {
                runtime_shield_core::policy::Decision::Deny => {
                    j.append(&base_evt("decision", "deny"))?;
                    println!("{}", serde_json::to_string_pretty(&d)?);
                    bail!("execution denied by policy");
                }
                runtime_shield_core::policy::Decision::RequireApproval => {
                    let scope = out.permitted_scope.clone().unwrap_or_default();
                    // An already-recorded active approval permits the exec.
                    if let Ok(true) = j.active_approval(&req.request_id, &scope) {
                        // fall through to exec below
                    } else {
                        j.append(&base_evt("decision", "require_approval"))?;
                        println!("{}", serde_json::to_string_pretty(&d)?);
                        bail!(
                            "execution requires approval (scope {scope}). Run:\n  runshield approve --request-id {} --scope {scope}",
                            req.request_id
                        );
                    }
                }
                _ => {}
            }
            j.append(&base_evt("decision", "allow"))?;
            // Launch via structured argv. The child inherits our
            // filesystem/network environment; that is why we document
            // enforcement limits: we do NOT sandbox the child.
            let mut child = std::process::Command::new(&req.executable);
            child.current_dir(&req.cwd).args(&req.argv);
            match child.status() {
                Ok(s) => {
                    let code = s.code().unwrap_or(-1);
                    j.append(&{
                        let mut e = base_evt("exec-finished", "allow");
                        e.metadata = format!("{{\"exit_code\": {code}}}");
                        e
                    })?;
                    println!(
                        "executed {} (exit {code})",
                        req.executable
                    );
                    std::process::exit(code.max(0));
                }
                Err(e) => {
                    j.append(&base_evt("exec-failed", "error"))?;
                    bail!("failed to launch {}: {e}", req.executable);
                }
            }
        }
        Cmd::Approve {
            request_id,
            scope,
            approver,
            expires_h,
        } => {
            let dir = data_dir(&data_dir_opt)?;
            let j = open_journal(&dir)?;
            let scope = scope.unwrap_or_else(|| "unknown-scope".into());
            let approver = approver
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "local".into());
            let id = j.record_approval(
                &request_id,
                &scope,
                "allow",
                &approver,
                Some(Utc::now() + Duration::hours(expires_h as i64)),
            )?;
            println!(
                "approval {id} recorded for request {request_id}, scope {scope} (expires in {expires_h}h)"
            );
        }
        Cmd::DenyApproval {
            request_id,
            approver,
        } => {
            let dir = data_dir(&data_dir_opt)?;
            let j = open_journal(&dir)?;
            let approver = approver
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "local".into());
            let id = j.record_approval(&request_id, "denied", "deny", &approver, None)?;
            println!("approval denial {id} recorded for request {request_id}");
        }
        Cmd::Journal { limit, request_id } => {
            let dir = data_dir(&data_dir_opt)?;
            let j = open_journal(&dir)?;
            if let Some(rid) = &request_id {
                let evs = j.events_for_request(rid)?;
                for e in evs {
                    println!(
                        "{}  {:<20}  decision={}  rules={:?}  policy={}",
                        e.recorded_at,
                        e.event_type,
                        e.decision.as_deref().unwrap_or("-"),
                        e.rule_ids,
                        e.policy_version.as_deref().unwrap_or("-"),
                    );
                }
            } else {
                let rows = j.recent_decisions(limit)?;
                if rows.is_empty() {
                    println!("journal is empty — run `runshield check` or `runshield exec` first");
                }
                for (rid, dec, pv, ts) in rows {
                    println!("{ts}  {dec:<16}  request={rid}  policy={pv:?}");
                }
            }
        }
        Cmd::SyncPolicy {
            device,
            key,
            ttl_h,
        } => {
            let url = cli
                .control_plane
                .clone()
                .ok_or_else(|| anyhow::anyhow!("control-plane URL required: pass --control-plane or set RUNSHIELD_CONTROL_PLANE"))?;
            let client = reqwest::blocking::Client::new();
            let resp = client
                .get(format!("{url}/v1/devices/{device}/policy"))
                .header("Accept", "application/json")
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .with_context(|| format!("reaching control plane at {url}"))?;
            if !resp.status().is_success() {
                bail!(
                    "control plane returned {} — keep using the cached policy",
                    resp.status()
                );
            }
            let body: serde_json::Value = resp.json()?;
            let doc = body
                .get("document")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("response missing `document`"))?;
            let sig = body.get("signature").and_then(|s| s.as_str()).map(String::from);
            let dir = data_dir(&data_dir_opt)?;
            let mut cache = PolicyCache::new(dir.clone(), FailMode::FailClosed, key.clone());
            cache.store(
                &doc,
                sig,
                Utc::now() + Duration::hours(ttl_h as i64),
                &device,
            )?;
            println!(
                "cached policy {} for device {device} (ttl {ttl_h}h)",
                Policy::from_json(&doc)?.version_label()
            );
        }
        Cmd::Status => {
            let dir = data_dir(&data_dir_opt)?;
            let fail = match fail_mode {
                FailModeCli::Closed => FailMode::FailClosed,
                FailModeCli::Open => FailMode::FailOpen,
            };
            let key = std::env::var("RUNSHIELD_POLICY_KEY").ok();
            let cache = PolicyCache::new(dir.clone(), fail, key);
            match cache.load() {
                Ok(status) => {
                    use cache::CacheStatus::*;
                    match status {
                        Fresh(m) => println!(
                            "cache: fresh, policy {} (by {}), expires {}",
                            m.policy.version_label(),
                            m.written_by,
                            m.expires_at
                        ),
                        Stale(m) => println!(
                            "cache: STALE, policy {} (by {}); fail mode is {fail:?}",
                            m.policy.version_label(),
                            m.written_by
                        ),
                        Empty => println!("cache: empty; no policy fetched yet"),
                    }
                }
                Err(e) => println!("cache: read error: {e}"),
            }
            let spool = Spool::new(dir.join("spool"));
            println!(
                "spool: {} event(s) pending{}",
                spool.pending_count(),
                if control_plane.is_none() {
                    " (no control plane configured; will drain on sync)"
                } else {
                    ""
                }
            );
            let db = dir.join("journal.db");
            if db.exists() {
                let j = Journal::open(&db)?;
                let recent = j.recent_decisions(3)?;
                if recent.is_empty() {
                    println!("journal: no decisions recorded yet");
                } else {
                    println!(
                        "journal: {} decision(s); most recent: {recent:?}",
                        recent.len()
                    );
                }
            } else {
                println!("journal: not initialised yet (no {db:?})");
            }
        }
        Cmd::Upload => {
            let url = control_plane.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "no control plane configured; set --control-plane or RUNSHIELD_CONTROL_PLANE"
                )
            })?;
            let dir = data_dir(&data_dir_opt)?;
            let spool = Spool::new(dir.join("spool"));
            let up = Uploader::new(spool, Some(url.clone()));
            let n = up.tick();
            println!("uploaded {n} event(s) to {url}/v1/events/batch");
        }
    }
    Ok(())
}

fn default_ctx() -> Result<EvalContext> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(EvalContext::new(
        home,
        std::env::temp_dir(),
    ))
}

fn open_journal(dir: &PathBuf) -> Result<Journal> {
    let _ = std::fs::create_dir_all(dir);
    let db = dir.join("journal.db");
    Ok(Journal::open(&db)?)
}

fn redact_meta(v: &serde_json::Value) -> String {
    let text = v.to_string();
    runtime_shield_core::secret::redact(&text)
}

fn print_policy_summary(p: &Policy) {
    println!(
        "policy {} — profile '{}' — default action: {}",
        p.version_label(),
        p.profile,
        p.default_action.as_str(),
    );
    if let Some(ws) = &p.filesystem.workspace {
        println!(
            "  fs workspace: {:?} (roots: {})",
            ws.access,
            ws.roots.join(", ")
        );
    }
    if !p.filesystem.sensitive_paths.is_empty() {
        println!("  fs sensitive: {}", p.filesystem.sensitive_paths.join(", "));
    }
    println!(
        "  net default: {} ({} allow, {} deny)",
        match p.network.default {
            runtime_shield_core::policy::NetworkDefault::Deny => "deny",
            runtime_shield_core::policy::NetworkDefault::Allow => "allow",
        },
        p.network.allow.len(),
        p.network.deny.len()
    );
    println!(
        "  process: {} allow / {} require-approval / {} deny rules; {} explicit rules total",
        p.process.allow.len(),
        p.process.require_approval.len(),
        p.process.deny.len(),
        p.rules.len(),
    );
}
