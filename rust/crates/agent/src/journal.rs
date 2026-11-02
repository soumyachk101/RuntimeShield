//! Append-only local audit journal in SQLite.
//!
//! Design notes (from the spec):
//! - the journal is append-only at the application level: the agent
//!   opens a fresh write-transaction per event and never updates or
//!   deletes rows. A tamper-evident hash chain is *planned* (spec
//!   non-functional requirement) and this schema leaves a
//!   `previous_hash` column for it.
//! - Raw secrets must never be written (spec §18: "no raw secret
//!   values in the audit log"). Every metadata string passed here is
//!   redacted by the caller before insert; the journal itself enforces
//!   the invariant with a debug assertion-style check using the
//!   builtin detector (cheap, best-effort).

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

use runtime_shield_core::secret;

#[derive(Debug, Clone, Serialize)]
pub struct JournalEvent {
    pub event_id: String,
    pub request_id: String,
    pub principal_id: String,
    pub principal_kind: String,
    pub event_type: String,
    pub decision: Option<String>,
    pub rule_ids: Vec<String>,
    pub policy_version: Option<String>,
    pub executable: Option<String>,
    pub argv_digest: Option<String>,
    pub cwd_digest: Option<String>,
    /// Redacted metadata only. Raw secrets are never stored here.
    pub metadata: String,
    pub recorded_at: DateTime<Utc>,
}

pub struct Journal {
    conn: Connection,
    /// Guards against concurrent appends from the uploader thread.
    guard: Mutex<()>,
}

impl Journal {
    pub fn open(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;
        // `PRAGMA journal_mode=WAL` returns a result row, so drive it via
        // `pragma_update` rather than a bare `execute` (which errors with
        // `ExecuteReturnedResults`).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS journal (
                event_id        TEXT PRIMARY KEY,
                request_id      TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                principal_kind  TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                decision        TEXT,
                rule_ids        TEXT NOT NULL DEFAULT '[]',
                policy_version  TEXT,
                executable      TEXT,
                argv_digest     TEXT,
                cwd_digest      TEXT,
                metadata        TEXT NOT NULL DEFAULT '{}',
                previous_hash   TEXT,
                recorded_at     TEXT NOT NULL
             );",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_journal_request ON journal (request_id, recorded_at);",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS approvals (
                approval_id   TEXT PRIMARY KEY,
                request_id    TEXT NOT NULL,
                scope         TEXT NOT NULL,
                decision      TEXT NOT NULL,
                approver_id   TEXT,
                expires_at    TEXT,
                created_at    TEXT NOT NULL
             );",
            [],
        )?;
        Ok(Self {
            conn,
            guard: Mutex::new(()),
        })
    }

    /// Append one event. The metadata string is checked against the
    /// builtin secret detector and, if a hit is found, replaced with a
    /// redacted form before it ever reaches the database.
    pub fn append(&self, ev: &JournalEvent) -> Result<(), rusqlite::Error> {
        let meta = secret::redact(&ev.metadata);
        let _g = self.guard.lock().unwrap();
        let rule_ids = serde_json::to_string(&ev.rule_ids).unwrap_or_else(|_| "[]".into());
        self.conn.execute(
            "INSERT INTO journal (
                event_id, request_id, principal_id, principal_kind, event_type,
                decision, rule_ids, policy_version, executable,
                argv_digest, cwd_digest, metadata, recorded_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                ev.event_id,
                ev.request_id,
                ev.principal_id,
                ev.principal_kind,
                ev.event_type,
                ev.decision,
                rule_ids,
                ev.policy_version,
                ev.executable,
                ev.argv_digest,
                ev.cwd_digest,
                meta,
                ev.recorded_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn record_approval(
        &self,
        request_id: &str,
        scope: &str,
        decision: &str,
        approver_id: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<String, rusqlite::Error> {
        let _g = self.guard.lock().unwrap();
        let id = Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO approvals (approval_id, request_id, scope, decision, approver_id, expires_at, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id,
                request_id,
                scope,
                decision,
                approver_id,
                expires_at.map(|t| t.to_rfc3339()),
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(id)
    }

    /// Chronological events for one request (audit replay).
    pub fn events_for_request(&self, request_id: &str) -> Result<Vec<JournalEvent>, rusqlite::Error> {
        let _g = self.guard.lock().unwrap();
        let mut stmt = self.conn.prepare(
            "SELECT event_id, request_id, principal_id, principal_kind, event_type,
                    decision, rule_ids, policy_version, executable,
                    argv_digest, cwd_digest, metadata, recorded_at
             FROM journal WHERE request_id = ?1 ORDER BY recorded_at, event_id",
        )?;
        let rows = stmt.query_map(params![request_id], |row| {
            let rule_ids: String = row.get(6)?;
            Ok(
                JournalEvent {
                    event_id: row.get(0)?,
                    request_id: row.get(1)?,
                    principal_id: row.get(2)?,
                    principal_kind: row.get(3)?,
                    event_type: row.get(4)?,
                    decision: row.get(5)?,
                    rule_ids: serde_json::from_str(&rule_ids).unwrap_or_default(),
                    policy_version: row.get(7)?,
                    executable: row.get(8)?,
                    argv_digest: row.get(9)?,
                    cwd_digest: row.get(10)?,
                    metadata: row.get(11)?,
                    recorded_at: DateTime::parse_from_rfc3339(&{
                        let s: String = row.get(12)?;
                        s
                    })
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                },
            )
        })?;
        rows.collect()
    }

    /// The most recent decision per request, paged (used by the CLI's
    /// `timeline` command and by the uploader's retry list).
    pub fn recent_decisions(
        &self,
        limit: i64,
    ) -> Result<Vec<(String, String, Option<String>, String)>, rusqlite::Error> {
        let _g = self.guard.lock().unwrap();
        let mut stmt = self.conn.prepare(
            "SELECT request_id, decision, policy_version, recorded_at
             FROM journal WHERE event_type = 'decision' ORDER BY recorded_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })?;
        rows.collect()
    }

    /// Approvals that are still in effect for a request (used by the
    /// approval re-check before a retry).
    pub fn active_approval(
        &self,
        request_id: &str,
        scope: &str,
    ) -> Result<bool, rusqlite::Error> {
        let _g = self.guard.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let row: Option<String> = self
            .conn
            .query_row(
                "SELECT approval_id FROM approvals
                 WHERE request_id = ?1 AND scope = ?2 AND decision = 'allow'
                   AND (expires_at IS NULL OR expires_at > ?3)
                 ORDER BY created_at DESC LIMIT 1",
                params![request_id, scope, now],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> JournalEvent {
        JournalEvent {
            event_id: Uuid::new_v4().to_string(),
            request_id: "r-1".into(),
            principal_id: "agent-x".into(),
            principal_kind: "agent".into(),
            event_type: "decision".into(),
            decision: Some("deny".into()),
            rule_ids: vec!["net-default-deny".into()],
            policy_version: Some("0.1.0".into()),
            executable: Some("curl".into()),
            argv_digest: Some("aa".into()),
            cwd_digest: Some("bb".into()),
            metadata: "{}".into(),
            recorded_at: Utc::now(),
        }
    }

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("j.db");
        let j = Journal::open(&db).unwrap();
        j.append(&sample()).unwrap();
        let evs = j.events_for_request("r-1").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].decision.as_deref(), Some("deny"));
        assert!(!j.recent_decisions(5).unwrap().is_empty());
    }

    #[test]
    fn secret_in_metadata_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("j2.db");
        let j = Journal::open(&db).unwrap();
        let mut ev = sample();
        ev.metadata = format!(
            "{{\"env\": {{\"AWS_KEY\": \"{}\"}}}}",
            "AKIAABCDEFGHIJKLMNOP"
        );
        j.append(&ev).unwrap();
        let evs = j.events_for_request("r-1").unwrap();
        let meta = evs[0].metadata.clone();
        assert!(!meta.contains("AKIA"));
        assert!(meta.contains("[redacted:aws-access-key:"));
        let _ = ev;
    }

    #[test]
    fn approval_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("j3.db");
        let j = Journal::open(&db).unwrap();
        j.record_approval("r-1", "exec:curl action:-s", "allow", "op-1", Some(Utc::now() + chrono::Duration::hours(1)))
            .unwrap();
        assert!(j.active_approval("r-1", "exec:curl action:-s").unwrap());
        assert!(!j.active_approval("r-1", "exec:other").unwrap());
    }
}
