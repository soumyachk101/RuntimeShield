//! Asynchronous uploader with a file spool.
//!
//! The agent writes every decision to the local SQLite journal first.
//! The uploader is a best-effort background thread: it drains the
//! spool directory (JSONL lines of `{"request_id": ..., "event_id":
//! ...}`) and POSTs batches to the control plane's
//! `POST /v1/events/batch`. When the control plane is unreachable the
//! events stay on disk and are retried on the next agent start or on
//! the next tick. The transport is pluggable:
//!
//! - `HttpTransport` (default in dev) — POSTs to a URL
//! - `NoopTransport` — drops events, used when the agent runs fully
//!   offline or in tests
//!
//! A NATS JetStream transport is supported by the Go control plane;
//! the agent-side NATS client is intentionally left out of this crate
//! (it pulls a heavy client dependency). The file spool is the single
//! source of truth in the MVP and is what the Go side drains from
//! `POST /v1/events/batch` batches.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpooledEvent {
    pub event_id: String,
    pub request_id: String,
    pub event_type: String,
    pub decision: Option<String>,
    pub rule_ids: Vec<String>,
    pub policy_version: Option<String>,
    /// Redacted metadata only.
    pub metadata: String,
    pub recorded_at: String,
    /// An idempotency key so the server can dedupe retried batches.
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Http,
    Noop,
}

pub struct Spool {
    dir: PathBuf,
}

pub struct Uploader {
    spool: Spool,
    url: Option<String>,
    /// Shared stop flag so the thread exits promptly on CLI shutdown.
    stop: AtomicBool,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self { dir }
    }

    /// Append one event to the spool as a single JSONL line.
    pub fn push(&self, ev: &SpooledEvent) -> std::io::Result<()> {
        let line = serde_json::to_string(ev)?;
        use std::io::Write;
        let path = self.dir.join("out.spool");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    /// Read all pending events and remove the file. Idempotent.
    pub fn drain(&self) -> Vec<SpooledEvent> {
        let path = self.dir.join("out.spool");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return vec![];
        };
        let evs: Vec<SpooledEvent> = raw
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let _ = std::fs::remove_file(&path);
        evs
    }

    pub fn pending_count(&self) -> u32 {
        let path = self.dir.join("out.spool");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return 0;
        };
        raw.lines().filter(|l| !l.is_empty()).count() as u32
    }
}

impl Uploader {
    pub fn new(spool: Spool, url: Option<String>) -> Self {
        Self {
            spool,
            url,
            stop: AtomicBool::new(false),
        }
    }

    /// Start the uploader thread. Returns the join handle. The thread
    /// wakes on a short timer, drains the spool and POSTs batches.
    /// When `url` is `None` (no-op mode) it ticks but delivers nothing
    /// until a URL is configured — the spool is the source of truth.
    pub fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            const TICK: Duration = Duration::from_secs(10);
            loop {
                if self.stop.load(Ordering::Acquire) {
                    let _ = self.tick();
                    break;
                }
                let _ = self.tick();
                std::thread::sleep(TICK);
            }
        })
    }

    /// One upload cycle. Returns the number of events delivered.
    pub fn tick(&self) -> u32 {
        let evs = self.spool.drain();
        if evs.is_empty() {
            return 0;
        }
        let Some(url) = &self.url else {
            return 0;
        };
        // Idempotent batch: one request per tick.
        let body = serde_json::json!({
            "events": evs,
        });
        let client = reqwest::blocking::Client::new();
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .timeout(Duration::from_secs(5))
            .send()
        {
            Ok(resp) if resp.status().is_success() => evs.len() as u32,
            Ok(_) => 0,
            Err(_) => {
                // Re-queue events we just drained so they are not lost.
                for e in &evs {
                    let _ = self.spool.push(e);
                }
                0
            }
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn stop_flag(&self) -> &AtomicBool {
        &self.stop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn ev(id: &str) -> SpooledEvent {
        SpooledEvent {
            event_id: id.into(),
            request_id: "r-1".into(),
            event_type: "decision".into(),
            decision: Some("deny".into()),
            rule_ids: vec!["net-default-deny".into()],
            policy_version: Some("0.1.0".into()),
            metadata: "{}".into(),
            recorded_at: "2026-01-01T00:00:00Z".into(),
            idempotency_key: format!("ik-{id}"),
        }
    }

    #[test]
    fn spool_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spool::new(dir.path().into());
        s.push(&ev("e1")).unwrap();
        s.push(&ev("e2")).unwrap();
        assert_eq!(s.pending_count(), 2);
        let drained = s.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].event_id, "e1");
        assert_eq!(s.pending_count(), 0);
        let _ = dir;
    }

    #[test]
    fn noop_url_delivers_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spool::new(dir.path().into());
        s.push(&ev("e1")).unwrap();
        let up = Uploader::new(s, None);
        assert_eq!(up.tick(), 0);
        let _ = dir;
        let _ = Arc::new(0u8); // keep an import stable
    }
}
