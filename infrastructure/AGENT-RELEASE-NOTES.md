# RuntimeShield — Agent Release & Packaging Notes

The Rust `runshield` agent (`rust/crates/agent`, binary name `runshield`,
workspace `runtime-shield-agent`) is **not containerised, by design**.

## Why no Dockerfile for the agent

The spec's trust boundary (01-RuntimeShield.md §6, "Trust boundaries") makes
the local agent the *trusted enforcement component* that sits **inside the
sandbox / on the host**, adjacent to the workload it guards. Three reasons keep
it out of a container image:

1. **Local enforcement must not run behind a container boundary.** The whole
   point of the agent is to evaluate and, when allowed, *launch* structured
   processes on the developer's machine with their real filesystem, network and
   environment. A containerised "agent" could not observe or gate the host
   processes it is supposed to protect; the security-critical path has to stay
   on the host (spec §5, "Important architecture decision": do not place the
   enforcement path inside a web UI / LLM / container service).
2. **It writes to per-user host state** (`$RUNSHIELD_DATA_DIR` /
   `~/.runshield`) — a SQLite journal, a policy-cache file pair and a spool
   directory (see "Expected binary layout on the host" below). Those belong to
   the invoking user, not to an image.
3. **Distribution is signed, not pushed as an image.** Spec §5 "Packaging":
   *signed binaries, Homebrew, apt/deb; later winget/MSI*. The agent is
   versioned and shipped as a signed local binary so that (a) installers can be
   authenticated, (b) the `restricted` profile can verify policy signatures
   against `RUNSHIELD_POLICY_KEY`, and (c) an attacker who can push a container
   image cannot silently replace the enforcement binary.

So this file documents distribution; there is deliberately **no `Dockerfile`
for the agent**. The only containerised components are the Go control plane
(`controlplane/Dockerfile`) and the web console front (`web/Dockerfile`),
stitched together in `docker-compose.yml`.

## Distribution channels (spec §5 "Packaging")

- **Signed local binary** — the primary channel. `cargo build --release`
  produces `target/release/runshield` (single, statically linked,
  `strip = "symbols"` per `rust/Cargo.toml` release profile; `rusqlite` is the
  bundled SQLite so no external C library is required at runtime).
- **Homebrew** (macOS) — a tap formula wrapping the signed release tarball.
- **apt/deb** (Linux) — a signed `.deb` placing the binary in `/usr/local/bin`.
- **winget / MSI** (Windows) — later; out of scope for the current release.

Every release is signed (GPG/shasum) so installers and the agent's own
signature verification can authenticate it.

## Expected binary layout on the host

Per user, under `$RUNSHIELD_DATA_DIR` (default `~/.runshield`; override with
`--data-dir` or the env var):

```
~/.runshield/
├── journal.db            # SQLite audit journal (WAL mode; append-only app-level)
├── policy_cache.doc.json # last signed policy document (0600, atomic-written)
├── policy_cache.meta.json# version label, signature, expiry, written_by
└── spool/                # offline event spool (JSONL lines, drained by upload)
    ├── *.jsonl
    └── .*.tmp
```

The binary itself lands on `$PATH` (`/usr/local/bin/runshield` on
deb/mac, `~/Library/…` or the homebrew prefix on Homebrew). Runtime env vars the
agent reads (`rust/crates/agent/src/main.rs`):

- `RUNSHIELD_CONTROL_PLANE` — control-plane base URL (policy pull / event upload)
- `RUNSHIELD_DATA_DIR` — the data directory above (default `~/.runshield`)
- `RUNSHIELD_POLICY_KEY` — hex key material for verifying policy signatures

These are the *agent-side* vars; the control-plane-side vars are documented in
`controlplane/.env.example` and wired in `docker-compose.yml`.

## What is NOT covered here

- Containerised control plane / web front → see `docker-compose.yml`,
  `controlplane/Dockerfile`, `web/Dockerfile`, `deploy/GUIDE.md`.
- NATS JetStream is a control-plane transport concern, not an agent one; the
  agent uploads to the control plane over `POST /v1/events/batch` and keeps the
  file spool as its durable offline buffer (spool.rs).
