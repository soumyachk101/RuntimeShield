# RuntimeShield — Known Limitations

Every item below is true on disk as of this milestone (the web console landing).
Nothing here is hedged: each names the file, what it does, and what's missing.

## Control plane

1. **NATS is a no-op: `RUNSHIELD_NATS_URL` is read but unconsumed.**
   `controlplane/internal/config/config.go` loads `RUNSHIELD_NATS_URL` into
   `Config.NATSURL` (the only consumer), and `internal/events` documents a
   NATS JetStream path in its package header — but `Ingestor.Ingest` only
   persists to the DB and dedupes in memory. Nothing publishes to JetStream.
   So the `nats` service in `docker-compose.yml` (behind the `nats` profile,
   pinned to the moving `nats:latest` tag) is a *documented reference
   service*, not a live dependency. The default stack runs without it, on the
   agent's file-spool fallback.

2. **`POST /v1/events/batch` does not populate the audit-timeline tables it
   should.** The ingestor calls only `store.InsertEvent` (execution_events).
   `store.InsertDecision` and `store.InsertExecutionRequest` exist in
   `controlplane/internal/store/repo.go` but no API handler calls them — so
   `GET /v1/decisions` (the audit timeline) has no ingestion path that fills
   `policy_decisions` / `execution_requests` today. The console's Audit screen
   is fully wired to the real route; it will show its empty state until an
   ingest path lands (or the rows are seeded directly). This is the main
   open gap between "the audit API exists" and "the audit API has data."

3. **No `controlplane/go.sum` in the repo.** `go.mod` declares its requires
   but the lock file is not committed, so a plain `go build` fails outside
   the Dockerfile's `go mod download && go build -mod=mod` workaround.
   Commit `go.sum` to make local `go run ./cmd/controlplane` and reproducible
   image builds possible.

4. **Org provisioning is not implemented.** `GET /v1/organizations` returns
   an empty set (`orgsList` in `server.go` writes `{"items": []}`); there is
   no create-org route. `ListUsers` reads `users` rows, but no route upserts
   users. The console's Team-admin screen handles this honestly (empty states
   named), and the org id is a local scope in the top bar until
   provisioning lands (FR-08 is read-side today).

5. **Key material is intentionally unset in the default compose stack.**
   `RUNSHIELD_SIGN_KEY` / `RUNSHIELD_SESSION_KEY` are optional in dev (the
   control plane falls back to an ephemeral random key and logs that tokens
   won't survive a restart); mandatory in production. With no sign key,
   `POST /v1/devices/{id}/token` still works (ephemeral) but signatures
   change per boot — the restricted profile's signature verification
   (`RUNSHIELD_POLICY_KEY`) needs a stable key in any real deployment.

## Agent

6. **`exec` does not sandbox the child.** When a request is allowed,
   `main.rs` launches the process via structured argv, but the child
   inherits the host filesystem/network environment. See
   `docs/ENFORCEMENT-LIMITS.md` — the OS-enforced isolation layer
   (seccomp / landlock / gVisor / Firecracker per spec §5) is a later phase.

7. **Local and team approval stores are not reconciled.** The Rust agent
   records approvals in its own SQLite journal (`record_approval`); the
   control plane records them in the `approvals` table. There is no sync
   between the two — an approval granted in the console does not unblock a
   local `exec` on the device, and vice-versa. Both are correct, independently
   scoped, expiring exceptions; the product has not yet made one the source
   of truth for the other (spec §10 lists `POST /v1/approvals` and
   `POST /v1/approvals/{id}/decision` as the team path).

8. **Tamper-evident chaining of the local journal is planned, not done.**
   The journal is append-only at the application layer (SQLite WAL); the
   cryptographic hash-chain that would make it *tamper-evident* (spec §4.2
   "Audit integrity") is not implemented.

## Web console

9. **Binary font files are not vendored.** The console's self-hosted fonts
   come from the `@fontsource/geist-sans` / `@fontsource/geist-mono` npm
   packages (declared in `web/package.json`, imported in `web/src/main.tsx`);
   the `.woff2` bytes arrive via `npm install`, not from the repo. The system
   fallback stack is set in `web/src/styles/global.css`
   (`--rs-font-ui` / `--rs-font-mono`). No lockfile ships yet, so the web
   build is not reproducible until `package-lock.json` is committed.

10. **Operator identity is keyed, not SSO.** With `RUNSHIELD_OPERATOR_KEY`
    set, the control plane's operator routes verify a real short-lived
    operator token (HMAC, same scheme as device tokens) and 401 on
    failure; device routes verify the device token minted by
    `/v1/devices/{id}/token`, the first enrol being the documented
    bootstrap exception. Without the key (zero-config dev mode) the
    routes stay open and log a WARN per request, stamping responses
    with `X-RS-Dev-Mode: true`. There is still no SSO/session store:
    the console keeps the operator id in `localStorage`, and the token
    itself has to be issued by a holder of the key (no issuance route
    yet — mint tokens out-of-band). Real team auth is a later phase
    (spec §15 / Phase 4).

## Deployment

11. **The compose smoke test has not been run end-to-end in this repo.**
    `deploy/GUIDE.md` quotes the command
    (`docker compose up -d --build && curl -fsS http://localhost:8081/v1/healthz`)
    and the expected `{"status":"ok","backend":"postgres",…}` — it is
    documented, not claimed to pass, because item 3 above (no `go.sum`) and
    the missing web entry point (now landing) blocked it when that guide was
    written. `deploy/NOTES-AND-GAPS.md` is the authoritative, up-to-date
    packaging-gap list; read it before running Stage 1.

12. **`nats:latest` is a moving tag.** Pin the NATS image before promoting
    the `nats` profile to production (and item 1 applies until a publisher
    lands).
