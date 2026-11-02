# RuntimeShield Control Plane — API Reference

Base path `/v1`. Every non-2xx response is the single error envelope
`{"error":{"code","message"}}` — see the error-code table below.

## Authentication per class

| Class | What authenticates it | Dev mode (no `RUNSHIELD_OPERATOR_KEY`) |
|---|---|---|
| public | nothing (probes only) | nothing |
| device | short-lived **device token** from `POST /v1/devices/{id}/token`, sent as `Authorization: Bearer <tok>` | open; WARN logged; responses carry `X-RS-Dev-Mode: true` |
| operator | short-lived **operator token** (same HMAC scheme, `role=operator`), sent as `Authorization: Bearer <tok>` or `X-RS-Operator: <tok>` | open; WARN logged per request |

- The **bootstrapping exception**: the very first `POST /v1/devices/enrol`
  needs no credential — there is none to present yet. Once a device has a
  token, every other device-class call requires it. This is what enforces
  the spec §6 trust boundary: a compromised agent cannot forge a trusted
  audit identity because `POST /v1/events/batch` requires a valid device
  token.
- Dev mode is zero-config: with no operator key configured, all routes are
  open and clearly marked (`X-RS-Dev-Mode: true`, WARN logs). With a key
  set, open mode is off and 401 uses the error envelope.

## Rate limits per class

Per-client (remote address) token buckets; one bucket per class, so a
heartbeat burst cannot starve event ingestion. 429 responses carry
`Retry-After` plus the envelope. Per-class env knobs:
`RUNSHIELD_RATE_<CLASS>_RPS` / `RUNSHIELD_RATE_<CLASS>_BURST`.

| Class | Routes | Default RPS | Default burst | Env knob |
|---|---|---|---|---|
| `events` | `/v1/events/batch` | 50 | 100 | `RUNSHIELD_RATE_EVENTS_RPS` / `_BURST` |
| `enrol` | `/v1/devices/enrol` | 5 | 10 | `RUNSHIELD_RATE_ENROL_RPS` / `_BURST` |
| `heartbeat` | `/v1/devices/{id}/heartbeat` | 10 | 20 | `RUNSHIELD_RATE_HEARTBEAT_RPS` / `_BURST` |
| `device` | `/v1/devices/{id}/policy`, `/v1/devices/{id}/token`, `/v1/healthz`, `/v1/workspaces/{id}/executions` | 20 | 40 | `RUNSHIELD_RATE_DEVICE_RPS` / `_BURST` |
| `operator` | policies / organizations / users / devices / decisions / approvals | 10 | 20 | `RUNSHIELD_RATE_OPERATOR_RPS` / `_BURST` |

`/v1/ready` is not rate-limited (probe traffic).

## Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 401 | `err_unauthorized` | missing/invalid/expired token (keyed mode) |
| 403 | `err_forbidden` | authenticated but not allowed (reserved) |
| 404 | `err_not_found` | no such resource/route |
| 413 | `err_payload_too_large` | body over cap (batch: >1 MiB or >500 rows) |
| 429 | `err_rate_limited` | over class budget; see `Retry-After` |
| 400 | `err_invalid_request` | bad JSON, missing required fields/params |
| 409 | `err_conflict` | state conflict (reserved) |
| 500/503 | `err_internal` | unexpected failure / store not ready |

## Public (no auth)

### `GET /v1/healthz`
Liveness alias; `{"status":"ok"|"degraded",...}` — shape is stable, the
web topbar and compose smoke test depend on it.

### `GET /v1/ready`
Readiness probe: 503 until the store answers, 200 `{"status":"ready"}`
after. Use it for LB/gate traffic, not healthz.

## Device class (device token; enrol is the bootstrap exception)

### `POST /v1/devices/enrol`
Enrol a device (bootstrap: no credential required). Body:
`device_id` (req), `public_key` (req), `organization`, `platform`,
`agent_version`. 200 `{"status":"enrolled","device","org"}`.

### `POST /v1/devices/{id}/heartbeat`
Liveness touch for an enrolled device. 200 `{"status":"ok"}`; 404 if the
device is unknown.

### `GET /v1/devices/{id}/policy?organization=`
Latest published policy for the org, signed. 200 with `document` (may be
`null` when nothing is published yet — agent keeps its cache),
`signature`, `version`, `expires_in`.

### `POST /v1/devices/{id}/token?organization=`
Mint a short-lived device credential. Operator-gated in keyed mode.
200 `{"status":"issued","device","token","expires":"24h"}`.

### `POST /v1/events/batch`
Ingest an agent audit batch. Body: `{"events":[{...}]}` — capped at
**500 rows and 1 MiB** (413 `err_payload_too_large` beyond). Idempotency
via per-event `idempotency_key` or the `Idempotency-Key` header.
200 `{"accepted":N,"idempotency"}`. **Requires a valid device token in
keyed mode** (the §6 trust boundary).

### `GET /v1/workspaces/{id}/executions?limit=`
Execution records for a workspace, newest first. Device-class auth.
200 `{"workspace","limit","items"}`.

## Operator class (operator token in keyed mode)

### Policies
- `GET /v1/policies?organization=` — list versions. 200 `{"items"}`.
- `GET /v1/policies/schema` — the JSON schema (console validates locally).
- `GET /v1/policies/{id}` — one policy + parsed document; 404 envelope
  when missing.
- `POST /v1/policies` — create a draft (validated, signed). Body:
  `organization` (req) + `document` (req, the policy document; byte cap
  1 MiB). 400 on missing fields or schema failure. 200
  `{"status":"created","id","version","status_out":"draft"}`.
- `POST /v1/policies/{id}/publish` — 200 `{"status":"published","id"}`; 404 if unknown.
- `POST /v1/policies/{id}/rollback` — 200 `{"status":"rolled_back","id"}`; 404 if unknown.

### Teams
- `GET /v1/organizations` — list orgs (today: empty set; no provisioning
  route yet, see KNOWN-LIMITATIONS). 200 `{"items":[]}`.
- `GET /v1/users?organization=` — members of an org. 200 `{"items"}`.
- `GET /v1/devices?organization=` — enrolled devices. 200 `{"items"}`.

### Audit
- `GET /v1/decisions?device_id=&policy_version=&decision=&limit=` —
  audit timeline; `limit` default 200. 200 `{"items","limit"}`.

### Approvals
- `GET /v1/approvals?status=` — list; `status` ∈ pending|approved|denied|"".
- `POST /v1/approvals` — create a pending approval. Body: `request_id`
  (req), `scope` (req), `reason`. 200 `{"status":"pending","id",...}`.
- `POST /v1/approvals/{id}/decision` — decide. Body: `decision`
  (allow|deny), `reason`. 200 `{"status":"recorded","id","decision",...}`;
  404 when the id is unknown.

## Response headers (all responses)

`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`. CORS is
`*` in dev mode; otherwise the configured origin list
(`RUNSHIELD_CORS_ORIGINS`). Dev mode additionally stamps
`X-RS-Dev-Mode: true`.

## Examples (placeholders only — never commit real tokens)

```bash
# public probes
curl -s http://localhost:8080/v1/healthz
curl -s http://localhost:8080/v1/ready

# bootstrap enrol (no token needed)
curl -s -X POST http://localhost:8080/v1/devices/enrol \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"dev-1","public_key":"<pinned-key>","organization":"acme"}'

# mint a device token (operator token in keyed mode)
curl -s -X POST 'http://localhost:8080/v1/devices/dev-1/token?organization=acme' \
  -H "Authorization: Bearer $RS_OPERATOR_TOKEN"

# pull the policy with the device token
curl -s 'http://localhost:8080/v1/devices/dev-1/policy?organization=acme' \
  -H "Authorization: Bearer $RS_DEVICE_TOKEN"

# ingest an audit batch (device token required in keyed mode)
curl -s -X POST http://localhost:8080/v1/events/batch \
  -H "Authorization: Bearer $RS_DEVICE_TOKEN" \
  -H 'Idempotency-Key: batch-0001' \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"e-1","request_id":"r-1","event_type":"exec","decision":"deny","rule_ids":["net.egress"],"policy_version":"3","metadata_redacted":"…","recorded_at":"2026-01-01T00:00:00Z","idempotency_key":"k-1"}]}'

# operator console reads (operator token in keyed mode)
curl -s 'http://localhost:8080/v1/devices?organization=acme' \
  -H "Authorization: Bearer $RS_OPERATOR_TOKEN"
curl -s 'http://localhost:8080/v1/decisions?decision=deny&limit=100' \
  -H "Authorization: Bearer $RS_OPERATOR_TOKEN"
```
