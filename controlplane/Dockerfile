# RuntimeShield control plane (Go).
#
# Build from the product root (which is also the compose build context):
#   docker build -f controlplane/Dockerfile .
#
# Multi-stage: build with the Go toolchain matching controlplane/go.mod
# (go 1.22), ship the static binary on a non-root distroless base.

FROM golang:1.22 AS build
WORKDIR /src
# Context root = product root: copy just the Go module.
COPY controlplane/ ./
# No go.sum is committed in this repo yet (see deploy/NOTES-AND-GAPS.md,
# gap: go-sum): download modules to populate hashes, then build with
# -mod=mod so any missing indirect requirement also resolves.
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" \
    -o /out/controlplane ./cmd/controlplane

# --- final stage: minimal, non-root ------------------------------------------
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/controlplane /controlplane
# CA bundle so TLS (RUNSHIELD_TLS_CERT/KEY) and https peers can verify.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# The policy service loads the JSON schema from disk at startup
# (cmd/controlplane/main.go; RUNSHIELD_POLICY_SCHEMA is read there, default
# is CWD-relative) — ship it with the image.
COPY policies/schema/policy.schema.json /app/policies/schema/

# Defaults match controlplane/internal/config (config.FromEnv). Compose
# overrides what a deployment needs (RUNSHIELD_BACKEND/RUNSHIELD_PG_DSN and
# the key material).
ENV RUNSHIELD_HTTP_ADDR=:8080 \
    RUNSHIELD_LOG_LEVEL=info \
    RUNSHIELD_RATE_LIMIT_RPS=50 \
    RUNSHIELD_RATE_LIMIT_BURST=100 \
    RUNSHIELD_POLICY_SCHEMA=/app/policies/schema/policy.schema.json

WORKDIR /app
EXPOSE 8080
CMD ["/controlplane"]
