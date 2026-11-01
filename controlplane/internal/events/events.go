// Package events implements the audit-ingestion pipeline: accept
// batches from the agent's uploader, dedupe on the idempotency key,
// persist redacted events, and (optionally) fan out to NATS JetStream.
//
// Transport selection (spec §5: NATS JetStream; §8 "offline policy
// cache"):
//
//   - NATS configured (RUNSHIELD_NATS_URL): events are published to a
//     durable stream and a downstream worker consumes it. The DB row
//     records the delivery status.
//   - NATS not configured: events are persisted to the DB only. The
//     agent's file spool is the durable buffer; the control plane is
//     not a queue. This keeps development mode free of an external
//     service.
//
// Idempotency: the agent sends an `idempotency_key` per batch event.
// A replayed batch (same key within the TTL) is accepted but not
// re-persisted, so a crashed uploader cannot double-count.
package events

import (
	"context"
	"time"

	"runshield.dev/controlplane/internal/store"
)

// Event is one redacted audit record.
type Event struct {
	EventID          string   `json:"event_id"`
	RequestID        string   `json:"request_id"`
	EventType        string   `json:"event_type"`
	Decision         *string  `json:"decision,omitempty"`
	RuleIDs          []string `json:"rule_ids"`
	PolicyVersion    string   `json:"policy_version"`
	MetadataRedacted string   `json:"metadata_redacted"`
	RecordedAt       string   `json:"recorded_at"`
	IdempotencyKey   string   `json:"idempotency_key"`
}

// Batch is what the agent POSTs to /v1/events/batch.
type Batch struct {
	Events []Event `json:"events"`
}

// Ingestor persists event batches with a short in-memory dedupe set.
type Ingestor struct {
	dedupeTTL time.Duration
	seen      map[string]time.Time
	mu        chan struct{} // tiny mutex via channel
}

// NewIngestor builds an ingestor. The store is passed to Ingest so the
// dedupe check and the insert happen against the same backend.
func NewIngestor(dedupeTTL time.Duration) *Ingestor {
	if dedupeTTL <= 0 {
		dedupeTTL = 10 * time.Minute
	}
	return &Ingestor{dedupeTTL: dedupeTTL, seen: map[string]time.Time{}, mu: make(chan struct{}, 1)}
}

// Ingest persists a batch via the store, returning the count of new
// events. Duplicates (same idempotency key within the TTL) are
// skipped. The method is safe for concurrent callers.
func (i *Ingestor) Ingest(ctx context.Context, b Batch, st store.Store) error {
	i.mu <- struct{}{}
	defer func() { <-i.mu }()

	now := time.Now()
	for k, t := range i.seen {
		if now.Sub(t) > i.dedupeTTL {
			delete(i.seen, k)
		}
	}
	for _, ev := range b.Events {
		key := ev.IdempotencyKey
		if key == "" {
			key = ev.EventID
		}
		if t, ok := i.seen[key]; ok && now.Sub(t) <= i.dedupeTTL {
			continue
		}
		e := store.ExecEvent{
			ID:               ev.EventID,
			RequestID:        ev.RequestID,
			EventType:        ev.EventType,
			MetadataRedacted: ev.MetadataRedacted,
			Sequence:         0,
		}
		if err := st.InsertEvent(ctx, e); err != nil {
			return err
		}
		i.seen[key] = now
	}
	return nil
}
