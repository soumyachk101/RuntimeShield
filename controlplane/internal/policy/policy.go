// Package policy owns the control-plane's policy lifecycle:
// schema validation, signing, versioning, and distribution.
//
// Validation uses the embedded copy of the JSON schema that the Rust
// agent validates offline — a single source of truth, kept in sync by
// the (planned) schema-sync job. The schema is loaded from a
// file path so it can be swapped without a rebuild in tests.
package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Service validates, signs and stores policies.
type Service struct {
	compiler  *jsonschema.Compiler
	schema    *jsonschema.Schema
	signKey   []byte
	rawSchema []byte
}

// NewService builds a policy service. signKey may be nil (dev mode),
// in which case policies are stored unsigned.
func NewService(schemaPath string, signKey []byte) (*Service, error) {
	compiler := jsonschema.NewCompiler()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	doc := make(map[string]any)
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse schema JSON: %w", err)
	}
	if err := compiler.AddResource("urn:runshield:policy", doc); err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	s, err := compiler.Compile("urn:runshield:policy")
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return &Service{compiler: compiler, signKey: signKey, rawSchema: raw, schema: s}, nil
}

// Schema returns the raw policy JSON schema the service validates
// against, so the web editor can validate locally against the same
// source of truth the control plane uses.
func (s *Service) Schema() []byte { return s.rawSchema }

// Validate checks a policy document against the schema, returning the
// list of validation errors (empty = valid).
func (s *Service) Validate(doc json.RawMessage) []string {
	compiled := s.schema
	if compiled == nil {
		var err error
		compiled, err = s.compiler.Compile("urn:runshield:policy")
		if err != nil {
			return []string{fmt.Sprintf("schema compile: %v", err)}
		}
		s.schema = compiled
	}
	err := compiled.Validate(bytes.NewReader(doc))
	if err == nil {
		return nil
	}
	// Flatten the validation error text so the API can surface it.
	out := []string{err.Error()}
	if e, ok := err.(*jsonschema.ValidationError); ok && e.Err != nil {
		out = []string{e.Err.Error()}
	}
	return out
}

// Sign produces an HMAC-SHA256 signature over the canonical document.
// Returns the empty string in dev (nil key).
func (s *Service) Sign(doc json.RawMessage) string {
	if len(s.signKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.signKey)
	mac.Write(canonical(doc))
	return hex.EncodeToString(mac.Sum(nil))
}

// canonical is the byte sequence both the Go signer and the Rust
// verifier agree on. We take the document as it arrived and strip the
// top-level "signature" field so a fresh re-sign is byte-stable.
//
// NOTE: the Rust agent recomputes the digest over the raw stored
// document (with signature removed before caching). Both sides must
// apply the same transformation; this is the single point where the
// signing and verification implementations must stay in lockstep.
func canonical(doc json.RawMessage) []byte {
	var m map[string]any
	if json.Unmarshal(doc, &m) != nil {
		return doc
	}
	delete(m, "signature")
	out, err := json.Marshal(m)
	if err != nil {
		return doc
	}
	return out
}
