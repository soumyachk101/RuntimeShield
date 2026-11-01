package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testSchema = `{
  "type": "object",
  "required": ["version", "profile", "default_action"],
  "properties": {
    "version": { "const": 1 },
    "profile": { "type": "string", "minLength": 1 },
    "default_action": { "enum": ["allow", "deny", "require_approval", "audit_only"] }
  }
}`

func newSvc(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	path := writeTemp(t, dir, "schema.json", []byte(testSchema))
	s, err := NewService(path, []byte("test-sign-key"))
	require.NoError(t, err)
	return s
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func TestPolicyValidation(t *testing.T) {
	s := newSvc(t)

	valid := json.RawMessage(`{"version":1,"profile":"restricted","default_action":"deny"}`)
	require.Empty(t, s.Validate(valid), "a minimal valid policy must pass")

	invalid := json.RawMessage(`{"version":2,"profile":"x","default_action":"deny"}`)
	require.NotEmpty(t, s.Validate(invalid), "unsupported version must fail")

	missing := json.RawMessage(`{"profile":"x","default_action":"deny"}`)
	require.NotEmpty(t, s.Validate(missing), "missing required field must fail")
}

func TestPolicySigningRoundTrip(t *testing.T) {
	s := newSvc(t)
	doc := json.RawMessage(`{"version":1,"profile":"restricted","default_action":"deny"}`)
	sig := s.Sign(doc)
	require.NotEmpty(t, sig, "with a key, sign returns a signature")
	require.Len(t, sig, 64, "HMAC-SHA256 hex is 64 chars")

	// Deterministic: same document + same key -> same signature.
	require.Equal(t, sig, s.Sign(doc))

	// Changing the document changes the signature.
	other := json.RawMessage(`{"version":1,"profile":"restricted","default_action":"allow"}`)
	require.NotEqual(t, sig, s.Sign(other))
}

func TestPolicySigningNoKey(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "schema.json", []byte(testSchema))
	s, err := NewService(path, nil)
	require.NoError(t, err)
	doc := json.RawMessage(`{"version":1,"profile":"restricted","default_action":"deny"}`)
	require.Equal(t, "", s.Sign(doc), "no key -> empty signature (dev mode)")
}
