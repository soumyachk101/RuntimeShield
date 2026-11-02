// Package auth handles short-lived device credentials and operator
// sessions.
//
// Design (spec §10, §11 "control-plane token is stolen"):
//   - devices enrol with their public key and receive a short-lived
//     signing credential; every request from the device signs the
//     payload with it. The control plane re-checks the signature on
//     each request, so a stolen token cannot outlive its TTL.
//   - operators get session tokens; the session cookie is
//     HttpOnly + SameSite=Strict.
//   - all credentials are short-lived and scoped: a device token can
//     only fetch its own policy; an operator session is role-scoped.
//
// This is a reference implementation: in production the session store
// would be Postgres or Redis and device keys verified against the
// org's KMS.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Claims carried by a signed device token.
type DeviceClaims struct {
	DeviceID string `json:"device_id"`
	OrgID    string `json:"org_id"`
	Role     string `json:"role"` // "device" | "operator"
	Expires  int64  `json:"exp"`
}

// TokenIssuer signs and verifies device tokens with the org signing
// key (RUNSHIELD_SIGN_KEY).
type TokenIssuer struct {
	key []byte
	ttl time.Duration
}

func NewTokenIssuer(key []byte, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{key: key, ttl: ttl}
}

// Issue creates a short-lived token for a device.
func (t *TokenIssuer) Issue(c DeviceClaims) (string, error) {
	c.Expires = time.Now().Add(t.ttl).Unix()
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(payload) + "." + hex.EncodeToString(t.sign(payload)), nil
}

// Verify checks a token and returns its claims.
func (t *TokenIssuer) Verify(token string) (*DeviceClaims, bool) {
	idx := strings.IndexByte(token, '.')
	if idx < 0 {
		return nil, false
	}
	payload, err := hex.DecodeString(token[:idx])
	if err != nil {
		return nil, false
	}
	sig, err := hex.DecodeString(token[idx+1:])
	if err != nil {
		return nil, false
	}
	if !hmac.Equal(t.sign(payload), sig) {
		return nil, false
	}
	var c DeviceClaims
	if json.Unmarshal(payload, &c) != nil {
		return nil, false
	}
	if c.Expires < time.Now().Unix() {
		return nil, false
	}
	return &c, true
}

func (t *TokenIssuer) sign(payload []byte) []byte {
	h := hmac.New(sha256.New, t.key)
	h.Write(payload)
	return h.Sum(nil)
}

// RequireDevice verifies a bearer token and forwards the identity as
// X-RS-* headers to the wrapped handler.
func RequireDevice(issuer *TokenIssuer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := stripBearer(r.Header.Get("Authorization"))
		claims, ok := issuer.Verify(tok)
		if !ok {
			httpError(w, http.StatusUnauthorized, "invalid or expired device token")
			return
		}
		r.Header.Set("X-RS-Device", claims.DeviceID)
		r.Header.Set("X-RS-Org", claims.OrgID)
		next(w, r)
	}
}

func stripBearer(v string) string {
	if len(v) > 7 && v[:7] == "Bearer " {
		return v[7:]
	}
	return v
}

// --- operator tokens --------------------------------------------------------
//
// Operator sessions use the SAME signing scheme as device tokens
// (HMAC-SHA256, short-lived, constant-time signature compare, expiry check)
// keyed on the RUNSHIELD_OPERATOR_KEY, so one implementation covers both
// credential classes. The operator role is stamped into the claims so a
// device token can never be replayed on an operator endpoint: VerifyOperator
// rejects any token whose role is not "operator".
//
// Dev mode: when the operator key is not configured (config default), the
// api layer keeps today's open behaviour and logs a WARN per unauthenticated
// request. When the key IS set, open mode is off and unauthenticated
// requests get 401 with the shared error envelope.

// OperatorVerifier verifies short-lived operator tokens.
type OperatorVerifier struct {
	issuer *TokenIssuer
}

// NewOperatorVerifier builds a verifier from the operator signing key
// (RUNSHIELD_OPERATOR_KEY) with the given token TTL.
func NewOperatorVerifier(key []byte, ttl time.Duration) *OperatorVerifier {
	return &OperatorVerifier{issuer: NewTokenIssuer(key, ttl)}}

// Issue signs an operator token for the given identity.
func (v *OperatorVerifier) Issue(operatorID string) (string, error) {
	if operatorID == "" {
		return "", fmt.Errorf("operator id required")
	}
	return v.issuer.Issue(DeviceClaims{DeviceID: operatorID, Role: "operator"})
}

// Verify checks a token: format, signature (constant-time), expiry, and
// role. A device token (role "device") never verifies here.
func (v *OperatorVerifier) Verify(token string) (*DeviceClaims, bool) {
	c, ok := v.issuer.Verify(token)
	if !ok || c == nil || c.Role != "operator" {
		return nil, false
	}
	return c, true
}

// DeviceVerifier verifies short-lived device tokens issued by
// /v1/devices/{id}/token (spec §10 "short-lived device credentials"). The
// same HMAC scheme as TokenIssuer; the device role is checked so an
// operator token cannot call device endpoints.
type DeviceVerifier struct {
	issuer *TokenIssuer
}

// NewDeviceVerifier builds a device-token verifier from the signing key.
func NewDeviceVerifier(key []byte, ttl time.Duration) *DeviceVerifier {
	return &DeviceVerifier{issuer: NewTokenIssuer(key, ttl)}
}

// Verify returns the claims; role must be "device".
func (v *DeviceVerifier) Verify(token string) (*DeviceClaims, bool) {
	c, ok := v.issuer.Verify(token)
	if !ok || c == nil || c.Role != "device" {
		return nil, false
	}
	return c, true
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
