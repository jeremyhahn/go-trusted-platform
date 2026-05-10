// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package kms

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// =============================================================================
// Key requests / responses (SDK kms.Client)
// =============================================================================

// GenerateKeyRequest is the JSON body for POST /api/v1/kms/keys.
//
// Two shapes are accepted:
//
//  1. Flat: {"name": "k", "algorithm": "aes-256-gcm", "usage": [...]}
//  2. SDK: {"name": "k", "keySpec": {"algorithm": "AES_256", "usage": [...]}}
//
// The handler unifies them via Resolve() before dispatching to the
// downstream KMS service. The flat form is the original REST contract
// preserved by integration tests; the nested form matches the JS SDK's
// `kms.generateKey({keySpec: {...}, name})` call.
type GenerateKeyRequest struct {
	Name        string            `json:"name"`
	Algorithm   string            `json:"algorithm,omitempty"`
	Usage       []string          `json:"usage,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	KeySpec     *KMSKeySpec       `json:"keySpec,omitempty"`
}

// KMSKeySpec mirrors the JS SDK KMSKeySpec used in nested GenerateKey
// requests. Only Algorithm and Usage are honored; the remainder is kept
// for forwards compatibility with future SDK revisions.
type KMSKeySpec struct {
	Algorithm string   `json:"algorithm,omitempty"`
	Usage     []string `json:"usage,omitempty"`
	KeySize   int      `json:"keySize,omitempty"`
	Curve     string   `json:"curve,omitempty"`
}

// Resolve flattens the optional KeySpec nested envelope into top-level
// Algorithm/Usage so handlers can stay agnostic of the wire shape.
func (r *GenerateKeyRequest) Resolve() {
	if r.KeySpec == nil {
		return
	}
	if r.Algorithm == "" {
		r.Algorithm = r.KeySpec.Algorithm
	}
	if len(r.Usage) == 0 {
		r.Usage = r.KeySpec.Usage
	}
}

// GenerateKeyResponse is the response for key generation.
type GenerateKeyResponse struct {
	KeyID     string `json:"key_id"`
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
}

// ImportKeyRequest is the JSON body for POST /api/v1/kms/keys/import.
type ImportKeyRequest struct {
	KeyMaterial   []byte            `json:"key_material"`
	WrappingKeyID string            `json:"wrapping_key_id,omitempty"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Algorithm     string            `json:"algorithm"`
	Usage         []string          `json:"usage,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// ImportKeyResponse is the response from importing a key.
type ImportKeyResponse struct {
	KeyID     string `json:"key_id"`
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
}

// KeyInfoResponse describes a single key.
type KeyInfoResponse struct {
	KeyID     string    `json:"key_id"`
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	Version   int       `json:"version"`
	Usage     []string  `json:"usage,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

// ListKeysResponse is the response from listing keys.
type ListKeysResponse struct {
	Keys []KeyInfoResponse `json:"keys"`
}

// RotateKeyResponse is the response from key rotation.
type RotateKeyResponse struct {
	KeyID      string `json:"key_id"`
	NewVersion int    `json:"new_version"`
}

// UpdateKeyStatusRequest is the JSON body for PUT /api/v1/kms/keys/{name}/status.
type UpdateKeyStatusRequest struct {
	Status  string `json:"status"`
	Version int    `json:"version,omitempty"`
}

// UpdateKeyStatusResponse confirms a status change.
type UpdateKeyStatusResponse struct {
	KeyID   string `json:"key_id"`
	Version int    `json:"version"`
	Status  string `json:"status"`
}

// KeyVersionInfoResponse describes a single key version.
type KeyVersionInfoResponse struct {
	Version    int       `json:"version"`
	Status     string    `json:"status"`
	Algorithm  string    `json:"algorithm"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	DisabledAt time.Time `json:"disabled_at,omitempty"`
}

// ListKeyVersionsResponse is the response from listing versions.
type ListKeyVersionsResponse struct {
	Versions []KeyVersionInfoResponse `json:"versions"`
}

// =============================================================================
// Crypto requests / responses (SDK crypto.Client)
// =============================================================================

// EncryptRequest is the JSON body for POST /api/v1/kms/encrypt/{name}.
type EncryptRequest struct {
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
}

// EncryptResponse contains the ciphertext.
type EncryptResponse struct {
	KeyID      string `json:"key_id"`
	Version    int    `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
}

// DecryptRequest is the JSON body for POST /api/v1/kms/decrypt/{name}.
type DecryptRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Version    int    `json:"version,omitempty"`
}

// DecryptResponse contains the plaintext.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// SignRequest is the JSON body for POST /api/v1/kms/sign/{name}.
type SignRequest struct {
	Data    []byte `json:"data"`
	Hash    string `json:"hash,omitempty"`
	Version int    `json:"version,omitempty"`
}

// SignResponse contains the signature.
type SignResponse struct {
	KeyID     string `json:"key_id"`
	Version   int    `json:"version"`
	Signature []byte `json:"signature"`
}

// VerifyRequest is the JSON body for POST /api/v1/kms/verify/{name}.
type VerifyRequest struct {
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash,omitempty"`
	Version   int    `json:"version,omitempty"`
}

// VerifyResponse reports whether the signature is valid.
type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// HMACRequest is the JSON body for POST /api/v1/kms/hmac/{name}.
type HMACRequest struct {
	Data []byte `json:"data"`
	Hash string `json:"hash,omitempty"`
}

// HMACResponse contains an HMAC tag.
type HMACResponse struct {
	KeyID string `json:"key_id"`
	HMAC  []byte `json:"hmac"`
}

// VerifyHMACRequest is the JSON body for POST /api/v1/kms/hmac/{name}/verify.
type VerifyHMACRequest struct {
	Data []byte `json:"data"`
	HMAC []byte `json:"hmac"`
	Hash string `json:"hash,omitempty"`
}

// VerifyHMACResponse reports whether an HMAC matches.
type VerifyHMACResponse struct {
	Valid bool `json:"valid"`
}

// HashRequest is the JSON body for POST /api/v1/kms/hash.
type HashRequest struct {
	Data []byte `json:"data"`
	Hash string `json:"hash"`
}

// HashResponse contains the digest.
type HashResponse struct {
	Hash   string `json:"hash"`
	Digest []byte `json:"digest"`
}

// GenerateRandomRequest is the JSON body for POST /api/v1/kms/random.
type GenerateRandomRequest struct {
	NumBytes int `json:"num_bytes"`
}

// GenerateRandomResponse contains random bytes.
type GenerateRandomResponse struct {
	Bytes []byte `json:"bytes"`
}

// =============================================================================
// DEK requests / responses (SDK dek.Client)
// =============================================================================

// CreateDEKRequest is the JSON body for POST /api/v1/kms/deks.
type CreateDEKRequest struct {
	Path        string `json:"path"`
	Algorithm   string `json:"algorithm"`
	Description string `json:"description,omitempty"`
}

// CreateDEKResponse confirms creation.
type CreateDEKResponse struct {
	Path      string `json:"path"`
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
}

// DEKInfoResponse describes a single DEK.
type DEKInfoResponse struct {
	Path        string    `json:"path"`
	Algorithm   string    `json:"algorithm"`
	Version     int       `json:"version"`
	Status      string    `json:"status,omitempty"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	UsageCount  uint64    `json:"usage_count,omitempty"`
	BytesUsed   uint64    `json:"bytes_used,omitempty"`
	Description string    `json:"description,omitempty"`
	BackendType string    `json:"backend_type,omitempty"`
}

// ListDEKsResponse lists the available DEKs.
type ListDEKsResponse struct {
	DEKs []DEKInfoResponse `json:"deks"`
}

// RotateDEKResponse confirms a DEK rotation.
type RotateDEKResponse struct {
	Path       string `json:"path"`
	NewVersion int    `json:"new_version"`
}

// DEKStatusResponse summarises detailed DEK status.
type DEKStatusResponse struct {
	Path           string    `json:"path"`
	Algorithm      string    `json:"algorithm"`
	Version        int       `json:"version"`
	Status         string    `json:"status,omitempty"`
	IsDefault      bool      `json:"is_default"`
	UsageCount     uint64    `json:"usage_count"`
	BytesUsed      uint64    `json:"bytes_used"`
	MaxUsageCount  uint64    `json:"max_usage_count,omitempty"`
	MaxBytesUsed   uint64    `json:"max_bytes_used,omitempty"`
	WarningPercent int       `json:"warning_percent,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty"`
	RotatedAt      time.Time `json:"rotated_at,omitempty"`
}

// =============================================================================
// Secrets requests / responses (SDK secrets.Client)
// =============================================================================

// StoreSecretRequest is the JSON body for POST /api/v1/kms/secrets.
//
// Both REST integration tests and the WebUI form drive this endpoint.
// The legacy contract used `path` + base64-encoded `value`; the WebUI
// sends `name` + plain string `value`. Both are accepted: the handler
// promotes Name → Path when Path is empty, and Value is decoded as
// either base64 or a plain UTF-8 string via SecretValue.
type StoreSecretRequest struct {
	Path        string            `json:"path,omitempty"`
	Name        string            `json:"name,omitempty"`
	Value       SecretValue       `json:"value"`
	ContentType string            `json:"content_type,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// SecretValue accepts either a base64-encoded JSON string (legacy
// contract decoded by the standard library to []byte), or a plain UTF-8
// string posted by browser forms. Output marshals to a base64 string to
// preserve the original wire format on responses.
type SecretValue []byte

// UnmarshalJSON implements json.Unmarshaler. The standard library's
// []byte decoder requires base64; this override falls back to
// interpreting any decode failure as a plain string so the WebUI's
// `{"value": "sekret"}` payload works without forcing the form to
// base64-encode user input client-side.
func (v *SecretValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*v = nil
		return nil
	}
	// JSON strings start with a quote. If it's not a string, fall back
	// to the default []byte handling (base64 + array).
	if data[0] != '"' {
		var raw []byte
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		*v = raw
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		*v = decoded
		return nil
	}
	*v = []byte(s)
	return nil
}

// MarshalJSON implements json.Marshaler so the type round-trips
// identically to the legacy []byte field on responses.
func (v SecretValue) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	return json.Marshal([]byte(v))
}

// StoreSecretResponse confirms storage.
type StoreSecretResponse struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

// SecretResponse describes a stored secret.
type SecretResponse struct {
	Path        string            `json:"path"`
	Version     int               `json:"version"`
	Value       []byte            `json:"value,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

// SecretSummary is a list-view summary.
type SecretSummary struct {
	Path      string    `json:"path"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// ListSecretsResponse is the response from listing secrets.
type ListSecretsResponse struct {
	Secrets []SecretSummary `json:"secrets"`
}

// SecretVersionResponse describes a specific secret version.
type SecretVersionResponse struct {
	Path      string    `json:"path"`
	Version   int       `json:"version"`
	Value     []byte    `json:"value,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	Status    string    `json:"status,omitempty"`
}

// ListSecretVersionsResponse is the response from listing versions.
type ListSecretVersionsResponse struct {
	Versions []SecretVersionResponse `json:"versions"`
}

// RotateSecretRequest is the JSON body for POST /api/v1/kms/secrets/{name}/rotate.
type RotateSecretRequest struct {
	Value []byte `json:"value,omitempty"`
}

// RotateSecretResponse confirms rotation.
type RotateSecretResponse struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

// RollbackSecretRequest is the JSON body for POST /api/v1/kms/secrets/{name}/rollback.
type RollbackSecretRequest struct {
	Version int `json:"version"`
}

// RollbackSecretResponse confirms rollback.
type RollbackSecretResponse struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

// UpdateSecretStatusRequest is the JSON body for PUT /api/v1/kms/secrets/{name}/status.
type UpdateSecretStatusRequest struct {
	Enabled bool `json:"enabled"`
}

// RotationPolicyRequest is the JSON body for PUT /api/v1/kms/secrets/{name}/policy.
type RotationPolicyRequest struct {
	Enabled              bool   `json:"enabled"`
	IntervalSeconds      int64  `json:"interval_seconds,omitempty"`
	NextRotationUnixTime int64  `json:"next_rotation,omitempty"`
	Method               string `json:"method,omitempty"`
}

// RotationPolicyResponse describes a rotation policy.
type RotationPolicyResponse struct {
	Enabled              bool      `json:"enabled"`
	IntervalSeconds      int64     `json:"interval_seconds,omitempty"`
	NextRotationUnixTime int64     `json:"next_rotation,omitempty"`
	Method               string    `json:"method,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
}
