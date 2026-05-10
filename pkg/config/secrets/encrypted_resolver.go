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

package secrets

import (
	"context"
	"log/slog"
	"strings"
)

const (
	// SchemeEncrypted is the URI scheme for AES-256-GCM encrypted config values.
	// Format: encrypted://base64url(nonce || ciphertext || tag)
	// The encryption key is the platform config-encryption key held in the KMS.
	SchemeEncrypted = "encrypted"

	// SchemeEncryptedPrefix is the simple prefix format "encrypted:"
	SchemeEncryptedPrefix = "encrypted:"

	// SchemeEncryptedURIPrefix is the URI format "encrypted://"
	SchemeEncryptedURIPrefix = "encrypted://"
)

// DecryptFunc performs AES-256-GCM decryption of the given ciphertext bytes.
// The ciphertext contains the nonce, encrypted data, and authentication tag
// as produced by the corresponding encrypt function. The implementation is
// provided by the KMS layer.
type DecryptFunc func(ctx context.Context, ciphertext []byte) ([]byte, error)

// EncryptedResolver decrypts encrypted:// config values using AES-256-GCM.
// The actual decryption is delegated to a caller-provided closure, keeping
// the resolver independent of the KMS implementation.
//
// The resolver supports secrets in two URI formats:
//   - encrypted:base64-encoded-ciphertext
//   - encrypted://base64-encoded-ciphertext
//
// The ciphertext is base64-decoded and passed to the decryptFn closure.
// The closure is expected to perform AES-256-GCM decryption using the
// platform config-encryption key.
//
// Thread-safety: This resolver is safe for concurrent use.
type EncryptedResolver struct {
	decryptFn DecryptFunc
	logger    *slog.Logger
}

// NewEncryptedResolver creates a new EncryptedResolver with the given
// decryption function and logger.
//
// The decryptFn should perform AES-256-GCM decryption using the platform
// config-encryption key from the KMS. For example:
//
//	decryptFn := func(ctx context.Context, ciphertext []byte) ([]byte, error) {
//	    return kms.DecryptAESGCM(ctx, configKeyID, ciphertext)
//	}
//	resolver := secrets.NewEncryptedResolver(decryptFn, logger)
//
// If logger is nil, a no-op logger is used.
func NewEncryptedResolver(decryptFn DecryptFunc, logger *slog.Logger) *EncryptedResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &EncryptedResolver{
		decryptFn: decryptFn,
		logger:    logger,
	}
}

// Scheme returns the URI scheme this resolver handles.
func (r *EncryptedResolver) Scheme() string {
	return SchemeEncrypted
}

// CanResolve returns true if the raw value can be resolved by this resolver.
// It checks for both "encrypted:" and "encrypted://" prefixes (case-insensitive).
func (r *EncryptedResolver) CanResolve(raw string) bool {
	if raw == "" {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, SchemeEncryptedPrefix) ||
		strings.HasPrefix(lower, SchemeEncryptedURIPrefix)
}

// Resolve decrypts the AES-256-GCM encrypted secret value.
//
// The raw value must be in the format:
//   - encrypted:base64-encoded-ciphertext
//   - encrypted://base64-encoded-ciphertext
//
// The ciphertext can be encoded using either standard base64 or URL-safe base64,
// with or without padding. The resolver tries all variants automatically.
//
// The context is checked for cancellation and deadline before and after decryption.
func (r *EncryptedResolver) Resolve(ctx context.Context, raw string) (*SecretValue, error) {
	// Check for nil decrypt function
	if r.decryptFn == nil {
		return nil, ErrEncryptedDecryptFailed{
			Cause: ErrDecrypterRequired{},
		}
	}

	// Check context before starting
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	// Validate input
	if !r.CanResolve(raw) {
		return nil, ErrEncryptedInvalidPayload{
			Reason: "does not match encrypted: or encrypted:// scheme",
		}
	}

	// Extract the base64-encoded ciphertext
	payloadB64 := extractEncryptedPayload(raw)
	if payloadB64 == "" {
		return nil, ErrEncryptedInvalidPayload{
			Reason: "empty payload after scheme prefix",
		}
	}

	// Decode base64 (try standard, URL-safe, raw, raw-URL)
	ciphertext, err := decodeBase64(payloadB64)
	if err != nil {
		return nil, ErrBase64DecodeFailed{Reason: err.Error()}
	}

	if len(ciphertext) == 0 {
		return nil, ErrEncryptedInvalidPayload{
			Reason: "empty ciphertext after base64 decode",
		}
	}

	// Check context before decryption
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	r.logger.Debug("decrypting config secret",
		slog.Int("ciphertext_len", len(ciphertext)),
	)

	// Decrypt using the caller-provided function
	plaintext, err := r.decryptFn(ctx, ciphertext)
	if err != nil {
		r.logger.Error("config secret decryption failed",
			slog.String("error", err.Error()),
		)
		return nil, ErrEncryptedDecryptFailed{Cause: err}
	}

	// Check context after decryption
	if err := checkContext(ctx); err != nil {
		// Clear plaintext on context error
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, err
	}

	r.logger.Debug("config secret decrypted successfully",
		slog.Int("plaintext_len", len(plaintext)),
	)

	return &SecretValue{
		Value:  plaintext,
		Source: SchemeEncrypted,
	}, nil
}

// extractEncryptedPayload removes the scheme prefix from the raw value.
func extractEncryptedPayload(raw string) string {
	lower := strings.ToLower(raw)

	// Check for URI format first (longer prefix)
	if strings.HasPrefix(lower, SchemeEncryptedURIPrefix) {
		return raw[len(SchemeEncryptedURIPrefix):]
	}

	// Check for simple prefix format
	if strings.HasPrefix(lower, SchemeEncryptedPrefix) {
		return raw[len(SchemeEncryptedPrefix):]
	}

	return ""
}
