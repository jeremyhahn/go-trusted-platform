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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log/slog"
	"strings"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// Compile-time check that IDevIDResolver implements quicbaassecret.SecretResolver.
var _ quicbaassecret.SecretResolver = (*IDevIDResolver)(nil)

const (
	// SchemeIDevID is the URI scheme for IDevID-encrypted secrets.
	SchemeIDevID = "idevid"

	// SchemePrefix is the simple prefix format "idevid:"
	SchemePrefix = "idevid:"

	// SchemeURIPrefix is the URI format "idevid://"
	SchemeURIPrefix = "idevid://"
)

// IDevIDResolver decrypts secrets that have been encrypted to a node's
// IDevID certificate. It implements the SecretResolver interface.
//
// The resolver supports secrets in two URI formats:
//   - idevid:base64-encoded-ciphertext
//   - idevid://base64-encoded-ciphertext
//
// The ciphertext is decrypted using RSA-OAEP with SHA-256 via the provided
// crypto.Decrypter interface. The decrypter is typically backed by the node's
// IDevID private key, which may be stored in a TPM or software XKMS.
//
// Thread-safety: This resolver is safe for concurrent use.
type IDevIDResolver struct {
	decrypter crypto.Decrypter
	logger    *slog.Logger
}

// NewIDevIDResolver creates a new IDevIDResolver with the given decrypter.
//
// The decrypter should be obtained from the platform's XKMS using the
// IDevID key attributes. For example:
//
//	decrypter, err := xkms.Decrypter(idevidAttrs)
//	if err != nil {
//	    return err
//	}
//	resolver := secrets.NewIDevIDResolver(decrypter)
//
// If logger is nil, a no-op logger is used.
func NewIDevIDResolver(decrypter crypto.Decrypter, logger *slog.Logger) *IDevIDResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &IDevIDResolver{
		decrypter: decrypter,
		logger:    logger,
	}
}

// Scheme returns the URI scheme this resolver handles.
func (r *IDevIDResolver) Scheme() string {
	return SchemeIDevID
}

// CanResolve returns true if the raw value can be resolved by this resolver.
// It checks for both "idevid:" and "idevid://" prefixes (case-insensitive).
func (r *IDevIDResolver) CanResolve(raw string) bool {
	if raw == "" {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, SchemePrefix) || strings.HasPrefix(lower, SchemeURIPrefix)
}

// Resolve decrypts the IDevID-encrypted secret value.
//
// The raw value must be in the format:
//   - idevid:base64-encoded-ciphertext
//   - idevid://base64-encoded-ciphertext
//
// The ciphertext can be encoded using either standard base64 or URL-safe base64.
// The resolver tries both encodings automatically.
//
// The context is checked for cancellation and deadline before and after decryption.
func (r *IDevIDResolver) Resolve(ctx context.Context, raw string) (*quicbaassecret.SecretValue, error) {
	// Check for nil decrypter
	if r.decrypter == nil {
		return nil, ErrDecrypterRequired{}
	}

	// Check context before starting
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	// Validate input
	if !r.CanResolve(raw) {
		return nil, ErrInvalidSecretFormat{
			Raw:    raw,
			Reason: "does not match idevid: or idevid:// scheme",
		}
	}

	// Extract the base64-encoded ciphertext
	ciphertextB64 := extractCiphertext(raw)
	if ciphertextB64 == "" {
		return nil, ErrInvalidSecretFormat{
			Raw:    raw,
			Reason: "empty ciphertext after scheme prefix",
		}
	}

	// Decode base64 (try both standard and URL-safe)
	ciphertext, err := decodeBase64(ciphertextB64)
	if err != nil {
		return nil, ErrBase64DecodeFailed{Reason: err.Error()}
	}

	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext{}
	}

	// Check context before decryption (which may be slow for TPM)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	r.logger.Debug("decrypting secret",
		slog.Int("ciphertext_len", len(ciphertext)),
	)

	// Decrypt using RSA-OAEP with SHA-256
	// The crypto.Decrypter interface handles the key-specific decryption
	plaintext, err := r.decrypt(ciphertext)
	if err != nil {
		r.logger.Error("decryption failed",
			slog.String("error", err.Error()),
		)
		return nil, ErrDecryptionFailed{Reason: err.Error()}
	}

	// Check context after decryption
	if err := checkContext(ctx); err != nil {
		// Clear plaintext on context error
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, err
	}

	r.logger.Debug("secret decrypted successfully",
		slog.Int("plaintext_len", len(plaintext)),
	)

	return quicbaassecret.NewSecretValue(raw, plaintext, quicbaassecret.StrategyLiteral), nil
}

// decrypt performs the actual decryption using the crypto.Decrypter interface.
// For RSA keys, it uses RSA-OAEP with SHA-256.
func (r *IDevIDResolver) decrypt(ciphertext []byte) ([]byte, error) {
	// Use RSA-OAEP with SHA-256 as the default decryption options
	// The crypto.Decrypter interface's Decrypt method signature is:
	// Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
	opts := &rsa.OAEPOptions{
		Hash: crypto.SHA256,
	}

	return r.decrypter.Decrypt(rand.Reader, ciphertext, opts)
}

// extractCiphertext removes the scheme prefix from the raw value.
func extractCiphertext(raw string) string {
	lower := strings.ToLower(raw)

	// Check for URI format first (longer prefix)
	if strings.HasPrefix(lower, SchemeURIPrefix) {
		return raw[len(SchemeURIPrefix):]
	}

	// Check for simple prefix format
	if strings.HasPrefix(lower, SchemePrefix) {
		return raw[len(SchemePrefix):]
	}

	return ""
}

// decodeBase64 attempts to decode the input using both standard and URL-safe base64.
// It tries standard base64 first, then URL-safe base64 on failure.
func decodeBase64(encoded string) ([]byte, error) {
	// Trim any whitespace
	encoded = strings.TrimSpace(encoded)

	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		return decoded, nil
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(encoded)
	if err == nil {
		return decoded, nil
	}

	// Try raw standard base64 (no padding)
	decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	if err == nil {
		return decoded, nil
	}

	// Try raw URL-safe base64 (no padding)
	decoded, err = base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

// checkContext checks if the context is canceled or deadline exceeded.
func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		if ctx.Err() == context.Canceled {
			return ErrContextCanceled{Reason: ctx.Err().Error()}
		}
		if ctx.Err() == context.DeadlineExceeded {
			return ErrContextDeadlineExceeded{Reason: ctx.Err().Error()}
		}
		return ErrContextCanceled{Reason: ctx.Err().Error()}
	default:
		return nil
	}
}
