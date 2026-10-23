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
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"
	"time"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// mockDecrypter implements crypto.Decrypter for testing.
type mockDecrypter struct {
	privateKey  *rsa.PrivateKey
	decryptFunc func(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

func (m *mockDecrypter) Public() crypto.PublicKey {
	if m.privateKey != nil {
		return &m.privateKey.PublicKey
	}
	return nil
}

func (m *mockDecrypter) Decrypt(randReader io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(randReader, msg, opts)
	}
	if m.privateKey != nil {
		return rsa.DecryptOAEP(sha256.New(), randReader, m.privateKey, msg, nil)
	}
	return nil, ErrDecryptionFailed{Reason: "no key or func configured"}
}

// newTestKeyPair generates an RSA key pair for testing.
func newTestKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

// encryptTestData encrypts data with the public key for testing.
func encryptTestData(t *testing.T, pubKey *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("failed to encrypt test data: %v", err)
	}
	return ciphertext
}

func TestNewIDevIDResolver(t *testing.T) {
	t.Run("with_decrypter_and_logger", func(t *testing.T) {
		key := newTestKeyPair(t)
		decrypter := &mockDecrypter{privateKey: key}
		logger := slog.Default()

		resolver := NewIDevIDResolver(decrypter, logger)

		if resolver == nil {
			t.Fatal("expected non-nil resolver")
		}
		if resolver.decrypter != decrypter {
			t.Error("decrypter not set correctly")
		}
		if resolver.logger != logger {
			t.Error("logger not set correctly")
		}
	})

	t.Run("with_nil_logger", func(t *testing.T) {
		key := newTestKeyPair(t)
		decrypter := &mockDecrypter{privateKey: key}

		resolver := NewIDevIDResolver(decrypter, nil)

		if resolver == nil {
			t.Fatal("expected non-nil resolver")
		}
		if resolver.logger == nil {
			t.Error("expected default logger to be set")
		}
	})

	t.Run("with_nil_decrypter", func(t *testing.T) {
		resolver := NewIDevIDResolver(nil, nil)

		if resolver == nil {
			t.Fatal("expected non-nil resolver")
		}
		// Should still create resolver, but Resolve will fail
	})
}

func TestIDevIDResolver_Scheme(t *testing.T) {
	resolver := NewIDevIDResolver(nil, nil)

	scheme := resolver.Scheme()

	if scheme != SchemeIDevID {
		t.Errorf("expected scheme %q, got %q", SchemeIDevID, scheme)
	}
}

func TestIDevIDResolver_CanResolve(t *testing.T) {
	resolver := NewIDevIDResolver(nil, nil)

	tests := []struct {
		name     string
		raw      string
		expected bool
	}{
		{
			name:     "simple_prefix",
			raw:      "idevid:SGVsbG8gV29ybGQ=",
			expected: true,
		},
		{
			name:     "uri_prefix",
			raw:      "idevid://SGVsbG8gV29ybGQ=",
			expected: true,
		},
		{
			name:     "uppercase_simple",
			raw:      "IDEVID:SGVsbG8gV29ybGQ=",
			expected: true,
		},
		{
			name:     "uppercase_uri",
			raw:      "IDEVID://SGVsbG8gV29ybGQ=",
			expected: true,
		},
		{
			name:     "mixed_case",
			raw:      "IDeViD:SGVsbG8gV29ybGQ=",
			expected: true,
		},
		{
			name:     "empty_string",
			raw:      "",
			expected: false,
		},
		{
			name:     "no_scheme",
			raw:      "SGVsbG8gV29ybGQ=",
			expected: false,
		},
		{
			name:     "wrong_scheme",
			raw:      "env:SECRET_KEY",
			expected: false,
		},
		{
			name:     "partial_match",
			raw:      "idevi:SGVsbG8gV29ybGQ=",
			expected: false,
		},
		{
			name:     "scheme_only_simple",
			raw:      "idevid:",
			expected: true,
		},
		{
			name:     "scheme_only_uri",
			raw:      "idevid://",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := resolver.CanResolve(tc.raw)
			if result != tc.expected {
				t.Errorf("CanResolve(%q) = %v, expected %v", tc.raw, result, tc.expected)
			}
		})
	}
}

func TestIDevIDResolver_Resolve_Success(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)
	ctx := context.Background()

	testCases := []struct {
		name      string
		plaintext string
		encoder   func([]byte) string
		prefix    string
	}{
		{
			name:      "standard_base64_simple_prefix",
			plaintext: "secret-password-123",
			encoder:   base64.StdEncoding.EncodeToString,
			prefix:    "idevid:",
		},
		{
			name:      "standard_base64_uri_prefix",
			plaintext: "database-connection-string",
			encoder:   base64.StdEncoding.EncodeToString,
			prefix:    "idevid://",
		},
		{
			name:      "urlsafe_base64_simple_prefix",
			plaintext: "api-key-with-special/chars+test",
			encoder:   base64.URLEncoding.EncodeToString,
			prefix:    "idevid:",
		},
		{
			name:      "urlsafe_base64_uri_prefix",
			plaintext: "token-with-newlines\nand\ttabs",
			encoder:   base64.URLEncoding.EncodeToString,
			prefix:    "idevid://",
		},
		{
			name:      "raw_standard_base64",
			plaintext: "no-padding-secret",
			encoder:   base64.RawStdEncoding.EncodeToString,
			prefix:    "idevid:",
		},
		{
			name:      "raw_urlsafe_base64",
			plaintext: "raw-urlsafe-secret",
			encoder:   base64.RawURLEncoding.EncodeToString,
			prefix:    "idevid://",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt the test plaintext
			ciphertext := encryptTestData(t, &key.PublicKey, []byte(tc.plaintext))

			// Encode the ciphertext
			encoded := tc.encoder(ciphertext)

			// Create the raw secret string
			raw := tc.prefix + encoded

			// Resolve the secret
			result, err := resolver.Resolve(ctx, raw)

			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if err := result.WithBytes(func(plaintext []byte) error {
				if string(plaintext) != tc.plaintext {
					t.Errorf("expected plaintext %q, got %q", tc.plaintext, plaintext)
				}
				return nil
			}); err != nil {
				t.Fatalf("WithBytes returned error: %v", err)
			}

			if result.Strategy != quicbaassecret.StrategyLiteral {
				t.Errorf("expected strategy %q, got %q", quicbaassecret.StrategyLiteral, result.Strategy)
			}

			// Verify Clear works
			result.Clear()
			if err := result.WithBytes(func(plaintext []byte) error {
				if plaintext != nil {
					t.Error("expected an empty plaintext after Clear()")
				}
				return nil
			}); err != nil {
				t.Fatalf("WithBytes returned error: %v", err)
			}
		})
	}
}

func TestIDevIDResolver_Resolve_NilDecrypter(t *testing.T) {
	resolver := NewIDevIDResolver(nil, nil)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "idevid:SGVsbG8=")

	if err == nil {
		t.Fatal("expected error for nil decrypter")
	}

	if _, ok := err.(ErrDecrypterRequired); !ok {
		t.Errorf("expected ErrDecrypterRequired, got %T: %v", err, err)
	}
}

func TestIDevIDResolver_Resolve_InvalidFormat(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "no_scheme",
			raw:  "SGVsbG8gV29ybGQ=",
		},
		{
			name: "wrong_scheme",
			raw:  "vault:secret/path",
		},
		{
			name: "empty_string",
			raw:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver.Resolve(ctx, tc.raw)

			if err == nil {
				t.Fatal("expected error for invalid format")
			}

			if _, ok := err.(ErrInvalidSecretFormat); !ok {
				t.Errorf("expected ErrInvalidSecretFormat, got %T: %v", err, err)
			}
		})
	}
}

func TestIDevIDResolver_Resolve_EmptyCiphertext(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "scheme_only_simple",
			raw:  "idevid:",
		},
		{
			name: "scheme_only_uri",
			raw:  "idevid://",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver.Resolve(ctx, tc.raw)

			if err == nil {
				t.Fatal("expected error for empty ciphertext")
			}

			if _, ok := err.(ErrInvalidSecretFormat); !ok {
				t.Errorf("expected ErrInvalidSecretFormat, got %T: %v", err, err)
			}
		})
	}
}

func TestIDevIDResolver_Resolve_InvalidBase64(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "invalid_characters",
			raw:  "idevid:!!!invalid!!!base64!!!",
		},
		{
			name: "invalid_padding",
			raw:  "idevid:SGVsbG8gV29ybGQ===",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver.Resolve(ctx, tc.raw)

			if err == nil {
				t.Fatal("expected error for invalid base64")
			}

			if _, ok := err.(ErrBase64DecodeFailed); !ok {
				t.Errorf("expected ErrBase64DecodeFailed, got %T: %v", err, err)
			}
		})
	}
}

func TestIDevIDResolver_Resolve_DecryptionFailed(t *testing.T) {
	key := newTestKeyPair(t)
	otherKey := newTestKeyPair(t)

	// Encrypt with one key, try to decrypt with another
	ciphertext := encryptTestData(t, &otherKey.PublicKey, []byte("secret"))
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "idevid:"+encoded)

	if err == nil {
		t.Fatal("expected error for decryption failure")
	}

	if _, ok := err.(ErrDecryptionFailed); !ok {
		t.Errorf("expected ErrDecryptionFailed, got %T: %v", err, err)
	}
}

func TestIDevIDResolver_Resolve_ContextCanceled(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ciphertext := encryptTestData(t, &key.PublicKey, []byte("secret"))
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	_, err := resolver.Resolve(ctx, "idevid:"+encoded)

	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if _, ok := err.(ErrContextCanceled); !ok {
		t.Errorf("expected ErrContextCanceled, got %T: %v", err, err)
	}
}

func TestIDevIDResolver_Resolve_ContextDeadlineExceeded(t *testing.T) {
	key := newTestKeyPair(t)
	decrypter := &mockDecrypter{privateKey: key}
	resolver := NewIDevIDResolver(decrypter, nil)

	// Create a context with an already-passed deadline
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	ciphertext := encryptTestData(t, &key.PublicKey, []byte("secret"))
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	_, err := resolver.Resolve(ctx, "idevid:"+encoded)

	if err == nil {
		t.Fatal("expected error for deadline exceeded")
	}

	if _, ok := err.(ErrContextDeadlineExceeded); !ok {
		t.Errorf("expected ErrContextDeadlineExceeded, got %T: %v", err, err)
	}
}

func TestSecretValue_Clear(t *testing.T) {
	t.Run("clears_bytes", func(t *testing.T) {
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte("secret-data"), quicbaassecret.StrategyLiteral)

		sv.Clear()

		if err := sv.WithBytes(func(plaintext []byte) error {
			if plaintext != nil {
				t.Error("expected an empty plaintext after Clear()")
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytes returned error: %v", err)
		}
	})

	t.Run("already_cleared", func(t *testing.T) {
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte("data"), quicbaassecret.StrategyLiteral)
		sv.Clear()
		// Second Clear must not panic
		sv.Clear()
	})
}

func TestSecretValue_Expired(t *testing.T) {
	t.Run("not_expired", func(t *testing.T) {
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte("secret"), quicbaassecret.StrategyLiteral)
		sv.ExpiresAt = time.Now().Add(time.Hour)

		if sv.Expired() {
			t.Error("expected not expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte("secret"), quicbaassecret.StrategyLiteral)
		sv.ExpiresAt = time.Now().Add(-time.Hour)

		if !sv.Expired() {
			t.Error("expected expired")
		}
	})

	t.Run("zero_expiry_never_expires", func(t *testing.T) {
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte("secret"), quicbaassecret.StrategyLiteral)

		if sv.Expired() {
			t.Error("expected not expired for zero expiry time")
		}
	})
}

// TestSecretValue_Plaintext covers the round trip a resolver depends on: the
// bytes handed to NewSecretValue are the bytes WithBytes yields back. The
// post-Clear half of this case lives in TestSecretValue_Clear/clears_bytes.
func TestSecretValue_Plaintext(t *testing.T) {
	t.Run("round_trips_plaintext", func(t *testing.T) {
		expected := "test-secret"
		sv := quicbaassecret.NewSecretValue("idevid://ref", []byte(expected), quicbaassecret.StrategyLiteral)

		if err := sv.WithBytes(func(plaintext []byte) error {
			if string(plaintext) != expected {
				t.Errorf("expected %q, got %q", expected, plaintext)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytes returned error: %v", err)
		}
	})
}

func TestExtractCiphertext(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "simple_prefix",
			raw:      "idevid:abc123",
			expected: "abc123",
		},
		{
			name:     "uri_prefix",
			raw:      "idevid://xyz789",
			expected: "xyz789",
		},
		{
			name:     "uppercase_simple",
			raw:      "IDEVID:ABC",
			expected: "ABC",
		},
		{
			name:     "uppercase_uri",
			raw:      "IDEVID://XYZ",
			expected: "XYZ",
		},
		{
			name:     "no_scheme",
			raw:      "just-data",
			expected: "",
		},
		{
			name:     "empty",
			raw:      "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCiphertext(tc.raw)
			if result != tc.expected {
				t.Errorf("extractCiphertext(%q) = %q, expected %q", tc.raw, result, tc.expected)
			}
		})
	}
}

func TestDecodeBase64(t *testing.T) {
	original := []byte("test data for encoding")

	tests := []struct {
		name    string
		encoder func([]byte) string
	}{
		{
			name:    "standard",
			encoder: base64.StdEncoding.EncodeToString,
		},
		{
			name:    "urlsafe",
			encoder: base64.URLEncoding.EncodeToString,
		},
		{
			name:    "raw_standard",
			encoder: base64.RawStdEncoding.EncodeToString,
		},
		{
			name:    "raw_urlsafe",
			encoder: base64.RawURLEncoding.EncodeToString,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.encoder(original)
			decoded, err := decodeBase64(encoded)

			if err != nil {
				t.Fatalf("decodeBase64 failed: %v", err)
			}

			if string(decoded) != string(original) {
				t.Errorf("expected %q, got %q", string(original), string(decoded))
			}
		})
	}

	t.Run("with_whitespace", func(t *testing.T) {
		encoded := "  " + base64.StdEncoding.EncodeToString(original) + "  "
		decoded, err := decodeBase64(encoded)

		if err != nil {
			t.Fatalf("decodeBase64 failed: %v", err)
		}

		if string(decoded) != string(original) {
			t.Errorf("expected %q, got %q", string(original), string(decoded))
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := decodeBase64("!!!not-valid-base64!!!")

		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}

func TestErrors(t *testing.T) {
	t.Run("ErrDecrypterRequired", func(t *testing.T) {
		err := ErrDecrypterRequired{}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
	})

	t.Run("ErrInvalidSecretFormat", func(t *testing.T) {
		err := ErrInvalidSecretFormat{Raw: "test", Reason: "bad format"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "test") || !contains(msg, "bad format") {
			t.Errorf("expected message to contain raw and reason, got %q", msg)
		}
	})

	t.Run("ErrBase64DecodeFailed", func(t *testing.T) {
		err := ErrBase64DecodeFailed{Reason: "invalid input"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "invalid input") {
			t.Errorf("expected message to contain reason, got %q", msg)
		}
	})

	t.Run("ErrDecryptionFailed", func(t *testing.T) {
		err := ErrDecryptionFailed{Reason: "key mismatch"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "key mismatch") {
			t.Errorf("expected message to contain reason, got %q", msg)
		}
	})

	t.Run("ErrContextCanceled", func(t *testing.T) {
		err := ErrContextCanceled{Reason: "user canceled"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "user canceled") {
			t.Errorf("expected message to contain reason, got %q", msg)
		}
	})

	t.Run("ErrContextDeadlineExceeded", func(t *testing.T) {
		err := ErrContextDeadlineExceeded{Reason: "timeout"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "timeout") {
			t.Errorf("expected message to contain reason, got %q", msg)
		}
	})

	t.Run("ErrEmptyCiphertext", func(t *testing.T) {
		err := ErrEmptyCiphertext{}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
	})

	t.Run("ErrUnsupportedKeyType", func(t *testing.T) {
		err := ErrUnsupportedKeyType{KeyType: "DSA"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "DSA") {
			t.Errorf("expected message to contain key type, got %q", msg)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
