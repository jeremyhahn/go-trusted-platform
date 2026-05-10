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
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// mockEncryptDecrypt provides symmetric encrypt/decrypt for testing.
// It simply XORs with a fixed key byte for reversibility.
type mockEncryptDecrypt struct {
	key       byte
	encryptFn func(ctx context.Context, plaintext []byte) ([]byte, error)
	decryptFn func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func newMockEncryptDecrypt() *mockEncryptDecrypt {
	m := &mockEncryptDecrypt{key: 0x42}
	m.encryptFn = func(ctx context.Context, plaintext []byte) ([]byte, error) {
		result := make([]byte, len(plaintext))
		for i, b := range plaintext {
			result[i] = b ^ m.key
		}
		return result, nil
	}
	m.decryptFn = func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		result := make([]byte, len(ciphertext))
		for i, b := range ciphertext {
			result[i] = b ^ m.key
		}
		return result, nil
	}
	return m
}

func TestEncryptedResolver_Scheme(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)

	scheme := resolver.Scheme()

	if scheme != SchemeEncrypted {
		t.Errorf("expected scheme %q, got %q", SchemeEncrypted, scheme)
	}
}

func TestEncryptedResolver_CanResolve(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)

	tests := []struct {
		name     string
		raw      string
		expected bool
	}{
		{
			name:     "simple_prefix",
			raw:      "encrypted:SGVsbG8gV29ybGQ",
			expected: true,
		},
		{
			name:     "uri_prefix",
			raw:      "encrypted://SGVsbG8gV29ybGQ",
			expected: true,
		},
		{
			name:     "uppercase_simple",
			raw:      "ENCRYPTED:SGVsbG8gV29ybGQ",
			expected: true,
		},
		{
			name:     "uppercase_uri",
			raw:      "ENCRYPTED://SGVsbG8gV29ybGQ",
			expected: true,
		},
		{
			name:     "mixed_case",
			raw:      "EnCrYpTeD:SGVsbG8gV29ybGQ",
			expected: true,
		},
		{
			name:     "empty_string",
			raw:      "",
			expected: false,
		},
		{
			name:     "no_scheme",
			raw:      "SGVsbG8gV29ybGQ",
			expected: false,
		},
		{
			name:     "idevid_scheme",
			raw:      "idevid://SGVsbG8gV29ybGQ",
			expected: false,
		},
		{
			name:     "kms_scheme",
			raw:      "kms://some/path",
			expected: false,
		},
		{
			name:     "scheme_only_simple",
			raw:      "encrypted:",
			expected: true,
		},
		{
			name:     "scheme_only_uri",
			raw:      "encrypted://",
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

func TestEncryptedResolver_Resolve_Success(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)
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
			prefix:    "encrypted:",
		},
		{
			name:      "standard_base64_uri_prefix",
			plaintext: "database-connection-string",
			encoder:   base64.StdEncoding.EncodeToString,
			prefix:    "encrypted://",
		},
		{
			name:      "urlsafe_base64_simple_prefix",
			plaintext: "api-key-with-special/chars+test",
			encoder:   base64.URLEncoding.EncodeToString,
			prefix:    "encrypted:",
		},
		{
			name:      "urlsafe_base64_uri_prefix",
			plaintext: "token-with-newlines\nand\ttabs",
			encoder:   base64.URLEncoding.EncodeToString,
			prefix:    "encrypted://",
		},
		{
			name:      "raw_standard_base64",
			plaintext: "no-padding-secret",
			encoder:   base64.RawStdEncoding.EncodeToString,
			prefix:    "encrypted:",
		},
		{
			name:      "raw_urlsafe_base64",
			plaintext: "raw-urlsafe-secret",
			encoder:   base64.RawURLEncoding.EncodeToString,
			prefix:    "encrypted://",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt the test plaintext using mock
			ciphertext, err := mock.encryptFn(ctx, []byte(tc.plaintext))
			if err != nil {
				t.Fatalf("mock encrypt failed: %v", err)
			}

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

			if string(result.Value) != tc.plaintext {
				t.Errorf("expected plaintext %q, got %q", tc.plaintext, string(result.Value))
			}

			if result.Source != SchemeEncrypted {
				t.Errorf("expected source %q, got %q", SchemeEncrypted, result.Source)
			}

			// Verify Clear works
			result.Clear()
			if result.Value != nil {
				t.Error("expected Value to be nil after Clear()")
			}
		})
	}
}

func TestEncryptedResolver_Resolve_InvalidBase64(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "invalid_characters",
			raw:  "encrypted:!!!invalid!!!base64!!!",
		},
		{
			name: "invalid_padding",
			raw:  "encrypted:SGVsbG8gV29ybGQ===",
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

func TestEncryptedResolver_Resolve_DecryptError(t *testing.T) {
	decryptErr := errors.New("aes-gcm: authentication failed")
	failingDecrypt := func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return nil, decryptErr
	}
	resolver := NewEncryptedResolver(failingDecrypt, nil)
	ctx := context.Background()

	// Valid base64 payload
	payload := base64.RawURLEncoding.EncodeToString([]byte("some-ciphertext-data"))
	raw := "encrypted://" + payload

	_, err := resolver.Resolve(ctx, raw)

	if err == nil {
		t.Fatal("expected error for decrypt failure")
	}

	var decryptFailed ErrEncryptedDecryptFailed
	if !errors.As(err, &decryptFailed) {
		t.Errorf("expected ErrEncryptedDecryptFailed, got %T: %v", err, err)
	}

	if !errors.Is(decryptFailed.Cause, decryptErr) {
		t.Errorf("expected cause to be original error, got %v", decryptFailed.Cause)
	}
}

func TestEncryptedResolver_Resolve_EmptyPayload(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "scheme_only_simple",
			raw:  "encrypted:",
		},
		{
			name: "scheme_only_uri",
			raw:  "encrypted://",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver.Resolve(ctx, tc.raw)

			if err == nil {
				t.Fatal("expected error for empty payload")
			}

			if _, ok := err.(ErrEncryptedInvalidPayload); !ok {
				t.Errorf("expected ErrEncryptedInvalidPayload, got %T: %v", err, err)
			}
		})
	}
}

func TestEncryptedResolver_Resolve_ContextCanceled(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Valid encrypted payload
	ciphertext, err := mock.encryptFn(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatalf("mock encrypt failed: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	raw := "encrypted://" + encoded

	_, err = resolver.Resolve(ctx, raw)

	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if _, ok := err.(ErrContextCanceled); !ok {
		t.Errorf("expected ErrContextCanceled, got %T: %v", err, err)
	}
}

func TestEncryptedResolver_Resolve_ContextDeadlineExceeded(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	ciphertext, err := mock.encryptFn(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatalf("mock encrypt failed: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	raw := "encrypted://" + encoded

	_, err = resolver.Resolve(ctx, raw)

	if err == nil {
		t.Fatal("expected error for deadline exceeded")
	}

	if _, ok := err.(ErrContextDeadlineExceeded); !ok {
		t.Errorf("expected ErrContextDeadlineExceeded, got %T: %v", err, err)
	}
}

func TestEncryptedResolver_Resolve_NilDecryptFn(t *testing.T) {
	resolver := NewEncryptedResolver(nil, nil)
	ctx := context.Background()

	payload := base64.RawURLEncoding.EncodeToString([]byte("data"))
	_, err := resolver.Resolve(ctx, "encrypted://"+payload)

	if err == nil {
		t.Fatal("expected error for nil decrypt function")
	}

	var decryptFailed ErrEncryptedDecryptFailed
	if !errors.As(err, &decryptFailed) {
		t.Errorf("expected ErrEncryptedDecryptFailed, got %T: %v", err, err)
	}
}

func TestEncryptedResolver_Resolve_InvalidScheme(t *testing.T) {
	mock := newMockEncryptDecrypt()
	resolver := NewEncryptedResolver(mock.decryptFn, nil)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "idevid://SGVsbG8")

	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}

	if _, ok := err.(ErrEncryptedInvalidPayload); !ok {
		t.Errorf("expected ErrEncryptedInvalidPayload, got %T: %v", err, err)
	}
}

func TestEncryptedResolver_NewWithLogger(t *testing.T) {
	t.Run("with_logger", func(t *testing.T) {
		mock := newMockEncryptDecrypt()
		logger := slog.Default()
		resolver := NewEncryptedResolver(mock.decryptFn, logger)

		if resolver == nil {
			t.Fatal("expected non-nil resolver")
		}
		if resolver.logger != logger {
			t.Error("logger not set correctly")
		}
	})

	t.Run("nil_logger_uses_discard", func(t *testing.T) {
		mock := newMockEncryptDecrypt()
		resolver := NewEncryptedResolver(mock.decryptFn, nil)

		if resolver == nil {
			t.Fatal("expected non-nil resolver")
		}
		if resolver.logger == nil {
			t.Error("expected default logger to be set")
		}
	})
}

func TestEncrypt_Success(t *testing.T) {
	mock := newMockEncryptDecrypt()
	ctx := context.Background()

	plaintext := []byte("my-secret-config-value")

	// Encrypt
	uri, err := Encrypt(ctx, plaintext, mock.encryptFn)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify URI format
	if len(uri) <= len(SchemeEncryptedURIPrefix) {
		t.Fatalf("URI too short: %q", uri)
	}
	if uri[:len(SchemeEncryptedURIPrefix)] != SchemeEncryptedURIPrefix {
		t.Errorf("expected prefix %q, got %q", SchemeEncryptedURIPrefix, uri[:len(SchemeEncryptedURIPrefix)])
	}

	// Round-trip: resolve the encrypted URI
	resolver := NewEncryptedResolver(mock.decryptFn, nil)
	result, err := resolver.Resolve(ctx, uri)
	if err != nil {
		t.Fatalf("Resolve failed on round-trip: %v", err)
	}

	if string(result.Value) != string(plaintext) {
		t.Errorf("round-trip failed: expected %q, got %q", string(plaintext), string(result.Value))
	}
}

func TestEncrypt_EncryptFnError(t *testing.T) {
	encryptErr := errors.New("kms: key not found")
	failingEncrypt := func(ctx context.Context, plaintext []byte) ([]byte, error) {
		return nil, encryptErr
	}
	ctx := context.Background()

	_, err := Encrypt(ctx, []byte("plaintext"), failingEncrypt)

	if err == nil {
		t.Fatal("expected error for encrypt failure")
	}

	var encFailed ErrEncryptFailed
	if !errors.As(err, &encFailed) {
		t.Errorf("expected ErrEncryptFailed, got %T: %v", err, err)
	}

	if !errors.Is(encFailed.Cause, encryptErr) {
		t.Errorf("expected cause to be original error, got %v", encFailed.Cause)
	}
}

func TestEncrypt_NilEncryptFn(t *testing.T) {
	ctx := context.Background()

	_, err := Encrypt(ctx, []byte("plaintext"), nil)

	if err == nil {
		t.Fatal("expected error for nil encrypt function")
	}

	var encFailed ErrEncryptFailed
	if !errors.As(err, &encFailed) {
		t.Errorf("expected ErrEncryptFailed, got %T: %v", err, err)
	}
}

func TestEncrypt_ContextCanceled(t *testing.T) {
	mock := newMockEncryptDecrypt()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Encrypt(ctx, []byte("plaintext"), mock.encryptFn)

	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if _, ok := err.(ErrContextCanceled); !ok {
		t.Errorf("expected ErrContextCanceled, got %T: %v", err, err)
	}
}

func TestEncryptedErrors(t *testing.T) {
	t.Run("ErrEncryptedDecryptFailed", func(t *testing.T) {
		cause := errors.New("test cause")
		err := ErrEncryptedDecryptFailed{Cause: cause}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !containsAt(msg, "decrypt failed", 0) && !contains(msg, "decrypt failed") {
			t.Errorf("expected message to contain 'decrypt failed', got %q", msg)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap did not return cause")
		}
	})

	t.Run("ErrEncryptedInvalidPayload", func(t *testing.T) {
		err := ErrEncryptedInvalidPayload{Reason: "empty"}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "empty") {
			t.Errorf("expected message to contain reason, got %q", msg)
		}
	})

	t.Run("ErrEncryptFailed", func(t *testing.T) {
		cause := errors.New("kms error")
		err := ErrEncryptFailed{Cause: cause}
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !contains(msg, "encrypt failed") {
			t.Errorf("expected message to contain 'encrypt failed', got %q", msg)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap did not return cause")
		}
	})
}

func TestExtractEncryptedPayload(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "simple_prefix",
			raw:      "encrypted:abc123",
			expected: "abc123",
		},
		{
			name:     "uri_prefix",
			raw:      "encrypted://xyz789",
			expected: "xyz789",
		},
		{
			name:     "uppercase_simple",
			raw:      "ENCRYPTED:ABC",
			expected: "ABC",
		},
		{
			name:     "uppercase_uri",
			raw:      "ENCRYPTED://XYZ",
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
		{
			name:     "idevid_scheme",
			raw:      "idevid://data",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractEncryptedPayload(tc.raw)
			if result != tc.expected {
				t.Errorf("extractEncryptedPayload(%q) = %q, expected %q", tc.raw, result, tc.expected)
			}
		})
	}
}
