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

package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// cov964Secret is a secret value that must never appear in an error message.
const cov964Secret = "hunter2-cov964"

// cov964Cause is a sentinel cause for wrapping assertions.
var cov964Cause = errors.New("cov964 cause")

// TestCov964TypedErrorMessagesAndUnwrap builds each typed error with and
// without a cause and asserts its message and its Unwrap result.
func TestCov964TypedErrorMessagesAndUnwrap(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantMsg   string
		wantCause error
	}{
		{
			name:    "message error has no cause",
			err:     &MessageError{Msg: "plain failure"},
			wantMsg: "plain failure",
		},
		{
			name:      "wrapped error joins message and cause",
			err:       &WrappedError{Msg: "context", Err: cov964Cause},
			wantMsg:   "context: cov964 cause",
			wantCause: cov964Cause,
		},
		{
			name:      "malformed secret value with decode cause",
			err:       ErrMalformedSecretValue{Type: "string", Err: cov964Cause},
			wantMsg:   "stored secret value is not base64 text: cov964 cause",
			wantCause: cov964Cause,
		},
		{
			name:    "malformed secret value without cause names the type",
			err:     ErrMalformedSecretValue{Type: "int"},
			wantMsg: "stored secret value has unexpected type int",
		},
		{
			name:      "secret data encoding wraps cause",
			err:       ErrSecretDataEncoding{Err: cov964Cause},
			wantMsg:   "secret data cannot be encoded: cov964 cause",
			wantCause: cov964Cause,
		},
		{
			name:      "secret data decoding wraps cause",
			err:       ErrSecretDataDecoding{Err: cov964Cause},
			wantMsg:   "secret data cannot be decoded: cov964 cause",
			wantCause: cov964Cause,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.wantMsg)
			}
			if got := errors.Unwrap(tt.err); got != tt.wantCause {
				t.Fatalf("Unwrap() = %v, want %v", got, tt.wantCause)
			}
			if tt.wantCause != nil && !errors.Is(tt.err, tt.wantCause) {
				t.Fatalf("errors.Is(%v, cause) = false, want true", tt.err)
			}
		})
	}
}

// TestCov964SecretErrorsNeverLeakValue drives the secret codecs into their
// typed errors with secret-bearing input and asserts the secret never
// reaches the message while the cause stays reachable.
func TestCov964SecretErrorsNeverLeakValue(t *testing.T) {
	t.Run("malformed base64 secret value", func(t *testing.T) {
		_, err := DecodeSecretValue(cov964Secret + "!")
		var malformed ErrMalformedSecretValue
		if !errors.As(err, &malformed) {
			t.Fatalf("DecodeSecretValue error = %T, want ErrMalformedSecretValue", err)
		}
		var corrupt base64.CorruptInputError
		if !errors.As(err, &corrupt) {
			t.Fatalf("cause = %T, want base64.CorruptInputError", errors.Unwrap(err))
		}
		if !strings.HasPrefix(err.Error(), "stored secret value is not base64 text: ") {
			t.Fatalf("message = %q", err.Error())
		}
		if strings.Contains(err.Error(), cov964Secret) {
			t.Fatalf("message leaks the secret: %q", err.Error())
		}
	})

	t.Run("unexpected secret value type", func(t *testing.T) {
		_, err := DecodeSecretValue(42)
		var malformed ErrMalformedSecretValue
		if !errors.As(err, &malformed) {
			t.Fatalf("DecodeSecretValue error = %T, want ErrMalformedSecretValue", err)
		}
		if errors.Unwrap(err) != nil {
			t.Fatalf("Unwrap() = %v, want nil", errors.Unwrap(err))
		}
		if err.Error() != "stored secret value has unexpected type int" {
			t.Fatalf("message = %q", err.Error())
		}
	})

	t.Run("unencodable secret data", func(t *testing.T) {
		_, err := EncodeSecretData(map[string]interface{}{
			"password": cov964Secret,
			"channel":  make(chan int),
		})
		var encoding ErrSecretDataEncoding
		if !errors.As(err, &encoding) {
			t.Fatalf("EncodeSecretData error = %T, want ErrSecretDataEncoding", err)
		}
		var unsupported *json.UnsupportedTypeError
		if !errors.As(err, &unsupported) {
			t.Fatalf("cause = %T, want *json.UnsupportedTypeError", errors.Unwrap(err))
		}
		if strings.Contains(err.Error(), cov964Secret) {
			t.Fatalf("message leaks the secret: %q", err.Error())
		}
	})

	t.Run("truncated secret data", func(t *testing.T) {
		_, err := DecodeSecretData([]byte(`{"password":"` + cov964Secret + `"`))
		var decoding ErrSecretDataDecoding
		if !errors.As(err, &decoding) {
			t.Fatalf("DecodeSecretData error = %T, want ErrSecretDataDecoding", err)
		}
		var syntax *json.SyntaxError
		if !errors.As(err, &syntax) {
			t.Fatalf("cause = %T, want *json.SyntaxError", errors.Unwrap(err))
		}
		if strings.Contains(err.Error(), cov964Secret) {
			t.Fatalf("message leaks the secret: %q", err.Error())
		}
	})
}

// TestCov964ToKeyAttributesTypedErrors asserts that invalid key
// configuration returns the package's typed errors with readable messages
// and never echoes the configured password.
func TestCov964ToKeyAttributesTypedErrors(t *testing.T) {
	t.Run("invalid hash is a message error", func(t *testing.T) {
		kc := &KeyConfig{Hash: "MD-17", Password: cov964Secret}
		attrs, err := kc.ToKeyAttributes()
		if attrs != nil {
			t.Fatalf("attrs = %v, want nil", attrs)
		}
		var msgErr *MessageError
		if !errors.As(err, &msgErr) {
			t.Fatalf("error = %T, want *MessageError", err)
		}
		if err.Error() != "invalid hash algorithm: MD-17" {
			t.Fatalf("message = %q", err.Error())
		}
		if strings.Contains(err.Error(), cov964Secret) {
			t.Fatalf("message leaks the password: %q", err.Error())
		}
	})

	t.Run("invalid key algorithm is a wrapped error", func(t *testing.T) {
		kc := &KeyConfig{KeyAlgorithm: "not-an-algorithm", Password: cov964Secret}
		attrs, err := kc.ToKeyAttributes()
		if attrs != nil {
			t.Fatalf("attrs = %v, want nil", attrs)
		}
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) {
			t.Fatalf("error = %T, want *WrappedError", err)
		}
		if wrapped.Unwrap() == nil {
			t.Fatal("Unwrap() = nil, want the parser's cause")
		}
		if !strings.HasPrefix(err.Error(), "invalid key algorithm: ") {
			t.Fatalf("message = %q", err.Error())
		}
		if strings.Contains(err.Error(), cov964Secret) {
			t.Fatalf("message leaks the password: %q", err.Error())
		}
	})
}
