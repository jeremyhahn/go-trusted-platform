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

package registry

import (
	"errors"
	"strings"
	"testing"
)

func TestErrAttestationRequired(t *testing.T) {
	err := ErrAttestationRequired{}

	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}

	if !strings.Contains(err.Error(), "attestation") {
		t.Errorf("expected error to contain 'attestation', got: %s", err.Error())
	}
}

func TestErrAttestationFailed(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		contains string
	}{
		{
			name:     "with reason",
			reason:   "quote signature invalid",
			contains: "quote signature invalid",
		},
		{
			name:     "empty reason",
			reason:   "",
			contains: "attestation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrAttestationFailed{Reason: tt.reason}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrInvalidQuote(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidQuote
		contains string
	}{
		{
			name:     "with reason",
			err:      ErrInvalidQuote{Reason: "malformed nonce"},
			contains: "malformed nonce",
		},
		{
			name:     "with cause",
			err:      ErrInvalidQuote{Cause: errors.New("underlying error")},
			contains: "underlying error",
		},
		{
			name:     "empty",
			err:      ErrInvalidQuote{},
			contains: "invalid TPM quote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrInvalidQuote{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrAccessDenied(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAccessDenied
		contains []string
	}{
		{
			name:     "with subject and resource",
			err:      ErrAccessDenied{Subject: "client1", Resource: "image:latest", Reason: "policy violation"},
			contains: []string{"client1", "image:latest", "policy violation"},
		},
		{
			name:     "reason only",
			err:      ErrAccessDenied{Reason: "unauthorized"},
			contains: []string{"unauthorized"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, c := range tt.contains {
				if !strings.Contains(errMsg, c) {
					t.Errorf("expected error to contain %q, got: %s", c, errMsg)
				}
			}
		})
	}
}

func TestErrImageNotFound(t *testing.T) {
	err := ErrImageNotFound{Reference: "myrepo/myimage:v1"}

	if !strings.Contains(err.Error(), "myrepo/myimage:v1") {
		t.Errorf("expected error to contain reference, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error to contain 'not found', got: %s", err.Error())
	}
}

func TestErrImageExists(t *testing.T) {
	err := ErrImageExists{Reference: "myrepo/myimage:v1"}

	if !strings.Contains(err.Error(), "myrepo/myimage:v1") {
		t.Errorf("expected error to contain reference, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected error to contain 'already exists', got: %s", err.Error())
	}
}

func TestErrDecryptionFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDecryptionFailed
		contains string
	}{
		{
			name:     "with layer and cause",
			err:      ErrDecryptionFailed{LayerID: "sha256:abc123", Cause: errors.New("key not found")},
			contains: "sha256:abc123",
		},
		{
			name:     "with reference and cause",
			err:      ErrDecryptionFailed{Reference: "myimage:v1", Cause: errors.New("key error")},
			contains: "myimage:v1",
		},
		{
			name:     "cause only",
			err:      ErrDecryptionFailed{Cause: errors.New("decrypt error")},
			contains: "decrypt error",
		},
		{
			name:     "empty",
			err:      ErrDecryptionFailed{},
			contains: "decryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrDecryptionFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrEncryptionFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrEncryptionFailed
		contains string
	}{
		{
			name:     "with layer and cause",
			err:      ErrEncryptionFailed{LayerID: "sha256:abc123", Cause: errors.New("key generation failed")},
			contains: "sha256:abc123",
		},
		{
			name:     "with reference and cause",
			err:      ErrEncryptionFailed{Reference: "myimage:v1", Cause: errors.New("key error")},
			contains: "myimage:v1",
		},
		{
			name:     "cause only",
			err:      ErrEncryptionFailed{Cause: errors.New("encrypt error")},
			contains: "encrypt error",
		},
		{
			name:     "empty",
			err:      ErrEncryptionFailed{},
			contains: "encryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrEncryptionFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrStorageError(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrStorageError
		contains []string
	}{
		{
			name:     "with key and cause",
			err:      ErrStorageError{Operation: "get", Key: "sha256:abc", Cause: errors.New("connection failed")},
			contains: []string{"get", "sha256:abc", "connection failed"},
		},
		{
			name:     "with cause only",
			err:      ErrStorageError{Operation: "put", Cause: errors.New("timeout")},
			contains: []string{"put", "timeout"},
		},
		{
			name:     "operation only",
			err:      ErrStorageError{Operation: "delete"},
			contains: []string{"delete"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, c := range tt.contains {
				if !strings.Contains(errMsg, c) {
					t.Errorf("expected error to contain %q, got: %s", c, errMsg)
				}
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrStorageError{Operation: "get", Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrRegistryNotInitialized(t *testing.T) {
	err := ErrRegistryNotInitialized{}

	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected error to contain 'not initialized', got: %s", err.Error())
	}
}

func TestErrRegistryClosed(t *testing.T) {
	err := ErrRegistryClosed{}

	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("expected error to contain 'closed', got: %s", err.Error())
	}
}

func TestErrInvalidImageRef(t *testing.T) {
	err := ErrInvalidImageRef{Reference: "INVALID/ref:tag", Reason: "uppercase not allowed"}

	if !strings.Contains(err.Error(), "INVALID/ref:tag") {
		t.Errorf("expected error to contain reference, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "uppercase not allowed") {
		t.Errorf("expected error to contain reason, got: %s", err.Error())
	}
}

func TestErrBlobNotFound(t *testing.T) {
	err := ErrBlobNotFound{Digest: "sha256:abc123def456"}

	if !strings.Contains(err.Error(), "sha256:abc123def456") {
		t.Errorf("expected error to contain digest, got: %s", err.Error())
	}
}

func TestErrManifestNotFound(t *testing.T) {
	err := ErrManifestNotFound{Reference: "myrepo/myimage:v1"}

	if !strings.Contains(err.Error(), "myrepo/myimage:v1") {
		t.Errorf("expected error to contain reference, got: %s", err.Error())
	}
}

func TestErrInvalidManifest(t *testing.T) {
	err := ErrInvalidManifest{Reference: "myimage:v1", Reason: "missing config"}

	if !strings.Contains(err.Error(), "myimage:v1") {
		t.Errorf("expected error to contain reference, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "missing config") {
		t.Errorf("expected error to contain reason, got: %s", err.Error())
	}
}

func TestErrKeyNotFound(t *testing.T) {
	err := ErrKeyNotFound{KeyID: "my-encryption-key"}

	if !strings.Contains(err.Error(), "my-encryption-key") {
		t.Errorf("expected error to contain key ID, got: %s", err.Error())
	}
}

func TestErrKeyCreationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrKeyCreationFailed
		contains string
	}{
		{
			name:     "with key and cause",
			err:      ErrKeyCreationFailed{KeyID: "my-key", Cause: errors.New("permission denied")},
			contains: "my-key",
		},
		{
			name:     "cause only",
			err:      ErrKeyCreationFailed{Cause: errors.New("db error")},
			contains: "db error",
		},
		{
			name:     "empty",
			err:      ErrKeyCreationFailed{},
			contains: "key creation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrKeyCreationFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrKeyWrapFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrKeyWrapFailed
		contains string
	}{
		{
			name:     "with key and cause",
			err:      ErrKeyWrapFailed{KeyID: "kek-1", Cause: errors.New("key expired")},
			contains: "kek-1",
		},
		{
			name:     "cause only",
			err:      ErrKeyWrapFailed{Cause: errors.New("crypto error")},
			contains: "crypto error",
		},
		{
			name:     "empty",
			err:      ErrKeyWrapFailed{},
			contains: "DEK wrap failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrKeyWrapFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrKeyUnwrapFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrKeyUnwrapFailed
		contains string
	}{
		{
			name:     "with key and cause",
			err:      ErrKeyUnwrapFailed{KeyID: "kek-1", Cause: errors.New("decryption failed")},
			contains: "kek-1",
		},
		{
			name:     "cause only",
			err:      ErrKeyUnwrapFailed{Cause: errors.New("invalid ciphertext")},
			contains: "invalid ciphertext",
		},
		{
			name:     "empty",
			err:      ErrKeyUnwrapFailed{},
			contains: "DEK unwrap failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrKeyUnwrapFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidConfig
		contains []string
	}{
		{
			name:     "with field and reason",
			err:      ErrInvalidConfig{Field: "listen_addr", Reason: "cannot be empty"},
			contains: []string{"listen_addr", "cannot be empty"},
		},
		{
			name:     "reason only",
			err:      ErrInvalidConfig{Reason: "missing required fields"},
			contains: []string{"missing required fields"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, c := range tt.contains {
				if !strings.Contains(errMsg, c) {
					t.Errorf("expected error to contain %q, got: %s", c, errMsg)
				}
			}
		})
	}
}

func TestErrPCRMismatch(t *testing.T) {
	expected := []byte{0x01, 0x02, 0x03}
	actual := []byte{0x04, 0x05, 0x06}
	err := ErrPCRMismatch{PCRIndex: 7, Expected: expected, Actual: actual}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "7") {
		t.Errorf("expected error to contain PCR index, got: %s", errMsg)
	}

	if !strings.Contains(errMsg, "010203") {
		t.Errorf("expected error to contain expected value, got: %s", errMsg)
	}

	if !strings.Contains(errMsg, "040506") {
		t.Errorf("expected error to contain actual value, got: %s", errMsg)
	}
}

func TestErrAIKNotAllowed(t *testing.T) {
	err := ErrAIKNotAllowed{AIK: "sha256:fingerprint123"}

	if !strings.Contains(err.Error(), "sha256:fingerprint123") {
		t.Errorf("expected error to contain AIK, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "not in allowed list") {
		t.Errorf("expected error to contain 'not in allowed list', got: %s", err.Error())
	}
}

func TestErrQuicBaaSConnection(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrQuicBaaSConnection
		contains []string
	}{
		{
			name:     "with cause",
			err:      ErrQuicBaaSConnection{Addr: "localhost:9000", Cause: errors.New("connection refused")},
			contains: []string{"localhost:9000", "connection refused"},
		},
		{
			name:     "without cause",
			err:      ErrQuicBaaSConnection{Addr: "localhost:9000"},
			contains: []string{"localhost:9000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, c := range tt.contains {
				if !strings.Contains(errMsg, c) {
					t.Errorf("expected error to contain %q, got: %s", c, errMsg)
				}
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrQuicBaaSConnection{Addr: "localhost:9000", Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrSessionExpired(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		contains  string
	}{
		{
			name:      "with session ID",
			sessionID: "session-123",
			contains:  "session-123",
		},
		{
			name:      "without session ID",
			sessionID: "",
			contains:  "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrSessionExpired{SessionID: tt.sessionID}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrSessionNotFound(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		contains  string
	}{
		{
			name:      "with session ID",
			sessionID: "session-456",
			contains:  "session-456",
		},
		{
			name:      "without session ID",
			sessionID: "",
			contains:  "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrSessionNotFound{SessionID: tt.sessionID}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrInvalidSession(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		contains string
	}{
		{
			name:     "with reason",
			reason:   "token malformed",
			contains: "token malformed",
		},
		{
			name:     "without reason",
			reason:   "",
			contains: "invalid session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidSession{Reason: tt.reason}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrOperationTimeout(t *testing.T) {
	err := ErrOperationTimeout{Operation: "pull"}

	if !strings.Contains(err.Error(), "pull") {
		t.Errorf("expected error to contain operation, got: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected error to contain 'timed out', got: %s", err.Error())
	}
}

func TestErrDigestMismatch(t *testing.T) {
	err := ErrDigestMismatch{Expected: "sha256:expected", Actual: "sha256:actual"}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "sha256:expected") {
		t.Errorf("expected error to contain expected digest, got: %s", errMsg)
	}

	if !strings.Contains(errMsg, "sha256:actual") {
		t.Errorf("expected error to contain actual digest, got: %s", errMsg)
	}
}

func TestErrNilClient(t *testing.T) {
	tests := []struct {
		name     string
		client   string
		contains string
	}{
		{
			name:     "with client name",
			client:   "QuicBaaS",
			contains: "QuicBaaS",
		},
		{
			name:     "without client name",
			client:   "",
			contains: "client is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrNilClient{Client: tt.client}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrNilContext(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		contains  string
	}{
		{
			name:      "with operation",
			operation: "Push",
			contains:  "Push",
		},
		{
			name:      "without operation",
			operation: "",
			contains:  "nil context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrNilContext{Operation: tt.operation}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, err.Error())
			}
		})
	}
}

func TestErrImageEmpty(t *testing.T) {
	err := ErrImageEmpty{}

	if !strings.Contains(err.Error(), "no layers") {
		t.Errorf("expected error to contain 'no layers', got: %s", err.Error())
	}
}

func TestErrPolicyEvaluationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrPolicyEvaluationFailed
		contains string
	}{
		{
			name:     "with policy and cause",
			err:      ErrPolicyEvaluationFailed{Policy: "registry.access", Cause: errors.New("undefined rule")},
			contains: "registry.access",
		},
		{
			name:     "cause only",
			err:      ErrPolicyEvaluationFailed{Cause: errors.New("rego error")},
			contains: "rego error",
		},
		{
			name:     "empty",
			err:      ErrPolicyEvaluationFailed{},
			contains: "policy evaluation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}

	// Test Unwrap
	cause := errors.New("wrapped error")
	err := ErrPolicyEvaluationFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestErrInvalidDigest(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidDigest
		contains string
	}{
		{
			name:     "with digest and reason",
			err:      ErrInvalidDigest{Digest: "invalid-digest", Reason: "missing algorithm prefix"},
			contains: "invalid-digest",
		},
		{
			name:     "digest only",
			err:      ErrInvalidDigest{Digest: "bad"},
			contains: "bad",
		},
		{
			name:     "empty",
			err:      ErrInvalidDigest{},
			contains: "invalid digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("expected error to contain %q, got: %s", tt.contains, tt.err.Error())
			}
		})
	}
}

// Test that all error types implement the error interface
func TestErrorsImplementErrorInterface(t *testing.T) {
	var _ error = ErrAttestationRequired{}
	var _ error = ErrAttestationFailed{}
	var _ error = ErrInvalidQuote{}
	var _ error = ErrAccessDenied{}
	var _ error = ErrImageNotFound{}
	var _ error = ErrImageExists{}
	var _ error = ErrDecryptionFailed{}
	var _ error = ErrEncryptionFailed{}
	var _ error = ErrStorageError{}
	var _ error = ErrRegistryNotInitialized{}
	var _ error = ErrRegistryClosed{}
	var _ error = ErrInvalidImageRef{}
	var _ error = ErrBlobNotFound{}
	var _ error = ErrManifestNotFound{}
	var _ error = ErrInvalidManifest{}
	var _ error = ErrKeyNotFound{}
	var _ error = ErrKeyCreationFailed{}
	var _ error = ErrKeyWrapFailed{}
	var _ error = ErrKeyUnwrapFailed{}
	var _ error = ErrInvalidConfig{}
	var _ error = ErrPCRMismatch{}
	var _ error = ErrAIKNotAllowed{}
	var _ error = ErrQuicBaaSConnection{}
	var _ error = ErrSessionExpired{}
	var _ error = ErrSessionNotFound{}
	var _ error = ErrInvalidSession{}
	var _ error = ErrOperationTimeout{}
	var _ error = ErrDigestMismatch{}
	var _ error = ErrNilClient{}
	var _ error = ErrNilContext{}
	var _ error = ErrImageEmpty{}
	var _ error = ErrPolicyEvaluationFailed{}
	var _ error = ErrInvalidDigest{}
}

// Test errors.Is for checking error types
func TestErrorsIs(t *testing.T) {
	err := ErrImageNotFound{Reference: "test:latest"}

	var target ErrImageNotFound
	if !errors.As(err, &target) {
		t.Error("errors.As should match ErrImageNotFound")
	}

	if target.Reference != "test:latest" {
		t.Errorf("expected reference 'test:latest', got: %s", target.Reference)
	}
}

// Test error wrapping chain
func TestErrorWrappingChain(t *testing.T) {
	root := errors.New("root cause")
	decryptErr := ErrDecryptionFailed{Reference: "myimage", Cause: root}
	storageErr := ErrStorageError{Operation: "get", Cause: decryptErr}

	// Should be able to unwrap to decryption error
	var decryptTarget ErrDecryptionFailed
	if !errors.As(storageErr, &decryptTarget) {
		t.Error("should be able to unwrap to ErrDecryptionFailed")
	}

	// Should be able to find root cause
	if !errors.Is(storageErr.Unwrap(), decryptErr) {
		t.Error("should find ErrDecryptionFailed in chain")
	}
}
