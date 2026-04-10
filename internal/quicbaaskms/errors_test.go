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

package quicbaaskms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdapterError(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := &AdapterError{
			Op:  "TestOp",
			Msg: "test message",
		}

		assert.Equal(t, "quicbaaskms adapter TestOp: test message", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &AdapterError{
			Op:    "TestOp",
			Msg:   "test message",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter TestOp: test message: underlying error", err.Error())
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &AdapterError{
			Op:    "TestOp",
			Msg:   "test message",
			Cause: cause,
		}

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("WithCause creates new error", func(t *testing.T) {
		original := &AdapterError{
			Op:  "TestOp",
			Msg: "test message",
		}
		cause := errors.New("new cause")

		newErr := original.WithCause(cause)

		assert.NotSame(t, original, newErr)
		assert.Equal(t, original.Op, newErr.Op)
		assert.Equal(t, original.Msg, newErr.Msg)
		assert.Equal(t, cause, newErr.Cause)
		assert.Nil(t, original.Cause) // Original unchanged
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrNilConfig", func(t *testing.T) {
		assert.Contains(t, ErrNilConfig.Error(), "configuration cannot be nil")
		assert.Equal(t, "NewAdapter", ErrNilConfig.Op)
	})

	t.Run("ErrNilLogger", func(t *testing.T) {
		assert.Contains(t, ErrNilLogger.Error(), "logger cannot be nil")
		assert.Equal(t, "NewAdapter", ErrNilLogger.Op)
	})

	t.Run("ErrAdapterClosed", func(t *testing.T) {
		assert.Contains(t, ErrAdapterClosed.Error(), "adapter is closed")
	})

	t.Run("ErrAdapterNotStarted", func(t *testing.T) {
		assert.Contains(t, ErrAdapterNotStarted.Error(), "adapter not started")
	})

	t.Run("ErrEmbeddedServiceRequired", func(t *testing.T) {
		assert.Contains(t, ErrEmbeddedServiceRequired.Error(), "embedded service is required")
	})

	t.Run("ErrMissingUnixSocket", func(t *testing.T) {
		assert.Contains(t, ErrMissingUnixSocket.Error(), "unix_socket is required")
	})

	t.Run("ErrMissingAddress", func(t *testing.T) {
		assert.Contains(t, ErrMissingAddress.Error(), "address is required")
	})
}

func TestErrUnsupportedTransport(t *testing.T) {
	t.Parallel()

	err := ErrUnsupportedTransport{Transport: Transport("invalid")}

	assert.Equal(t, "quicbaaskms adapter: unsupported transport: invalid", err.Error())
}

func TestErrConnectionFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrConnectionFailed{
			Address:   "localhost:50051",
			Transport: TransportGRPC,
		}

		assert.Equal(t, "quicbaaskms adapter: connection failed to localhost:50051 via grpc", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrConnectionFailed{
			Address:   "localhost:50051",
			Transport: TransportGRPC,
			Cause:     cause,
		}

		assert.Equal(t, "quicbaaskms adapter: connection failed to localhost:50051 via grpc: connection refused", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrKeyNotFound(t *testing.T) {
	t.Parallel()

	err := ErrKeyNotFound{KeyID: "test-key-123"}

	assert.Equal(t, "quicbaaskms adapter: key not found: test-key-123", err.Error())
}

func TestErrInvalidKeyAlgorithm(t *testing.T) {
	t.Parallel()

	err := ErrInvalidKeyAlgorithm{Algorithm: "INVALID"}

	assert.Equal(t, "quicbaaskms adapter: invalid key algorithm: INVALID", err.Error())
}

func TestErrSigningFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrSigningFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: signing failed for key test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("key not accessible")
		err := ErrSigningFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: signing failed for key test-key: key not accessible", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrVerificationFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrVerificationFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: verification failed for key test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("invalid signature format")
		err := ErrVerificationFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: verification failed for key test-key: invalid signature format", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrEncryptionFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrEncryptionFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: encryption failed for key test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("plaintext too large")
		err := ErrEncryptionFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: encryption failed for key test-key: plaintext too large", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrDecryptionFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrDecryptionFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: decryption failed for key test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("invalid ciphertext")
		err := ErrDecryptionFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: decryption failed for key test-key: invalid ciphertext", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrKeyGenerationFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrKeyGenerationFailed{Name: "my-new-key"}

		assert.Equal(t, "quicbaaskms adapter: key generation failed for my-new-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("insufficient entropy")
		err := ErrKeyGenerationFailed{
			Name:  "my-new-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: key generation failed for my-new-key: insufficient entropy", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrKeyDeletionFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrKeyDeletionFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: key deletion failed for test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("key in use")
		err := ErrKeyDeletionFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: key deletion failed for test-key: key in use", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrKeyRotationFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrKeyRotationFailed{KeyID: "test-key"}

		assert.Equal(t, "quicbaaskms adapter: key rotation failed for test-key", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("rotation limit reached")
		err := ErrKeyRotationFailed{
			KeyID: "test-key",
			Cause: cause,
		}

		assert.Equal(t, "quicbaaskms adapter: key rotation failed for test-key: rotation limit reached", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrHealthCheckFailed(t *testing.T) {
	t.Parallel()

	t.Run("Error without cause", func(t *testing.T) {
		err := ErrHealthCheckFailed{}

		assert.Equal(t, "quicbaaskms adapter: health check failed", err.Error())
	})

	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("service unavailable")
		err := ErrHealthCheckFailed{Cause: cause}

		assert.Equal(t, "quicbaaskms adapter: health check failed: service unavailable", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrorsUnwrap(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("root cause")

	testCases := []struct {
		name string
		err  error
	}{
		{"ErrConnectionFailed", ErrConnectionFailed{Cause: underlyingErr}},
		{"ErrSigningFailed", ErrSigningFailed{Cause: underlyingErr}},
		{"ErrVerificationFailed", ErrVerificationFailed{Cause: underlyingErr}},
		{"ErrEncryptionFailed", ErrEncryptionFailed{Cause: underlyingErr}},
		{"ErrDecryptionFailed", ErrDecryptionFailed{Cause: underlyingErr}},
		{"ErrKeyGenerationFailed", ErrKeyGenerationFailed{Cause: underlyingErr}},
		{"ErrKeyDeletionFailed", ErrKeyDeletionFailed{Cause: underlyingErr}},
		{"ErrKeyRotationFailed", ErrKeyRotationFailed{Cause: underlyingErr}},
		{"ErrHealthCheckFailed", ErrHealthCheckFailed{Cause: underlyingErr}},
		{"AdapterError", &AdapterError{Cause: underlyingErr}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, errors.Is(tc.err, underlyingErr))
		})
	}
}
