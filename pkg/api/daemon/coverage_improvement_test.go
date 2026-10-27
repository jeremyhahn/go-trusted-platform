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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Error Types Tests - errors.go coverage
// =============================================================================

func TestErrorTypes_TPM2ServiceErrors(t *testing.T) {
	t.Run("ErrInvalidCertificatePEM", func(t *testing.T) {
		err := ErrInvalidCertificatePEM{}
		assert.Equal(t, "invalid PEM-encoded certificate", err.Error())
	})

	t.Run("ErrTPM2ServiceNotAvailable", func(t *testing.T) {
		err := ErrTPM2ServiceNotAvailable{}
		assert.Equal(t, "TPM2 service not available", err.Error())
	})

	t.Run("ErrIDevIDNotFound", func(t *testing.T) {
		err := ErrIDevIDNotFound{}
		assert.Equal(t, "IDevID not found in TPM", err.Error())
	})

	t.Run("ErrIAKNotFound", func(t *testing.T) {
		err := ErrIAKNotFound{}
		assert.Equal(t, "IAK not found in TPM", err.Error())
	})

	t.Run("ErrIDevIDCertificateNotFound", func(t *testing.T) {
		err := ErrIDevIDCertificateNotFound{}
		assert.Equal(t, "IDevID certificate not installed", err.Error())
	})

	t.Run("ErrIAKCertificateNotFound", func(t *testing.T) {
		err := ErrIAKCertificateNotFound{}
		assert.Equal(t, "IAK certificate not installed", err.Error())
	})

	t.Run("ErrTPM2OperationFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrTPM2OperationFailed{Operation: "CreateIDevID", Cause: cause}
		assert.Contains(t, err.Error(), "TPM2 operation CreateIDevID failed")
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestErrorTypes_ContainerServiceErrors(t *testing.T) {
	t.Run("ErrContainerServiceNotAvailable", func(t *testing.T) {
		err := ErrContainerServiceNotAvailable{}
		assert.Equal(t, "container service not available", err.Error())
	})

	t.Run("ErrContainerNotFound", func(t *testing.T) {
		err := ErrContainerNotFound{ContainerID: "container-123"}
		assert.Equal(t, "container not found: container-123", err.Error())
	})

	t.Run("ErrContainerOperationFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrContainerOperationFailed{Operation: "Start", Cause: cause}
		assert.Contains(t, err.Error(), "container operation Start failed")
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestIDevIDTypes_NormalizeKeyAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ecdsa-p256", "ECDSA-P256"},
		{"ECDSA-P256", "ECDSA-P256"},
		{"p256", "ECDSA-P256"},
		{"ec-p256", "ECDSA-P256"},
		{"ecp256", "ECDSA-P256"},
		{"ecdsa-p384", "ECDSA-P384"},
		{"p384", "ECDSA-P384"},
		{"ec-p384", "ECDSA-P384"},
		{"ecp384", "ECDSA-P384"},
		{"rsa-2048", "RSA-2048"},
		{"rsa2048", "RSA-2048"},
		{"rsa-3072", "RSA-3072"},
		{"rsa3072", "RSA-3072"},
		{"", "ECDSA-P256"},
		{"unknown", "ECDSA-P256"},
		{"  p256  ", "ECDSA-P256"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeKeyAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// MCP Service Container Operations Tests - mcp_service.go coverage
// =============================================================================

func TestMCPServiceContainerOperations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	provider := &MCPServiceProvider{
		logger: logger,
	}

	t.Run("ContainerCreate returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerCreate(ctx, "test", "image", nil)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("ContainerStart returns not implemented", func(t *testing.T) {
		err := provider.ContainerStart(ctx, "id")
		assert.Error(t, err)
	})

	t.Run("ContainerStop returns not implemented", func(t *testing.T) {
		err := provider.ContainerStop(ctx, "id", 10)
		assert.Error(t, err)
	})

	t.Run("ContainerRemove returns not implemented", func(t *testing.T) {
		err := provider.ContainerRemove(ctx, "id", true)
		assert.Error(t, err)
	})

	t.Run("ContainerGet returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerGet(ctx, "id")
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("ContainerList returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerList(ctx, true, nil, 10)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("ContainerAttest returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerAttest(ctx, "id")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}
