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

//go:build iam && codec_msgpack && codec_cbor && codec_json && !attestation_grpc

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// Attestation gRPC Service Stub Tests - attestation_grpc_service_stub.go coverage
// =============================================================================

func TestAttestationServiceStub(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("NewAttestationServiceServer", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		require.NotNil(t, server)
		assert.Equal(t, logger, server.logger)
	})

	t.Run("attestationNotAvailable", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		err := server.attestationNotAvailable()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Attestation gRPC service not available")
	})

	ctx := context.Background()

	t.Run("GetManifest returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.GetManifest(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("BuildManifest returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.BuildManifest(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("VerifyManifest returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.VerifyManifest(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("ListManifests returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.ListManifests(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("DeleteManifest returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.DeleteManifest(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("GetAttestationQuote returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.GetAttestationQuote(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("VerifyAttestationQuote returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.VerifyAttestationQuote(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("CollectHostAttestation returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.CollectHostAttestation(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("CollectVMAttestation returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.CollectVMAttestation(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("CollectContainerAttestation returns unimplemented", func(t *testing.T) {
		server := NewAttestationServiceServer(nil, logger)
		_, err := server.CollectContainerAttestation(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
	})
}

// =============================================================================
// Service Provider Container Operations Tests - service_provider.go coverage
// =============================================================================

func TestServiceProviderContainerOperations(t *testing.T) {
	// Create a minimal platform service provider for testing
	// These are stub implementations that should return ErrContainerServiceNotAvailable
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	provider := &PlatformServiceProvider{
		logger: logger,
	}

	t.Run("ContainerCreate returns not available", func(t *testing.T) {
		result, err := provider.ContainerCreate(ctx, "test", "image:latest", nil)
		assert.Nil(t, result)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerStart returns not available", func(t *testing.T) {
		err := provider.ContainerStart(ctx, "container-id")
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerStop returns not available", func(t *testing.T) {
		err := provider.ContainerStop(ctx, "container-id", 10)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerRemove returns not available", func(t *testing.T) {
		err := provider.ContainerRemove(ctx, "container-id", true)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerGet returns not available", func(t *testing.T) {
		result, err := provider.ContainerGet(ctx, "container-id")
		assert.Nil(t, result)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerList returns not available", func(t *testing.T) {
		result, err := provider.ContainerList(ctx, true, nil, 10)
		assert.Nil(t, result)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerLogs returns not available", func(t *testing.T) {
		result, err := provider.ContainerLogs(ctx, "container-id", false, true, true, "100", false)
		assert.Empty(t, result)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ContainerAttest returns not available", func(t *testing.T) {
		result, err := provider.ContainerAttest(ctx, "container-id")
		assert.Nil(t, result)
		var notAvailableErr ErrContainerServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})
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

	t.Run("ContainerLogs returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerLogs(ctx, "id", false, true, true, "100", false)
		assert.Empty(t, result)
		assert.Error(t, err)
	})

	t.Run("ContainerAttest returns not implemented", func(t *testing.T) {
		result, err := provider.ContainerAttest(ctx, "id")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

// =============================================================================
// MCP IDevID Operations Tests - mcp_idevid.go coverage
// =============================================================================

func TestMCPIDevIDOperations_NoTPM2Service(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	provider := &MCPServiceProvider{
		logger:      logger,
		tpm2Service: nil, // No TPM2 service
	}

	t.Run("IDevIDGenerate without TPM2 service", func(t *testing.T) {
		result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ECDSA-P256", Overwrite: false})
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDInfo without TPM2 service", func(t *testing.T) {
		result, err := provider.IDevIDInfo(ctx)
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("HasIDevID without TPM2 service", func(t *testing.T) {
		result, err := provider.HasIDevID(ctx)
		assert.False(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDDelete without TPM2 service", func(t *testing.T) {
		err := provider.IDevIDDelete(ctx)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDCreateCSR without TPM2 service", func(t *testing.T) {
		result, err := provider.IDevIDCreateCSR(ctx, "CN=Test", "Org", "US", false)
		assert.Empty(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDInstallCertificate without TPM2 service", func(t *testing.T) {
		err := provider.IDevIDInstallCertificate(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDGetCertificate without TPM2 service", func(t *testing.T) {
		result, err := provider.IDevIDGetCertificate(ctx)
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IDevIDDeleteCertificate without TPM2 service", func(t *testing.T) {
		err := provider.IDevIDDeleteCertificate(ctx)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})
}

func TestMCPIAKOperations_NoTPM2Service(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	provider := &MCPServiceProvider{
		logger:      logger,
		tpm2Service: nil, // No TPM2 service
	}

	t.Run("IAKGenerate without TPM2 service", func(t *testing.T) {
		result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ECDSA-P256", Overwrite: false})
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKInfo without TPM2 service", func(t *testing.T) {
		result, err := provider.IAKInfo(ctx)
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("HasIAK without TPM2 service", func(t *testing.T) {
		result, err := provider.HasIAK(ctx)
		assert.False(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKDelete without TPM2 service", func(t *testing.T) {
		err := provider.IAKDelete(ctx)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKCreateCSR without TPM2 service", func(t *testing.T) {
		result, err := provider.IAKCreateCSR(ctx, "CN=Test", "Org", "US", false)
		assert.Empty(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKInstallCertificate without TPM2 service", func(t *testing.T) {
		err := provider.IAKInstallCertificate(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKGetCertificate without TPM2 service", func(t *testing.T) {
		result, err := provider.IAKGetCertificate(ctx)
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("IAKDeleteCertificate without TPM2 service", func(t *testing.T) {
		err := provider.IAKDeleteCertificate(ctx)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("DeviceAttributes without TPM2 service", func(t *testing.T) {
		result, err := provider.DeviceAttributes(ctx)
		assert.Nil(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})

	t.Run("ActivateCredential without TPM2 service", func(t *testing.T) {
		result, err := provider.ActivateCredential(ctx, []byte("credential"), []byte("secret"))
		assert.Empty(t, result)
		var notAvailableErr ErrTPM2ServiceNotAvailable
		assert.ErrorAs(t, err, &notAvailableErr)
	})
}

// =============================================================================
// MCP IDevID Helper Functions Tests - mcp_idevid.go coverage
// =============================================================================

func TestMCPIDevID_FormatHelpers(t *testing.T) {
	t.Run("formatKeyAttributesMap with nil", func(t *testing.T) {
		result := formatKeyAttributesMap(nil)
		require.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("formatX509CertificateInfo with nil", func(t *testing.T) {
		result := formatX509CertificateInfo(nil)
		require.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("formatX509CertificateInfo with valid cert", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(12345),
			Subject:      pkix.Name{CommonName: "Test Subject"},
			Issuer:       pkix.Name{CommonName: "Test Issuer"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		result := formatX509CertificateInfo(cert)
		require.NotNil(t, result)
		assert.Equal(t, "Test Subject", result["subject_cn"])
		assert.NotEmpty(t, result["serial_number"])
		assert.NotEmpty(t, result["fingerprint"])
	})
}

// =============================================================================
// Helper test config function
// =============================================================================

func createTestCertPEM(t *testing.T) string {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	return string(pem.EncodeToMemory(pemBlock))
}
