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

package tpm

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  platformv1.DeviceKeyAlgorithm
		expectErr bool
	}{
		{
			name:     "ECDSA-P256",
			input:    "ECDSA-P256",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "ECDSA-P256 lowercase",
			input:    "ecdsa-p256",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "P256 shorthand",
			input:    "P256",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "ECDSA-P384",
			input:    "ECDSA-P384",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
		},
		{
			name:     "P384 shorthand",
			input:    "P384",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
		},
		{
			name:     "RSA-2048",
			input:    "RSA-2048",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
		},
		{
			name:     "RSA2048 without hyphen",
			input:    "RSA2048",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
		},
		{
			name:     "RSA-3072",
			input:    "RSA-3072",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
		},
		{
			name:     "with whitespace",
			input:    "  ECDSA-P256  ",
			expected: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:      "invalid algorithm",
			input:     "INVALID",
			expected:  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED,
			expectErr: true,
		},
		{
			name:      "empty string",
			input:     "",
			expected:  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAlgorithm(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
				var algErr ErrInvalidAlgorithm
				assert.ErrorAs(t, err, &algErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAlgorithmToString(t *testing.T) {
	tests := []struct {
		name     string
		input    platformv1.DeviceKeyAlgorithm
		expected string
	}{
		{
			name:     "ECDSA-P256",
			input:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
			expected: "ECDSA-P256",
		},
		{
			name:     "ECDSA-P384",
			input:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
			expected: "ECDSA-P384",
		},
		{
			name:     "RSA-2048",
			input:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
			expected: "RSA-2048",
		},
		{
			name:     "RSA-3072",
			input:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
			expected: "RSA-3072",
		},
		{
			name:     "Unspecified",
			input:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED,
			expected: "UNSPECIFIED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := algorithmToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildKeyInfoOutput(t *testing.T) {
	createdAt := time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)

	info := &platformv1.DeviceKeyInfo{
		Handle:         0x81010100,
		Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		PublicKeyPem:   []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"),
		CreatedAt:      timestamppb.New(createdAt),
		HasCertificate: false,
	}

	output := buildKeyInfoOutput(info)

	assert.Equal(t, "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----", output["public_key_pem"])
	assert.Equal(t, "ECDSA-P256", output["algorithm"])
	assert.Equal(t, "0x81010100", output["handle"])
	assert.Equal(t, int64(createdAt.Unix()), output["created_at"])
	assert.Equal(t, false, output["has_certificate"])
}

func TestBuildKeyInfoOutputWithCertificate(t *testing.T) {
	createdAt := time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)
	issuedAt := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)

	info := &platformv1.DeviceKeyInfo{
		Handle:         0x81010100,
		Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
		PublicKeyPem:   []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"),
		CreatedAt:      timestamppb.New(createdAt),
		HasCertificate: true,
		CertificateInfo: &platformv1.DeviceIdentityCertificate{
			SubjectCn:          "device-001",
			IssuerCn:           "Test CA",
			SerialNumber:       "1234567890",
			Fingerprint:        "abc123",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA",
			KeySize:            2048,
			IssuedAt:           timestamppb.New(issuedAt),
			ExpiresAt:          timestamppb.New(expiresAt),
		},
	}

	output := buildKeyInfoOutput(info)

	assert.Equal(t, "RSA-2048", output["algorithm"])
	assert.Equal(t, "0x81010100", output["handle"])
	assert.Equal(t, true, output["has_certificate"])

	certInfo, ok := output["certificate_info"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "device-001", certInfo["subject_cn"])
	assert.Equal(t, "Test CA", certInfo["issuer_cn"])
	assert.Equal(t, "1234567890", certInfo["serial_number"])
	assert.Equal(t, int64(issuedAt.Unix()), certInfo["issued_at"])
	assert.Equal(t, int64(expiresAt.Unix()), certInfo["expires_at"])
}

func TestBuildGenerateKeyOutput(t *testing.T) {
	t.Run("with key info", func(t *testing.T) {
		createdAt := time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)
		info := &platformv1.DeviceKeyInfo{
			Handle:       0x81010100,
			Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
			PublicKeyPem: []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"),
			CreatedAt:    timestamppb.New(createdAt),
		}

		output := buildGenerateKeyOutput(info, "ECDSA-P256")

		assert.Equal(t, "ECDSA-P256", output["algorithm"])
		assert.Equal(t, "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----", output["public_key_pem"])
		assert.Equal(t, "0x81010100", output["handle"])
		assert.Equal(t, int64(createdAt.Unix()), output["created_at"])
	})

	t.Run("with nil info", func(t *testing.T) {
		output := buildGenerateKeyOutput(nil, "RSA-2048")

		assert.Equal(t, "RSA-2048", output["algorithm"])
		assert.Nil(t, output["public_key_pem"])
		assert.Nil(t, output["handle"])
	})

	t.Run("with info but no created_at", func(t *testing.T) {
		info := &platformv1.DeviceKeyInfo{
			Handle:       0x81010100,
			Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
			PublicKeyPem: []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"),
		}

		output := buildGenerateKeyOutput(info, "RSA-2048")

		assert.Equal(t, "RSA-2048", output["algorithm"])
		assert.Equal(t, "0x81010100", output["handle"])
		assert.Nil(t, output["created_at"])
	})
}

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "Yes", formatBool(true))
	assert.Equal(t, "No", formatBool(false))
}

func TestFormatTimestamp(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC))
		result := formatTimestamp(ts)
		assert.Equal(t, "2025-01-07T12:00:00Z", result)
	})

	t.Run("nil timestamp", func(t *testing.T) {
		result := formatTimestamp(nil)
		assert.Equal(t, "N/A", result)
	})
}

func TestBuildCertificateOutput(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		issuedAt := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)
		expiresAt := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)

		cert := &platformv1.DeviceIdentityCertificate{
			Pem:          []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			SubjectCn:    "device-001",
			IssuerCn:     "Test CA",
			SerialNumber: "1234567890",
			IssuedAt:     timestamppb.New(issuedAt),
			ExpiresAt:    timestamppb.New(expiresAt),
		}

		output := buildCertificateOutput(cert)

		assert.Equal(t, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", output["certificate_pem"])
		assert.Equal(t, "device-001", output["subject"])
		assert.Equal(t, "Test CA", output["issuer"])
		assert.Equal(t, "1234567890", output["serial_number"])
		assert.Equal(t, int64(issuedAt.Unix()), output["not_before"])
		assert.Equal(t, int64(expiresAt.Unix()), output["not_after"])
	})

	t.Run("without timestamps", func(t *testing.T) {
		cert := &platformv1.DeviceIdentityCertificate{
			Pem:          []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			SubjectCn:    "device-001",
			IssuerCn:     "Test CA",
			SerialNumber: "1234567890",
		}

		output := buildCertificateOutput(cert)

		assert.Equal(t, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", output["certificate_pem"])
		assert.Equal(t, "device-001", output["subject"])
		assert.Nil(t, output["not_before"])
		assert.Nil(t, output["not_after"])
	})
}

func TestReadFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		expectedContent := "-----BEGIN CERTIFICATE-----\ntest content\n-----END CERTIFICATE-----"
		_, err = tmpFile.WriteString(expectedContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Read the file
		content, err := readFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, expectedContent, content)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := readFile("/nonexistent/path/file.pem")
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		// Create an empty temporary file
		tmpFile, err := os.CreateTemp("", "test-empty-*.pem")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		content, err := readFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, "", content)
	})
}
