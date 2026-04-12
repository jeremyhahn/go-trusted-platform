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
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// printTPMInfoDetails Tests
// =============================================================================

func TestPrintTPMInfoDetails(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: true,
			Properties: map[string]string{
				"info": "TPM Information\nVersion: 2.0\nManufacturer: Test TPM\nModel: Model X\nFirmware: 1.0.0\nMax NVRAM: 4096\nPCR Banks: SHA1, SHA256\nFIPS Mode: No\nSimulator: Yes",
			},
		}

		printTPMInfoDetails(printer, resp)

		result := output.String()
		assert.Contains(t, result, "2.0")
		assert.Contains(t, result, "Test TPM")
	})

	t.Run("without properties", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: false,
		}

		printTPMInfoDetails(printer, resp)

		// Should not panic
		_ = output.String()
	})

	t.Run("empty properties", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: false,
			Properties:  map[string]string{},
		}

		printTPMInfoDetails(printer, resp)

		// Should not panic
		_ = output.String()
	})

	t.Run("info property only", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: true,
			Properties: map[string]string{
				"info": "TPM Information\nVersion: 1.2",
			},
		}

		printTPMInfoDetails(printer, resp)

		result := output.String()
		assert.Contains(t, result, "1.2")
	})
}

// =============================================================================
// printKeyInfoDetails Tests
// =============================================================================

func TestPrintKeyInfoDetails(t *testing.T) {
	t.Run("with certificate info", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		createdAt := time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)
		issuedAt := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)
		expiresAt := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)

		info := &platformv1.DeviceKeyInfo{
			Handle:         0x81010100,
			Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
			CreatedAt:      timestamppb.New(createdAt),
			HasCertificate: true,
			CertificateInfo: &platformv1.DeviceIdentityCertificate{
				SubjectCn:          "device-001",
				IssuerCn:           "Test CA",
				SerialNumber:       "1234567890",
				Fingerprint:        "abc123",
				KeyAlgorithm:       "ECDSA",
				SignatureAlgorithm: "SHA256-ECDSA",
				KeySize:            256,
				IssuedAt:           timestamppb.New(issuedAt),
				ExpiresAt:          timestamppb.New(expiresAt),
			},
		}

		printKeyInfoDetails(printer, info, "IDevID")

		result := output.String()
		assert.Contains(t, result, "0x81010100")
		assert.Contains(t, result, "ECDSA-P256")
		assert.Contains(t, result, "device-001")
		assert.Contains(t, result, "Test CA")
		assert.Contains(t, result, "1234567890")
		assert.Contains(t, result, "abc123")
	})

	t.Run("without certificate", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		createdAt := time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)

		info := &platformv1.DeviceKeyInfo{
			Handle:         0x81010100,
			Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
			CreatedAt:      timestamppb.New(createdAt),
			HasCertificate: false,
		}

		printKeyInfoDetails(printer, info, "IAK")

		result := output.String()
		assert.Contains(t, result, "0x81010100")
		assert.Contains(t, result, "RSA-2048")
		assert.Contains(t, result, "No") // Has Certificate
	})

	t.Run("without created_at", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		info := &platformv1.DeviceKeyInfo{
			Handle:         0x81010100,
			Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
			HasCertificate: false,
		}

		printKeyInfoDetails(printer, info, "IDevID")

		result := output.String()
		assert.Contains(t, result, "0x81010100")
		assert.Contains(t, result, "RSA-3072")
	})
}

// =============================================================================
// printCertificateDetails Tests
// =============================================================================

func TestPrintCertificateDetails(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		issuedAt := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)
		expiresAt := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)

		cert := &platformv1.DeviceIdentityCertificate{
			Pem:                []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			SubjectCn:          "device-001",
			IssuerCn:           "Test CA",
			SerialNumber:       "1234567890",
			Fingerprint:        "abc123",
			KeyAlgorithm:       "ECDSA",
			SignatureAlgorithm: "SHA256-ECDSA",
			KeySize:            256,
			IssuedAt:           timestamppb.New(issuedAt),
			ExpiresAt:          timestamppb.New(expiresAt),
		}

		printCertificateDetails(printer, cert, "IDevID")

		result := output.String()
		assert.Contains(t, result, "device-001")
		assert.Contains(t, result, "Test CA")
		assert.Contains(t, result, "1234567890")
		assert.Contains(t, result, "abc123")
	})
}

// =============================================================================
// printStatusDetails Tests
// =============================================================================

func TestPrintStatusDetails(t *testing.T) {
	t.Run("with message", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		status := &platformv1.Status{
			Success: true,
			Message: "Key generated successfully",
		}

		printStatusDetails(printer, status, "ECDSA-P256")

		result := output.String()
		assert.Contains(t, result, "ECDSA-P256")
		assert.Contains(t, result, "Key generated successfully")
	})

	t.Run("without message", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		status := &platformv1.Status{
			Success: true,
		}

		printStatusDetails(printer, status, "RSA-2048")

		result := output.String()
		assert.Contains(t, result, "RSA-2048")
	})
}
