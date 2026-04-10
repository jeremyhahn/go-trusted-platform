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

package ca

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// parseKeyAlgorithm Tests
// =============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  platformv1.KeyAlgorithm
		expectErr bool
	}{
		{"RSA-2048", "RSA-2048", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, false},
		{"RSA-2048 lowercase", "rsa-2048", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, false},
		{"RSA-3072", "RSA-3072", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, false},
		{"RSA-4096", "RSA-4096", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, false},
		{"ECDSA-P256", "ECDSA-P256", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, false},
		{"EC-P256", "EC-P256", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, false},
		{"ECDSA-P384", "ECDSA-P384", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, false},
		{"EC-P384", "EC-P384", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, false},
		{"ED25519", "ED25519", platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, false},
		{"ed25519 lowercase", "ed25519", platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, false},
		{"invalid algorithm", "DSA", platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, true},
		{"empty string", "", platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseKeyAlgorithm(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				assert.IsType(t, ErrInvalidKeyAlgorithm{}, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// =============================================================================
// splitCSV Tests
// =============================================================================

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty string", "", nil},
		{"single value", "web", []string{"web"}},
		{"multiple values", "web,email", []string{"web", "email"}},
		{"with spaces", " web , email , tls ", []string{"web", "email", "tls"}},
		{"trailing comma", "web,email,", []string{"web", "email"}},
		{"empty entries filtered", "web,,email", []string{"web", "email"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitCSV(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// parseStatusFilter Tests
// =============================================================================

func TestParseStatusFilter(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  platformv1.CertificateStatus
		expectErr bool
	}{
		{"all", "all", platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED, false},
		{"empty", "", platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED, false},
		{"valid", "valid", platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, false},
		{"active", "active", platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, false},
		{"revoked", "revoked", platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED, false},
		{"expired", "expired", platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED, false},
		{"pending", "pending", platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING, false},
		{"VALID uppercase", "VALID", platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, false},
		{"invalid status", "suspended", platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseStatusFilter(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				assert.IsType(t, ErrInvalidStatus{}, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// =============================================================================
// parseRevocationReason Tests
// =============================================================================

func TestParseRevocationReason(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  platformv1.RevocationReason
		expectErr bool
	}{
		{"unspecified", "unspecified", platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED, false},
		{"empty", "", platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED, false},
		{"key-compromise", "key-compromise", platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, false},
		{"keycompromise", "keycompromise", platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, false},
		{"ca-compromise", "ca-compromise", platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE, false},
		{"cacompromise", "cacompromise", platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE, false},
		{"affiliation-changed", "affiliation-changed", platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED, false},
		{"affiliationchanged", "affiliationchanged", platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED, false},
		{"superseded", "superseded", platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED, false},
		{"cessation", "cessation", platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION, false},
		{"cessation-of-operation", "cessation-of-operation", platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION, false},
		{"hold", "hold", platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD, false},
		{"certificate-hold", "certificate-hold", platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD, false},
		{"privilege-withdrawn", "privilege-withdrawn", platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, false},
		{"privilegewithdrawn", "privilegewithdrawn", platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, false},
		{"invalid reason", "bad-reason", platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseRevocationReason(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				assert.IsType(t, ErrInvalidRevocationReason{}, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// =============================================================================
// truncateString / truncateSerial Tests
// =============================================================================

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short unchanged", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world foo", 8, "hello..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, truncateString(tt.input, tt.maxLen))
		})
	}
}

func TestTruncateSerial(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short unchanged", "ABC123", 10, "ABC123"},
		{"exact length", "ABC12", 5, "ABC12"},
		{"truncated", "ABCDEFGHIJKLMNO", 8, "ABCDE..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, truncateSerial(tt.input, tt.maxLen))
		})
	}
}

// =============================================================================
// formatBool / formatTimestamp Tests
// =============================================================================

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "Yes", formatBool(true))
	assert.Equal(t, "No", formatBool(false))
}

func TestFormatTimestamp(t *testing.T) {
	t.Run("nil timestamp", func(t *testing.T) {
		assert.Equal(t, "N/A", formatTimestamp(nil))
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
		result := formatTimestamp(ts)
		assert.Contains(t, result, "2025-06-15")
		assert.Contains(t, result, "12:00:00")
	})
}

// =============================================================================
// printCertificateDetails Tests
// =============================================================================

func TestPrintCertificateDetails(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		printCertificateDetails(printer, nil)
		assert.Empty(t, output.String())
	})

	t.Run("full certificate", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		cert := &platformv1.Certificate{
			Serial: "123456",
			Subject: &platformv1.Subject{
				CommonName:   "example.com",
				Organization: "Test Org",
			},
			Issuer:             "CN=Root CA",
			NotBefore:          timestamppb.Now(),
			NotAfter:           timestamppb.Now(),
			Status:             platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
			KeyAlgorithm:       platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
			SignatureAlgorithm: "SHA256WithRSA",
			IsCa:               false,
			FingerprintSha256:  "aa:bb:cc:dd",
		}
		printCertificateDetails(printer, cert)
		out := output.String()
		assert.Contains(t, out, "123456")
		assert.Contains(t, out, "example.com")
		assert.Contains(t, out, "Test Org")
		assert.Contains(t, out, "CN=Root CA")
	})

	t.Run("certificate without org and fingerprint", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		cert := &platformv1.Certificate{
			Serial:  "999",
			Subject: &platformv1.Subject{CommonName: "test.local"},
			Issuer:  "CN=CA",
			Status:  platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		}
		printCertificateDetails(printer, cert)
		out := output.String()
		assert.Contains(t, out, "999")
		assert.Contains(t, out, "test.local")
		assert.NotContains(t, out, "Organization")
	})
}

// =============================================================================
// printCAInfoTable Tests
// =============================================================================

func TestPrintCAInfoTable(t *testing.T) {
	t.Run("nil ca info", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		resp := &platformv1.GetCAInfoResponse{CaInfo: nil}
		printCAInfoTable(printer, resp)
		assert.Contains(t, output.String(), "No CA information available")
	})

	t.Run("basic ca info", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		resp := &platformv1.GetCAInfoResponse{
			CaInfo: &platformv1.CAInfo{
				IsInitialized:       true,
				CommonName:          "Root CA",
				IsIntermediate:      false,
				DefaultAlgorithm:    "RSA-2048",
				DefaultValidityDays: 365,
			},
		}
		printCAInfoTable(printer, resp)
		out := output.String()
		assert.Contains(t, out, "Root CA")
		assert.Contains(t, out, "Yes")
	})

	t.Run("ca info with root cert", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		resp := &platformv1.GetCAInfoResponse{
			CaInfo: &platformv1.CAInfo{
				IsInitialized:       true,
				CommonName:          "Root CA",
				DefaultAlgorithm:    "RSA-2048",
				DefaultValidityDays: 365,
				RootCert: &platformv1.CertificateSummary{
					CommonName:   "Root CA",
					Serial:       "001",
					Issuer:       "CN=Root CA",
					Status:       platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
					KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
				},
			},
		}
		printCAInfoTable(printer, resp)
		out := output.String()
		assert.Contains(t, out, "Root CA")
	})

	t.Run("ca info with intermediates", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		resp := &platformv1.GetCAInfoResponse{
			CaInfo: &platformv1.CAInfo{
				IsInitialized:       true,
				CommonName:          "Root CA",
				DefaultAlgorithm:    "RSA-2048",
				DefaultValidityDays: 365,
				Intermediates: []*platformv1.CertificateSummary{
					{CommonName: "Intermediate CA", Serial: "002"},
				},
			},
		}
		printCAInfoTable(printer, resp)
		out := output.String()
		assert.Contains(t, out, "Root CA")
	})

	t.Run("ca info with keystores", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		resp := &platformv1.GetCAInfoResponse{
			CaInfo: &platformv1.CAInfo{
				IsInitialized:       true,
				CommonName:          "Root CA",
				DefaultAlgorithm:    "RSA-2048",
				DefaultValidityDays: 365,
				KeyStores: []*platformv1.KeyStoreInfo{
					{Type: "software", Available: true, Capabilities: []string{"sign", "verify"}},
					{Type: "tpm", Available: false},
				},
			},
		}
		printCAInfoTable(printer, resp)
		out := output.String()
		assert.Contains(t, out, "Root CA")
	})
}

// =============================================================================
// printCertSummary Tests
// =============================================================================

func TestPrintCertSummary(t *testing.T) {
	t.Run("nil cert summary", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		printCertSummary(printer, nil, "  ")
		assert.Empty(t, output.String())
	})
}

// =============================================================================
// printKeyStoreInfo Tests
// =============================================================================

func TestPrintKeyStoreInfo(t *testing.T) {
	t.Run("nil store info", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		printKeyStoreInfo(printer, nil)
		assert.Empty(t, output.String())
	})
}
