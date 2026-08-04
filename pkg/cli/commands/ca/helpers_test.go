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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// =============================================================================
// parseKeyAlgorithm Tests
// =============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  casvc.KeyAlgorithm
		expectErr bool
	}{
		{"RSA-2048", "RSA-2048", casvc.KeyAlgorithmRSA2048, false},
		{"RSA-2048 lowercase", "rsa-2048", casvc.KeyAlgorithmRSA2048, false},
		{"RSA-3072", "RSA-3072", casvc.KeyAlgorithmRSA3072, false},
		{"RSA-4096", "RSA-4096", casvc.KeyAlgorithmRSA4096, false},
		{"ECDSA-P256", "ECDSA-P256", casvc.KeyAlgorithmECDSAP256, false},
		{"EC-P256", "EC-P256", casvc.KeyAlgorithmECDSAP256, false},
		{"ECDSA-P384", "ECDSA-P384", casvc.KeyAlgorithmECDSAP384, false},
		{"EC-P384", "EC-P384", casvc.KeyAlgorithmECDSAP384, false},
		{"ED25519", "ED25519", casvc.KeyAlgorithmEd25519, false},
		{"ed25519 lowercase", "ed25519", casvc.KeyAlgorithmEd25519, false},
		{"invalid algorithm", "DSA", casvc.KeyAlgorithmUnspecified, true},
		{"empty string", "", casvc.KeyAlgorithmUnspecified, true},
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
		expected  casvc.CertificateStatus
		expectErr bool
	}{
		{"all", "all", casvc.CertificateStatusUnspecified, false},
		{"empty", "", casvc.CertificateStatusUnspecified, false},
		{"valid", "valid", casvc.CertificateStatusValid, false},
		{"active", "active", casvc.CertificateStatusValid, false},
		{"revoked", "revoked", casvc.CertificateStatusRevoked, false},
		{"expired", "expired", casvc.CertificateStatusExpired, false},
		{"pending", "pending", casvc.CertificateStatusPending, false},
		{"VALID uppercase", "VALID", casvc.CertificateStatusValid, false},
		{"invalid status", "suspended", casvc.CertificateStatusUnspecified, true},
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
		expected  casvc.RevocationReason
		expectErr bool
	}{
		{"unspecified", "unspecified", casvc.RevocationReasonUnspecified, false},
		{"empty", "", casvc.RevocationReasonUnspecified, false},
		{"key-compromise", "key-compromise", casvc.RevocationReasonKeyCompromise, false},
		{"keycompromise", "keycompromise", casvc.RevocationReasonKeyCompromise, false},
		{"ca-compromise", "ca-compromise", casvc.RevocationReasonCACompromise, false},
		{"cacompromise", "cacompromise", casvc.RevocationReasonCACompromise, false},
		{"affiliation-changed", "affiliation-changed", casvc.RevocationReasonAffiliationChanged, false},
		{"affiliationchanged", "affiliationchanged", casvc.RevocationReasonAffiliationChanged, false},
		{"superseded", "superseded", casvc.RevocationReasonSuperseded, false},
		{"cessation", "cessation", casvc.RevocationReasonCessationOfOperation, false},
		{"cessation-of-operation", "cessation-of-operation", casvc.RevocationReasonCessationOfOperation, false},
		{"hold", "hold", casvc.RevocationReasonCertificateHold, false},
		{"certificate-hold", "certificate-hold", casvc.RevocationReasonCertificateHold, false},
		{"privilege-withdrawn", "privilege-withdrawn", casvc.RevocationReasonPrivilegeWithdrawn, false},
		{"privilegewithdrawn", "privilegewithdrawn", casvc.RevocationReasonPrivilegeWithdrawn, false},
		{"invalid reason", "bad-reason", casvc.RevocationReasonUnspecified, true},
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
// formatBool / formatTime Tests
// =============================================================================

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "Yes", formatBool(true))
	assert.Equal(t, "No", formatBool(false))
}

func TestFormatTime(t *testing.T) {
	t.Run("zero time", func(t *testing.T) {
		assert.Equal(t, "N/A", formatTime(time.Time{}))
	})

	t.Run("valid time", func(t *testing.T) {
		ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
		result := formatTime(ts)
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
		cert := &casvc.Certificate{
			Serial: "123456",
			Subject: &casvc.Subject{
				CommonName:   "example.com",
				Organization: "Test Org",
			},
			Issuer:             "CN=Root CA",
			NotBefore:          time.Now(),
			NotAfter:           time.Now(),
			Status:             casvc.CertificateStatusValid,
			KeyAlgorithm:       casvc.KeyAlgorithmRSA2048,
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
		cert := &casvc.Certificate{
			Serial:  "999",
			Subject: &casvc.Subject{CommonName: "test.local"},
			Issuer:  "CN=CA",
			Status:  casvc.CertificateStatusRevoked,
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
		printCAInfoTable(printer, nil)
		assert.Contains(t, output.String(), "No CA information available")
	})

	t.Run("basic ca info", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		info := &casvc.CAInfo{
			IsInitialized:       true,
			CommonName:          "Root CA",
			IsIntermediate:      false,
			DefaultAlgorithm:    "RSA-2048",
			DefaultValidityDays: 365,
		}
		printCAInfoTable(printer, info)
		out := output.String()
		assert.Contains(t, out, "Root CA")
		assert.Contains(t, out, "Yes")
	})

	t.Run("ca info with root cert", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		info := &casvc.CAInfo{
			IsInitialized:       true,
			CommonName:          "Root CA",
			DefaultAlgorithm:    "RSA-2048",
			DefaultValidityDays: 365,
			RootCert: &casvc.CertificateSummary{
				CommonName:   "Root CA",
				Serial:       "001",
				Issuer:       "CN=Root CA",
				Status:       casvc.CertificateStatusValid,
				KeyAlgorithm: casvc.KeyAlgorithmRSA2048,
			},
		}
		printCAInfoTable(printer, info)
		out := output.String()
		assert.Contains(t, out, "Root CA")
	})

	t.Run("ca info with intermediates", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		info := &casvc.CAInfo{
			IsInitialized:       true,
			CommonName:          "Root CA",
			DefaultAlgorithm:    "RSA-2048",
			DefaultValidityDays: 365,
			Intermediates: []*casvc.CertificateSummary{
				{CommonName: "Intermediate CA", Serial: "002"},
			},
		}
		printCAInfoTable(printer, info)
		out := output.String()
		assert.Contains(t, out, "Root CA")
	})

	t.Run("ca info with keystores", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
		info := &casvc.CAInfo{
			IsInitialized:       true,
			CommonName:          "Root CA",
			DefaultAlgorithm:    "RSA-2048",
			DefaultValidityDays: 365,
			KeyStores: []*casvc.KeyStoreInfo{
				{Type: "software", Available: true, Capabilities: []string{"sign", "verify"}},
				{Type: "tpm", Available: false},
			},
		}
		printCAInfoTable(printer, info)
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
