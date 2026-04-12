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

	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// printCRLDetails Tests
// =============================================================================

func TestPrintCRLDetails_NilCRL(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	printCRLDetails(printer, nil)
	assert.Contains(t, output.String(), "No CRL data available")
}

func TestPrintCRLDetails_Empty(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	crl := &casvc.CRL{
		LastUpdate:   time.Now(),
		NextUpdate:   time.Now(),
		RevokedCount: 0,
	}
	printCRLDetails(printer, crl)
	out := output.String()
	assert.Contains(t, out, "0")
}

func TestPrintCRLDetails_WithRevokedCerts(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	crl := &casvc.CRL{
		LastUpdate:   time.Now(),
		NextUpdate:   time.Now(),
		RevokedCount: 2,
		RevokedCerts: []*casvc.RevokedCertEntry{
			{
				Serial:         "ABC123",
				RevocationTime: time.Now(),
				Reason:         casvc.RevocationReasonKeyCompromise,
			},
			{
				Serial:         "DEF456",
				RevocationTime: time.Now(),
				Reason:         casvc.RevocationReasonSuperseded,
			},
		},
	}
	printCRLDetails(printer, crl)
	out := output.String()
	assert.Contains(t, out, "2")
}

// =============================================================================
// printVerificationResult Tests
// =============================================================================

func TestPrintVerificationResult_Valid(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &casvc.VerifyCertificateResult{
		Valid: true,
		Chain: []string{"CN=Root CA", "CN=Intermediate CA", "CN=leaf.example.com"},
	}
	printVerificationResult(printer, resp)
	out := output.String()
	assert.Contains(t, out, "valid")
}

func TestPrintVerificationResult_Invalid(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &casvc.VerifyCertificateResult{
		Valid:    false,
		Errors:   []string{"certificate expired", "chain incomplete"},
		Warnings: []string{"weak key size"},
	}
	printVerificationResult(printer, resp)
	out := output.String()
	assert.Contains(t, out, "invalid")
}

func TestPrintVerificationResult_NoChainNoErrors(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &casvc.VerifyCertificateResult{
		Valid: true,
	}
	printVerificationResult(printer, resp)
	assert.Contains(t, output.String(), "valid")
}
