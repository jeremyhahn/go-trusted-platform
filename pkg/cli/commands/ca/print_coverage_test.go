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

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// printCRLDetails Tests
// =============================================================================

func TestPrintCRLDetails_NilCRL(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &platformv1.GetCRLResponse{Crl: nil}
	printCRLDetails(printer, resp)
	assert.Contains(t, output.String(), "No CRL data available")
}

func TestPrintCRLDetails_Empty(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &platformv1.GetCRLResponse{
		Crl: &platformv1.CRL{
			LastUpdate:   timestamppb.Now(),
			NextUpdate:   timestamppb.Now(),
			RevokedCount: 0,
		},
	}
	printCRLDetails(printer, resp)
	out := output.String()
	assert.Contains(t, out, "0")
}

func TestPrintCRLDetails_WithRevokedCerts(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &platformv1.GetCRLResponse{
		Crl: &platformv1.CRL{
			LastUpdate:   timestamppb.Now(),
			NextUpdate:   timestamppb.Now(),
			RevokedCount: 2,
			RevokedCerts: []*platformv1.RevokedCertEntry{
				{
					Serial:         "ABC123",
					RevocationTime: timestamppb.Now(),
					Reason:         platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
				},
				{
					Serial:         "DEF456",
					RevocationTime: timestamppb.Now(),
					Reason:         platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED,
				},
			},
		},
	}
	printCRLDetails(printer, resp)
	out := output.String()
	assert.Contains(t, out, "2")
}

// =============================================================================
// printVerificationResult Tests
// =============================================================================

func TestPrintVerificationResult_Valid(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)
	resp := &platformv1.VerifyCertificateResponse{
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
	resp := &platformv1.VerifyCertificateResponse{
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
	resp := &platformv1.VerifyCertificateResponse{
		Valid: true,
	}
	printVerificationResult(printer, resp)
	assert.Contains(t, output.String(), "valid")
}
