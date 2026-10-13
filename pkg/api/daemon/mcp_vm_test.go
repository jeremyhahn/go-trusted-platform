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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The MCP VM attestation tools carry the quote's declared signature scheme
// out of vm_attest and back into vm_attest_verify, so a verifier never has
// to infer it from the AK key type (#482).
func TestMCPServiceProvider_VMAttest_CarriesSignatureAlgorithm(t *testing.T) {
	provider := &MCPServiceProvider{computeOrchestrator: newVMCapableMockOrchestrator()}

	result, err := provider.VMAttest(context.Background(), "vm1", []byte("nonce"), []int{0, 7})
	require.NoError(t, err)

	out, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), out["signature_algorithm"])
}

func TestMCPServiceProvider_VMAttest_NoCompute(t *testing.T) {
	provider := &MCPServiceProvider{}

	_, err := provider.VMAttest(context.Background(), "vm1", []byte("nonce"), nil)
	require.ErrorAs(t, err, &ErrVMComputeNotAvailable{})
}

func TestMCPServiceProvider_VMAttestVerify_ForwardsSignatureAlgorithm(t *testing.T) {
	orchestrator := newVMCapableMockOrchestrator()
	provider := &MCPServiceProvider{computeOrchestrator: orchestrator}

	_, err := provider.VMAttestVerify(context.Background(), "vm1", &mcp.VMAttestVerifyMCPRequest{
		Quote:              []byte("quote"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		Nonce:              []byte("nonce"),
	})
	require.NoError(t, err)

	require.NotNil(t, orchestrator.lastEvidence)
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), orchestrator.lastEvidence.SignatureAlgorithm)
}

func TestMCPServiceProvider_VMAttestVerify_NilEvidence(t *testing.T) {
	provider := &MCPServiceProvider{computeOrchestrator: newVMCapableMockOrchestrator()}

	_, err := provider.VMAttestVerify(context.Background(), "vm1", nil)
	require.ErrorAs(t, err, &ErrVMEvidenceRequired{})
}
