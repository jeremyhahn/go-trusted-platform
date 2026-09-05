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

package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

// #483: these converters set `Verified: true` from a literal, so the field was
// true for every attestation they ever converted. These assert the verdict
// reaches the response — restore the literal and both fail.

// TestVMResponseCarriesTheVerdictItWasGiven.
//
// The converter must not decide anything; it must report what the verifier
// returned. Asserting a FAILING verdict propagates is the half that catches a
// literal — a passing one is indistinguishable from `Verified: true`.
func TestVMResponseCarriesTheVerdictItWasGiven(t *testing.T) {
	h := &AttestationHandlers{}
	evidence := &manifest.VMAttestation{VMID: "vm-1", HostID: "host-1"}

	v := verdict.VerifyVMAttestation(evidence, []byte("a-nonce"))
	require.False(t, v.Verified, "fixture must be unverifiable, or this asserts nothing")

	resp := h.vmAttestationToResponse(evidence, v)

	require.NotNil(t, resp)
	assert.False(t, resp.Verified,
		"the response reported verified for evidence the verifier rejected (#483)")
	assert.Equal(t, string(v.Status), resp.VerificationStatus)
	assert.Equal(t, v.Reason, resp.VerificationError)
	assert.NotEmpty(t, resp.VerificationError)
}

// TestContainerResponseCarriesTheVerdictItWasGiven — the same for containers,
// where the evidence carries no signature at all and so can never be a pass.
func TestContainerResponseCarriesTheVerdictItWasGiven(t *testing.T) {
	h := &AttestationHandlers{}
	evidence := &manifest.ContainerAttestation{
		ContainerID: "ctr-1",
		Digest:      []byte("d"),
		PCRValue:    []byte("p"),
	}

	v := verdict.VerifyContainerAttestation(evidence)
	require.False(t, v.Verified)

	resp := h.containerAttestationToResponse(evidence, v)

	require.NotNil(t, resp)
	assert.False(t, resp.Verified,
		"the response reported verified for container evidence nothing verified (#483)")
	assert.Equal(t, string(verdict.StatusNotEvaluated), resp.VerificationStatus)
	assert.Contains(t, resp.VerificationError, "no signature")
}

// TestVMResponseCanStillReportAPass is the control. Without it a converter
// that hardcoded `Verified: false` would satisfy both tests above — the same
// defect with the sign flipped.
func TestVMResponseCanStillReportAPass(t *testing.T) {
	h := &AttestationHandlers{}
	resp := h.vmAttestationToResponse(
		&manifest.VMAttestation{VMID: "vm-1"},
		verdict.WorkloadVerdict{Status: verdict.StatusVerified, Verified: true},
	)

	require.NotNil(t, resp)
	assert.True(t, resp.Verified)
	assert.Equal(t, string(verdict.StatusVerified), resp.VerificationStatus)
	assert.Empty(t, resp.VerificationError)
}
