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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestComputeHandlers_VerifyVMAttestation_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify", VerifyVMAttestationRequest{
		Quote:     b64([]byte("quote")),
		Signature: b64([]byte("signature")),
		Nonce:     b64([]byte("nonce")),
		ExpectedPCRs: map[int]string{
			0: b64([]byte{0x01}),
		},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp VerifyVMAttestationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "vm-1", resp.VMID)
	assert.True(t, resp.Verified)
	assert.True(t, resp.SignatureValid)
	assert.True(t, resp.NonceValid)
	assert.True(t, resp.PCRsValid)
	assert.Equal(t, "attestation verified", resp.Message)
}

func TestComputeHandlers_VerifyVMAttestation_InvalidBase64(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify", VerifyVMAttestationRequest{
		Quote:     "!!!not-base64!!!",
		Signature: b64([]byte("signature")),
		Nonce:     b64([]byte("nonce")),
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_VerifyVMAttestation_NotSupported(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify", VerifyVMAttestationRequest{
		Quote:     b64([]byte("quote")),
		Signature: b64([]byte("signature")),
		Nonce:     b64([]byte("nonce")),
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestComputeHandlers_VerifyVMAttestation_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify", VerifyVMAttestationRequest{
		Quote:     b64([]byte("quote")),
		Signature: b64([]byte("signature")),
		Nonce:     b64([]byte("nonce")),
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_VerifyVMAttestation_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/missing/attest/verify", VerifyVMAttestationRequest{
		Quote:     b64([]byte("quote")),
		Signature: b64([]byte("signature")),
		Nonce:     b64([]byte("nonce")),
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
