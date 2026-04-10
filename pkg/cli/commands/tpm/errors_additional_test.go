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
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// TPM Service Error Tests
// =============================================================================

func TestErrTPMInfoFailed(t *testing.T) {
	err := ErrTPMInfoFailed{Reason: "connection refused"}
	assert.Equal(t, "failed to get TPM info: connection refused", err.Error())
}

func TestErrTPMProvisionFailed(t *testing.T) {
	err := ErrTPMProvisionFailed{Reason: "authorization error"}
	assert.Equal(t, "failed to provision TPM: authorization error", err.Error())
}

func TestErrTPMClearFailed(t *testing.T) {
	err := ErrTPMClearFailed{Reason: "lockout enabled"}
	assert.Equal(t, "failed to clear TPM: lockout enabled", err.Error())
}

func TestErrDaemonConnectionRequired(t *testing.T) {
	err := ErrDaemonConnectionRequired{Operation: "install"}
	assert.Equal(t, "daemon connection required: operation 'install' not yet supported", err.Error())
}

// =============================================================================
// EK Error Tests
// =============================================================================

func TestErrEKCreateFailed(t *testing.T) {
	err := ErrEKCreateFailed{Reason: "TPM busy"}
	assert.Equal(t, "failed to create EK: TPM busy", err.Error())
}

func TestErrEKNotFound(t *testing.T) {
	err := ErrEKNotFound{Reason: "handle not found"}
	assert.Equal(t, "EK not found: handle not found", err.Error())
}

func TestErrEKCertificateNotFound(t *testing.T) {
	err := ErrEKCertificateNotFound{Reason: "NV index empty"}
	assert.Equal(t, "EK certificate not found: NV index empty", err.Error())
}

func TestErrEKDeleteFailed(t *testing.T) {
	err := ErrEKDeleteFailed{Reason: "authorization failed"}
	assert.Equal(t, "failed to delete EK: authorization failed", err.Error())
}

func TestErrInvalidKeyAlgorithm(t *testing.T) {
	err := ErrInvalidKeyAlgorithm{Algorithm: "INVALID-ALG"}
	assert.Equal(t, "invalid key algorithm: INVALID-ALG", err.Error())
}

// =============================================================================
// SRK Error Tests
// =============================================================================

func TestErrSRKCreateFailed(t *testing.T) {
	err := ErrSRKCreateFailed{Reason: "parent not found"}
	assert.Equal(t, "failed to create SRK: parent not found", err.Error())
}

func TestErrSRKNotFound(t *testing.T) {
	err := ErrSRKNotFound{Reason: "handle not found"}
	assert.Equal(t, "SRK not found: handle not found", err.Error())
}

func TestErrSRKDeleteFailed(t *testing.T) {
	err := ErrSRKDeleteFailed{Reason: "authorization error"}
	assert.Equal(t, "failed to delete SRK: authorization error", err.Error())
}

// =============================================================================
// Seal/Unseal Error Tests
// =============================================================================

func TestErrSealFailed(t *testing.T) {
	err := ErrSealFailed{Reason: "PCR mismatch"}
	assert.Equal(t, "failed to seal data: PCR mismatch", err.Error())
}

func TestErrUnsealFailed(t *testing.T) {
	err := ErrUnsealFailed{Reason: "policy not satisfied"}
	assert.Equal(t, "failed to unseal data: policy not satisfied", err.Error())
}

// =============================================================================
// Event Log Error Tests
// =============================================================================

func TestErrEventLogFailed(t *testing.T) {
	err := ErrEventLogFailed{Reason: "file not found"}
	assert.Equal(t, "failed to get event log: file not found", err.Error())
}

// =============================================================================
// NVRAM Error Tests
// =============================================================================

func TestErrNVRAMDefineFailed(t *testing.T) {
	err := ErrNVRAMDefineFailed{Index: 0x01000001, Reason: "index already exists"}
	assert.Equal(t, "failed to define NV index 0x01000001: index already exists", err.Error())
}

func TestErrNVRAMWriteFailed(t *testing.T) {
	err := ErrNVRAMWriteFailed{Index: 0x01000001, Reason: "write locked"}
	assert.Equal(t, "failed to write NV index 0x01000001: write locked", err.Error())
}

func TestErrNVRAMReadFailed(t *testing.T) {
	err := ErrNVRAMReadFailed{Index: 0x01000001, Reason: "read locked"}
	assert.Equal(t, "failed to read NV index 0x01000001: read locked", err.Error())
}

func TestErrNVRAMDeleteFailed(t *testing.T) {
	err := ErrNVRAMDeleteFailed{Index: 0x01000001, Reason: "authorization failed"}
	assert.Equal(t, "failed to delete NV index 0x01000001: authorization failed", err.Error())
}
