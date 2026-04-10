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

package bmc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrServerURLRequired(t *testing.T) {
	err := ErrServerURLRequired{}
	assert.Equal(t, "bmc: --server-url is required", err.Error())
}

func TestErrProfileIDRequired(t *testing.T) {
	err := ErrProfileIDRequired{}
	assert.Equal(t, "bmc: --profile-id is required", err.Error())
}

func TestErrISOURLRequired(t *testing.T) {
	err := ErrISOURLRequired{}
	assert.Equal(t, "bmc: --iso-url is required", err.Error())
}

func TestErrDeviceRequired(t *testing.T) {
	err := ErrDeviceRequired{}
	assert.Equal(t, "bmc: --device is required", err.Error())
}

func TestErrRequestFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrRequestFailed{URL: "https://platform:8443/api/v1/bmc/server-01/power", Cause: cause}
	assert.Contains(t, err.Error(), "https://platform:8443/api/v1/bmc/server-01/power")
	assert.Contains(t, err.Error(), "request to")
	assert.ErrorIs(t, err, cause)
}

func TestErrRequestFailed_NilCause(t *testing.T) {
	err := ErrRequestFailed{URL: "https://example.com", Cause: nil}
	assert.Contains(t, err.Error(), "https://example.com")
	assert.Nil(t, err.Unwrap())
}

func TestErrUnexpectedStatus(t *testing.T) {
	err := ErrUnexpectedStatus{StatusCode: 503, Body: "service unavailable"}
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "service unavailable")
}

func TestErrUnexpectedStatus_404(t *testing.T) {
	err := ErrUnexpectedStatus{StatusCode: 404, Body: "not found"}
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrResponseDecodeFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrResponseDecodeFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to decode")
	assert.ErrorIs(t, err, cause)
}

func TestErrResponseDecodeFailed_NilCause(t *testing.T) {
	err := ErrResponseDecodeFailed{Cause: nil}
	assert.Contains(t, err.Error(), "failed to decode")
	assert.Nil(t, err.Unwrap())
}

func TestErrInvalidPowerAction(t *testing.T) {
	err := ErrInvalidPowerAction{Action: "hibernate"}
	assert.Contains(t, err.Error(), "hibernate")
	assert.Contains(t, err.Error(), "valid: on, off, reset, cycle")
}

func TestErrInvalidPowerAction_Empty(t *testing.T) {
	err := ErrInvalidPowerAction{Action: ""}
	assert.Contains(t, err.Error(), "invalid power action")
}

func TestErrInvalidBootDevice(t *testing.T) {
	err := ErrInvalidBootDevice{Device: "floppy"}
	assert.Contains(t, err.Error(), "floppy")
	assert.Contains(t, err.Error(), "valid: pxe, disk, cdrom, bios")
}

func TestErrInvalidBootDevice_Empty(t *testing.T) {
	err := ErrInvalidBootDevice{Device: ""}
	assert.Contains(t, err.Error(), "invalid boot device")
}

func TestErrRequestBuildFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrRequestBuildFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to build request")
	assert.ErrorIs(t, err, cause)
}

func TestErrRequestBuildFailed_NilCause(t *testing.T) {
	err := ErrRequestBuildFailed{Cause: nil}
	assert.Contains(t, err.Error(), "failed to build request")
	assert.Nil(t, err.Unwrap())
}

func TestErrRequestEncodeFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrRequestEncodeFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to encode request body")
	assert.ErrorIs(t, err, cause)
}

func TestErrRequestEncodeFailed_NilCause(t *testing.T) {
	err := ErrRequestEncodeFailed{Cause: nil}
	assert.Contains(t, err.Error(), "failed to encode request body")
	assert.Nil(t, err.Unwrap())
}

// =============================================================================
// Error Interface Compliance Tests
// =============================================================================

func TestErrorTypes_ImplementError(t *testing.T) {
	// Verify all error types satisfy the error interface
	var _ error = ErrServerURLRequired{}
	var _ error = ErrProfileIDRequired{}
	var _ error = ErrISOURLRequired{}
	var _ error = ErrDeviceRequired{}
	var _ error = ErrRequestFailed{}
	var _ error = ErrUnexpectedStatus{}
	var _ error = ErrResponseDecodeFailed{}
	var _ error = ErrInvalidPowerAction{}
	var _ error = ErrInvalidBootDevice{}
	var _ error = ErrRequestBuildFailed{}
	var _ error = ErrRequestEncodeFailed{}
}

func TestWrappingErrors_Unwrap(t *testing.T) {
	cause := assert.AnError

	tests := []struct {
		name string
		err  error
	}{
		{"ErrRequestFailed", ErrRequestFailed{URL: "https://example.com", Cause: cause}},
		{"ErrResponseDecodeFailed", ErrResponseDecodeFailed{Cause: cause}},
		{"ErrRequestBuildFailed", ErrRequestBuildFailed{Cause: cause}},
		{"ErrRequestEncodeFailed", ErrRequestEncodeFailed{Cause: cause}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.err, cause)
		})
	}
}
