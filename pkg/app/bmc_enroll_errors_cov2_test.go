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

package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// w1bmcCause is the shared sentinel used across BMC enroll error tests.
var w1bmcCause = errors.New("w1bmc: underlying cause")

// =============================================================================
// ErrBMCEnrollNoTrustResolver
// =============================================================================

func TestW1_ErrBMCEnrollNoTrustResolver_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollNoTrustResolver{}
	assert.Contains(t, e.Error(), "BMC enrollment")
	assert.Contains(t, e.Error(), "trust resolver")
	assert.NotEmpty(t, e.Error())
}

func TestW1_ErrBMCEnrollNoTrustResolver_ImplementsError(t *testing.T) {
	t.Parallel()
	var err error = ErrBMCEnrollNoTrustResolver{}
	require.NotNil(t, err)
}

// =============================================================================
// ErrBMCEnrollFactoryCert
// =============================================================================

func TestW1_ErrBMCEnrollFactoryCert_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollFactoryCert{DeviceID: 42, Cause: w1bmcCause}
	assert.Contains(t, e.Error(), "42")
	assert.Contains(t, e.Error(), "factory cert")
	assert.Contains(t, e.Error(), "w1bmc: underlying cause")
}

func TestW1_ErrBMCEnrollFactoryCert_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollFactoryCert{DeviceID: 1, Cause: w1bmcCause}
	assert.Equal(t, w1bmcCause, e.Unwrap())
	assert.ErrorIs(t, e, w1bmcCause)
}

func TestW1_ErrBMCEnrollFactoryCert_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollFactoryCert{DeviceID: 99}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "99")
}

// =============================================================================
// ErrBMCEnrollCertVerify
// =============================================================================

func TestW1_ErrBMCEnrollCertVerify_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCertVerify{DeviceID: 7, Cause: w1bmcCause}
	assert.Contains(t, e.Error(), "7")
	assert.Contains(t, e.Error(), "cert verification")
	assert.Contains(t, e.Error(), "w1bmc: underlying cause")
}

func TestW1_ErrBMCEnrollCertVerify_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCertVerify{DeviceID: 7, Cause: w1bmcCause}
	assert.Equal(t, w1bmcCause, e.Unwrap())
	assert.ErrorIs(t, e, w1bmcCause)
}

func TestW1_ErrBMCEnrollCertVerify_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCertVerify{DeviceID: 7}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "7")
}

// =============================================================================
// ErrBMCEnrollNoInternalZone
// =============================================================================

func TestW1_ErrBMCEnrollNoInternalZone_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollNoInternalZone{DeviceID: 55}
	assert.Contains(t, e.Error(), "55")
	assert.Contains(t, e.Error(), "dns-register")
	assert.Contains(t, e.Error(), "zone")
	assert.NotEmpty(t, e.Error())
}

func TestW1_ErrBMCEnrollNoInternalZone_ImplementsError(t *testing.T) {
	t.Parallel()
	var err error = ErrBMCEnrollNoInternalZone{DeviceID: 1}
	require.NotNil(t, err)
}

// =============================================================================
// ErrBMCEnrollCredStore
// =============================================================================

func TestW1_ErrBMCEnrollCredStore_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCredStore{DeviceID: 100, Cause: w1bmcCause}
	assert.Contains(t, e.Error(), "100")
	assert.Contains(t, e.Error(), "credential store")
	assert.Contains(t, e.Error(), "w1bmc: underlying cause")
}

func TestW1_ErrBMCEnrollCredStore_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCredStore{DeviceID: 100, Cause: w1bmcCause}
	assert.Equal(t, w1bmcCause, e.Unwrap())
	assert.ErrorIs(t, e, w1bmcCause)
}

func TestW1_ErrBMCEnrollCredStore_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollCredStore{DeviceID: 100}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "100")
}

// =============================================================================
// ErrBMCEnrollDeviceSave
// =============================================================================

func TestW1_ErrBMCEnrollDeviceSave_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceSave{DeviceID: 200, Cause: w1bmcCause}
	assert.Contains(t, e.Error(), "200")
	assert.Contains(t, e.Error(), "device save")
	assert.Contains(t, e.Error(), "w1bmc: underlying cause")
}

func TestW1_ErrBMCEnrollDeviceSave_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceSave{DeviceID: 200, Cause: w1bmcCause}
	assert.Equal(t, w1bmcCause, e.Unwrap())
	assert.ErrorIs(t, e, w1bmcCause)
}

func TestW1_ErrBMCEnrollDeviceSave_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceSave{DeviceID: 200}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "200")
}

// =============================================================================
// ErrBMCEnrollDeviceLoad
// =============================================================================

func TestW1_ErrBMCEnrollDeviceLoad_Error(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceLoad{DeviceID: 300, Cause: w1bmcCause}
	assert.Contains(t, e.Error(), "300")
	assert.Contains(t, e.Error(), "device load")
	assert.Contains(t, e.Error(), "w1bmc: underlying cause")
}

func TestW1_ErrBMCEnrollDeviceLoad_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceLoad{DeviceID: 300, Cause: w1bmcCause}
	assert.Equal(t, w1bmcCause, e.Unwrap())
	assert.ErrorIs(t, e, w1bmcCause)
}

func TestW1_ErrBMCEnrollDeviceLoad_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBMCEnrollDeviceLoad{DeviceID: 300}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "300")
}

// =============================================================================
// Table-driven completeness sweep
// =============================================================================

// TestW1_BMCEnrollErrors_AllNonEmpty verifies every BMC enrollment error type
// produces a non-empty, non-panicking message.
func TestW1_BMCEnrollErrors_AllNonEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"ErrBMCEnrollNoTrustResolver", ErrBMCEnrollNoTrustResolver{}},
		{"ErrBMCEnrollFactoryCert", ErrBMCEnrollFactoryCert{DeviceID: 1, Cause: w1bmcCause}},
		{"ErrBMCEnrollCertVerify", ErrBMCEnrollCertVerify{DeviceID: 2, Cause: w1bmcCause}},
		{"ErrBMCEnrollNoInternalZone", ErrBMCEnrollNoInternalZone{DeviceID: 3}},
		{"ErrBMCEnrollCredStore", ErrBMCEnrollCredStore{DeviceID: 4, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceSave", ErrBMCEnrollDeviceSave{DeviceID: 5, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceLoad", ErrBMCEnrollDeviceLoad{DeviceID: 6, Cause: w1bmcCause}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

// TestW1_BMCEnrollErrors_Unwrap verifies wrapping error types return the cause
// from Unwrap.
func TestW1_BMCEnrollErrors_Unwrap(t *testing.T) {
	t.Parallel()
	type unwrapper interface{ Unwrap() error }
	tests := []struct {
		name string
		err  unwrapper
	}{
		{"ErrBMCEnrollFactoryCert", ErrBMCEnrollFactoryCert{DeviceID: 1, Cause: w1bmcCause}},
		{"ErrBMCEnrollCertVerify", ErrBMCEnrollCertVerify{DeviceID: 2, Cause: w1bmcCause}},
		{"ErrBMCEnrollCredStore", ErrBMCEnrollCredStore{DeviceID: 4, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceSave", ErrBMCEnrollDeviceSave{DeviceID: 5, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceLoad", ErrBMCEnrollDeviceLoad{DeviceID: 6, Cause: w1bmcCause}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, w1bmcCause, tt.err.Unwrap())
		})
	}
}

// TestW1_BMCEnrollErrors_DeviceIDZero verifies zero DeviceID renders correctly.
func TestW1_BMCEnrollErrors_DeviceIDZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"ErrBMCEnrollFactoryCert", ErrBMCEnrollFactoryCert{DeviceID: 0, Cause: w1bmcCause}},
		{"ErrBMCEnrollCertVerify", ErrBMCEnrollCertVerify{DeviceID: 0, Cause: w1bmcCause}},
		{"ErrBMCEnrollNoInternalZone", ErrBMCEnrollNoInternalZone{DeviceID: 0}},
		{"ErrBMCEnrollCredStore", ErrBMCEnrollCredStore{DeviceID: 0, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceSave", ErrBMCEnrollDeviceSave{DeviceID: 0, Cause: w1bmcCause}},
		{"ErrBMCEnrollDeviceLoad", ErrBMCEnrollDeviceLoad{DeviceID: 0, Cause: w1bmcCause}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Zero device ID should still produce a valid (non-empty) error string.
			assert.NotEmpty(t, tt.err.Error())
			assert.Contains(t, tt.err.Error(), "0")
		})
	}
}
