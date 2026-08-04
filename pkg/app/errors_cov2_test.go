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

// w1sentinel is a reusable sentinel error for the w1 coverage tests.
var w1sentinel = errors.New("w1: sentinel cause")

// =============================================================================
// ErrBarrierRequiresQuicBaaS
// =============================================================================

func TestW1_ErrBarrierRequiresQuicBaaS_Error(t *testing.T) {
	t.Parallel()
	e := ErrBarrierRequiresQuicBaaS{}
	assert.Contains(t, e.Error(), "barrier")
	assert.Contains(t, e.Error(), "QuicBaaS")
	assert.NotEmpty(t, e.Error())
}

func TestW1_ErrBarrierRequiresQuicBaaS_ImplementsError(t *testing.T) {
	t.Parallel()
	var err error = ErrBarrierRequiresQuicBaaS{}
	require.NotNil(t, err)
}

// =============================================================================
// ErrBarrierSyncStatus
// =============================================================================

func TestW1_ErrBarrierSyncStatus_Error(t *testing.T) {
	t.Parallel()
	e := ErrBarrierSyncStatus{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "sync barrier status")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrBarrierSyncStatus_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBarrierSyncStatus{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrBarrierSyncStatus_NilCause(t *testing.T) {
	t.Parallel()
	// Cause field is a non-pointer error; nil is the zero value but
	// the Error() method calls e.Cause.Error() directly — so we only
	// verify Unwrap returns nil here (the nil-cause Error() call would
	// panic and is a caller bug, not a branch in the method body).
	e := ErrBarrierSyncStatus{Cause: w1sentinel}
	require.NotNil(t, e.Unwrap())
}

// =============================================================================
// ErrDANEPublish
// =============================================================================

func TestW1_ErrDANEPublish_Error(t *testing.T) {
	t.Parallel()
	e := ErrDANEPublish{Hostname: "host.example.com", Cause: w1sentinel}
	assert.Contains(t, e.Error(), "DANE TLSA")
	assert.Contains(t, e.Error(), "host.example.com")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrDANEPublish_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrDANEPublish{Hostname: "h", Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrDANEPublish_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrDANEPublish{Hostname: "h.test"}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "h.test")
}

// =============================================================================
// ErrDANECertParse
// =============================================================================

func TestW1_ErrDANECertParse_Error(t *testing.T) {
	t.Parallel()
	e := ErrDANECertParse{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "DANE")
	assert.Contains(t, e.Error(), "certificate")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrDANECertParse_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrDANECertParse{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrDANECertParse_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrDANECertParse{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// ErrDANENoZone
// =============================================================================

func TestW1_ErrDANENoZone_Error(t *testing.T) {
	t.Parallel()
	e := ErrDANENoZone{Hostname: "node.internal.example.com"}
	assert.Contains(t, e.Error(), "DNS zone")
	assert.Contains(t, e.Error(), "node.internal.example.com")
	assert.NotEmpty(t, e.Error())
}

func TestW1_ErrDANENoZone_ImplementsError(t *testing.T) {
	t.Parallel()
	var err error = ErrDANENoZone{Hostname: "host"}
	require.NotNil(t, err)
}

// =============================================================================
// ErrBootstrapClientInit
// =============================================================================

func TestW1_ErrBootstrapClientInit_Error(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapClientInit{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "bootstrap client")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrBootstrapClientInit_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapClientInit{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrBootstrapClientInit_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapClientInit{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// ErrBootstrapFetchBundle
// =============================================================================

func TestW1_ErrBootstrapFetchBundle_Error(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapFetchBundle{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "CA bundle")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrBootstrapFetchBundle_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapFetchBundle{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrBootstrapFetchBundle_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapFetchBundle{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// ErrBootstrapInstallBundle
// =============================================================================

func TestW1_ErrBootstrapInstallBundle_Error(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapInstallBundle{Path: "/usr/local/share/ca-certificates/tp.crt", Cause: w1sentinel}
	assert.Contains(t, e.Error(), "system trust")
	assert.Contains(t, e.Error(), "/usr/local/share/ca-certificates/tp.crt")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrBootstrapInstallBundle_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapInstallBundle{Path: "/p", Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrBootstrapInstallBundle_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapInstallBundle{Path: "/p"}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "/p")
}

// =============================================================================
// ErrSDNConfigValidation
// =============================================================================

func TestW1_ErrSDNConfigValidation_Error(t *testing.T) {
	t.Parallel()
	e := ErrSDNConfigValidation{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "sdn")
	assert.Contains(t, e.Error(), "validation")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrSDNConfigValidation_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrSDNConfigValidation{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrSDNConfigValidation_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrSDNConfigValidation{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// ErrSDNOVSClientInit
// =============================================================================

func TestW1_ErrSDNOVSClientInit_Error(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSClientInit{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "ovs client")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrSDNOVSClientInit_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSClientInit{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrSDNOVSClientInit_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSClientInit{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// ErrSDNOVSConnect
// =============================================================================

func TestW1_ErrSDNOVSConnect_Error(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSConnect{Socket: "/var/run/openvswitch/db.sock", Cause: w1sentinel}
	assert.Contains(t, e.Error(), "ovs")
	assert.Contains(t, e.Error(), "/var/run/openvswitch/db.sock")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrSDNOVSConnect_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSConnect{Socket: "/s", Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrSDNOVSConnect_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrSDNOVSConnect{Socket: "/s"}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "/s")
}

// =============================================================================
// ErrSDNBridgeCreate
// =============================================================================

func TestW1_ErrSDNBridgeCreate_Error(t *testing.T) {
	t.Parallel()
	e := ErrSDNBridgeCreate{Bridge: "br-platform", Cause: w1sentinel}
	assert.Contains(t, e.Error(), "ovs bridge")
	assert.Contains(t, e.Error(), "br-platform")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrSDNBridgeCreate_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrSDNBridgeCreate{Bridge: "b", Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrSDNBridgeCreate_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrSDNBridgeCreate{Bridge: "br0"}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "br0")
}

// =============================================================================
// ErrSDNIPAMPoolCreate
// =============================================================================

func TestW1_ErrSDNIPAMPoolCreate_Error(t *testing.T) {
	t.Parallel()
	e := ErrSDNIPAMPoolCreate{Pool: "10.0.0.0/8", Cause: w1sentinel}
	assert.Contains(t, e.Error(), "ipam pool")
	assert.Contains(t, e.Error(), "10.0.0.0/8")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrSDNIPAMPoolCreate_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrSDNIPAMPoolCreate{Pool: "p", Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrSDNIPAMPoolCreate_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrSDNIPAMPoolCreate{Pool: "192.168.0.0/24"}
	assert.Nil(t, e.Unwrap())
	assert.Contains(t, e.Error(), "192.168.0.0/24")
}

// =============================================================================
// ErrWebserviceCertRead
// =============================================================================

func TestW1_ErrWebserviceCertRead_Error(t *testing.T) {
	t.Parallel()
	e := ErrWebserviceCertRead{Cause: w1sentinel}
	assert.Contains(t, e.Error(), "webservice cert read")
	assert.Contains(t, e.Error(), "w1: sentinel cause")
}

func TestW1_ErrWebserviceCertRead_Unwrap(t *testing.T) {
	t.Parallel()
	e := ErrWebserviceCertRead{Cause: w1sentinel}
	assert.Equal(t, w1sentinel, e.Unwrap())
	assert.ErrorIs(t, e, w1sentinel)
}

func TestW1_ErrWebserviceCertRead_NilCause(t *testing.T) {
	t.Parallel()
	e := ErrWebserviceCertRead{}
	assert.Nil(t, e.Unwrap())
}

// =============================================================================
// Table-driven completeness sweep
// =============================================================================

// TestW1_AllRemainingErrors_NonEmpty verifies every newly covered error type
// produces a non-empty message.
func TestW1_AllRemainingErrors_NonEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"ErrBarrierRequiresQuicBaaS", ErrBarrierRequiresQuicBaaS{}},
		{"ErrBarrierSyncStatus", ErrBarrierSyncStatus{Cause: w1sentinel}},
		{"ErrDANEPublish", ErrDANEPublish{Hostname: "h", Cause: w1sentinel}},
		{"ErrDANECertParse", ErrDANECertParse{Cause: w1sentinel}},
		{"ErrDANENoZone", ErrDANENoZone{Hostname: "h"}},
		{"ErrBootstrapClientInit", ErrBootstrapClientInit{Cause: w1sentinel}},
		{"ErrBootstrapFetchBundle", ErrBootstrapFetchBundle{Cause: w1sentinel}},
		{"ErrBootstrapInstallBundle", ErrBootstrapInstallBundle{Path: "/p", Cause: w1sentinel}},
		{"ErrSDNConfigValidation", ErrSDNConfigValidation{Cause: w1sentinel}},
		{"ErrSDNOVSClientInit", ErrSDNOVSClientInit{Cause: w1sentinel}},
		{"ErrSDNOVSConnect", ErrSDNOVSConnect{Socket: "/s", Cause: w1sentinel}},
		{"ErrSDNBridgeCreate", ErrSDNBridgeCreate{Bridge: "b", Cause: w1sentinel}},
		{"ErrSDNIPAMPoolCreate", ErrSDNIPAMPoolCreate{Pool: "p", Cause: w1sentinel}},
		{"ErrWebserviceCertRead", ErrWebserviceCertRead{Cause: w1sentinel}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

// TestW1_AllRemainingErrors_Unwrap verifies every wrapping error type in this
// sweep returns the expected cause from Unwrap.
func TestW1_AllRemainingErrors_Unwrap(t *testing.T) {
	t.Parallel()
	type unwrapper interface{ Unwrap() error }
	tests := []struct {
		name string
		err  unwrapper
	}{
		{"ErrBarrierSyncStatus", ErrBarrierSyncStatus{Cause: w1sentinel}},
		{"ErrDANEPublish", ErrDANEPublish{Hostname: "h", Cause: w1sentinel}},
		{"ErrDANECertParse", ErrDANECertParse{Cause: w1sentinel}},
		{"ErrBootstrapClientInit", ErrBootstrapClientInit{Cause: w1sentinel}},
		{"ErrBootstrapFetchBundle", ErrBootstrapFetchBundle{Cause: w1sentinel}},
		{"ErrBootstrapInstallBundle", ErrBootstrapInstallBundle{Path: "/p", Cause: w1sentinel}},
		{"ErrSDNConfigValidation", ErrSDNConfigValidation{Cause: w1sentinel}},
		{"ErrSDNOVSClientInit", ErrSDNOVSClientInit{Cause: w1sentinel}},
		{"ErrSDNOVSConnect", ErrSDNOVSConnect{Socket: "/s", Cause: w1sentinel}},
		{"ErrSDNBridgeCreate", ErrSDNBridgeCreate{Bridge: "b", Cause: w1sentinel}},
		{"ErrSDNIPAMPoolCreate", ErrSDNIPAMPoolCreate{Pool: "p", Cause: w1sentinel}},
		{"ErrWebserviceCertRead", ErrWebserviceCertRead{Cause: w1sentinel}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, w1sentinel, tt.err.Unwrap())
		})
	}
}
