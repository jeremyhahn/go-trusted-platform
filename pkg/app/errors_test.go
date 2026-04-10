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

func TestErrXKMSStorageInit_Error(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrXKMSStorageInit{Path: "/data/keys", Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create xkms storage backend")
	assert.Contains(t, err.Error(), "/data/keys")
	assert.Contains(t, err.Error(), "permission denied")
}

func TestErrXKMSStorageInit_Unwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrXKMSStorageInit{Path: "/data/keys", Cause: cause}

	assert.ErrorIs(t, err, cause)
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrXKMSStorageInit_NilCause(t *testing.T) {
	err := ErrXKMSStorageInit{Path: "/data/keys"}

	assert.Contains(t, err.Error(), "/data/keys")
	assert.Nil(t, err.Unwrap())
}

func TestErrXKMSBackendInit_Error(t *testing.T) {
	cause := errors.New("backend failure")
	err := ErrXKMSBackendInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create xkms software backend")
	assert.Contains(t, err.Error(), "backend failure")
}

func TestErrXKMSBackendInit_Unwrap(t *testing.T) {
	cause := errors.New("backend failure")
	err := ErrXKMSBackendInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrXKMSServiceInit_Error(t *testing.T) {
	cause := errors.New("service init failure")
	err := ErrXKMSServiceInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to initialize xkms service")
	assert.Contains(t, err.Error(), "service init failure")
}

func TestErrXKMSServiceInit_Unwrap(t *testing.T) {
	cause := errors.New("service init failure")
	err := ErrXKMSServiceInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrXKMSKeystoreInit_Error(t *testing.T) {
	cause := errors.New("keystore failure")
	err := ErrXKMSKeystoreInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create xkms keystore")
	assert.Contains(t, err.Error(), "keystore failure")
}

func TestErrXKMSKeystoreInit_Unwrap(t *testing.T) {
	cause := errors.New("keystore failure")
	err := ErrXKMSKeystoreInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrQuicBaaSConfig_Error(t *testing.T) {
	cause := errors.New("bad config")
	err := ErrQuicBaaSConfig{Cause: cause}

	assert.Contains(t, err.Error(), "app: invalid quicbaas configuration")
	assert.Contains(t, err.Error(), "bad config")
}

func TestErrQuicBaaSConfig_Unwrap(t *testing.T) {
	cause := errors.New("bad config")
	err := ErrQuicBaaSConfig{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrQuicBaaSFactory_Error(t *testing.T) {
	cause := errors.New("factory failure")
	err := ErrQuicBaaSFactory{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create quicbaas factory")
	assert.Contains(t, err.Error(), "factory failure")
}

func TestErrQuicBaaSFactory_Unwrap(t *testing.T) {
	cause := errors.New("factory failure")
	err := ErrQuicBaaSFactory{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrQuicBaaSStart_Error(t *testing.T) {
	cause := errors.New("start failure")
	err := ErrQuicBaaSStart{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to start quicbaas factory")
	assert.Contains(t, err.Error(), "start failure")
}

func TestErrQuicBaaSStart_Unwrap(t *testing.T) {
	cause := errors.New("start failure")
	err := ErrQuicBaaSStart{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrPlatformCAInit_Error(t *testing.T) {
	cause := errors.New("CA init failure")
	err := ErrPlatformCAInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to initialize platform CA")
	assert.Contains(t, err.Error(), "CA init failure")
}

func TestErrPlatformCAInit_Unwrap(t *testing.T) {
	cause := errors.New("CA init failure")
	err := ErrPlatformCAInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrStorageInit_Error(t *testing.T) {
	cause := errors.New("storage failure")
	err := ErrStorageInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to configure storage")
	assert.Contains(t, err.Error(), "storage failure")
}

func TestErrStorageInit_Unwrap(t *testing.T) {
	cause := errors.New("storage failure")
	err := ErrStorageInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrBarrierInit_Error(t *testing.T) {
	cause := errors.New("barrier failure")
	err := ErrBarrierInit{Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create barrier manager")
	assert.Contains(t, err.Error(), "barrier failure")
}

func TestErrBarrierInit_Unwrap(t *testing.T) {
	cause := errors.New("barrier failure")
	err := ErrBarrierInit{Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrKeyBackendInit_Error(t *testing.T) {
	cause := errors.New("key backend failure")
	err := ErrKeyBackendInit{Path: "/data/keystore", Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create key backend")
	assert.Contains(t, err.Error(), "/data/keystore")
	assert.Contains(t, err.Error(), "key backend failure")
}

func TestErrKeyBackendInit_Unwrap(t *testing.T) {
	cause := errors.New("key backend failure")
	err := ErrKeyBackendInit{Path: "/data/keystore", Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrKeyBackendInit_NilCause(t *testing.T) {
	err := ErrKeyBackendInit{Path: "/data/keystore"}

	assert.Contains(t, err.Error(), "/data/keystore")
	assert.Nil(t, err.Unwrap())
}

func TestErrBootstrapStoreInit_Error(t *testing.T) {
	cause := errors.New("bootstrap failure")
	err := ErrBootstrapStoreInit{Store: "cert-storage", CN: "my-ca", Cause: cause}

	assert.Contains(t, err.Error(), "app: failed to create bootstrap cert-storage")
	assert.Contains(t, err.Error(), "my-ca")
	assert.Contains(t, err.Error(), "bootstrap failure")
}

func TestErrBootstrapStoreInit_Unwrap(t *testing.T) {
	cause := errors.New("bootstrap failure")
	err := ErrBootstrapStoreInit{Store: "cert-storage", CN: "my-ca", Cause: cause}

	assert.ErrorIs(t, err, cause)
}

func TestErrBootstrapStoreInit_NilCause(t *testing.T) {
	err := ErrBootstrapStoreInit{Store: "cert-storage", CN: "my-ca"}

	assert.Contains(t, err.Error(), "cert-storage")
	assert.Contains(t, err.Error(), "my-ca")
	assert.Nil(t, err.Unwrap())
}

// TestAllErrorTypes_ImplementError verifies all error types implement the error interface.
func TestAllErrorTypes_ImplementError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrXKMSStorageInit", ErrXKMSStorageInit{Path: "p", Cause: errors.New("x")}},
		{"ErrXKMSBackendInit", ErrXKMSBackendInit{Cause: errors.New("x")}},
		{"ErrXKMSServiceInit", ErrXKMSServiceInit{Cause: errors.New("x")}},
		{"ErrXKMSKeystoreInit", ErrXKMSKeystoreInit{Cause: errors.New("x")}},
		{"ErrQuicBaaSConfig", ErrQuicBaaSConfig{Cause: errors.New("x")}},
		{"ErrQuicBaaSFactory", ErrQuicBaaSFactory{Cause: errors.New("x")}},
		{"ErrQuicBaaSStart", ErrQuicBaaSStart{Cause: errors.New("x")}},
		{"ErrPlatformCAInit", ErrPlatformCAInit{Cause: errors.New("x")}},
		{"ErrStorageInit", ErrStorageInit{Cause: errors.New("x")}},
		{"ErrBarrierInit", ErrBarrierInit{Cause: errors.New("x")}},
		{"ErrKeyBackendInit", ErrKeyBackendInit{Path: "p", Cause: errors.New("x")}},
		{"ErrBootstrapStoreInit", ErrBootstrapStoreInit{Store: "s", CN: "cn", Cause: errors.New("x")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEmpty(t, tt.err.Error())
		})
	}
}

// TestAllErrorTypes_Unwrap verifies Unwrap returns the cause for all wrapping error types.
func TestAllErrorTypes_Unwrap(t *testing.T) {
	cause := errors.New("original cause")

	type unwrapper interface {
		Unwrap() error
	}

	tests := []struct {
		name string
		err  unwrapper
	}{
		{"ErrXKMSStorageInit", ErrXKMSStorageInit{Cause: cause}},
		{"ErrXKMSBackendInit", ErrXKMSBackendInit{Cause: cause}},
		{"ErrXKMSServiceInit", ErrXKMSServiceInit{Cause: cause}},
		{"ErrXKMSKeystoreInit", ErrXKMSKeystoreInit{Cause: cause}},
		{"ErrQuicBaaSConfig", ErrQuicBaaSConfig{Cause: cause}},
		{"ErrQuicBaaSFactory", ErrQuicBaaSFactory{Cause: cause}},
		{"ErrQuicBaaSStart", ErrQuicBaaSStart{Cause: cause}},
		{"ErrPlatformCAInit", ErrPlatformCAInit{Cause: cause}},
		{"ErrStorageInit", ErrStorageInit{Cause: cause}},
		{"ErrBarrierInit", ErrBarrierInit{Cause: cause}},
		{"ErrKeyBackendInit", ErrKeyBackendInit{Cause: cause}},
		{"ErrBootstrapStoreInit", ErrBootstrapStoreInit{Cause: cause}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, cause, tt.err.Unwrap())
		})
	}
}
