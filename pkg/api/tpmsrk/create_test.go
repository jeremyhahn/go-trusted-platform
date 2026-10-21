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

package tpmsrk

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

const testSSRKHandle = tpm2.TPMHandle(0x81000001)

// createTPM answers only Config, ReadHandle, EKAttributes and CreateSRK.
// The embedded nil interface means any other call panics, so a change that
// starts reading the SSRK back through SSRKAttributes -- TPM_RC_HANDLE on
// the empty handle Create exists for -- is loud.
type createTPM struct {
	xkmssdk.TrustedPlatformModule

	cfg       *xkmssdk.TPMConfig
	name      tpm2.TPM2BName
	readErr   error
	ekAttrs   *xkmssdk.KeyAttributes
	ekErr     error
	createErr error
	deleteErr error

	readHandle tpm2.TPMHandle
	created    *xkmssdk.KeyAttributes
	deleted    *xkmssdk.KeyAttributes
}

func (f *createTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *createTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	f.readHandle = handle
	return f.name, tpm2.TPMTPublic{}, f.readErr
}

func (f *createTPM) DeleteKey(keyAttrs *xkmssdk.KeyAttributes, _ xkmssdk.TPMKeyBackend) error {
	f.deleted = keyAttrs
	return f.deleteErr
}

func (f *createTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) { return f.ekAttrs, f.ekErr }

func (f *createTPM) CreateSRK(attrs *xkmssdk.KeyAttributes) error {
	f.created = attrs
	return f.createErr
}

// errAbsent is what ReadHandle returns for an empty persistent handle.
var errAbsent = errors.New("TPM_RC_HANDLE")

func emptySSRKHandle(cfg *xkmssdk.TPMConfig) *createTPM {
	return &createTPM{cfg: cfg, readErr: errAbsent}
}

// After TPM2_Clear the SSRK handle is empty; Create builds the key from
// tpm.ssrk rather than reading it back.
func TestCreate_EmptyHandleCreatesFromConfig(t *testing.T) {
	tpm := emptySSRKHandle(&xkmssdk.TPMConfig{
		SSRK: &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle), HierarchyAuth: "so-pin"},
	})

	got, err := Create(tpm)

	require.NoError(t, err)
	assert.Equal(t, testSSRKHandle, tpm.readHandle, "Create must probe the configured SSRK handle")
	require.Same(t, got, tpm.created)
	assert.Equal(t, testSSRKHandle, got.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMAlgRSA, got.TPMAttributes.Template.Type)
	assert.Equal(t, "so-pin", string(got.TPMAttributes.HierarchyAuth.Bytes()))
	assert.Nil(t, got.Parent, "no bus encryption, no salting parent")
}

func TestCreate_EncryptSessionParentsOnTheEK(t *testing.T) {
	ek := &xkmssdk.KeyAttributes{CN: "ek"}
	tpm := emptySSRKHandle(&xkmssdk.TPMConfig{
		EncryptSession: true,
		SSRK:           &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle)},
	})
	tpm.ekAttrs = ek

	got, err := Create(tpm)

	require.NoError(t, err)
	assert.Same(t, ek, got.Parent)
}

func TestCreate_OccupiedHandleIsAlreadyExists(t *testing.T) {
	tpm := &createTPM{cfg: &xkmssdk.TPMConfig{SSRK: &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle)}}}

	_, err := Create(tpm)

	require.ErrorAs(t, err, &ErrExists{})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Contains(t, err.Error(), "0x81000001")
	assert.Nil(t, tpm.created, "an occupied handle must never reach CreatePrimary")
}

func TestCreate_NotConfigured(t *testing.T) {
	for name, cfg := range map[string]*xkmssdk.TPMConfig{
		"no config":   nil,
		"no tpm.ssrk": {},
		"zero handle": {SSRK: &xkmssdk.SRKConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := emptySSRKHandle(cfg)

			_, err := Create(tpm)

			require.ErrorAs(t, err, &ErrNotConfigured{})
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Nil(t, tpm.created)
		})
	}
}

func TestCreate_PropagatesBackendErrors(t *testing.T) {
	ekErr := errors.New("EK config is nil")
	createErr := errors.New("TPM_RC_BAD_AUTH")
	encrypting := &xkmssdk.TPMConfig{EncryptSession: true, SSRK: &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle)}}
	plain := &xkmssdk.TPMConfig{SSRK: &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle)}}
	cases := map[string]struct {
		tpm  *createTPM
		want error
	}{
		"EKAttributes": {tpm: &createTPM{cfg: encrypting, readErr: errAbsent, ekErr: ekErr}, want: ekErr},
		"CreateSRK":    {tpm: &createTPM{cfg: plain, readErr: errAbsent, createErr: createErr}, want: createErr},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Create(tc.tpm)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestCreate_NilTPM(t *testing.T) {
	_, err := Create(nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
}

// persistedSSRK is a TPM holding the Shared SRK at the configured handle.
func persistedSSRK() *createTPM {
	return &createTPM{cfg: &xkmssdk.TPMConfig{
		SSRK: &xkmssdk.SRKConfig{Handle: uint32(testSSRKHandle), HierarchyAuth: "so-pin"},
	}}
}

func TestDelete_EvictsThePersistedSSRK(t *testing.T) {
	name := tpm2.TPM2BName{Buffer: []byte{0x00, 0x0B, 0x5A}}
	tpm := persistedSSRK()
	tpm.name = name

	handle, err := Delete(tpm)

	require.NoError(t, err)
	assert.Equal(t, uint32(testSSRKHandle), handle)
	assert.Equal(t, testSSRKHandle, tpm.readHandle, "Delete must read the configured SSRK handle")
	require.NotNil(t, tpm.deleted, "a persisted SSRK must reach TPM2_EvictControl")
	assert.Equal(t, testSSRKHandle, tpm.deleted.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMHTPersistent, tpm.deleted.TPMAttributes.HandleType,
		"only a persistent handle type is evicted rather than flushed")
	assert.Equal(t, name, tpm.deleted.TPMAttributes.Name, "EvictControl names the object it evicts")
	assert.Equal(t, "so-pin", string(tpm.deleted.TPMAttributes.HierarchyAuth.Bytes()),
		"eviction is authorised by the owner auth the SSRK was persisted with")
}

func TestDelete_EmptyHandleIsNotFound(t *testing.T) {
	tpm := persistedSSRK()
	tpm.readErr = fmt.Errorf("read public: %w", tpm2.TPMRCHandle)

	_, err := Delete(tpm)

	require.ErrorAs(t, err, &ErrNotFound{})
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), "0x81000001")
	assert.Nil(t, tpm.deleted, "an empty handle must never reach TPM2_EvictControl")
}

func TestDelete_NotConfigured(t *testing.T) {
	for name, cfg := range map[string]*xkmssdk.TPMConfig{
		"no config":   nil,
		"no tpm.ssrk": {},
		"zero handle": {SSRK: &xkmssdk.SRKConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := &createTPM{cfg: cfg}

			_, err := Delete(tpm)

			require.ErrorAs(t, err, &ErrNotConfigured{})
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Nil(t, tpm.deleted)
		})
	}
}

func TestDelete_PropagatesBackendErrors(t *testing.T) {
	t.Run("ReadHandle", func(t *testing.T) {
		readErr := errors.New("TPM_RC_FAILURE")
		tpm := persistedSSRK()
		tpm.readErr = readErr

		_, err := Delete(tpm)

		require.ErrorIs(t, err, readErr)
		assert.Nil(t, tpm.deleted)
	})
	t.Run("DeleteKey", func(t *testing.T) {
		deleteErr := errors.New("TPM_RC_BAD_AUTH")
		tpm := persistedSSRK()
		tpm.deleteErr = deleteErr

		_, err := Delete(tpm)

		require.ErrorIs(t, err, deleteErr)
	})
}

func TestDelete_NilTPM(t *testing.T) {
	_, err := Delete(nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
}

func TestAttributesFromConfig(t *testing.T) {
	rsa, err := AttributesFromConfig(&xkmssdk.SRKConfig{
		Handle:        uint32(testSSRKHandle),
		RSAConfig:     &xkmssdk.RSAConfig{KeySize: 2048},
		HierarchyAuth: "so-pin",
	})
	require.NoError(t, err)
	require.Equal(t, x509.RSA, rsa.KeyAlgorithm)
	require.Equal(t, "shared-srk", rsa.CN)
	require.Equal(t, tpm2.TPMAlgRSA, rsa.TPMAttributes.Template.Type)
	require.Equal(t, testSSRKHandle, rsa.TPMAttributes.Handle)
	require.Equal(t, tpm2.TPMHTPersistent, rsa.TPMAttributes.HandleType)
	require.Equal(t, tpm2.TPMHandle(tpm2.TPMRHOwner), rsa.TPMAttributes.Hierarchy)
	require.Equal(t, "so-pin", string(rsa.TPMAttributes.HierarchyAuth.Bytes()))
	require.Nil(t, rsa.Password, "an empty password stays nil")
	require.Empty(t, rsa.TPMAttributes.Template.AuthPolicy.Buffer, "the SSRK carries no platform policy")

	ecc, err := AttributesFromConfig(&xkmssdk.SRKConfig{
		CN:        "ssrk",
		Handle:    uint32(testSSRKHandle),
		ECCConfig: &xkmssdk.ECCConfig{Curve: "P-256"},
		Password:  "srk-pin",
	})
	require.NoError(t, err)
	require.Equal(t, x509.ECDSA, ecc.KeyAlgorithm)
	require.Equal(t, "ssrk", ecc.CN)
	require.Equal(t, tpm2.TPMAlgECC, ecc.TPMAttributes.Template.Type)
	require.Equal(t, "srk-pin", string(ecc.Password.Bytes()))
	require.Nil(t, ecc.TPMAttributes.HierarchyAuth, "an empty hierarchy auth stays nil")
}

func TestAttributesFromConfig_BadAlgorithm(t *testing.T) {
	_, err := AttributesFromConfig(&xkmssdk.SRKConfig{KeyAlgorithm: "not-an-algorithm"})
	require.Error(t, err)

	_, err = AttributesFromConfig(&xkmssdk.SRKConfig{KeyAlgorithm: "Ed25519"})
	var algErr *ErrAlgorithm
	require.ErrorAs(t, err, &algErr)
	assert.Equal(t, "Ed25519", algErr.Algorithm)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}
