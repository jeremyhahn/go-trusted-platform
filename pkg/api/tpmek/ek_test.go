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

package tpmek

import (
	"crypto/elliptic"
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

const testEKHandle = tpm2.TPMHandle(0x81010001)

// fakeTPM answers only Config, ReadHandle and CreateEK. The embedded nil
// interface means any other call panics, so a change that starts reading
// the EK back through EKAttributes -- TPM_RC_HANDLE on the empty handle
// Create exists for -- is loud.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	cfg       *xkmssdk.TPMConfig
	name      tpm2.TPM2BName
	readErr   error
	createErr error
	deleteErr error

	readHandle tpm2.TPMHandle
	created    *xkmssdk.KeyAttributes
	deleted    *xkmssdk.KeyAttributes
}

func (f *fakeTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *fakeTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	f.readHandle = handle
	return f.name, tpm2.TPMTPublic{}, f.readErr
}

func (f *fakeTPM) DeleteKey(keyAttrs *xkmssdk.KeyAttributes, _ xkmssdk.TPMKeyBackend) error {
	f.deleted = keyAttrs
	return f.deleteErr
}

func (f *fakeTPM) CreateEK(attrs *xkmssdk.KeyAttributes) error {
	f.created = attrs
	return f.createErr
}

// absentHandle is what ReadHandle returns for an empty persistent handle.
var absentHandle = errors.New("TPM_RC_HANDLE")

func configuredEK() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{EK: &xkmssdk.EKConfig{
		Handle:        uint32(testEKHandle),
		CertHandle:    0x01C00002,
		HierarchyAuth: "endorsement-pin",
		RSAConfig:     &xkmssdk.RSAConfig{KeySize: 2048},
	}}
}

// After TPM2_Clear the EK handle is empty; Create builds the key from
// tpm.ek rather than reading it back.
func TestCreate_EmptyHandleCreatesFromConfig(t *testing.T) {
	tpm := &fakeTPM{cfg: configuredEK(), readErr: absentHandle}

	got, err := Create(tpm)

	require.NoError(t, err)
	assert.Equal(t, testEKHandle, tpm.readHandle, "Create must probe the configured EK handle")
	require.Same(t, got, tpm.created)
	assert.Equal(t, testEKHandle, got.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMAlgRSA, got.TPMAttributes.Template.Type)
	assert.Equal(t, tpm2.TPMHandle(tpm2.TPMRHEndorsement), got.TPMAttributes.Hierarchy)
	assert.Equal(t, "endorsement-pin", string(got.TPMAttributes.HierarchyAuth.Bytes()))
}

func TestCreate_OccupiedHandleIsAlreadyExists(t *testing.T) {
	tpm := &fakeTPM{cfg: configuredEK()}

	_, err := Create(tpm)

	require.ErrorAs(t, err, &ErrEKExists{})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Contains(t, err.Error(), "0x81010001")
	assert.Nil(t, tpm.created, "an occupied handle must never reach CreatePrimary")
}

func TestCreate_NotConfigured(t *testing.T) {
	for name, cfg := range map[string]*xkmssdk.TPMConfig{
		"no config":   nil,
		"no tpm.ek":   {},
		"zero handle": {EK: &xkmssdk.EKConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := &fakeTPM{cfg: cfg, readErr: absentHandle}

			_, err := Create(tpm)

			require.ErrorAs(t, err, &ErrNotConfigured{})
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Nil(t, tpm.created)
		})
	}
}

func TestCreate_BadAlgorithmNeverReachesCreatePrimary(t *testing.T) {
	cfg := configuredEK()
	cfg.EK.KeyAlgorithm = "Ed25519"
	tpm := &fakeTPM{cfg: cfg, readErr: absentHandle}

	_, err := Create(tpm)

	var algErr *ErrAlgorithm
	require.ErrorAs(t, err, &algErr)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Nil(t, tpm.created)
}

func TestCreate_PropagatesBackendErrors(t *testing.T) {
	createErr := errors.New("TPM_RC_BAD_AUTH")
	tpm := &fakeTPM{cfg: configuredEK(), readErr: absentHandle, createErr: createErr}

	_, err := Create(tpm)

	require.ErrorIs(t, err, createErr)
}

func TestCreate_NilTPM(t *testing.T) {
	_, err := Create(nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestDelete_EvictsThePersistedEK(t *testing.T) {
	name := tpm2.TPM2BName{Buffer: []byte{0x00, 0x0B, 0xEC}}
	tpm := &fakeTPM{cfg: configuredEK(), name: name}

	handle, err := Delete(tpm)

	require.NoError(t, err)
	assert.Equal(t, uint32(testEKHandle), handle)
	assert.Equal(t, testEKHandle, tpm.readHandle, "Delete must read the configured EK handle")
	require.NotNil(t, tpm.deleted, "a persisted EK must reach TPM2_EvictControl")
	assert.Equal(t, testEKHandle, tpm.deleted.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMHTPersistent, tpm.deleted.TPMAttributes.HandleType,
		"only a persistent handle type is evicted rather than flushed")
	assert.Equal(t, name, tpm.deleted.TPMAttributes.Name, "EvictControl names the object it evicts")
	assert.Equal(t, "endorsement-pin", string(tpm.deleted.TPMAttributes.HierarchyAuth.Bytes()),
		"eviction is authorised by the hierarchy auth the EK was persisted with")
}

func TestDelete_EmptyHandleIsNotFound(t *testing.T) {
	tpm := &fakeTPM{cfg: configuredEK(), readErr: fmt.Errorf("read public: %w", tpm2.TPMRCHandle)}

	_, err := Delete(tpm)

	require.ErrorAs(t, err, &ErrNotFound{})
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), "0x81010001")
	assert.Nil(t, tpm.deleted, "an empty handle must never reach TPM2_EvictControl")
}

func TestDelete_NotConfigured(t *testing.T) {
	for name, cfg := range map[string]*xkmssdk.TPMConfig{
		"no config":   nil,
		"no tpm.ek":   {},
		"zero handle": {EK: &xkmssdk.EKConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := &fakeTPM{cfg: cfg}

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
		tpm := &fakeTPM{cfg: configuredEK(), readErr: readErr}

		_, err := Delete(tpm)

		require.ErrorIs(t, err, readErr)
		assert.Nil(t, tpm.deleted)
	})
	t.Run("DeleteKey", func(t *testing.T) {
		deleteErr := errors.New("TPM_RC_BAD_AUTH")
		tpm := &fakeTPM{cfg: configuredEK(), deleteErr: deleteErr}

		_, err := Delete(tpm)

		require.ErrorIs(t, err, deleteErr)
	})
}

func TestDelete_NilTPM(t *testing.T) {
	_, err := Delete(nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestAttributesFromConfig(t *testing.T) {
	rsa, err := AttributesFromConfig(configuredEK().EK)
	require.NoError(t, err)
	require.Equal(t, x509.RSA, rsa.KeyAlgorithm)
	require.Equal(t, "ek", rsa.CN)
	require.Equal(t, tpm2.TPMAlgRSA, rsa.TPMAttributes.Template.Type)
	require.Equal(t, tpm2.TPMHandle(0x01C00002), rsa.TPMAttributes.CertHandle)
	require.Equal(t, tpm2.TPMHTPersistent, rsa.TPMAttributes.HandleType)
	require.Equal(t, 2048, rsa.RSAAttributes.KeySize)
	require.Nil(t, rsa.Password, "an empty password stays nil")
	require.False(t, rsa.PlatformPolicy)

	ecc, err := AttributesFromConfig(&xkmssdk.EKConfig{
		CN:             "ek-device",
		Handle:         uint32(testEKHandle),
		ECCConfig:      &xkmssdk.ECCConfig{Curve: "P-256"},
		Password:       "ek-pin",
		PlatformPolicy: true,
	})
	require.NoError(t, err)
	require.Equal(t, x509.ECDSA, ecc.KeyAlgorithm)
	require.Equal(t, "ek-device", ecc.CN)
	require.Equal(t, tpm2.TPMAlgECC, ecc.TPMAttributes.Template.Type)
	require.Equal(t, elliptic.P256(), ecc.ECCAttributes.Curve)
	require.Equal(t, "ek-pin", string(ecc.Password.Bytes()))
	require.True(t, ecc.PlatformPolicy, "CreateEK applies the policy digest when asked")
	require.Nil(t, ecc.TPMAttributes.HierarchyAuth, "an empty hierarchy auth stays nil")
}

func TestAttributesFromConfig_BadConfig(t *testing.T) {
	_, err := AttributesFromConfig(&xkmssdk.EKConfig{KeyAlgorithm: "not-an-algorithm"})
	require.Error(t, err)

	_, err = AttributesFromConfig(&xkmssdk.EKConfig{ECCConfig: &xkmssdk.ECCConfig{Curve: "not-a-curve"}})
	require.Error(t, err)

	_, err = AttributesFromConfig(&xkmssdk.EKConfig{KeyAlgorithm: "Ed25519"})
	var algErr *ErrAlgorithm
	require.ErrorAs(t, err, &algErr)
	assert.Equal(t, "Ed25519", algErr.Algorithm)
}
