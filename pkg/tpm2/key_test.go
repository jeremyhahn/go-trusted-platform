package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestEKAttributes(t *testing.T) {

	_, tpm := createSim(true, true)
	defer tpm.Close()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	assert.Equal(t, tpm.Config().EK.Handle, uint32(ekAttrs.TPMAttributes.Handle))
}

func TestSRKAttributes(t *testing.T) {

	_, tpm := createSim(true, true)
	defer tpm.Close()

	ssrkAttrs, err := tpm.SSRKAttributes()
	assert.Nil(t, err)

	assert.Equal(t, tpm.Config().SSRK.Handle, uint32(ssrkAttrs.TPMAttributes.Handle))
}

func TestRSA(t *testing.T) {

	_, tpm := createSim(true, false)
	defer tpm.Close()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Create SRK with password
	srkAttrs := &keystore.KeyAttributes{
		CN:             "srk-with-policy",
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_STORAGE,
		Parent:         ekAttrs,
		Password:       keystore.NewClearPassword([]byte("srk-auth")),
		PlatformPolicy: true,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		}}
	err = tpm.CreateSRK(srkAttrs)
	assert.Nil(t, err)

	// Create SRK child w/ the platform PCR authorization policy attribute
	keyAttrs := &keystore.KeyAttributes{
		CN:             "test",
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_CA,
		Parent:         srkAttrs,
		PlatformPolicy: true,
		Password:       keystore.NewClearPassword([]byte("test-pass")),
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
	rsaPub, err := tpm.CreateRSA(keyAttrs, nil)
	assert.Nil(t, err)
	assert.NotNil(t, rsaPub)
}

func TestECDSA(t *testing.T) {

	_, tpm := createSim(true, false)
	defer tpm.Close()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Create SRK with password
	srkAttrs := &keystore.KeyAttributes{
		CN:             "srk-with-policy",
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_STORAGE,
		Parent:         ekAttrs,
		Password:       keystore.NewClearPassword([]byte("srk-auth")),
		PlatformPolicy: true,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		}}

	err = tpm.CreateSRK(srkAttrs)
	assert.Nil(t, err)

	// Create SRK child w/ the platform PCR authorization policy attribute
	keyAttrs := &keystore.KeyAttributes{
		CN:             "test",
		KeyAlgorithm:   x509.ECDSA,
		KeyType:        keystore.KEY_TYPE_CA,
		Parent:         srkAttrs,
		PlatformPolicy: true,
		Password:       keystore.NewClearPassword([]byte("test-pass")),
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
	rsaPub, err := tpm.CreateECDSA(keyAttrs, nil)
	assert.Nil(t, err)
	assert.NotNil(t, rsaPub)
}
