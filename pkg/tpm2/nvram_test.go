package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestNVWithAuthNoPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	policyOpts := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, policyOpt := range policyOpts {

			_, tpm := createSim(encryptOpt, false)

			userPIN := keystore.NewClearPassword([]byte("user-pin"))
			secret := []byte("secret")

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			oldHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			// Change the hierarchy authorization passwords to user-pin
			err = tpm.SetHierarchyAuth(oldHierarchyAuth, userPIN, nil)
			assert.Nil(t, err)

			ekAttrs.TPMAttributes.HierarchyAuth = userPIN

			keyAttrs := &keystore.KeyAttributes{
				Parent:         ekAttrs,
				Password:       keystore.NewClearPassword([]byte("test")),
				PlatformPolicy: policyOpt,
				TPMAttributes: &keystore.TPMAttributes{
					Handle:        nvramOwnerIndex,
					HashAlg:       tpm2.TPMAlgSHA256,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: userPIN,
				},
				Secret: keystore.NewClearPassword(secret),
			}

			// providing valid auth - should work
			err = tpm.NVWrite(keyAttrs)
			assert.Nil(t, err)

			// correct auth, no PCR policy - should work
			dataSize := uint16(len(secret))
			nvSecret, err := tpm.NVRead(keyAttrs, dataSize)
			assert.Nil(t, err)
			assert.NotNil(t, nvSecret)
			assert.Equal(t, secret, nvSecret)

			// providing invalid hierarchy auth - should fail
			keyAttrs.Parent.TPMAttributes.HierarchyAuth = keystore.NewClearPassword([]byte("test"))
			err = tpm.NVWrite(keyAttrs)
			assert.NotNil(t, err)

			// // providing invalid key auth - should fail
			// keyAttrs.Password = keystore.NewClearPassword([]byte{})
			// err = tpm.NVWrite(keyAttrs)
			// assert.NotNil(t, err)

			keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
			keyAttrs.Password = keystore.NewClearPassword([]byte{})
			if policyOpt {

				// invalid key auth with platform policy - should succeed
				nvSecret, err = tpm.NVRead(keyAttrs, dataSize)
				assert.Nil(t, err)
				assert.NotNil(t, nvSecret)

			} else {

				// // invalid key auth without platform policy - should fail
				// nvSecret, err = tpm.NVRead(keyAttrs, dataSize)
				// assert.NotNil(t, err)
				// assert.Nil(t, nvSecret)
			}

			tpm.Close()
		}
	}
}
