package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestSealUnseal(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	policyOpts := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, policyOpt := range policyOpts {

			if policyOpt == false {

				for _, passwdOpt := range passwdOpts {

					logger, tpm := createSim(encryptOpt, policyOpt)

					ekAttrs, err := tpm.EKAttributes()
					assert.Nil(t, err)

					hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

					srkTemplate := tpm2.RSASRKTemplate
					srkTemplate.ObjectAttributes.NoDA = false

					var srkAuth keystore.Password
					var keyAuth keystore.Password
					if passwdOpt {
						srkAuth = keystore.NewClearPassword([]byte("srk-password"))
						keyAuth = keystore.NewClearPassword([]byte("key-password"))
					}

					srkAttrs := &keystore.KeyAttributes{
						CN:             "srk-with-policy",
						KeyAlgorithm:   x509.RSA,
						KeyType:        keystore.KEY_TYPE_STORAGE,
						Password:       srkAuth,
						PlatformPolicy: policyOpt,
						StoreType:      keystore.STORE_TPM2,
						TPMAttributes: &keystore.TPMAttributes{
							Handle:        keyStoreHandle,
							HandleType:    tpm2.TPMHTPersistent,
							Hierarchy:     tpm2.TPMRHOwner,
							HierarchyAuth: hierarchyAuth,
							Template:      srkTemplate,
						}}

					err = tpm.CreateSRK(srkAttrs)
					assert.Nil(t, err)

					keyAttrs := &keystore.KeyAttributes{
						CN:             "test",
						KeyAlgorithm:   x509.RSA,
						KeyType:        keystore.KEY_TYPE_CA,
						Parent:         srkAttrs,
						Password:       keyAuth,
						PlatformPolicy: policyOpt,
						StoreType:      keystore.STORE_TPM2,
						TPMAttributes: &keystore.TPMAttributes{
							Hierarchy: tpm2.TPMRHOwner,
						}}

					_, err = tpm.Seal(keyAttrs, nil, false)
					assert.Nil(t, err)

					// Retrieve the AES-256 key protected
					// by the platform PCR session policy
					secret, err := tpm.Unseal(keyAttrs, nil)
					assert.Nil(t, err)
					assert.NotNil(t, secret)
					assert.Equal(t, 32, len(secret))

					// Print the secret and TPM handles
					logger.Debug(string(secret))

					if policyOpt {
						// Extend the PCR and read again - policy check should fail
						extendRandomBytes(tpm.Transport())
						secret2, err := tpm.Unseal(keyAttrs, nil)
						assert.NotNil(t, err)
						assert.Nil(t, secret2)
						assert.Equal(t, ErrPolicyCheckFailed, err)
					}

					// Close / reset the simulator between tests
					tpm.Close()
				}
			}
		}
	}
}

func TestCreateKeyWithPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, passwdOpt := range passwdOpts {

			_, tpm := createSim(encryptOpt, false)

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			srkTemplate := tpm2.RSASRKTemplate
			srkTemplate.ObjectAttributes.NoDA = false

			var srkAuth keystore.Password
			var keyAuth keystore.Password
			if passwdOpt {
				srkAuth = keystore.NewClearPassword([]byte("srk-password"))
				keyAuth = keystore.NewClearPassword([]byte("key-password"))
			}

			srkAttrs := &keystore.KeyAttributes{
				CN:             "srk-with-policy",
				KeyAlgorithm:   x509.RSA,
				KeyType:        keystore.KEY_TYPE_STORAGE,
				Password:       srkAuth,
				PlatformPolicy: true,
				StoreType:      keystore.STORE_TPM2,
				TPMAttributes: &keystore.TPMAttributes{
					Handle:        keyStoreHandle,
					HandleType:    tpm2.TPMHTPersistent,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: hierarchyAuth,
					Template:      srkTemplate,
				}}

			err = tpm.CreateSRK(srkAttrs)
			assert.Nil(t, err)

			keyAttrs := &keystore.KeyAttributes{
				CN:             "test",
				KeyAlgorithm:   x509.RSA,
				KeyType:        keystore.KEY_TYPE_CA,
				Parent:         srkAttrs,
				Password:       keyAuth,
				PlatformPolicy: true,
				StoreType:      keystore.STORE_TPM2,
				TPMAttributes: &keystore.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				}}
			rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err)
			assert.NotNil(t, rsaPub)

			// nil password with policy auth - should succeed
			keyAttrs.Parent.Password = nil
			keyAttrs.CN = "test4"
			rsaPub4, err4 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err4)
			assert.NotNil(t, rsaPub4)

			// incorrect password with policy auth - should work
			keyAttrs.Parent.Password = keystore.NewClearPassword([]byte("foo"))
			keyAttrs.CN = "test5"
			rsaPub5, err5 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err5)
			assert.NotNil(t, rsaPub5)

			// correct password with policy auth - should work
			keyAttrs.Parent.Password = srkAuth
			keyAttrs.CN = "test6"
			rsaPub6, err6 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err6)
			assert.NotNil(t, rsaPub6)

			// Extend the PCR and read again - policy check should fail
			extendRandomBytes(tpm.Transport())
			secret2, err := tpm.Unseal(keyAttrs, nil)
			assert.NotNil(t, err)
			assert.Nil(t, secret2)
			assert.Equal(t, ErrPolicyCheckFailed, err)

			// Close / reset the simulator between tests
			tpm.Close()
		}
	}
}

func TestCreateKeyWithoutPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, passwdOpt := range passwdOpts {

			_, tpm := createSim(encryptOpt, false)

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			srkTemplate := tpm2.RSASRKTemplate
			srkTemplate.ObjectAttributes.NoDA = false

			var srkAuth keystore.Password
			var keyAuth keystore.Password
			if passwdOpt {
				srkAuth = keystore.NewClearPassword([]byte("srk-password"))
				keyAuth = keystore.NewClearPassword([]byte("key-password"))
			}

			srkAttrs := &keystore.KeyAttributes{
				CN:           "srk-with-policy",
				KeyAlgorithm: x509.RSA,
				KeyType:      keystore.KEY_TYPE_STORAGE,
				Password:     srkAuth,
				StoreType:    keystore.STORE_TPM2,
				TPMAttributes: &keystore.TPMAttributes{
					Handle:        keyStoreHandle,
					HandleType:    tpm2.TPMHTPersistent,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: hierarchyAuth,
					Template:      srkTemplate,
				}}

			err = tpm.CreateSRK(srkAttrs)
			assert.Nil(t, err)

			keyAttrs := &keystore.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: x509.RSA,
				KeyType:      keystore.KEY_TYPE_CA,
				Parent:       srkAttrs,
				Password:     keyAuth,
				StoreType:    keystore.STORE_TPM2,
				TPMAttributes: &keystore.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				}}
			rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err)
			assert.NotNil(t, rsaPub)

			if passwdOpt {
				// nil password without policy auth - should fail
				keyAttrs.Parent.Password = nil
				keyAttrs.CN = "test4"
				rsaPub2, err2 := tpm.CreateRSA(keyAttrs, nil, false)
				assert.NotNil(t, err2)
				assert.Nil(t, rsaPub2)
				assert.Equal(t, ErrAuthFailWithDA, err2)
			} else {
				// nil password without policy auth - should work
				keyAttrs.Parent.Password = nil
				keyAttrs.CN = "test4"
				rsaPub2, err2 := tpm.CreateRSA(keyAttrs, nil, false)
				assert.Nil(t, err2)
				assert.NotNil(t, rsaPub2)
			}

			// incorrect password without policy auth - should fail
			keyAttrs.Parent.Password = keystore.NewClearPassword([]byte("foo"))
			keyAttrs.CN = "test5"
			rsaPub3, err3 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.NotNil(t, err3)
			assert.Nil(t, rsaPub3)
			assert.Equal(t, ErrAuthFailWithDA, err3)

			// correct password without policy auth - should work
			keyAttrs.Parent.Password = srkAuth
			keyAttrs.CN = "test6"
			rsaPub6, err6 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err6)
			assert.NotNil(t, rsaPub6)

			// Close / reset the simulator between tests
			tpm.Close()
		}
	}

}
