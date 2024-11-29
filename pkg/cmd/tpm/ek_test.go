package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/stretchr/testify/assert"
)

func Test_EK(t *testing.T) {

	algFlags := []string{
		"rsa",
		"ecdsa",
	}

	policyFlags := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	passwordFlags := map[string][]byte{
		"withPassword":    []byte("test"),
		"withoutPassword": nil,
		"invalidPassword": []byte("foo"),
	}

	for _, algo := range algFlags {

		for _, policyFlag := range policyFlags {

			for _, passwdFlag := range passwordFlags {

				// When the EK certificate handle is 0, the cert
				// is loaded from the x509 store instead of TPM
				// NV RAM
				app.DefaultConfig.TPMConfig.EK.CertHandle = 0
				app.DefaultConfig.TPMConfig.EK.HierarchyAuth = string(InitParams.SOPin)

				// Set ECDSA configs
				if algo == "ecdsa" {

					app.DefaultConfig.TPMConfig.EK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.EK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.EK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}

					app.DefaultConfig.TPMConfig.SSRK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.SSRK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}

					app.DefaultConfig.TPMConfig.IAK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.IAK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.IAK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
					app.DefaultConfig.TPMConfig.IAK.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

					app.DefaultConfig.TPMConfig.IDevID.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.IDevID.RSAConfig = nil
					app.DefaultConfig.TPMConfig.IDevID.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
					app.DefaultConfig.TPMConfig.IDevID.SignatureAlgorithm = x509.ECDSAWithSHA256.String()
				}

				App = app.DefaultTestConfig()

				// Part 2: Load and test

				// Set initialize to false so when the command is invoked
				// and App.Init is called again, it performs a load instead
				// of re-initializing the platform.
				InitParams.Initialize = false

				algFlag := fmt.Sprintf("--%s", algo)
				polFlag := fmt.Sprintf("--policy=%t", policyFlag)
				passwordFlag := fmt.Sprintf("--password=%s", passwdFlag)

				// ek create-key: creates a new key
				response := executeCommand(EKCmd, []string{"create-key", algFlag, polFlag, passwordFlag})
				// response := executeCommand(EKCmd, []string{"create-key", algFlag, polFlag})
				assert.True(t, strings.Contains(response, "-----BEGIN PUBLIC KEY"))

				// ek certificate: returns not found; not created yet
				response = executeCommand(EKCmd, []string{"certificate", algFlag, polFlag, passwordFlag})
				// response = executeCommand(EKCmd, []string{"certificate", algFlag, polFlag})
				assert.True(t, strings.Contains(response, tpm2.ErrEndorsementCertNotFound.Error()))

				// ek: no args, returns the public key
				response = executeCommand(EKCmd, []string{algFlag, polFlag, passwordFlag})
				// response = executeCommand(EKCmd, []string{algFlag, polFlag})
				assert.True(t, strings.Contains(response, "-----BEGIN PUBLIC KEY"))

				// Parse the key to ensure it's the correct algorithm
				pattern := regexp.MustCompile("(?ms)(-----BEGIN PUBLIC KEY.*-----END PUBLIC KEY-----)")
				matches := pattern.FindStringSubmatch(response)
				assert.Equal(t, 2, len(matches))
				key, err := keystore.DecodePubKeyPEM([]byte(matches[0]))
				assert.Nil(t, err)

				if algo == "rsa" {
					_, ok := key.(*rsa.PublicKey)
					assert.True(t, ok)
				} else {
					_, ok := key.(*ecdsa.PublicKey)
					assert.True(t, ok)
				}

				// ek delete-key: deletes the key
				response = executeCommand(EKCmd, []string{"delete-key", algFlag, polFlag})
				assert.True(t, len(response) == 0)

				App.TPM.Close()
			}
		}
	}

}

func Test_EK_Certificate(t *testing.T) {

	algFlags := []string{
		"rsa",
		"ecdsa",
	}

	policyFlags := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	passwordFlags := map[string][]byte{
		"withPassword":    []byte("test"),
		"withoutPassword": nil,
		"invalidPassword": []byte("foo"),
	}

	for _, algo := range algFlags {

		for _, policyFlag := range policyFlags {

			for _, passwdFlag := range passwordFlags {

				var err error

				// Part 1: provision and initialize the platform
				InitParams.Initialize = true
				InitParams.Pin = []byte("test")
				InitParams.SOPin = []byte("test")
				InitParams.Env = app.EnvTest.String()

				// When the EK certificate handle is 0, the cert
				// is loaded from the x509 store instead of TPM
				// NV RAM
				app.DefaultConfig.TPMConfig.EK.CertHandle = 0
				app.DefaultConfig.TPMConfig.EK.HierarchyAuth = string(InitParams.SOPin)

				// Set ECDSA configs
				if algo == "ecdsa" {

					app.DefaultConfig.TPMConfig.EK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.EK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.EK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}

					app.DefaultConfig.TPMConfig.SSRK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.SSRK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}

					app.DefaultConfig.TPMConfig.IAK.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.IAK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.IAK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
					app.DefaultConfig.TPMConfig.IAK.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

					app.DefaultConfig.TPMConfig.IDevID.KeyAlgorithm = x509.ECDSA.String()
					app.DefaultConfig.TPMConfig.IDevID.RSAConfig = nil
					app.DefaultConfig.TPMConfig.IDevID.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
					app.DefaultConfig.TPMConfig.IDevID.SignatureAlgorithm = x509.ECDSAWithSHA256.String()
				}

				App = app.DefaultTestConfig()

				// Provision the TPM simulator and CA so the platform
				// is initialized and ready to import certificates
				App, err = App.Init(InitParams)
				assert.Nil(t, err)

				// Part 2: Load and test

				// Set initialize to false so when the command is invoked
				// and App.Init is called again, it performs a load instead
				// of re-initializing the platform.
				InitParams.Initialize = false

				// Set the algorithm flag [ --rsa | --ecdsa ]
				algFlag := fmt.Sprintf("--%s", algo)
				polFlag := fmt.Sprintf("--policy=%t", policyFlag)
				passwordFlag := fmt.Sprintf("--password=%s", passwdFlag)

				// Import the certificate
				response := executeCommand(EKCmd, []string{"import-certificate", algFlag, polFlag, passwordFlag})
				// response := executeCommand(EKCmd, []string{"import-certificate", algFlag, polFlag})
				assert.True(t, strings.Contains(response, "-----BEGIN CERTIFICATE"))

				// Retrieve the imported certificate
				response = executeCommand(EKCmd, []string{"certificate", algFlag, polFlag, passwordFlag})
				// response = executeCommand(EKCmd, []string{"certificate", algFlag, polFlag})
				assert.True(t, strings.Contains(response, "-----BEGIN CERTIFICATE"))

				// Parse the PEM certificate from the response, decode the certificate
				// and ensure the algorithm matches the flag
				pattern := regexp.MustCompile("(?ms)(-----BEGIN CERTIFICATE.*-----END CERTIFICATE-----)")
				matches := pattern.FindStringSubmatch(response)
				assert.Equal(t, 2, len(matches))
				cert, err := certstore.DecodePEM([]byte(matches[0]))
				assert.Nil(t, err)
				assert.Equal(t, algo, strings.ToLower(cert.PublicKeyAlgorithm.String()))

				App.TPM.Close()
			}
		}
	}

}
