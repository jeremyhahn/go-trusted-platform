package tpm

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func Test_SealUnseal(t *testing.T) {

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

				// Part 1: provision and initialize the platform

				// When the EK certificate handle is 0, the cert
				// is loaded from the x509 store instead of TPM
				// NV RAM
				app.DefaultConfig.TPMConfig.EK.CertHandle = 0

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

				InitParams.Initialize = true
				InitParams.Pin = []byte("test")
				InitParams.SOPin = []byte("test")
				InitParams.Env = app.EnvTest.String()

				App = app.DefaultTestConfig()

				// Provision the TPM simulator and CA so the platform
				// is initialized and ready to import certificates
				App, err := App.Init(InitParams)
				assert.Nil(t, err)

				// Part 2: Load and test

				// Set initialize to false so when the command is invoked
				// and App.Init is called again, it performs a load instead
				// of re-initializing the platform.
				InitParams.Initialize = false

				if algo == "ecdsa" {
					app.DefaultConfig.TPMConfig.SSRK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.SSRK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
				}

				// Set CLI flags
				polFlag := fmt.Sprintf("--policy=%t", policyFlag)
				passwordFlag := fmt.Sprintf("--password=%s", passwdFlag)

				cn := "test"
				secret := "$ecret!"

				// seal: seal the secret to a new keyed hash object under the platform SRK
				response := executeCommand(SealCmd, []string{cn, secret, polFlag, passwordFlag})
				assert.Equal(t, "", response)

				response = executeCommand(UnsealCmd, []string{cn, polFlag, passwordFlag})
				assert.Equal(t, secret, strings.TrimSpace(response))

				App.TPM.Close()
			}
		}
	}

}
