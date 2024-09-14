package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func Test_SRK(t *testing.T) {

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
					app.DefaultConfig.TPMConfig.EK.RSAConfig = nil
					app.DefaultConfig.TPMConfig.EK.ECCConfig = &keystore.ECCConfig{
						Curve: elliptic.P256().Params().Name,
					}
				}

				InitParams.Initialize = true
				InitParams.Pin = []byte("test")
				InitParams.SOPin = []byte("test")

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
				algFlag := fmt.Sprintf("--%s", algo)
				polFlag := fmt.Sprintf("--policy=%t", policyFlag)
				passordFlag := fmt.Sprintf("--password=%s", passwdFlag)
				handleFlag := fmt.Sprintf("--handle=0x81000005")

				// srk create-key: creates a new key
				response := executeCommand(SRKCmd, []string{"create-key", handleFlag, algFlag, polFlag, passordFlag})
				assert.True(t, strings.Contains(response, "-----BEGIN PUBLIC KEY"))

				// srk: no args, returns the public key
				response = executeCommand(SRKCmd, []string{handleFlag, algFlag, polFlag, passordFlag})
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

				// srk delete-key: deletes the key
				response = executeCommand(SRKCmd, []string{"delete-key", handleFlag, algFlag, polFlag})
				// response = executeCommand(SRKCmd, []string{"delete-key", handleFlag, algFlag})
				assert.True(t, len(response) == 0)

				App.TPM.Close()
			}
		}
	}

}
