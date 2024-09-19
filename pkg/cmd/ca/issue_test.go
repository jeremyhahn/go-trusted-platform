package ca

import (
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func Test_Issue(t *testing.T) {

	algFlags := []string{
		"rsa",
		"ecdsa",
	}

	stores := []string{
		"pkcs8",
		// "pkcs11",
		"tpm2",
	}

	for _, algo := range algFlags {

		for _, store := range stores {

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

			cn := "test.com"

			// issue new cert
			response := executeCommand(IssueCmd, []string{cn, store, algo})
			assert.True(t, strings.Contains(response, "-----BEGIN CERTIFICATE"))

			App.TPM.Close()
		}
	}
}
