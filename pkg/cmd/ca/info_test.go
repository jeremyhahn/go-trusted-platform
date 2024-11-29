package ca

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Info(t *testing.T) {

	// Part 1: provision and initialize the platform

	// When the EK certificate handle is 0, the cert
	// is loaded from the x509 store instead of TPM
	// NV RAM
	app.DefaultConfig.TPMConfig.EK.CertHandle = 0

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

	// info: retrieves CA initialization and key info
	response := executeCommand(InfoCmd, []string{})
	assert.True(t, strings.Count(response, "Key Algorithm: RSA") == 2)
	assert.True(t, strings.Count(response, "Key Algorithm: ECDSA") == 2)
	assert.True(t, strings.Count(response, "Key Algorithm: Ed25519") == 1)
	assert.True(t, strings.Count(response, "Store: pkcs8") == 3)
	assert.True(t, strings.Count(response, "Store: tpm2") == 2)

	App.TPM.Close()
}
