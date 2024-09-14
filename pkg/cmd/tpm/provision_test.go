package tpm

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Provision(t *testing.T) {

	InitParams.Pin = []byte("test")
	InitParams.SOPin = []byte("test")

	App = app.DefaultTestConfig()

	response := executeCommand(ProvisionCmd, []string{})
	assert.True(t, strings.Contains(response, "ENDORSEMENT"))
	assert.True(t, strings.Contains(response, "STORAGE"))
	assert.True(t, strings.Contains(response, "ATTESTATION"))

	App.TPM.Close()
}
