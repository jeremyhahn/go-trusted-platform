package ca

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Init(t *testing.T) {

	InitParams.Initialize = true
	InitParams.Pin = []byte("test")
	InitParams.SOPin = []byte("test")

	App = app.DefaultTestConfig()

	// init: initializes the CA
	response := executeCommand(InitCmd, []string{})
	assert.Equal(t, "Certificate Authority successfully initialized\n", response)

	App.TPM.Close()
}
