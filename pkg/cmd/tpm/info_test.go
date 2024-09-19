package tpm

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Info(t *testing.T) {

	InitParams.Pin = []byte("test")
	InitParams.SOPin = []byte("test")
	InitParams.Initialize = true

	App = app.DefaultTestConfig()

	response := executeCommand(InfoCmd, []string{})
	assert.True(t, strings.Contains(response, "Microsoft"))
	assert.True(t, strings.Contains(response, "xCG fTPM"))

	App.TPM.Close()
}
