package platform

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Install(t *testing.T) {

	// When the EK certificate handle is 0, the cert
	// is loaded from the x509 store instead of TPM
	// NV RAM
	app.DefaultConfig.TPMConfig.EK.CertHandle = 0

	InitParams.Pin = []byte("test")
	InitParams.SOPin = []byte("test")

	App = app.DefaultTestConfig()

	response := executeCommand(InstallCmd, []string{})
	assert.True(t, strings.Contains(response, "-----BEGIN CERTIFICATE"))

	App.TPM.Close()
}
