package platform

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/stretchr/testify/assert"
)

func Test_Policy(t *testing.T) {

	// When the EK certificate handle is 0, the cert
	// is loaded from the x509 store instead of TPM
	// NV RAM
	app.DefaultConfig.TPMConfig.EK.CertHandle = 0

	InitParams.Initialize = true
	InitParams.Pin = []byte("test")
	InitParams.SOPin = []byte("test")
	InitParams.Env = app.EnvTest.String()

	App = app.DefaultTestConfig()

	response := executeCommand(PolicyCmd, []string{})
	assert.True(t, strings.Contains(response, "Hash"))

	App.TPM.Close()
}
