// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package app

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// webTestExample is the platformd config the web console flows start
// (make integration-test-web, make config, entrypoint.sh, web/Makefile).
const webTestExample = "../../configs/platform/standalone/web-test.example.yaml"

// TestWebTestExample_Loads loads the web-test example through platformd's
// strict check, decode and required-key check, and checks it gives the
// web flows what they start against.
func TestWebTestExample_Loads(t *testing.T) {
	a := loadTemplate(t, webTestExample)
	require.NoError(t, checkRequiredConfig(webTestExample, a.QuicBaaSConfig))

	assert.Equal(t, "/tmp/swtpm/swtpm.sock", a.TPMConfig.Device, "the devcontainer's swtpm")
	require.NotNil(t, a.QuicBaaSConfig, "quicbaas section")
	assert.Equal(t, quicbaas.StorageBackendMemory, a.QuicBaaSConfig.StorageBackend)

	public := a.WebService("public")
	require.NotNil(t, public, "public webservice")
	assert.Equal(t, 8443, public.TLSPort)
	require.NotNil(t, public.WebAuthn, "webauthn relying party")
	assert.Equal(t, "localhost", public.WebAuthn.RPID)
	assert.Contains(t, public.WebAuthn.RPOrigins, "https://localhost:3000")
	require.NotNil(t, public.CORS, "cors")
	assert.Contains(t, public.CORS.AllowedOrigins, "https://localhost:3000")

	require.NotNil(t, a.SecretsConfig, "secrets section")
	assert.True(t, a.SecretsConfig.Enabled, "kms:// references are resolved at startup")
	require.NotNil(t, a.PlatformConfig, "platform section")
	assert.True(t, strings.HasPrefix(a.PlatformConfig.SOPin, "kms://"), "so-pin decodes as a kms:// reference")
	require.NotNil(t, public.Key, "webservice key")
	assert.True(t, strings.HasPrefix(public.Key.Password, "kms://"), "key password decodes as a kms:// reference")
}

// TestWebTestExample_SecretsAreKMS checks every secret the example sets
// is a kms:// reference, never a literal.
func TestWebTestExample_SecretsAreKMS(t *testing.T) {
	raw, err := os.ReadFile(webTestExample)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))

	var kms int
	walkSecrets(doc, "", func(path, value string) {
		assert.True(t, strings.HasPrefix(value, "kms://"), "%s is not a kms:// reference", path)
		kms++
	})
	assert.Positive(t, kms, "the example sets its secrets")
}

// TestWebTestExample_RequiresSPIFFETrustDomain proves the required-key
// check can fail: the example without its SPIFFE trust domain is refused.
func TestWebTestExample_RequiresSPIFFETrustDomain(t *testing.T) {
	a := loadTemplate(t, webTestExample)
	require.NotNil(t, a.QuicBaaSConfig, "quicbaas section")
	a.QuicBaaSConfig.SPIFFETrustDomain = ""
	require.Error(t, checkRequiredConfig(webTestExample, a.QuicBaaSConfig))
}
