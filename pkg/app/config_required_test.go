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
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// loadConfigFile runs the daemon's config load (initConfig) against doc
// written to a temporary config.yaml, on a fresh App as NewApp returns it,
// and returns the App, the file path and the load error. The global viper
// that initConfig reads is reset afterwards.
func loadConfigFile(t *testing.T, doc string) (*App, string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(path)

	a := NewApp()
	err := a.initConfig("")
	return a, path, err
}

// TestInitConfig_RejectsMissingSPIFFETrustDomain is #528: a config the
// embedded server cannot start on fails at load, naming the file and the
// key, rather than at factory construction inside App.Init. A config with
// no quicbaas: section selects the embedded server too, so it fails the
// same way.
func TestInitConfig_RejectsMissingSPIFFETrustDomain(t *testing.T) {
	cases := map[string]string{
		"section without the key": "quicbaas:\n  data-dir: /var/lib/platform/quicbaas\n",
		"no quicbaas section":     "log-dir: /var/log/platform\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, path, err := loadConfigFile(t, doc)

			var keyErr *config.ErrInvalidConfigKey
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, path, keyErr.File)
			assert.Equal(t, "quicbaas.spiffe-trust-domain", keyErr.Key)
			assert.Contains(t, err.Error(), path)
			assert.Contains(t, err.Error(), "quicbaas.spiffe-trust-domain")

			var invalid quicbaas.ErrInvalidConfig
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, "SPIFFETrustDomain", invalid.Field)
		})
	}
}

// TestInitConfig_LoadsConfigWithSPIFFETrustDomain proves a config carrying
// the key still loads, with the value decoded.
func TestInitConfig_LoadsConfigWithSPIFFETrustDomain(t *testing.T) {
	a, _, err := loadConfigFile(t,
		"quicbaas:\n  data-dir: /var/lib/platform/quicbaas\n  spiffe-trust-domain: prod.internal\n")

	require.NoError(t, err)
	require.NotNil(t, a.QuicBaaSConfig)
	assert.Equal(t, "prod.internal", a.QuicBaaSConfig.SPIFFETrustDomain)
}

// TestCheckRequiredConfig_RemoteTransportNeedsNoTrustDomain covers the
// transports that run no first boot: they load without the key.
func TestCheckRequiredConfig_RemoteTransportNeedsNoTrustDomain(t *testing.T) {
	qc := &quicbaas.Config{TransportStr: "grpc", Address: "127.0.0.1:9000"}

	assert.NoError(t, checkRequiredConfig("config.yaml", qc))
}

// TestCheckRequiredConfig_UnknownTransportNamesTransportKey proves an
// unknown transport is blamed on quicbaas.transport, not on the trust
// domain it prevented checking.
func TestCheckRequiredConfig_UnknownTransportNamesTransportKey(t *testing.T) {
	err := checkRequiredConfig("config.yaml", &quicbaas.Config{TransportStr: "carrier-pigeon"})

	var keyErr *config.ErrInvalidConfigKey
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, "config.yaml", keyErr.File)
	assert.Equal(t, "quicbaas.transport", keyErr.Key)
	var transport quicbaas.ErrInvalidTransport
	assert.ErrorAs(t, err, &transport)
}
