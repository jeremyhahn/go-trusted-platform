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

package quicbaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// adminEnrollmentConfig returns a minimally valid embedded config with the
// admin enrollment fields set to distinguishable values.
func adminEnrollmentConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		DataDir:                   t.TempDir(),
		SPIFFETrustDomain:         "trusted-platform.internal",
		BootstrapAdminCSRPath:     "/etc/platform/admin.csr",
		BootstrapAdminPIVCertPath: "/etc/platform/admin-piv.crt",
		AdminFactors:              []string{"mtls", "fido2"},
		PasskeyDevice:             "/dev/hidraw0",
	}
	c.SetDefaults()
	return c
}

// TestToQuicBaaSConfig_AdminEnrollmentPassthrough proves the admin
// enrollment paths and login factors reach the embedded server's auth
// config. Before #173 the platform declared none of these, so every
// deployment silently fell back to path A — the node generating the admin
// keypair and writing the private key to disk — with no way to ask for the
// CSR or PIV path from platform YAML.
func TestToQuicBaaSConfig_AdminEnrollmentPassthrough(t *testing.T) {
	cfg := adminEnrollmentConfig(t).ToQuicBaaSConfig()

	assert.Equal(t, "/etc/platform/admin.csr", cfg.Auth.BootstrapAdminCSRPath,
		"the CSR path is what keeps the admin private key off this host")
	assert.Equal(t, "/etc/platform/admin-piv.crt", cfg.Auth.BootstrapAdminPIVCertPath)
	assert.Equal(t, []string{"mtls", "fido2"}, cfg.Auth.AdminFactors)
	assert.Equal(t, "/dev/hidraw0", cfg.Auth.PasskeyDevice)
}

// TestToQuicBaaSConfig_AdminEnrollmentDefaultsEmpty is the other half: an
// operator who configures none of this must get exactly the upstream
// default (path A), not a platform-invented one. An empty value has to mean
// upstream's empty, so the platform must not substitute anything.
func TestToQuicBaaSConfig_AdminEnrollmentDefaultsEmpty(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: "trusted-platform.internal"}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()

	assert.Empty(t, cfg.Auth.BootstrapAdminCSRPath)
	assert.Empty(t, cfg.Auth.BootstrapAdminPIVCertPath)
	assert.Empty(t, cfg.Auth.AdminFactors)
	assert.Empty(t, cfg.Auth.PasskeyDevice)
}

// TestConfig_AdminEnrollmentYAMLKeys pins the operator-facing spelling.
// These keys are the platform's public config surface, so a rename is a
// breaking change for every deployment's bootstrap.yaml; the test exists so
// that rename cannot happen silently.
func TestConfig_AdminEnrollmentYAMLKeys(t *testing.T) {
	const doc = `
data-dir: /var/lib/platform
spiffe-trust-domain: trusted-platform.internal
bootstrap-admin-csr-path: /etc/platform/admin.csr
bootstrap-admin-piv-cert-path: /etc/platform/admin-piv.crt
admin-factors:
  - mtls
  - piv
passkey-device: /dev/hidraw1
`
	var c Config
	require.NoError(t, yaml.Unmarshal([]byte(doc), &c))

	assert.Equal(t, "/etc/platform/admin.csr", c.BootstrapAdminCSRPath)
	assert.Equal(t, "/etc/platform/admin-piv.crt", c.BootstrapAdminPIVCertPath)
	assert.Equal(t, []string{"mtls", "piv"}, c.AdminFactors)
	assert.Equal(t, "/dev/hidraw1", c.PasskeyDevice)
}

// TestConfig_AdminEnrollmentOmittedFromYAMLWhenUnset keeps the rendered
// config clean: these are optional, so a deployment that does not use them
// should not carry four empty keys in every generated file.
func TestConfig_AdminEnrollmentOmittedFromYAMLWhenUnset(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: "trusted-platform.internal"}

	out, err := yaml.Marshal(c)
	require.NoError(t, err)

	rendered := string(out)
	for _, key := range []string{
		"bootstrap-admin-csr-path",
		"bootstrap-admin-piv-cert-path",
		"admin-factors",
		"passkey-device",
	} {
		assert.NotContains(t, rendered, key,
			"unset optional enrollment keys should be omitted from rendered YAML")
	}
}
