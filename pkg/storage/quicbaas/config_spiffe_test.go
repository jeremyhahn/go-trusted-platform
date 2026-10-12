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
)

// TestToQuicBaaSConfig_SPIFFETrustDomain proves the platform's
// spiffe-trust-domain key reaches the embedded server's IAM config — the
// value qrdb first-boot requires to issue the admin certificate and create
// the system tenant.
func TestToQuicBaaSConfig_SPIFFETrustDomain(t *testing.T) {
	c := &Config{
		DataDir:           t.TempDir(),
		SPIFFETrustDomain: "example.internal",
	}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, "example.internal", cfg.IAM.SPIFFETrustDomain)
}

// TestValidate_SPIFFETrustDomain_Required proves the embedded
// configuration fails closed without a trust domain: qrdb first-boot
// cannot seed IAM, so a server without one would be a partially
// initialized security service.
func TestValidate_SPIFFETrustDomain_Required(t *testing.T) {
	c := &Config{DataDir: t.TempDir()}
	err := c.Validate()
	var invalid ErrInvalidConfig
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "SPIFFETrustDomain", invalid.Field)
}

// TestValidate_SPIFFETrustDomain_Format accepts valid trust domain names
// and rejects malformed ones (scheme, path, port, uppercase, spaces).
func TestValidate_SPIFFETrustDomain_Format(t *testing.T) {
	valid := []string{"example.internal", "example.internal", "a", "prod-1.corp_x.io"}
	for _, d := range valid {
		c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: d}
		assert.NoError(t, c.Validate(), d)
	}
	invalid := []string{"spiffe://x.io", "x.io/path", "X.IO", "has space", ".leadingdot", "trailingdot.", "host:443"}
	for _, d := range invalid {
		c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: d}
		err := c.Validate()
		var bad ErrInvalidConfig
		require.ErrorAs(t, err, &bad, d)
		assert.Equal(t, "SPIFFETrustDomain", bad.Field, d)
	}
}

// TestValidateSPIFFETrustDomain_AcceptsWhatTheFactoryAccepts covers the
// configs config load must let through: an embedded server carrying a
// valid trust domain, and the remote transports, which run no first boot.
func TestValidateSPIFFETrustDomain_AcceptsWhatTheFactoryAccepts(t *testing.T) {
	cases := map[string]*Config{
		"embedded by default":   {SPIFFETrustDomain: "prod.internal"},
		"embedded explicitly":   {TransportStr: "embedded", SPIFFETrustDomain: "prod.internal"},
		"grpc without domain":   {TransportStr: "grpc", Address: "127.0.0.1:9000"},
		"unix without domain":   {TransportStr: "unix", UnixSocket: "/run/q.sock"},
		"parsed remote, no str": {Transport: TransportREST, Address: "http://127.0.0.1"},
	}
	for name, c := range cases {
		assert.NoError(t, c.ValidateSPIFFETrustDomain(), name)
	}
}

// TestValidateSPIFFETrustDomain_RejectsWhatTheFactoryRejects proves config
// load fails on the configs NewFactory would refuse: an embedded server
// with an absent or malformed trust domain, and an absent quicbaas:
// section (nil Config), which selects the embedded server.
func TestValidateSPIFFETrustDomain_RejectsWhatTheFactoryRejects(t *testing.T) {
	cases := map[string]*Config{
		"absent section":      nil,
		"section without key": {DataDir: "/var/lib/q"},
		"embedded, empty key": {TransportStr: "embedded"},
		"malformed key":       {SPIFFETrustDomain: "spiffe://x.io"},
	}
	for name, c := range cases {
		err := c.ValidateSPIFFETrustDomain()
		var invalid ErrInvalidConfig
		require.ErrorAs(t, err, &invalid, name)
		assert.Equal(t, "SPIFFETrustDomain", invalid.Field, name)
	}

	err := (&Config{TransportStr: "carrier-pigeon"}).ValidateSPIFFETrustDomain()
	var transport ErrInvalidTransport
	require.ErrorAs(t, err, &transport)
	assert.Equal(t, "carrier-pigeon", transport.Value)
}

// TestToQuicBaaSConfig_WebAuthnRP proves the programmatically injected
// relying-party settings reach the embedded server's IAM WebAuthn config —
// without them quicbaas derives a localhost issuer RP that browsers reject
// on a real origin.
func TestToQuicBaaSConfig_WebAuthnRP(t *testing.T) {
	c := &Config{
		DataDir:               t.TempDir(),
		SPIFFETrustDomain:     "example.internal",
		WebAuthnRPID:          "cp.example.com",
		WebAuthnRPDisplayName: "Trusted Platform",
		WebAuthnRPOrigins:     []string{"https://cp.example.com:8443"},
	}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, "cp.example.com", cfg.IAM.WebAuthn.RPID)
	assert.Equal(t, "Trusted Platform", cfg.IAM.WebAuthn.RPDisplayName)
	assert.Equal(t, []string{"https://cp.example.com:8443"}, cfg.IAM.WebAuthn.RPOrigins)
}
