// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxy

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const controlPlaneYAML = `
defaults:
  attestation-max-age: 10m
  backend-zone: trusted
pools:
  - id: console
    backends:
      - url: https://cp.example.internal:8443
        weight: 2
    balancer: round-robin
    tls:
      trust-class: internal
      mtls-client-cert: true
    max-idle-conns-per-host: 8
    idle-conn-timeout: 90s
routes:
  - id: console
    hosts: [Console.Example.com]
    path-prefix: /
    pool: console
    auth:
      mode: mtls-or-token
      require-idevid: true
      allowed-zones: [trusted, management]
      require-attestation: true
      required-roles: [admin]
      token-zone: trusted
    preserve-host: true
`

// TestControlPlaneConfig_DecodesHyphenatedKeys pins the YAML contract the
// platformd proxy: section and the persisted entities share (#570).
func TestControlPlaneConfig_DecodesHyphenatedKeys(t *testing.T) {
	var cfg ControlPlaneConfig
	require.NoError(t, yaml.Unmarshal([]byte(controlPlaneYAML), &cfg))
	require.NoError(t, cfg.Validate())

	require.Len(t, cfg.Routes, 1)
	r := cfg.Routes[0]
	assert.Equal(t, "console", r.ID)
	assert.Equal(t, []string{"console.example.com"}, r.Hosts, "Validate lowercases hosts")
	assert.Equal(t, "/", r.PathPrefix)
	assert.Equal(t, "console", r.PoolID)
	assert.Equal(t, AuthModeMTLSOrToken, r.Auth.Mode)
	assert.True(t, r.Auth.RequireIDevID)
	assert.Equal(t, []string{"trusted", "management"}, r.Auth.AllowedZones)
	assert.True(t, r.Auth.RequireAttestation)
	assert.Equal(t, []string{"admin"}, r.Auth.RequiredRoles)
	assert.Equal(t, "trusted", r.Auth.TokenZone)
	assert.True(t, r.PreserveHost)

	require.Len(t, cfg.Pools, 1)
	p := cfg.Pools[0]
	assert.Equal(t, "https://cp.example.internal:8443", p.Backends[0].URL)
	assert.Equal(t, 2, p.Backends[0].Weight)
	assert.Equal(t, "internal", p.TLS.TrustClass)
	assert.True(t, p.TLS.MTLSClientCert)
	assert.Equal(t, 8, p.MaxIdleConnsPerHost)
	assert.Equal(t, 90*time.Second, p.IdleConnTimeout)
	assert.Equal(t, 10*time.Minute, cfg.Defaults.AttestationMaxAge)
	assert.Equal(t, "trusted", cfg.Defaults.BackendZone)
}

func TestControlPlaneConfig_ValidateFailsClosed(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want error
	}{
		"route without pool": {`
routes:
  - id: r
    path-prefix: /
    auth: {mode: public}
`, ErrRoutePoolRequired},
		"route with unknown auth mode": {`
pools:
  - id: p
    backends: [{url: http://b:80}]
routes:
  - id: r
    path-prefix: /
    pool: p
    auth: {mode: magic}
`, ErrInvalidAuthMode},
		"route referencing an undeclared pool": {`
routes:
  - id: r
    path-prefix: /
    pool: nope
    auth: {mode: public}
`, ErrUnknownPoolID},
		"tcp passthrough": {`
pools:
  - id: p
    backends: [{url: http://b:80}]
routes:
  - id: r
    path-prefix: /
    pool: p
    passthrough-tcp: true
    auth: {mode: public}
`, ErrTCPPassthroughUnsupported},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var cfg ControlPlaneConfig
			require.NoError(t, yaml.Unmarshal([]byte(c.yaml), &cfg))
			err := cfg.Validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, c.want), "got %v", err)
		})
	}
}

func TestControlPlaneConfig_EmptyIsValid(t *testing.T) {
	var cfg ControlPlaneConfig
	assert.NoError(t, cfg.Validate())
}

// TestConfig_JSONRoundTrip pins the json tags the persistent store encodes
// entities with: a route survives encode/decode unchanged.
func TestConfig_JSONRoundTrip(t *testing.T) {
	in := RouteConfig{
		ID: "r", Hosts: []string{"a.example"}, PathPrefix: "/api", PoolID: "p",
		Auth:        AuthRequirements{Mode: AuthModeToken, RequiredScopes: []string{"dns:read"}, AttestationMaxAge: time.Minute},
		StripPrefix: true,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"path_prefix":"/api"`)
	assert.Contains(t, string(raw), `"required_scopes":["dns:read"]`)
	var out RouteConfig
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}
