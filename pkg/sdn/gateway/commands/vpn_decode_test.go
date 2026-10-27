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

package commands

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// loadVPNSection decodes a gateway.management_vpn body as gatewayd does.
func loadVPNSection(t *testing.T, body string) *ServeConfig {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte("gateway:\n  management_vpn:\n"+body))))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Gateway)
	require.NotNil(t, cfg.Gateway.ManagementVPN)
	return cfg
}

// TestLoadServeConfig_ManagementVPNMASQUEKeysDecode pins that gatewayd reads
// the `masque.*` keys, the RFC 9484 routes as prefixes, and that the section
// validates.
func TestLoadServeConfig_ManagementVPNMASQUEKeysDecode(t *testing.T) {
	cfg := loadVPNSection(t, `    enabled: true
    pool: remote-access
    allow-to: [management]
    masque:
      template: https://gw.example:4433/.well-known/masque/ip/
      routes: [10.0.0.0/8, "fd00::/8"]
`)
	section := cfg.Gateway.ManagementVPN
	assert.Equal(t, "https://gw.example:4433/.well-known/masque/ip/", section.MASQUE.Template)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}, section.MASQUE.Routes)
	require.NoError(t, section.Validate())
}

// TestLoadServeConfig_ManagementVPNWithoutMASQUEKeysRefused: MASQUE is the
// default plane, so a section that names no template is refused by name.
func TestLoadServeConfig_ManagementVPNWithoutMASQUEKeysRefused(t *testing.T) {
	cfg := loadVPNSection(t, `    enabled: true
    pool: remote-access
    allow-to: [management]
`)
	var invalid *vpn.ErrInvalidConfig
	require.True(t, errors.As(cfg.Gateway.ManagementVPN.Validate(), &invalid))
	assert.Equal(t, "masque.template", invalid.Field)
}
