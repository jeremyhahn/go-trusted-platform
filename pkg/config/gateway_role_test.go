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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestGatewayRoleEnabled(t *testing.T) {
	cases := map[string]struct {
		config string
		want   bool
	}{
		"gateway role":             {"domain: gw.example.com\ngateway:\n  enabled: true\n  id: gw-1\n", true},
		"gateway section disabled": {"gateway:\n  enabled: false\n", false},
		"no gateway section":       {"domain: cp.example.com\nsdn:\n  enabled: true\n", false},
		"empty config":             {"", false},
		"gateway without enabled":  {"gateway:\n  id: gw-1\n", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := GatewayRoleEnabled([]byte(c.config))
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestGatewayRoleEnabled_UnparseableIsAnError(t *testing.T) {
	_, err := GatewayRoleEnabled([]byte("gateway: [unterminated"))
	var want *ErrPlatformConfigUnreadable
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Contains(t, err.Error(), "could not be parsed")
	assert.Error(t, errors.Unwrap(err))
}

func TestGatewaydConfigSections_MatchesWhatGatewaydDecodes(t *testing.T) {
	// The whitelist is CLOSED and SILENT: a section gatewayd decodes but
	// which is missing here is dropped on the way to
	// /etc/gatewayd/config.yaml, and the gateway then fails closed at
	// service start with nothing in its configuration to explain why.
	// `secret-store` shipped exactly that way — the templates documented a
	// projection that was not happening, so every kms:// reference in a
	// gateway configuration was unresolvable.
	assert.ElementsMatch(t,
		[]string{"gateway", "proxy", "trust", "platform-ca-file", "secret-store", "sdn", "control-plane"},
		GatewaydConfigSections)
}

// TestShippedTemplates_GatewayRoleIsTheGatewayTemplatesOnly pins the role
// signal against the shipped device templates: the two gateway templates
// enable it and carry the control-plane reporter section that firstboot
// projects into /etc/gatewayd/config.yaml (#66); the control-plane and
// worker templates do not.
func TestShippedTemplates_GatewayRoleIsTheGatewayTemplatesOnly(t *testing.T) {
	root := filepath.Join("..", "..", "configs", "platform", "templates", "dedicated")
	cases := map[string]bool{
		"supermicro/x10/gateway.yaml":       true,
		"dell/r640/gateway.yaml":            true,
		"supermicro/x10/control-plane.yaml": false,
		"supermicro/x10/compute.yaml":       false,
		"dell/r640/control-plane.yaml":      false,
		"dell/r640/compute.yaml":            false,
	}
	for rel, want := range cases {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			require.NoError(t, err)
			got, err := GatewayRoleEnabled(data)
			require.NoError(t, err)
			assert.Equal(t, want, got)

			var doc struct {
				Gateway *struct {
					ID string `yaml:"id"`
				} `yaml:"gateway"`
				ControlPlane *struct {
					GatewayID string `yaml:"gateway-id"`
					CertFile  string `yaml:"cert-file"`
				} `yaml:"control-plane"`
			}
			require.NoError(t, yaml.Unmarshal(data, &doc))
			if want {
				require.NotNil(t, doc.ControlPlane, "a gateway template carries the reporter section")
				assert.Equal(t, doc.Gateway.ID, doc.ControlPlane.GatewayID, "gateway-id must equal gateway.id (the certificate CN the control plane binds to)")
				assert.NotEmpty(t, doc.ControlPlane.CertFile)
			}
		})
	}
}
