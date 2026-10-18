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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// standaloneCPTemplate is the plan-free control plane template: platformd
// standalone on an existing host whose network it does not own (tgw-01 on
// VLAN 405).
var standaloneCPTemplate = filepath.Join(templateRoot, "single-node", "standalone-cp.example.yaml")

// standaloneCPAddress is the VLAN 405 address every listener names.
const standaloneCPAddress = "192.0.2.1"

// planFreeTemplates are the shipped templates that configure no host
// network and build no reference-network plan. Listing them keeps a
// template that drops its sdn section by mistake from passing as plan-free.
var planFreeTemplates = map[string]bool{
	filepath.Join("single-node", "standalone-cp.example.yaml"): true,
}

// secretKeys are the leaf keys whose value is a secret. Each one set in a
// plan-free template is a kms:// reference.
var secretKeys = map[string]bool{
	"password":       true,
	"so-pin":         true,
	"user-pin":       true,
	"srk-auth":       true,
	"hierarchy-auth": true,
	"auth":           true,
	"key-uri":        true,
}

// TestStandaloneCPTemplate loads the standalone control plane template
// through platformd's strict check and decode and checks it is plan-free
// and listens on 192.0.2.1 only.
func TestStandaloneCPTemplate(t *testing.T) {
	a := loadTemplate(t, standaloneCPTemplate)

	require.NotNil(t, a.SDNConfig, "sdn section")
	assert.False(t, a.SDNConfig.Enabled, "sdn is off: the host network is the gateway's")
	plan, err := a.NetworkPlan()
	require.NoError(t, err)
	assert.Nil(t, plan, "no reference-network plan without sdn")

	require.NotNil(t, a.NetworkConfig, "network section")
	nc := a.NetworkConfig
	assert.Empty(t, nc.Role, "no host role")
	assert.False(t, nc.IPForward, "no forwarding")
	assert.Nil(t, nc.PlatformVRF, "no platform VRF")
	assert.Empty(t, nc.Interfaces, "no interfaces")
	assert.Empty(t, nc.Bridges, "no bridges")
	assert.Empty(t, nc.Bonds, "no bonds")
	assert.Empty(t, nc.VLANs, "no VLANs")
	require.NoError(t, nc.Validate(nil), "plan-free network validates with no plan")
	require.NoError(t, a.validateHostNetwork())
	require.NoError(t, a.validateWebServices())

	public := a.WebService("public")
	require.NotNil(t, public, "public webservice")
	assert.Equal(t, 0, public.Port, "no plaintext listener: :8080 is the boot node's")
	assert.Equal(t, standaloneCPAddress, public.BindHost)
	internal := a.WebService("internal")
	require.NotNil(t, internal, "internal webservice")
	assert.Equal(t, standaloneCPAddress, internal.BindHost)

	require.NotNil(t, a.DNSConfig, "dns section")
	assert.Equal(t, standaloneCPAddress, a.DNSConfig.PrivateIPv4,
		"internal records carry the VLAN 405 address")

	listeners := templateDaemonListeners(t, standaloneCPTemplate)
	assert.Equal(t, standaloneCPAddress, listeners.GRPC.BindHost)
	assert.Equal(t, standaloneCPAddress, listeners.QUIC.BindHost)
	assert.Equal(t, "127.0.0.1", listeners.MCP.BindHost)
}

// TestStandaloneCPTemplate_SecretsAreKMS checks every secret the template
// sets is a kms:// reference resolved by the local KMS.
func TestStandaloneCPTemplate_SecretsAreKMS(t *testing.T) {
	raw, err := os.ReadFile(standaloneCPTemplate)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))

	var kms int
	walkSecrets(doc, "", func(path, value string) {
		assert.True(t, strings.HasPrefix(value, "kms://"), "%s is not a kms:// reference", path)
		kms++
	})
	assert.Positive(t, kms, "the template sets its secrets")
}

// TestStandaloneCPTemplate_RoleNeedsPlan proves the plan-free check can
// fail: the template given a host role is refused, because a role needs
// the plan sdn.enabled: false does not build.
func TestStandaloneCPTemplate_RoleNeedsPlan(t *testing.T) {
	raw, err := os.ReadFile(standaloneCPTemplate)
	require.NoError(t, err)
	doc := strings.Replace(string(raw), "\nnetwork:\n", "\nnetwork:\n  role: control-plane\n", 1)
	require.NotEqual(t, string(raw), doc, "the network section is present")
	path := filepath.Join(t.TempDir(), "standalone-cp.yaml")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	a := loadTemplate(t, path)
	err = a.validateHostNetwork()
	var planRequired *installer.ErrNetworkPlanRequired
	require.True(t, errors.As(err, &planRequired), "got %v", err)
	assert.Equal(t, "network.role", planRequired.Field)
}

// templateDaemonListeners resolves the daemon transports from a template
// the way platformd does: the defaults layer under the file.
func templateDaemonListeners(t *testing.T, path string) config.DaemonListeners {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	config.SetDaemonListenerDefaults(v)
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	listeners, err := config.ResolveDaemonListeners(v)
	require.NoError(t, err)
	return listeners
}

// walkSecrets calls found for every non-empty string set under a secret
// key in node.
func walkSecrets(node any, path string, found func(path, value string)) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			child := path + "." + k
			if s, ok := v.(string); ok && secretKeys[k] && s != "" {
				found(child, s)
				continue
			}
			walkSecrets(v, child, found)
		}
	case []any:
		for _, v := range n {
			walkSecrets(v, path+"[]", found)
		}
	}
}
