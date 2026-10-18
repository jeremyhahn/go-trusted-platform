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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// templateRoot is the tree of shipped platform templates.
const templateRoot = "../../configs/platform/templates"

// shippedPlatformTemplates returns every platformd template (gatewayd's own
// config file is checked in pkg/sdn/gateway/commands, and the override
// examples beside the templates are listed in overrideExamples).
func shippedPlatformTemplates(t *testing.T) []string {
	t.Helper()
	return platformConfigsUnder(t, templateRoot)
}

// platformConfigsUnder lists the platform config documents under root:
// every .yaml file except the gateway daemon's gatewayd.yaml.
func platformConfigsUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" || filepath.Base(path) == "gatewayd.yaml" {
			return nil
		}
		rel, err := filepath.Rel(configRoot, path)
		if err != nil {
			return err
		}
		if _, isOverride := overrideExamples[filepath.ToSlash(rel)]; isOverride {
			return nil
		}
		out = append(out, path)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out, "the shipped configs under %s must be present", root)
	return out
}

// loadTemplate decodes a template the way platformd does: viper plus the
// platform decode hook.
func loadTemplate(t *testing.T, path string) *App {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	require.NoError(t, CheckPlatformConfigViper(v), "%s: no stale network/sdn keys", path)
	var a App
	require.NoError(t, v.Unmarshal(&a, config.DecodeHook()), path)
	return &a
}

// TestShippedTemplates_FollowTheReferenceNetwork loads every platform
// template and checks it against the reference network (a plan-free template
// is checked for having no plan instead): the SDN section
// validates and derives a plan on environment 4 (fabric included), the host
// network validates by role against that plan, the trunk rides br-fabric,
// and no template carries the retired model (zone trusted, br-int,
// 172.16.x).
func TestShippedTemplates_FollowTheReferenceNetwork(t *testing.T) {
	for _, path := range shippedPlatformTemplates(t) {
		rel, err := filepath.Rel(templateRoot, path)
		require.NoError(t, err)
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			for _, retired := range []string{"trusted0", "zone: trusted", "172.16.", "subnets:", "segments:"} {
				assert.False(t, strings.Contains(string(raw), retired), "%s: retired network model %q", rel, retired)
			}

			a := loadTemplate(t, path)
			require.NotNil(t, a.SDNConfig, "sdn section")
			if planFreeTemplates[rel] {
				// Plan-free: no plan, no host network, checked in full by
				// TestStandaloneCPTemplate.
				require.False(t, a.SDNConfig.Enabled, "a plan-free template builds no plan")
				require.NotNil(t, a.NetworkConfig, "network section")
				require.NoError(t, a.NetworkConfig.Validate(nil))
				require.NoError(t, a.validateHostNetwork())
				return
			}
			require.True(t, a.SDNConfig.Enabled)
			require.NoError(t, a.SDNConfig.Validate(), "sdn section must validate (zones, plan, fabric)")
			plan := a.SDNConfig.Plan()
			require.NotNil(t, plan)
			assert.Equal(t, uint16(4), plan.Environment().ID, "templates use the reference block 4")
			require.NotNil(t, a.SDNConfig.OVS)
			assert.Equal(t, "br-fabric", a.SDNConfig.OVS.Bridge, "the trunk rides br-fabric")

			require.NotNil(t, a.NetworkConfig, "network section")
			assert.NotEmpty(t, a.NetworkConfig.Role, "every template declares its host role")
			require.NoError(t, a.NetworkConfig.Validate(plan), "host addressing by role")
			require.NoError(t, a.validateHostNetwork())

			if a.NetworkConfig.Role != installer.HostRoleGateway {
				assert.False(t, a.NetworkConfig.IPForward, "only a gateway forwards")
			}
			for _, br := range a.NetworkConfig.Bridges {
				if br.Name == "br-int" {
					assert.Empty(t, br.Interfaces, "br-int never carries the trunk")
				}
			}
			require.NotNil(t, a.NetworkConfig.PlatformVRF, "every attested host has a platform-VRF address")
		})
	}
}

// TestShippedTemplates_FabricPortClasses checks the template that carries
// the switch fabric assigns every port a class the plan can realise.
func TestShippedTemplates_FabricPortClasses(t *testing.T) {
	var withFabric int
	for _, path := range shippedPlatformTemplates(t) {
		a := loadTemplate(t, path)
		if a.SDNConfig == nil || a.SDNConfig.Fabric == nil {
			continue
		}
		withFabric++
		require.NoError(t, a.SDNConfig.Validate(), path)
		plan := a.SDNConfig.Plan()
		require.NotEmpty(t, a.SDNConfig.Fabric.Ports, "%s: a fabric declares its ports", path)
		for _, p := range a.SDNConfig.Fabric.Ports {
			pc, err := plan.PortClass(zone.PortClass(p.Class))
			require.NoError(t, err, "%s: port %s", path, p.Port)
			assert.Equal(t, 9216, pc.MTU)
		}
	}
	assert.Positive(t, withFabric, "at least one template carries the switch fabric")
}

// TestShippedTemplates_RetiredKeysAreGone guards against the removed SDN keys
// silently reappearing: they would be ignored by the decoder.
func TestShippedTemplates_RetiredKeysAreGone(t *testing.T) {
	for _, path := range shippedPlatformTemplates(t) {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, key := range []string{"networks:", "transit:", "mode: vlan", "members:"} {
				if strings.HasPrefix(trimmed, key) && !strings.HasPrefix(line, key) {
					// Only nested (sdn/network) keys are retired; a top-level
					// key of the same name belongs to another section.
					t.Errorf("%s: retired key %q: %s", path, key, trimmed)
				}
			}
		}
	}
}

// TestShippedTemplates_NoLiteralSecrets holds every shipped template, and
// every override example beside one, to the no-literal-secrets rule: each
// PIN, password and key field the App schema marks secret holds a secret
// reference (kms://), never a value an operator could copy into a
// deployment. platformd resolves the references before any field is read.
func TestShippedTemplates_NoLiteralSecrets(t *testing.T) {
	paths := shippedPlatformTemplates(t)
	for rel := range overrideExamples {
		paths = append(paths, filepath.Join(configRoot, rel))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		fields, err := bootstrap.PlaintextSecretFields(raw, reflect.TypeFor[App]())
		require.NoError(t, err, path)
		assert.Empty(t, fields, "%s: literal secret values; use a kms:// reference", path)
	}
}

// TestShippedTemplates_NoLiteralSecretsCatchesALiteral proves the check
// above can fail: a template carrying the literal PINs it replaced is
// reported field by field.
func TestShippedTemplates_NoLiteralSecretsCatchesALiteral(t *testing.T) {
	doc := []byte("platform:\n  so-pin: \"12345678\"\n  user-pin: \"kms://platform/user-pin?ensure=true&len=6&enc=numeric\"\n")
	fields, err := bootstrap.PlaintextSecretFields(doc, reflect.TypeFor[App]())
	require.NoError(t, err)
	assert.Equal(t, []string{"platform.so-pin"}, fields)
}

// TestShippedTemplates_QuicBaaSValidates runs every template's quicbaas
// section through the validation platformd runs before it opens the store,
// including the Raft rule: a template with join-addresses advertises a
// routable raft-address, or platformd refuses to start.
func TestShippedTemplates_QuicBaaSValidates(t *testing.T) {
	for _, path := range shippedPlatformTemplates(t) {
		a := loadTemplate(t, path)
		require.NotNil(t, a.QuicBaaSConfig, "%s: quicbaas section", path)
		require.NoError(t, a.QuicBaaSConfig.Validate(), path)
		if len(a.QuicBaaSConfig.JoinAddresses) > 0 {
			assert.True(t, quicbaas.IsRoutableRaftAddress(a.QuicBaaSConfig.RaftAddress),
				"%s: a node that joins peers advertises a routable raft-address", path)
		}
	}
}

// TestShippedTemplates_JoinWithoutRaftAddressRefused proves the check above
// can fail: a shipped template made to join a peer without a routable
// raft-address is refused naming the setting.
func TestShippedTemplates_JoinWithoutRaftAddressRefused(t *testing.T) {
	for _, path := range shippedPlatformTemplates(t) {
		a := loadTemplate(t, path)
		require.NotNil(t, a.QuicBaaSConfig, "%s: quicbaas section", path)
		a.QuicBaaSConfig.JoinAddresses = []string{"10.4.6.10:63000"}
		a.QuicBaaSConfig.RaftAddress = "127.0.0.1:63000"
		var target quicbaas.ErrRaftAdvertiseAddress
		require.ErrorAs(t, a.QuicBaaSConfig.Validate(), &target, path)
	}
}

// clusterExampleRoot holds the multi-node cluster example configurations.
var clusterExampleRoot = filepath.Join(configRoot, "platform", "cluster")

// TestShippedClusterExamples_ServersFormOneCluster checks the three server
// examples describe one cluster: each is clustered, all carry the same
// member list, deployment ID and Raft CA, and each lists itself at its own
// raft-address (Validate refuses anything else).
func TestShippedClusterExamples_ServersFormOneCluster(t *testing.T) {
	var first *quicbaas.Config
	for id := uint64(1); id <= 3; id++ {
		path := filepath.Join(clusterExampleRoot, fmt.Sprintf("server%d.example.com.yaml", id))
		c := loadTemplate(t, path).QuicBaaSConfig
		require.NotNil(t, c, "%s: quicbaas section", path)
		require.NoError(t, c.Validate(), path)
		require.True(t, c.IsClustered(), path)
		assert.Equal(t, id, c.NodeID, path)
		assert.Len(t, c.JoinAddresses, 3, path)
		if first == nil {
			first = c
			continue
		}
		assert.Equal(t, first.JoinAddresses, c.JoinAddresses, path)
		assert.Equal(t, first.DeploymentID, c.DeploymentID, path)
		assert.Equal(t, first.RaftTLSCAFile, c.RaftTLSCAFile, path)
	}
}

// TestShippedClusterExamples_ServersForwardToTheirInternalDNS pins the
// servers' dnsmasq forwarder where platformd decodes it, network.dnsmasq:
// under dns: the key is never read, and the resolver at 127.0.0.1 the
// servers name would have nothing behind it.
func TestShippedClusterExamples_ServersForwardToTheirInternalDNS(t *testing.T) {
	for id := 1; id <= 3; id++ {
		path := filepath.Join(clusterExampleRoot, fmt.Sprintf("server%d.example.com.yaml", id))
		n := loadTemplate(t, path).NetworkConfig
		require.NotNil(t, n, "%s: network section", path)
		require.NotNil(t, n.DNSMasq, "%s: network.dnsmasq", path)
		assert.True(t, n.DNSMasq.Enabled, path)
		assert.Equal(t, []string{"127.0.0.1:9053"}, n.DNSMasq.UpstreamServers, path)
	}
}
