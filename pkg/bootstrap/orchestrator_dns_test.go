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

package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	dnsconfig "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

func TestInternalDNSPort(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		config map[string]interface{}
		want   int
	}{
		"no dns section uses the default":   {config: map[string]interface{}{}, want: dnsconfig.DefaultInternalPort},
		"no internal zone uses the default": {config: map[string]interface{}{"dns": map[string]interface{}{}}, want: dnsconfig.DefaultInternalPort},
		"internal zone without a port uses the default": {
			config: map[string]interface{}{"dns": map[string]interface{}{"internal": map[string]interface{}{}}},
			want:   dnsconfig.DefaultInternalPort,
		},
		"configured port wins": {
			config: map[string]interface{}{"dns": map[string]interface{}{"internal": map[string]interface{}{"port": 5353}}},
			want:   5353,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := internalDNSPort(tc.config)
			if err != nil {
				t.Fatalf("internalDNSPort: %v", err)
			}
			if got != tc.want {
				t.Errorf("internalDNSPort = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestInternalDNSPort_RejectsAValueThatIsNotAPort(t *testing.T) {
	t.Parallel()

	cases := map[string]interface{}{
		"zero":         0,
		"negative":     -1,
		"out of range": maxPort + 1,
		"string":       "9053",
	}
	for name, port := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := map[string]interface{}{"dns": map[string]interface{}{"internal": map[string]interface{}{"port": port}}}

			var invalid ErrInvalidPort
			if _, err := internalDNSPort(config); !errors.As(err, &invalid) {
				t.Fatalf("internalDNSPort = %v, want ErrInvalidPort", err)
			}
			if invalid.Field != internalDNSPortField {
				t.Errorf("error must name %s, got %+v", internalDNSPortField, invalid)
			}
		})
	}
}

// newDNSTestOrchestrator builds an orchestrator for a control plane with a
// static address and a worker, both resolved from templates on disk. The
// control-plane template carries cpDNS verbatim as its dns section.
func newDNSTestOrchestrator(t *testing.T, cpDNS string) *Orchestrator {
	t.Helper()
	templateDir := t.TempDir()
	cpTemplate := filepath.Join(templateDir, "control-plane.yaml")
	workerTemplate := filepath.Join(templateDir, "worker.yaml")
	if err := os.WriteFile(cpTemplate, []byte("domain: cp.example.com\n"+cpDNS), 0o644); err != nil {
		t.Fatalf("write control-plane template: %v", err)
	}
	if err := os.WriteFile(workerTemplate, []byte("domain: worker.example.com\n"), 0o644); err != nil {
		t.Fatalf("write worker template: %v", err)
	}
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com", InternalDomain: "example.internal"},
		Templates:   map[string]string{RoleControlPlane: cpTemplate, RoleWorker: workerTemplate},
		Nodes: []NodeConfig{
			{
				Hostname: "cp-01",
				Role:     RoleControlPlane,
				MACs:     []string{"aa:bb:cc:dd:ee:01"},
				Interfaces: []installer.InterfaceConfig{{
					Name:        "eth0",
					Type:        installer.InterfaceTypeStatic,
					IPv4Address: "10.0.0.5/24",
				}},
			},
			{Hostname: "worker-01", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:02"}},
		},
	}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	return o
}

// resolvedUpstreamDNS resolves a node's config and returns the dnsmasq
// upstream the installer will forward to.
func resolvedUpstreamDNS(t *testing.T, o *Orchestrator, hostname, role string) string {
	t.Helper()
	resolved, err := o.resolveNodeConfig(hostname, role, nil)
	if err != nil {
		t.Fatalf("resolveNodeConfig(%s): %v", hostname, err)
	}
	var parsed struct {
		Network struct {
			DNS struct {
				UpstreamDNS string `yaml:"upstream-dns"`
			} `yaml:"dns"`
		} `yaml:"network"`
	}
	if err := yaml.Unmarshal([]byte(resolved), &parsed); err != nil {
		t.Fatalf("resolved config should be valid YAML: %v", err)
	}
	return parsed.Network.DNS.UpstreamDNS
}

func TestOrchestrator_ResolveNodeConfig_UpstreamDNSFollowsTheControlPlanePort(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		cpDNS      string
		wantWorker string
		wantCP     string
	}{
		"configured port": {
			cpDNS:      "dns:\n  internal:\n    port: 5353\n",
			wantWorker: "10.0.0.5#5353",
			wantCP:     "127.0.0.1#5353",
		},
		"unset port uses the DNS service default": {
			cpDNS:      "",
			wantWorker: "10.0.0.5#9053",
			wantCP:     "127.0.0.1#9053",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := newDNSTestOrchestrator(t, tc.cpDNS)
			if got := resolvedUpstreamDNS(t, o, "worker-01", RoleWorker); got != tc.wantWorker {
				t.Errorf("worker upstream-dns = %q, want %q", got, tc.wantWorker)
			}
			if got := resolvedUpstreamDNS(t, o, "cp-01", RoleControlPlane); got != tc.wantCP {
				t.Errorf("control-plane upstream-dns = %q, want %q", got, tc.wantCP)
			}
		})
	}
}

func TestOrchestrator_ResolveNodeConfig_InvalidControlPlaneDNSPortFails(t *testing.T) {
	t.Parallel()

	o := newDNSTestOrchestrator(t, "dns:\n  internal:\n    port: 70000\n")
	for _, node := range []struct{ hostname, role string }{
		{"worker-01", RoleWorker},
		{"cp-01", RoleControlPlane},
	} {
		_, err := o.resolveNodeConfig(node.hostname, node.role, nil)
		var merge ErrTemplateMergeFailed
		if !errors.As(err, &merge) {
			t.Fatalf("%s: resolveNodeConfig = %v, want ErrTemplateMergeFailed", node.hostname, err)
		}
		var invalid ErrInvalidPort
		if !errors.As(err, &invalid) || invalid.Field != internalDNSPortField {
			t.Errorf("%s: error must carry the invalid %s, got %v", node.hostname, internalDNSPortField, err)
		}
	}
}

func TestNetworkDNS(t *testing.T) {
	t.Parallel()

	empty := map[string]interface{}{}
	networkDNS(empty)["upstream-dns"] = "10.0.0.5#9053"
	network, ok := empty["network"].(map[string]interface{})
	if !ok {
		t.Fatalf("networkDNS must create the network section, got %v", empty)
	}
	if dnsSection, ok := network["dns"].(map[string]interface{}); !ok || dnsSection["upstream-dns"] != "10.0.0.5#9053" {
		t.Fatalf("networkDNS must create the dns section it returns, got %v", network)
	}

	existing := map[string]interface{}{"network": map[string]interface{}{"dns": map[string]interface{}{"keep": true}}}
	if got := networkDNS(existing); got["keep"] != true {
		t.Errorf("networkDNS must return the existing section, got %v", got)
	}
}
