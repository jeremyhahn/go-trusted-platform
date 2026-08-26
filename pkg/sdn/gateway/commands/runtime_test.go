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

package commands

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func TestBuildGatewayRuntimeAbsentOrDisabled(t *testing.T) {
	runtime, err := buildGatewayRuntime(context.Background(), nil, "", testLogger())
	if err != nil || runtime != nil {
		t.Fatalf("nil section: runtime=%v err=%v, want nil/nil", runtime, err)
	}
	runtime, err = buildGatewayRuntime(context.Background(), &sdn.Config{Enabled: false}, "", testLogger())
	if err != nil || runtime != nil {
		t.Fatalf("disabled section: runtime=%v err=%v, want nil/nil", runtime, err)
	}
}

func TestBuildGatewayRuntimeMissingOVS(t *testing.T) {
	cfg := &sdn.Config{Enabled: true}
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", testLogger()); !errors.Is(err, ErrSDNOVSRequired) {
		t.Fatalf("err = %v, want ErrSDNOVSRequired", err)
	}
}

func TestBuildGatewayRuntimeInvalidSection(t *testing.T) {
	cfg := &sdn.Config{
		Enabled: true,
		OVS:     &sdn.OVSConfig{Socket: "/nonexistent/db.sock", Bridge: "br0"},
		Networks: []sdn.NetworkConfig{{
			Name: "bogus",
			VLAN: 200,
			Zone: zone.Zone("undeclared-zone"),
		}},
	}
	var sectionErr *ErrConfigSection
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", testLogger()); !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection", err)
	}
}

func TestBuildGatewayRuntimeConnectFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing.sock")
	cfg := &sdn.Config{
		Enabled: true,
		OVS:     &sdn.OVSConfig{Socket: socket, Bridge: "br0"},
	}
	var connectErr *ErrOVSConnectFailed
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", testLogger()); !errors.As(err, &connectErr) {
		t.Fatalf("err = %v, want *ErrOVSConnectFailed", err)
	}
}

func TestBuildGatewayRuntimeEmptyZoneMatrixFailsClosed(t *testing.T) {
	// A zone-matrix service with no VLAN-bearing networks would compile
	// an empty matrix and pass all traffic; assembly must refuse before
	// even dialing OVSDB.
	cfg := &sdn.Config{
		Enabled: true,
		OVS:     &sdn.OVSConfig{Socket: "/nonexistent/db.sock", Bridge: "br0"},
	}
	var noNetsErr *ErrNoZoneNetworks
	_, err := buildGatewayRuntime(context.Background(), cfg, gateway.ServiceFirewall, testLogger())
	if !errors.As(err, &noNetsErr) || noNetsErr.Service != gateway.ServiceFirewall {
		t.Fatalf("err = %v, want ErrNoZoneNetworks{firewall}", err)
	}
}

func TestZoneProvidersDefaults(t *testing.T) {
	cfg := &sdn.Config{Enabled: true}
	zonesFn, networksFn, err := zoneProviders(cfg)
	if err != nil {
		t.Fatalf("zoneProviders: %v", err)
	}
	zones := zonesFn()
	if len(zones) == 0 {
		t.Fatal("zones must fall back to built-in defaults")
	}
	if nets := networksFn(); len(nets) != 0 {
		t.Fatalf("networks = %v, want empty without a networks: section", nets)
	}
}

func TestZoneProvidersWithNetworks(t *testing.T) {
	cfg := &sdn.Config{
		Enabled: true,
		Networks: []sdn.NetworkConfig{{
			Name:   "trusted-net",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Subnet: netip.MustParsePrefix("10.20.0.0/24"),
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	_, networksFn, err := zoneProviders(cfg)
	if err != nil {
		t.Fatalf("zoneProviders: %v", err)
	}
	nets := networksFn()
	summary, ok := nets[zone.ZoneTrusted]
	if !ok {
		t.Fatalf("networks = %v, want trusted zone entry", nets)
	}
	if summary.VLAN != 200 || summary.Subnet != "10.20.0.0/24" {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestZoneProvidersBadNetworkZone(t *testing.T) {
	cfg := &sdn.Config{
		Enabled: true,
		Networks: []sdn.NetworkConfig{{
			Name: "bogus",
			VLAN: 200,
			Zone: zone.Zone("undeclared-zone"),
		}},
	}
	if _, _, err := zoneProviders(cfg); err == nil {
		t.Fatal("network referencing an undeclared zone must fail")
	}
}

func TestDatapathService(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *gateway.GatewayConfig
		service string
	}{
		{"firewall", &gateway.GatewayConfig{Firewall: &gateway.FirewallConfig{Enabled: true}}, gateway.ServiceFirewall},
		{"nat", &gateway.GatewayConfig{NAT: &gateway.NATConfig{Enabled: true}}, gateway.ServiceNAT},
		{"load-balancer", &gateway.GatewayConfig{LoadBalancer: &gateway.LoadBalancerConfig{Enabled: true}}, gateway.ServiceLoadBalancer},
		{"none", &gateway.GatewayConfig{Enabled: true}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := datapathService(tc.cfg); got != tc.service {
				t.Fatalf("datapathService = %q, want %q", got, tc.service)
			}
		})
	}
}

func TestZoneMatrixService(t *testing.T) {
	lbOnly := &gateway.GatewayConfig{LoadBalancer: &gateway.LoadBalancerConfig{Enabled: true}}
	if got := zoneMatrixService(lbOnly); got != "" {
		t.Fatalf("zoneMatrixService(lb) = %q, want empty — the LB does not compile the zone matrix", got)
	}
	fw := &gateway.GatewayConfig{Firewall: &gateway.FirewallConfig{Enabled: true}}
	if got := zoneMatrixService(fw); got != gateway.ServiceFirewall {
		t.Fatalf("zoneMatrixService(firewall) = %q", got)
	}
	nat := &gateway.GatewayConfig{NAT: &gateway.NATConfig{Enabled: true}}
	if got := zoneMatrixService(nat); got != gateway.ServiceNAT {
		t.Fatalf("zoneMatrixService(nat) = %q", got)
	}
}

func TestBuildGatewayDatapathServiceWithoutSDN(t *testing.T) {
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{
			Enabled:  true,
			ID:       "gw-fw",
			Firewall: &gateway.FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
		},
	}
	var reqErr *ErrSDNRequiredForService
	if _, err := BuildGateway(context.Background(), cfg, testLogger()); !errors.As(err, &reqErr) {
		t.Fatalf("err = %v, want *ErrSDNRequiredForService", err)
	}
}

func TestBuildGatewaySkipsRuntimeWithoutDatapathService(t *testing.T) {
	// A proxy-less, datapath-less gateway with an sdn: section must not
	// dial OVSDB at all: the bogus socket would fail the build if it did.
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: true, ID: "gw-plain"},
		SDN: &sdn.Config{
			Enabled: true,
			OVS:     &sdn.OVSConfig{Socket: filepath.Join(t.TempDir(), "missing.sock"), Bridge: "br0"},
		},
	}
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	if gw.GetConfig().Runtime != nil {
		t.Fatal("runtime must not be assembled without a datapath service")
	}
}
