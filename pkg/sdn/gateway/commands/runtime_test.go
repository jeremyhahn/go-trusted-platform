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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func TestBuildGatewayRuntimeAbsentOrDisabled(t *testing.T) {
	runtime, err := buildGatewayRuntime(context.Background(), nil, "", false, testLogger())
	if err != nil || runtime != nil {
		t.Fatalf("nil section: runtime=%v err=%v, want nil/nil", runtime, err)
	}
	runtime, err = buildGatewayRuntime(context.Background(), &sdn.Config{Enabled: false}, "", false, testLogger())
	if err != nil || runtime != nil {
		t.Fatalf("disabled section: runtime=%v err=%v, want nil/nil", runtime, err)
	}
}

func TestBuildGatewayRuntimeMissingOVS(t *testing.T) {
	cfg := &sdn.Config{Enabled: true, Environment: &netplan.Environment{ID: 4}}
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", false, testLogger()); !errors.Is(err, ErrSDNOVSRequired) {
		t.Fatalf("err = %v, want ErrSDNOVSRequired", err)
	}
}

func TestBuildGatewayRuntimeInvalidSection(t *testing.T) {
	cfg := &sdn.Config{
		Enabled: true,
		OVS:     &sdn.OVSConfig{Socket: "/nonexistent/db.sock", Bridge: "br-fabric"},
		// Environment 1 is the site's VLAN block, never the platform's.
		Environment: &netplan.Environment{ID: 1},
	}
	var sectionErr *ErrConfigSection
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", false, testLogger()); !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection", err)
	}
}

func TestBuildGatewayRuntimeConnectFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing.sock")
	cfg := &sdn.Config{
		Enabled:     true,
		OVS:         &sdn.OVSConfig{Socket: socket, Bridge: "br-fabric"},
		Environment: &netplan.Environment{ID: 4},
	}
	var connectErr *ErrOVSConnectFailed
	if _, err := buildGatewayRuntime(context.Background(), cfg, "", false, testLogger()); !errors.As(err, &connectErr) {
		t.Fatalf("err = %v, want *ErrOVSConnectFailed", err)
	}
}

func TestBuildGatewayRuntimeNoEnvironment(t *testing.T) {
	// Without an environment nothing is numbered; assembly refuses before
	// dialing OVSDB.
	cfg := &sdn.Config{
		Enabled: true,
		OVS:     &sdn.OVSConfig{Socket: "/nonexistent/db.sock", Bridge: "br-fabric"},
	}
	var sectionErr *ErrConfigSection
	_, err := buildGatewayRuntime(context.Background(), cfg, gateway.ServiceFirewall, false, testLogger())
	if !errors.As(err, &sectionErr) || !errors.As(err, new(sdn.ErrEnvironmentRequired)) {
		t.Fatalf("err = %v, want ErrConfigSection wrapping ErrEnvironmentRequired", err)
	}
}

func TestZoneProvidersFromPlan(t *testing.T) {
	cfg := &sdn.Config{Enabled: true, Environment: &netplan.Environment{ID: 4}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	zonesFn, networksFn, err := zoneProviders(cfg)
	if err != nil {
		t.Fatalf("zoneProviders: %v", err)
	}
	if got := len(zonesFn()); got != 9 {
		t.Fatalf("zones = %d, want the 9 built-ins", got)
	}
	summary, ok := networksFn()[zone.ZoneControlPlane]
	if !ok || summary.VLAN != 406 || summary.Subnet != "10.4.6.0/24" {
		t.Fatalf("control-plane summary = %+v (%v), want VLAN 406 10.4.6.0/24", summary, ok)
	}
}

func TestZoneProvidersUnvalidated(t *testing.T) {
	// An unvalidated section has no plan: no zones are guessed.
	if _, _, err := zoneProviders(&sdn.Config{Enabled: true}); !errors.As(err, new(sdn.ErrEnvironmentRequired)) {
		t.Fatalf("err = %v, want ErrEnvironmentRequired", err)
	}
}

func TestErrNoZoneNetworksMessage(t *testing.T) {
	msg := (&ErrNoZoneNetworks{Service: gateway.ServiceFirewall}).Error()
	if !strings.Contains(msg, "sdn.environment") || !strings.Contains(msg, "firewall") {
		t.Fatalf("message %q", msg)
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
		// A supervised child that hosts no datapath service never opens
		// OVSDB, whatever else the shared configuration enables.
		{"firewall hosted elsewhere", &gateway.GatewayConfig{
			Firewall:       &gateway.FirewallConfig{Enabled: true},
			HostedServices: []string{gateway.ServiceTransit},
		}, ""},
		{"nat hosted here", &gateway.GatewayConfig{
			Firewall:       &gateway.FirewallConfig{Enabled: true},
			NAT:            &gateway.NATConfig{Enabled: true},
			HostedServices: []string{gateway.ServiceNAT},
		}, gateway.ServiceNAT},
		{"overlay", &gateway.GatewayConfig{Overlay: &gateway.OverlayServiceConfig{Enabled: true}}, gateway.ServiceOverlay},
		// The routing child reads the same configuration as the datapath
		// process; an overlay it does not host opens nothing (#765).
		{"overlay hosted elsewhere", &gateway.GatewayConfig{
			Overlay:        &gateway.OverlayServiceConfig{Enabled: true},
			HostedServices: []string{gateway.ServiceTransit},
		}, ""},
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

// supervisedDatapathConfig enables every OVS-backed datapath service over an
// sdn: section whose OVSDB socket does not exist, so any dial fails the build.
func supervisedDatapathConfig(t *testing.T) *ServeConfig {
	t.Helper()
	return &ServeConfig{
		Gateway: &gateway.GatewayConfig{
			Enabled:  true,
			ID:       "gw-supervisor",
			Firewall: &gateway.FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
			NAT: &gateway.NATConfig{
				Enabled:        true,
				ExternalIP:     "203.0.113.10",
				PortRangeStart: 1024,
				PortRangeEnd:   65535,
				MaxSessions:    1000,
				InternalCIDR:   "10.0.100.0/24",
			},
			LoadBalancer: &gateway.LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "hash",
				HealthCheckInterval: time.Hour,
				HealthCheckTimeout:  time.Second,
				MaxBackends:         8,
			},
		},
		SDN: &sdn.Config{
			Enabled:     true,
			OVS:         &sdn.OVSConfig{Socket: filepath.Join(t.TempDir(), "missing.sock"), Bridge: "br0"},
			Environment: &netplan.Environment{ID: 4},
		},
		Process: supervisorSettings(t),
		DataDir: t.TempDir(),
	}
}

func TestBuildGatewaySupervisorRelaysTheDatapathWithoutDialingOVSDB(t *testing.T) {
	// The datapath child holds the OVS runtime (#557, R14); the supervising
	// parent relays to it and must not dial OVSDB itself.
	cfg := supervisedDatapathConfig(t)
	if _, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "/etc/gatewayd/config.yaml"}, testLogger()); err != nil {
		t.Fatalf("BuildSupervisor: %v", err)
	}
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway must relay the datapath, not dial OVSDB: %v", err)
	}
	if gw.GetConfig().Runtime != nil {
		t.Fatal("the supervising parent must not hold the OVS runtime")
	}
	registered := make(map[string]bool)
	for _, report := range gw.ServiceReports() {
		registered[report.Name] = true
	}
	for _, service := range []string{gateway.ServiceFirewall, gateway.ServiceNAT, gateway.ServiceLoadBalancer} {
		if !registered[service] {
			t.Fatalf("the supervising parent must register the %s relay", service)
		}
	}
}

func TestBuildGatewayWithoutSupervisorDialsOVSDBForTheDatapath(t *testing.T) {
	// The same configuration without a supervisor runs the datapath in this
	// process, so the missing OVSDB socket fails the build.
	var connectErr *ErrOVSConnectFailed
	if _, err := BuildGateway(context.Background(), supervisedDatapathConfig(t), testLogger()); !errors.As(err, &connectErr) {
		t.Fatalf("err = %v, want *ErrOVSConnectFailed: an unsupervised datapath dials OVSDB", err)
	}
}

func TestRunsOverlay(t *testing.T) {
	cases := []struct {
		name string
		cfg  *gateway.GatewayConfig
		want bool
	}{
		{"no overlay section", &gateway.GatewayConfig{}, false},
		{"overlay disabled", &gateway.GatewayConfig{Overlay: &gateway.OverlayServiceConfig{}}, false},
		{"overlay hosted by the only process", &gateway.GatewayConfig{Overlay: &gateway.OverlayServiceConfig{Enabled: true}}, true},
		{"overlay hosted here", &gateway.GatewayConfig{
			Overlay:        &gateway.OverlayServiceConfig{Enabled: true},
			HostedServices: []string{gateway.ServiceOverlay},
		}, true},
		{"overlay hosted elsewhere", &gateway.GatewayConfig{
			Overlay:        &gateway.OverlayServiceConfig{Enabled: true},
			HostedServices: []string{gateway.ServiceTransit},
		}, false},
		{"hosted but disabled", &gateway.GatewayConfig{
			Overlay:        &gateway.OverlayServiceConfig{},
			HostedServices: []string{gateway.ServiceOverlay},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runsOverlay(tc.cfg); got != tc.want {
				t.Fatalf("runsOverlay = %v, want %v", got, tc.want)
			}
		})
	}
}

// overlaySharedConfig is the configuration every supervised gatewayd
// process reads on an overlay gateway, with hosted as the process's
// HostedServices. Its OVS socket does not exist and its platformd protocol
// is unknown, so opening OVSDB or dialing platformd fails the build.
func overlaySharedConfig(t *testing.T, hosted ...string) *ServeConfig {
	t.Helper()
	return &ServeConfig{
		Gateway: &gateway.GatewayConfig{
			Enabled:        true,
			ID:             "gw-overlay",
			HostedServices: hosted,
			Overlay: &gateway.OverlayServiceConfig{
				Enabled:           true,
				LocalVTEP:         netip.MustParseAddr("10.4.100.20"),
				UnderlayInterface: "vtep0",
				UnderlayMTU:       9216,
				AccessPort:        "patch-workloads",
				OverlayASN:        65000,
				VXLANPort:         4789,
				VNIs:              []gateway.OverlayVNIConfig{{VNI: 40100, VLAN: 100}},
				DefaultVNI:        40100,
				MaxVNIs:           gateway.DefaultMaxVNIs,
				VerdictMaxAge:     time.Minute,
			},
		},
		SDN: &sdn.Config{
			Enabled:     true,
			OVS:         &sdn.OVSConfig{Socket: filepath.Join(t.TempDir(), "missing.sock"), Bridge: "br0"},
			Environment: &netplan.Environment{ID: 4},
		},
		Proxy: &proxysvc.Config{Platformd: proxysvc.PlatformdConfig{Protocol: "carrier-pigeon"}},
	}
}

func TestBuildGateway_RoutingChildAssemblesNoOverlay(t *testing.T) {
	cfg := overlaySharedConfig(t, gateway.ServiceTransit)
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v (the routing child opened OVSDB or dialed platformd)", err)
	}
	if gw.GetConfig().Runtime != nil {
		t.Fatal("the routing child must not assemble the overlay runtime")
	}
}

func TestBuildGateway_OverlayHostOpensOVSDB(t *testing.T) {
	for _, hosted := range [][]string{nil, {gateway.ServiceOverlay}} {
		cfg := overlaySharedConfig(t, hosted...)
		var connectErr *ErrOVSConnectFailed
		if _, err := BuildGateway(context.Background(), cfg, testLogger()); !errors.As(err, &connectErr) {
			t.Fatalf("hosted %v: err = %v, want *ErrOVSConnectFailed", hosted, err)
		}
	}
}

func TestWireOverlayRuntime_DialsOnlyInTheOverlayHost(t *testing.T) {
	runtime := &gateway.GatewayRuntime{}
	if err := wireOverlayRuntime(context.Background(), overlaySharedConfig(t, gateway.ServiceTransit), nil, runtime); err != nil {
		t.Fatalf("routing child: err = %v, want no dial", err)
	}
	if runtime.OverlayPlatform != nil {
		t.Fatal("routing child: the overlay platform must not be wired")
	}

	var cfgErr *proxysvc.ErrConfigInvalid
	if err := wireOverlayRuntime(context.Background(), overlaySharedConfig(t, gateway.ServiceOverlay), nil, runtime); !errors.As(err, &cfgErr) {
		t.Fatalf("overlay host: err = %v, want the dial's *proxysvc.ErrConfigInvalid", err)
	}
}
