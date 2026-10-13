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

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// loopbackVTEP is the VTEP of a node configured with vtep-address 127.0.0.1
// on underlay-interface lo, without IPsec.
var loopbackVTEP = overlayVTEP{addr: netip.MustParseAddr("127.0.0.1"), iface: "lo"}

// errInterfaceLookup stands in for a fabric interface that cannot be read.
var errInterfaceLookup = errors.New("injected interface lookup failure")

// fabricAddrs reports addrs on bond0 and fails for every other interface.
func fabricAddrs(addrs ...string) interfaceAddrsFunc {
	return func(name string) ([]netip.Addr, error) {
		if name != "bond0" {
			return nil, errInterfaceLookup
		}
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// noInterfaceLookup fails the test when the interfaces are read.
func noInterfaceLookup(t *testing.T) interfaceAddrsFunc {
	return func(name string) ([]netip.Addr, error) {
		t.Fatalf("interface %s read on a node without overlay IPsec", name)
		return nil, errInterfaceLookup
	}
}

// overlayTestApp is an App with a validated environment-4 SDN section.
func overlayTestApp(t *testing.T) *app.App {
	t.Helper()
	a := &app.App{
		Hostname: "cp-01",
		SDNConfig: &sdn.Config{
			Enabled:     true,
			Environment: &netplan.Environment{ID: 4},
			OVS:         &sdn.OVSConfig{Socket: "/var/run/openvswitch/db.sock", Bridge: "br-fabric"},
			Overlay:     &sdn.OverlayConfig{Enabled: true},
		},
	}
	if err := a.SDNConfig.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return a
}

// TestBuildOverlayController_EnvironmentAndBridge wires the plan's
// environment and the br-int integration bridge, never the trunk bridge.
func TestBuildOverlayController_EnvironmentAndBridge(t *testing.T) {
	logger := logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
	ctrl, err := buildOverlayController(context.Background(), overlayTestApp(t), loopbackVTEP, "", logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })

	cfg := &overlay.VNIConfig{}
	if err := ctrl.AddVNI(context.Background(), cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}
	if cfg.VNI != 400001 {
		t.Fatalf("derived VNI %d, want 400001 (environment 4)", cfg.VNI)
	}
}

// TestBuildOverlayController_NoPlanNeedsExplicitVNIs starts without an
// environment; a derived VNI is then refused.
func TestBuildOverlayController_NoPlanNeedsExplicitVNIs(t *testing.T) {
	logger := logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
	a := &app.App{Hostname: "cp-01", SDNConfig: &sdn.Config{Overlay: &sdn.OverlayConfig{}}}
	ctrl, err := buildOverlayController(context.Background(), a, loopbackVTEP, "", logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })
	if err := ctrl.AddVNI(context.Background(), &overlay.VNIConfig{}); err == nil {
		t.Fatal("deriving a VNI without an environment must fail")
	}
}

// TestBuildOverlayController_RegistersTheVTEPItIsGiven: the controller takes
// its VTEP address and underlay interface from the resolved VTEP alone.
func TestBuildOverlayController_RegistersTheVTEPItIsGiven(t *testing.T) {
	logger := logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
	a := overlayTestApp(t)
	a.PublicIPv4 = net.ParseIP("203.0.113.7")
	vtep := overlayVTEP{addr: netip.MustParseAddr("10.20.0.11"), iface: "bond0"}
	ctrl, err := buildOverlayController(context.Background(), a, vtep, "", logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })
	if cfg := ctrl.GetConfig(); cfg.VTEPIP != vtep.addr || cfg.UnderlayInterface != vtep.iface {
		t.Fatalf("controller VTEP %s on %s, want %s on %s", cfg.VTEPIP, cfg.UnderlayInterface, vtep.addr, vtep.iface)
	}
	if _, err := ctrl.GetVTEP(context.Background(), vtep.addr); err != nil {
		t.Fatalf("local VTEP %s not registered: %v", vtep.addr, err)
	}
}

// overlayOnFabric is an enabled overlay whose IPsec local endpoint is the
// private fabric address 10.20.0.11 on bond0.
func overlayOnFabric() *sdn.OverlayConfig {
	return &sdn.OverlayConfig{
		Enabled: true,
		IPsec: &ipsecconfig.Config{
			Enabled:         true,
			FabricInterface: "bond0",
			LocalAddress:    "10.20.0.11",
		},
	}
}

func TestResolveOverlayVTEP_IsTheIPsecEndpoint(t *testing.T) {
	public := net.ParseIP("203.0.113.7")
	for _, tt := range []struct {
		name     string
		underlay string
	}{
		{"underlay unset", ""},
		{"underlay is the fabric", "bond0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := overlayOnFabric()
			cfg.UnderlayInterface = tt.underlay
			vtep, err := resolveOverlayVTEP(public, cfg, fabricAddrs("fe80::1", "10.20.0.11"))
			if err != nil {
				t.Fatalf("resolveOverlayVTEP: %v", err)
			}
			want := overlayVTEP{addr: netip.MustParseAddr("10.20.0.11"), iface: "bond0"}
			if vtep != want {
				t.Fatalf("VTEP %+v, want the IPsec endpoint %+v (not the public %s)", vtep, want, public)
			}
		})
	}
}

func TestResolveOverlayVTEP_WithoutIPsec(t *testing.T) {
	for _, tt := range []struct {
		name   string
		public net.IP
		cfg    *sdn.OverlayConfig
		want   overlayVTEP
	}{
		{"configured loopback node", nil, &sdn.OverlayConfig{Enabled: true, VTEPAddress: "127.0.0.1", UnderlayInterface: "lo"}, loopbackVTEP},
		{
			"configured address wins over the public one", net.ParseIP("203.0.113.7"),
			&sdn.OverlayConfig{Enabled: true, VTEPAddress: "10.20.0.11", UnderlayInterface: "bond0"},
			overlayVTEP{addr: netip.MustParseAddr("10.20.0.11"), iface: "bond0"},
		},
		{
			"configured IPv4-mapped address is unmapped", nil,
			&sdn.OverlayConfig{Enabled: true, VTEPAddress: "::ffff:10.20.0.11", UnderlayInterface: "bond0"},
			overlayVTEP{addr: netip.MustParseAddr("10.20.0.11"), iface: "bond0"},
		},
		{
			"public address on the uplink", net.ParseIP("203.0.113.7"),
			&sdn.OverlayConfig{Enabled: true, UnderlayInterface: "eth0"},
			overlayVTEP{addr: netip.MustParseAddr("203.0.113.7"), iface: "eth0"},
		},
		{
			"IPsec disabled", net.ParseIP("203.0.113.7"),
			&sdn.OverlayConfig{Enabled: true, UnderlayInterface: "eth0", IPsec: &ipsecconfig.Config{FabricInterface: "bond0", LocalAddress: "10.20.0.11"}},
			overlayVTEP{addr: netip.MustParseAddr("203.0.113.7"), iface: "eth0"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			vtep, err := resolveOverlayVTEP(tt.public, tt.cfg, noInterfaceLookup(t))
			if err != nil || vtep != tt.want {
				t.Fatalf("resolveOverlayVTEP = %+v, %v; want %+v", vtep, err, tt.want)
			}
		})
	}
}

// TestResolveOverlayVTEP_RefusesAnUndeterminedVTEP: without IPsec nothing is
// guessed; a missing or unusable address or interface names the key to set.
func TestResolveOverlayVTEP_RefusesAnUndeterminedVTEP(t *testing.T) {
	for _, tt := range []struct {
		name    string
		public  net.IP
		cfg     *sdn.OverlayConfig
		setting string
		value   string
	}{
		{"no address at all", nil, &sdn.OverlayConfig{Enabled: true, UnderlayInterface: "lo"}, overlayVTEPAddressKey, ""},
		{"unspecified public address", net.IPv4zero, &sdn.OverlayConfig{Enabled: true, UnderlayInterface: "eth0"}, overlayVTEPAddressKey, ""},
		{"configured address is not an IP", nil, &sdn.OverlayConfig{Enabled: true, VTEPAddress: "node-1", UnderlayInterface: "eth0"}, overlayVTEPAddressKey, "node-1"},
		{"configured address is unspecified", nil, &sdn.OverlayConfig{Enabled: true, VTEPAddress: "0.0.0.0", UnderlayInterface: "eth0"}, overlayVTEPAddressKey, "0.0.0.0"},
		{"configured address is multicast", nil, &sdn.OverlayConfig{Enabled: true, VTEPAddress: "239.1.1.1", UnderlayInterface: "eth0"}, overlayVTEPAddressKey, "239.1.1.1"},
		{"no underlay interface", net.ParseIP("203.0.113.7"), &sdn.OverlayConfig{Enabled: true}, overlayUnderlayInterfaceKey, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveOverlayVTEP(tt.public, tt.cfg, noInterfaceLookup(t))
			var settingErr *OverlayVTEPSettingError
			if !errors.As(err, &settingErr) {
				t.Fatalf("err = %v, want an OverlayVTEPSettingError", err)
			}
			if settingErr.Setting != tt.setting || settingErr.Value != tt.value {
				t.Fatalf("error names %s=%q, want %s=%q", settingErr.Setting, settingErr.Value, tt.setting, tt.value)
			}
		})
	}
}

func TestOverlayVTEPSettingError_Message(t *testing.T) {
	missing := &OverlayVTEPSettingError{Setting: overlayVTEPAddressKey}
	if want := "daemon: overlay VTEP undetermined: set sdn.overlay.vtep-address"; missing.Error() != want {
		t.Fatalf("Error() = %q, want %q", missing.Error(), want)
	}
	invalid := &OverlayVTEPSettingError{Setting: overlayVTEPAddressKey, Value: "0.0.0.0"}
	if want := `daemon: overlay VTEP: sdn.overlay.vtep-address "0.0.0.0" is not a unicast IP address`; invalid.Error() != want {
		t.Fatalf("Error() = %q, want %q", invalid.Error(), want)
	}
}

func TestResolveOverlayVTEP_RefusesAVTEPTheFloorDoesNotProtect(t *testing.T) {
	for _, tt := range []struct {
		name     string
		underlay string
		addrs    interfaceAddrsFunc
		want     error
	}{
		{"address not on the fabric", "", fabricAddrs("10.20.0.12", "fe80::1"), ErrVTEPNotOnFabric},
		{"underlay is not the fabric", "eth0", fabricAddrs("10.20.0.11"), ErrUnderlayNotFabric},
		{"fabric interface unreadable", "", func(string) ([]netip.Addr, error) { return nil, errInterfaceLookup }, errInterfaceLookup},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := overlayOnFabric()
			cfg.UnderlayInterface = tt.underlay
			_, err := resolveOverlayVTEP(net.ParseIP("203.0.113.7"), cfg, tt.addrs)
			var vtepErr *OverlayVTEPError
			if !errors.As(err, &vtepErr) || !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want an OverlayVTEPError wrapping %v", err, tt.want)
			}
			if vtepErr.Address != netip.MustParseAddr("10.20.0.11") {
				t.Fatalf("error names %s, want the IPsec local address", vtepErr.Address)
			}
		})
	}
}

func TestResolveOverlayVTEP_RefusesAnUnusableLocalAddress(t *testing.T) {
	cfg := overlayOnFabric()
	cfg.IPsec.LocalAddress = "0.0.0.0"
	_, err := resolveOverlayVTEP(nil, cfg, fabricAddrs("10.20.0.11"))
	var cfgErr *ipsecconfig.ConfigError
	if !errors.As(err, &cfgErr) || cfgErr.Field != "local-address" {
		t.Fatalf("err = %v, want a ConfigError on local-address", err)
	}
}

func TestOverlayVTEPError_Message(t *testing.T) {
	err := &OverlayVTEPError{Address: netip.MustParseAddr("10.20.0.11"), Interface: "bond0", Err: ErrVTEPNotOnFabric}
	want := "daemon: overlay VTEP 10.20.0.11 on bond0: " + ErrVTEPNotOnFabric.Error()
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestInterfaceAddrs(t *testing.T) {
	addrs, err := interfaceAddrs("lo")
	if err != nil {
		t.Fatalf("interfaceAddrs(lo): %v", err)
	}
	if !slices.Contains(addrs, netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("lo addresses %v, want 127.0.0.1 unmapped", addrs)
	}
	if _, err := interfaceAddrs("tp-no-such0"); err == nil {
		t.Fatal("an interface that does not exist was read")
	}
}
