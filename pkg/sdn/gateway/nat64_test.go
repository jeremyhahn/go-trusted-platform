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

package gateway

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// TestNAT64Config_HyphenatedKeysDecode is the config-reachability test this
// project keeps needing: mapstructure falls back to field names, so a
// hyphenated key without an explicit tag decodes to nothing and the section
// is silently dropped (#606, #607). Every key the docs promise is asserted
// to arrive.
func TestNAT64Config_HyphenatedKeysDecode(t *testing.T) {
	const doc = `
nat64:
  enabled: true
  prefix: "64:ff9b::/96"
  instance: tp-nat64
  translator-port: nat640
  bridge: trusted0
  pool4:
    uplink: primary
    addresses: ["203.0.113.64-203.0.113.71"]
    port-range-start: 61001
    port-range-end: 65535
  session-timeouts:
    udp: 5m
    tcp-established: 2h4m
    tcp-transitory: 4m
    icmp: 1m
  client-zones:
    - name: iot
      vlan: 300
`
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte(doc))))

	var cfg NAT64Config
	require.NoError(t, v.UnmarshalKey("nat64", &cfg))

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "64:ff9b::/96", cfg.Prefix)
	assert.Equal(t, "tp-nat64", cfg.Instance)
	assert.Equal(t, "nat640", cfg.TranslatorPort, "translator-port is where the table-27 gate sends frames")
	assert.Equal(t, "trusted0", cfg.Bridge)
	assert.Equal(t, "primary", cfg.Pool4.Uplink)
	assert.Equal(t, []string{"203.0.113.64-203.0.113.71"}, cfg.Pool4.Addresses)
	assert.Equal(t, uint16(61001), cfg.Pool4.PortRangeStart)
	assert.Equal(t, uint16(65535), cfg.Pool4.PortRangeEnd)
	assert.Equal(t, 5*time.Minute, cfg.SessionTimeouts.UDP)
	assert.Equal(t, 2*time.Hour+4*time.Minute, cfg.SessionTimeouts.TCPEstablished)
	assert.Equal(t, 4*time.Minute, cfg.SessionTimeouts.TCPTransitory)
	assert.Equal(t, time.Minute, cfg.SessionTimeouts.ICMP)
	require.Len(t, cfg.ClientZones, 1)
	assert.Equal(t, "iot", cfg.ClientZones[0].Name)
	assert.Equal(t, uint16(300), cfg.ClientZones[0].VLAN)

	require.NoError(t, cfg.Validate(), "the section the docs show must be one the daemon accepts")
}

func TestNAT64Config_ServiceConfigCarriesEveryFieldAcross(t *testing.T) {
	cfg := &NAT64Config{
		Enabled:        true,
		Prefix:         "2001:db8:1::/48",
		Instance:       "site-nat64",
		TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64", "203.0.113.80-203.0.113.87"},
			PortRangeStart: 1024,
			PortRangeEnd:   65535,
		},
		SessionTimeouts: NAT64TimeoutsConfig{UDP: 10 * time.Minute},
		ClientZones:     []NAT64ClientZoneConfig{{Name: "iot", VLAN: 300}},
	}
	svc := cfg.ServiceConfig("runtime-bridge")

	assert.Equal(t, "runtime-bridge", svc.Bridge, "the runtime bridge is used when the section names none")
	assert.Equal(t, "2001:db8:1::/48", svc.Prefix)
	assert.Equal(t, "site-nat64", svc.Instance)
	require.Len(t, svc.Pool4, 2, "one Pool4Range per address entry")
	assert.Equal(t, uint16(1024), svc.Pool4[1].PortStart, "the port range applies to every address")
	assert.Equal(t, 10*time.Minute, svc.Timeouts.UDP)
	require.Len(t, svc.ClientZones, 1)
	assert.Equal(t, uint16(300), svc.ClientZones[0].VLAN)
}

func TestNAT64Config_SectionBridgeOverridesTheRuntime(t *testing.T) {
	cfg := &NAT64Config{Bridge: "edge0"}
	assert.Equal(t, "edge0", cfg.ServiceConfig("trusted0").Bridge)
}

func TestNAT64Config_DisabledSectionValidatesTrivially(t *testing.T) {
	// A disabled section is not held to the contract; an operator who
	// switches it off should not have to fix its fields first.
	cfg := &NAT64Config{Enabled: false, Prefix: "not-a-prefix"}
	assert.NoError(t, cfg.Validate())
}

func TestNAT64Config_EnabledSectionIsHeldToTheWholeContract(t *testing.T) {
	cfg := &NAT64Config{Enabled: true, Prefix: "2001:db8::/44"}
	err := cfg.Validate()
	var typed *ErrNAT64ConfigInvalid
	require.True(t, errors.As(err, &typed), "got %v", err)
	var prefixErr *nat64.ErrInvalidNAT64Prefix
	assert.True(t, errors.As(err, &prefixErr), "the section error must carry the service's own reason: %v", err)
}

func TestGatewayConfig_NAT64SectionIsValidatedWithTheRest(t *testing.T) {
	cfg := baseGatewayConfig("nat64-gw")
	cfg.NAT64 = &NAT64Config{Enabled: true, TranslatorPort: "nat640"}
	err := cfg.Validate()
	var typed *ErrNAT64ConfigInvalid
	require.True(t, errors.As(err, &typed), "a broken nat64 section must fail the gateway config: %v", err)
}

func TestNAT64_NeedsPipeline(t *testing.T) {
	// The service programs the datapath, so the gateway must own the base
	// pipeline before it starts — otherwise its table-10 gate has no
	// pipeline to gate out of (#567).
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = &GatewayRuntime{}
	assert.False(t, cfg.needsPipeline(), "no datapath service is enabled yet")

	cfg.NAT64 = &NAT64Config{Enabled: true}
	assert.True(t, cfg.needsPipeline(), "nat64 programs flows and needs the base pipeline")
}

// TestNAT44Ranges_ReadsBothNATShapes covers the overlap check's input: the
// multi-uplink pools and the single-external-address shape.
func TestNAT44Ranges_ReadsBothNATShapes(t *testing.T) {
	t.Run("no NAT service", func(t *testing.T) {
		assert.Nil(t, nat44Ranges(nil))
		assert.Nil(t, nat44Ranges(&NATConfig{Enabled: false}))
	})

	t.Run("single external address", func(t *testing.T) {
		got := nat44Ranges(&NATConfig{
			Enabled: true, ExternalIP: "203.0.113.10", PortRangeStart: 1024, PortRangeEnd: 65535,
		})
		require.Len(t, got, 1)
		assert.Equal(t, "203.0.113.10", got[0].Addresses)
		assert.Equal(t, uint16(1024), got[0].PortStart)
	})

	t.Run("static externals own every port", func(t *testing.T) {
		got := nat44Ranges(&NATConfig{
			Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535,
			Uplinks: []NATUplinkConfig{{Name: "primary", Addresses: []string{"203.0.113.10"}}},
			Static:  []NATStaticConfig{{Internal: "10.0.0.5", External: "203.0.113.70", Uplink: "primary"}},
		})
		require.Len(t, got, 2)
		assert.Equal(t, nat64.NAT44Range{Uplink: "primary", Addresses: "203.0.113.70", PortStart: 1, PortEnd: 65535}, got[0])
	})

	t.Run("per-uplink pools", func(t *testing.T) {
		got := nat44Ranges(&NATConfig{
			Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535,
			Uplinks: []NATUplinkConfig{
				{Name: "primary", Addresses: []string{"203.0.113.10", "203.0.113.11"}},
				{Name: "backup", Addresses: []string{"198.51.100.10"}, PortRangeStart: 30000, PortRangeEnd: 40000},
			},
		})
		require.Len(t, got, 3, "one range per address")
		assert.Equal(t, "primary", got[0].Uplink)
		assert.Equal(t, uint16(1024), got[1].PortStart, "an uplink without its own range takes the config-wide one")
		assert.Equal(t, uint16(30000), got[2].PortStart, "an uplink's own range wins")
	})
}

func TestBuildNAT64_RefusesAPoolNAT44AlreadyAllocates(t *testing.T) {
	// Two allocators handing out the same address and port produce a
	// collision that looks like packet loss and explains itself nowhere.
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = &GatewayRuntime{Bridge: "trusted0"}
	cfg.NAT = &NATConfig{
		Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10,
		InternalCIDR: "10.0.0.0/24",
		Uplinks:      []NATUplinkConfig{{Name: "primary", Addresses: []string{"203.0.113.64-203.0.113.79"}}},
	}
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64-203.0.113.71"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}

	_, err := buildNAT64(&Gateway{config: cfg})
	var overlap *nat64.ErrNAT64PoolOverlap
	require.True(t, errors.As(err, &overlap), "got %v", err)
	assert.Equal(t, "primary", overlap.Uplink)
}

func TestBuildNAT64_RefusesAPoolThatTakesAStaticExternal(t *testing.T) {
	// A 1:1 static translation owns every port of its external address; a
	// pool4 range on it collides with each inbound connection.
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = &GatewayRuntime{Bridge: "trusted0"}
	cfg.NAT = &NATConfig{
		Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10,
		InternalCIDR: "10.0.0.0/24",
		Uplinks:      []NATUplinkConfig{{Name: "primary", Addresses: []string{"203.0.113.10"}}},
		Static:       []NATStaticConfig{{Internal: "10.0.0.5", External: "203.0.113.70", Uplink: "primary"}},
	}
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64-203.0.113.71"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}

	_, err := buildNAT64(&Gateway{config: cfg})
	var overlap *nat64.ErrNAT64PoolOverlap
	require.True(t, errors.As(err, &overlap), "got %v", err)
	assert.Equal(t, "203.0.113.70", overlap.Conflict)
}

func TestNAT64Config_Pool4UplinkMustNameANATUplink(t *testing.T) {
	section := func(uplink string) *NAT64Config {
		return &NAT64Config{
			Enabled: true, TranslatorPort: "nat640",
			Pool4: NAT64Pool4Config{
				Uplink:         uplink,
				Addresses:      []string{"203.0.113.64"},
				PortRangeStart: 61001, PortRangeEnd: 65535,
			},
		}
	}
	nat := &NATConfig{Enabled: true, Uplinks: []NATUplinkConfig{{Name: "primary"}}}

	assert.NoError(t, section("").validateUplink(nil), "the field is optional")
	assert.NoError(t, section("primary").validateUplink(nat))

	for name, natCfg := range map[string]*NATConfig{
		"an unknown uplink": nat,
		"no nat section":    nil,
		"a disabled nat":    {Enabled: false, Uplinks: []NATUplinkConfig{{Name: "backup"}}},
	} {
		t.Run(name, func(t *testing.T) {
			err := section("backup").validateUplink(natCfg)
			var unknown *ErrNAT64UplinkUnknown
			require.ErrorAs(t, err, &unknown)
			assert.Equal(t, "backup", unknown.Uplink)
			assert.Contains(t, err.Error(), `"backup"`)
		})
	}

	disabled := section("nowhere")
	disabled.Enabled = false
	assert.NoError(t, disabled.validateUplink(nil), "a disabled section is not checked")

	gw := baseGatewayConfig("nat64-gw")
	gw.NAT64 = section("nowhere")
	var unknown *ErrNAT64UplinkUnknown
	assert.ErrorAs(t, gw.Validate(), &unknown, "GatewayConfig.Validate runs the check")
}

func TestBuildNAT64_AcceptsADisjointPool(t *testing.T) {
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = newTestRuntime()
	cfg.NAT = &NATConfig{
		Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10,
		InternalCIDR: "10.0.0.0/24",
		Uplinks:      []NATUplinkConfig{{Name: "primary", Addresses: []string{"203.0.113.10-203.0.113.20"}}},
	}
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64-203.0.113.71"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}
	cfg.Host = &HostRuntime{NAT64Driver: &stubNAT64Driver{}}

	svc, err := buildNAT64(&Gateway{config: cfg})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.False(t, svc.Active(), "a built service has not started yet")
}

func TestBuildNAT64_UsesTheInjectedDriver(t *testing.T) {
	// Without the seam the builder opens the real jool tool, which needs
	// the kernel module; the daemon and the tests inject their own.
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = newTestRuntime()
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}
	driver := &stubNAT64Driver{}
	cfg.Host = &HostRuntime{NAT64Driver: driver}

	svc, err := buildNAT64(&Gateway{config: cfg})
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// stubNAT64Driver is an injected driver that programs nothing.
type stubNAT64Driver struct{}

func (*stubNAT64Driver) Apply(_ context.Context, _ nat64.Instance) (bool, error) { return true, nil }
func (*stubNAT64Driver) Remove(_ context.Context, _ string) error                { return nil }
func (*stubNAT64Driver) Stats(_ context.Context, _ string) (nat64.Stats, error) {
	return nat64.Stats{Present: true}, nil
}

// TestBuildHostFW_OpensNothingForTheTranslator: the host filter's input
// chain never sees translator traffic. Jool hooks PREROUTING, and what it
// translates is sent straight to POSTROUTING, skipping INPUT and FORWARD;
// what it does not translate is not addressed to the host. Leaving the
// translator port unfiltered, as #614 first did, opened every local
// listener to anything arriving on that interface.
func TestBuildHostFW_OpensNothingForTheTranslator(t *testing.T) {
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = newTestRuntime()
	cfg.HostFW = &hostfw.Config{Enabled: true}
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}
	cfg.Host = &HostRuntime{HostFWApplier: &fakeHostFWApplier{}}

	svc, err := buildHostFW(&Gateway{config: cfg})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	backend, ok := svc.(hostFWBackend)
	require.True(t, ok)
	rendered := backend.Rendered()
	require.NotNil(t, rendered)
	assert.NotContains(t, rendered.Text, "nat640",
		"the translator port must not be an unfiltered interface")
}

// TestSnapshot_ReportsNAT64Health is the surface requirement: the section's
// liveness has to reach the operator. It rides the handler registry, so a
// refused or unhealthy translator shows up as an unhealthy component rather
// than a missing one.
func TestSnapshot_ReportsNAT64Health(t *testing.T) {
	cfg := baseGatewayConfig("nat64-gw")
	cfg.Runtime = newTestRuntime()
	cfg.NAT64 = &NAT64Config{
		Enabled: true, TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"203.0.113.64"},
			PortRangeStart: 61001, PortRangeEnd: 65535,
		},
	}
	cfg.Host = &HostRuntime{NAT64Driver: &stubNAT64Driver{}}

	gw, err := NewGateway(cfg)
	require.NoError(t, err)

	snap := gw.Snapshot()
	require.NotNil(t, snap)
	status, ok := snap.Health.Components[ServiceNAT64]
	require.True(t, ok, "nat64 is enabled but absent from the health components: %v", snap.Health.Components)
	assert.Equal(t, componentUnhealthy, status,
		"an unstarted translator is not healthy; a bool that says otherwise is the #568 defect")
}

// TestPipelineInvariant_NAT64GateIsRouted runs the repository's general
// reachability invariant (#567) over a gateway that actually started the
// nat64 service. It is the strongest form of the claim: table 27 is
// reachable from table 0 through the rules the running gateway compiled,
// not merely through the ones the package renders in isolation.
func TestPipelineInvariant_NAT64GateIsRouted(t *testing.T) {
	base, err := BasePipelineRules(TerminalNormal)
	require.NoError(t, err)

	cfg := lbGatewayConfig()
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.Uplinks = []UplinkConfig{{Name: "eth0", MTU: 1500}}
	cfg.NAT = natGatewayConfig().NAT
	cfg.NAT64 = &NAT64Config{
		Enabled:        true,
		TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			// Disjoint from the NAT44 external address above.
			Addresses:      []string{"198.51.100.8-198.51.100.15"},
			PortRangeStart: 61001,
			PortRangeEnd:   65535,
		},
		ClientZones: []NAT64ClientZoneConfig{{Name: "iot", VLAN: 300}},
	}
	cfg.Host = &HostRuntime{NAT64Driver: &stubNAT64Driver{}}

	gw := startGateway(t, cfg)
	defer func() { _ = gw.Stop(context.Background()) }()

	rules := cfg.Runtime.Controller.(*fakeFlowController).allRules()
	assertEveryGotoTargetIsRouted(t, append(base, rules...))

	// And specifically: something reaches table 27, and table 27 has rules.
	var into, inside int
	for _, r := range rules {
		if r.Table == int(modes.TableNAT64) {
			inside++
		}
		for _, target := range gotoTargets(r.Actions) {
			if target == int(modes.TableNAT64) {
				into++
			}
		}
	}
	assert.Positive(t, into, "nothing routes into table 27; the hand-off would be dead flows")
	assert.Positive(t, inside, "table 27 is empty; the divert would be a black hole")
}

// TestServiceFlowCookies_OwnerIDsAreUnique is the teardown-isolation
// invariant. Every datapath service stamps its flows with an owner id in the
// high 32 bits of the cookie and tears them down with DeleteFlowsByCookie
// under the same mask, so two services sharing an owner id delete each
// other's flows: a load balancer Stop silently wipes the live NAT64 gate,
// divert and hand-off while NAT64 keeps reporting itself healthy, and
// nothing re-installs them.
//
// NAT64 shipped on 0xF1BE0003 — the load balancer's id — and this assertion
// is what catches the next one.
func TestServiceFlowCookies_OwnerIDsAreUnique(t *testing.T) {
	owners := map[string]uint64{
		"pipeline":     CookiePipeline & CookiePipelineMask,
		"firewall":     firewall.CookieFirewall & firewall.CookieMask,
		"nat":          firewall.CookieNAT & firewall.CookieMask,
		"loadbalancer": loadbalancer.CookieLoadBalancer & loadbalancer.CookieMask,
		"nat64":        nat64.CookieNAT64 & nat64.CookieMask,
		"perf":         perf.FlowCookie & CookiePipelineMask,
	}

	seen := make(map[uint64]string, len(owners))
	for name, owner := range owners {
		if other, clash := seen[owner]; clash {
			t.Errorf("services %q and %q share flow-cookie owner id 0x%X: "+
				"either one's cookie-scoped delete tears down the other's flows",
				other, name, owner)
			continue
		}
		seen[owner] = name
	}
}

// TestGatewayGates_Table10PriorityIsUnique is the install-time counterpart to
// TestServiceFlowCookies_OwnerIDsAreUnique. The cookie scopes DELETION; the
// (table, priority, match) triple is the flow's IDENTITY on OFPFC_ADD, so two
// services rendering an empty-match table-10 gate at the same priority do not
// get two gates — the second ADD replaces the first, and one resident flow is
// left carrying one service's cookie. Whichever service owns that cookie then
// deletes the only gate on Stop, taking the other still-running service's
// traffic off table 20 while it goes on reporting itself healthy.
//
// This runs the real gateway with all four datapath services enabled and reads
// the flows they actually compiled, because the collision is invisible to the
// services in isolation. NAT64 shipped its gate on the load balancer's
// priority 3.
func TestGatewayGates_Table10PriorityIsUnique(t *testing.T) {
	cfg := lbGatewayConfig()
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.Uplinks = []UplinkConfig{{Name: "eth0", MTU: 1500}}
	cfg.NAT = natGatewayConfig().NAT
	cfg.NAT64 = &NAT64Config{
		Enabled:        true,
		TranslatorPort: "nat640",
		Pool4: NAT64Pool4Config{
			Addresses:      []string{"198.51.100.8-198.51.100.15"},
			PortRangeStart: 61001,
			PortRangeEnd:   65535,
		},
		ClientZones: []NAT64ClientZoneConfig{{Name: "iot", VLAN: 300}},
	}
	cfg.Host = &HostRuntime{NAT64Driver: &stubNAT64Driver{}}

	gw := startGateway(t, cfg)
	defer func() { _ = gw.Stop(context.Background()) }()

	// An empty-match table-10 flow is a catch-all gate. Two of them at one
	// priority are one flow, not two.
	seen := make(map[int]int)
	for _, r := range cfg.Runtime.Controller.(*fakeFlowController).allRules() {
		if r.Table != int(modes.TableVXLANDecap) || r.Match != "" {
			continue
		}
		seen[r.Priority]++
	}

	require.NotEmpty(t, seen, "no empty-match table-10 gates were compiled; this test would pass vacuously")

	for priority, count := range seen {
		assert.Equal(t, 1, count,
			"%d services installed an empty-match table 10 gate at priority %d: "+
				"identical (table, priority, match) means the second OFPFC_ADD replaces "+
				"the first, so one service's Stop tears down the other's gate",
			count, priority)
	}
}
