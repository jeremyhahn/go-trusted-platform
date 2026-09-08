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

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// testNATConfig returns a valid NAT configuration.
func testNATConfig() NATConfig {
	return NATConfig{
		ExternalIP:     "203.0.113.10",
		PortRangeStart: 1024,
		PortRangeEnd:   65535,
		InternalCIDR:   "10.0.100.0/24",
		UplinkPort:     "eth0",
		Bridge:         "br-test",
	}
}

// mustAddrPort parses an AddrPort, failing the test on error.
func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ap
}

func TestNATConfig_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg := testNATConfig()
		external, internal, err := cfg.Validate()
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if external.String() != "203.0.113.10" {
			t.Errorf("external = %s", external)
		}
		if internal.String() != "10.0.100.0/24" {
			t.Errorf("internal = %s", internal)
		}
	})

	t.Run("valid without internal cidr", func(t *testing.T) {
		cfg := testNATConfig()
		cfg.InternalCIDR = ""
		_, internal, err := cfg.Validate()
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if internal.IsValid() {
			t.Error("internal prefix should be zero when unset")
		}
	})

	tests := []struct {
		name    string
		mutate  func(c *NATConfig)
		wantErr error
	}{
		{name: "missing external ip", mutate: func(c *NATConfig) { c.ExternalIP = "" }, wantErr: ErrInvalidExternalIP},
		{name: "bad external ip", mutate: func(c *NATConfig) { c.ExternalIP = "bogus" }, wantErr: ErrInvalidExternalIP},
		{name: "ipv6 external ip", mutate: func(c *NATConfig) { c.ExternalIP = "2001:db8::1" }, wantErr: ErrInvalidExternalIP},
		{name: "zero port start", mutate: func(c *NATConfig) { c.PortRangeStart = 0 }, wantErr: ErrInvalidPortRange},
		{name: "inverted range", mutate: func(c *NATConfig) { c.PortRangeStart = 5000; c.PortRangeEnd = 4000 }, wantErr: ErrInvalidPortRange},
		{name: "empty bridge", mutate: func(c *NATConfig) { c.Bridge = "" }, wantErr: ErrEmptyBridge},
		{name: "bad internal cidr", mutate: func(c *NATConfig) { c.InternalCIDR = "bogus" }, wantErr: ErrInvalidInternalCIDR},
		{name: "ipv6 internal cidr", mutate: func(c *NATConfig) { c.InternalCIDR = "2001:db8::/64" }, wantErr: ErrInvalidInternalCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testNATConfig()
			tt.mutate(&cfg)
			if _, _, err := cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewNAT(t *testing.T) {
	deps, _, _, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	if nat.Active() {
		t.Error("new NAT service must not be active")
	}
}

func TestNewNAT_Validation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(d *Deps, c *NATConfig)
		wantErr error
	}{
		{name: "nil controller", mutate: func(d *Deps, c *NATConfig) { d.Controller = nil }, wantErr: ErrNilController},
		{name: "nil ovs", mutate: func(d *Deps, c *NATConfig) { d.OVS = nil }, wantErr: ErrNilOVSClient},
		{name: "nil allocator", mutate: func(d *Deps, c *NATConfig) { d.Allocator = nil }, wantErr: ErrNilAllocator},
		{name: "bad config", mutate: func(d *Deps, c *NATConfig) { c.ExternalIP = "bogus" }, wantErr: ErrInvalidExternalIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, _, _ := testDeps()
			cfg := testNATConfig()
			tt.mutate(&deps, &cfg)
			if _, err := NewNAT(deps, cfg); !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNAT_Start(t *testing.T) {
	deps, controller, _, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	ctx := context.Background()

	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !nat.Active() {
		t.Fatal("nat should be active")
	}

	rules := controller.allRules()

	// Gate + 4 table-25 scaffolding rules + 2 SNAT rules from InternalCIDR.
	if len(rules) != 7 {
		t.Fatalf("expected 7 rules, got %d: %+v", len(rules), rules)
	}

	gate := rules[0]
	if gate.Table != gateTable || gate.Priority != natGatePriority || gate.Actions != "goto_table:20" {
		t.Errorf("unexpected gate rule: %+v", gate)
	}

	wantCookie := fmt.Sprintf("0x%x", CookieNAT)
	for i, rule := range rules {
		if rule.Cookie != wantCookie {
			t.Errorf("rule %d cookie = %q, want %q", i, rule.Cookie, wantCookie)
		}
	}

	// SNAT commit references the external IP and port range.
	health := nat.Health()
	if !health.Active || !health.SNATEnabled || health.CTZone == 0 {
		t.Errorf("unexpected health: %+v", health)
	}
	snatCommit := rules[6]
	wantActions := fmt.Sprintf("ct(commit,zone=%d,nat(src=203.0.113.10:1024-65535)),goto_table:30", health.CTZone)
	if snatCommit.Actions != wantActions {
		t.Errorf("snat commit actions = %q, want %q", snatCommit.Actions, wantActions)
	}
}

func TestNAT_StartErrors(t *testing.T) {
	t.Run("already started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		ctx := context.Background()
		if err := nat.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := nat.Start(ctx); !errors.Is(err, ErrAlreadyStarted) {
			t.Errorf("expected ErrAlreadyStarted, got %v", err)
		}
	})

	t.Run("install failure", func(t *testing.T) {
		deps, controller, _, _ := testDeps()
		controller.installErr = errors.New("switch down")
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		err = nat.Start(context.Background())
		var opErr *OpError
		if !errors.As(err, &opErr) || opErr.Op != "install" {
			t.Errorf("expected install OpError, got %v", err)
		}
	})
}

func TestNAT_Stop(t *testing.T) {
	deps, _, ovsClient, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	ctx := context.Background()

	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := nat.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if nat.Active() {
		t.Error("nat should be inactive after stop")
	}

	ovsClient.mu.Lock()
	defer ovsClient.mu.Unlock()
	if len(ovsClient.cookieDeletes) != 1 || ovsClient.cookieDeletes[0] != CookieNAT {
		t.Errorf("expected cookie sweep for CookieNAT, got %v", ovsClient.cookieDeletes)
	}

	if _, ok := deps.Allocator.Lookup(AllocatorOwnerNAT, natZoneKey); ok {
		t.Error("nat ct zone not released on stop")
	}
}

func TestNAT_StopNotStarted(t *testing.T) {
	deps, _, _, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	if err := nat.Stop(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}
}

func TestNAT_SNATLifecycle(t *testing.T) {
	deps, _, ovsClient, _ := testDeps()
	cfg := testNATConfig()
	cfg.InternalCIDR = "" // no automatic SNAT
	nat, err := NewNAT(deps, cfg)
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	ctx := context.Background()

	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if nat.Health().SNATEnabled {
		t.Fatal("SNAT must be off without InternalCIDR")
	}

	prefix := netip.MustParsePrefix("192.168.10.0/24")
	if err := nat.EnableSNAT(ctx, prefix); err != nil {
		t.Fatalf("enable snat: %v", err)
	}
	if !nat.Health().SNATEnabled {
		t.Error("SNAT should be enabled")
	}

	if err := nat.EnableSNAT(ctx, prefix); !errors.Is(err, ErrSNATAlreadyEnabled) {
		t.Errorf("expected ErrSNATAlreadyEnabled, got %v", err)
	}

	if err := nat.DisableSNAT(ctx); err != nil {
		t.Fatalf("disable snat: %v", err)
	}
	if nat.Health().SNATEnabled {
		t.Error("SNAT should be disabled")
	}

	// The two SNAT flows were strict-deleted.
	ovsClient.mu.Lock()
	strictDeletes := len(ovsClient.strictDeletes)
	ovsClient.mu.Unlock()
	if strictDeletes != 2 {
		t.Errorf("expected 2 strict deletes, got %d", strictDeletes)
	}

	if err := nat.DisableSNAT(ctx); !errors.Is(err, ErrSNATNotEnabled) {
		t.Errorf("expected ErrSNATNotEnabled, got %v", err)
	}
}

func TestNAT_SNATErrors(t *testing.T) {
	deps, _, _, _ := testDeps()
	cfg := testNATConfig()
	cfg.InternalCIDR = ""
	nat, err := NewNAT(deps, cfg)
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	ctx := context.Background()

	prefix := netip.MustParsePrefix("192.168.10.0/24")
	if err := nat.EnableSNAT(ctx, prefix); !errors.Is(err, ErrNotStarted) {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}
	if err := nat.DisableSNAT(ctx); !errors.Is(err, ErrNotStarted) {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}

	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := nat.EnableSNAT(ctx, netip.Prefix{}); !errors.Is(err, ErrInvalidInternalCIDR) {
		t.Errorf("expected ErrInvalidInternalCIDR, got %v", err)
	}
	if err := nat.EnableSNAT(ctx, netip.MustParsePrefix("2001:db8::/64")); !errors.Is(err, ErrInvalidInternalCIDR) {
		t.Errorf("expected ErrInvalidInternalCIDR for IPv6, got %v", err)
	}
}

func TestNAT_DNATLifecycle(t *testing.T) {
	deps, controller, _, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	ctx := context.Background()

	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	external := mustAddrPort(t, "203.0.113.10:443")
	internal := mustAddrPort(t, "10.0.100.5:8443")

	if err := nat.AddDNAT(ctx, "tcp", external, internal); err != nil {
		t.Fatalf("add dnat: %v", err)
	}
	if nat.Health().DNATRules != 1 {
		t.Errorf("expected 1 dnat rule, got %d", nat.Health().DNATRules)
	}

	// The commit rule matches the uplink OF port (fake resolves to 7) and
	// translates to the internal endpoint.
	rules := controller.allRules()
	commit := rules[len(rules)-1]
	wantMatch := "ct_state=+new+trk,in_port=7,dl_type=0x0800,nw_proto=6,nw_dst=203.0.113.10,tp_dst=443"
	if commit.Match != wantMatch {
		t.Errorf("dnat commit match = %q, want %q", commit.Match, wantMatch)
	}
	wantActions := fmt.Sprintf("ct(commit,zone=%d,nat(dst=10.0.100.5:8443)),goto_table:30", nat.Health().CTZone)
	if commit.Actions != wantActions {
		t.Errorf("dnat commit actions = %q, want %q", commit.Actions, wantActions)
	}

	if err := nat.AddDNAT(ctx, "tcp", external, internal); !errors.Is(err, ErrDNATExists) {
		t.Errorf("expected ErrDNATExists, got %v", err)
	}

	if err := nat.RemoveDNAT(ctx, "tcp", external); err != nil {
		t.Fatalf("remove dnat: %v", err)
	}
	if nat.Health().DNATRules != 0 {
		t.Errorf("expected 0 dnat rules, got %d", nat.Health().DNATRules)
	}
	if err := nat.RemoveDNAT(ctx, "tcp", external); !errors.Is(err, ErrDNATNotFound) {
		t.Errorf("expected ErrDNATNotFound, got %v", err)
	}
}

func TestNAT_DNATErrors(t *testing.T) {
	external := netip.MustParseAddrPort("203.0.113.10:443")
	internal := netip.MustParseAddrPort("10.0.100.5:8443")
	ctx := context.Background()

	t.Run("not started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		if err := nat.AddDNAT(ctx, "tcp", external, internal); !errors.Is(err, ErrNotStarted) {
			t.Errorf("expected ErrNotStarted, got %v", err)
		}
		if err := nat.RemoveDNAT(ctx, "tcp", external); !errors.Is(err, ErrNotStarted) {
			t.Errorf("expected ErrNotStarted, got %v", err)
		}
	})

	t.Run("invalid protocol", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		if err := nat.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := nat.AddDNAT(ctx, "sctp", external, internal); !errors.Is(err, ErrInvalidProtocol) {
			t.Errorf("expected ErrInvalidProtocol, got %v", err)
		}
	})

	t.Run("invalid endpoints", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		if err := nat.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
		if err := nat.AddDNAT(ctx, "tcp", v6, internal); !errors.Is(err, ErrInvalidAddrPort) {
			t.Errorf("expected ErrInvalidAddrPort for v6 external, got %v", err)
		}
		if err := nat.AddDNAT(ctx, "tcp", external, v6); !errors.Is(err, ErrInvalidAddrPort) {
			t.Errorf("expected ErrInvalidAddrPort for v6 internal, got %v", err)
		}
		zeroPort := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), 0)
		if err := nat.AddDNAT(ctx, "tcp", zeroPort, internal); !errors.Is(err, ErrInvalidAddrPort) {
			t.Errorf("expected ErrInvalidAddrPort for zero port, got %v", err)
		}
	})

	t.Run("missing uplink", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		cfg := testNATConfig()
		cfg.UplinkPort = ""
		nat, err := NewNAT(deps, cfg)
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		if err := nat.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := nat.AddDNAT(ctx, "tcp", external, internal); !errors.Is(err, ErrEmptyUplink) {
			t.Errorf("expected ErrEmptyUplink, got %v", err)
		}
	})

	t.Run("uplink resolution failure", func(t *testing.T) {
		deps, _, ovsClient, _ := testDeps()
		ovsClient.ofPortErr = errors.New("no such port")
		nat, err := NewNAT(deps, testNATConfig())
		if err != nil {
			t.Fatalf("new nat: %v", err)
		}
		if err := nat.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		err = nat.AddDNAT(ctx, "tcp", external, internal)
		var opErr *OpError
		if !errors.As(err, &opErr) || opErr.Op != "resolve-uplink" {
			t.Errorf("expected resolve-uplink OpError, got %v", err)
		}
	})
}

func TestNAT_ZoneIsDisjointFromFirewall(t *testing.T) {
	deps, _, _, _ := testDeps()
	ctx := context.Background()

	// Start the firewall first so its zones are allocated.
	fw, err := New(deps)
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := fw.Start(ctx); err != nil {
		t.Fatalf("start firewall: %v", err)
	}

	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start nat: %v", err)
	}

	natZone := nat.Health().CTZone
	for name, fwZone := range fw.Health().CTZones {
		if fwZone == natZone {
			t.Errorf("nat zone %d collides with firewall zone %q", natZone, name)
		}
	}

	// Both trusted and public firewall zones exist alongside NAT.
	if _, ok := deps.Allocator.Lookup(AllocatorOwnerFirewall, string(zone.ZoneTrusted)); !ok {
		t.Error("firewall trusted zone missing")
	}
	if _, ok := deps.Allocator.Lookup(AllocatorOwnerNAT, natZoneKey); !ok {
		t.Error("nat zone missing")
	}
}

// TestNAT_ReconcileAccessors covers the state the desired-config reconciler
// reads back (#555): the SNAT prefix and the installed DNAT bindings with
// their targets.
func TestNAT_ReconcileAccessors(t *testing.T) {
	deps, _, _, _ := testDeps()
	nat, err := NewNAT(deps, testNATConfig())
	if err != nil {
		t.Fatalf("NewNAT: %v", err)
	}
	ctx := context.Background()
	if _, enabled := nat.SNATPrefix(); enabled {
		t.Fatal("SNAT reported enabled before Start")
	}
	if err := nat.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer nat.Stop(ctx)

	prefix, enabled := nat.SNATPrefix()
	if !enabled || prefix.String() != "10.0.100.0/24" {
		t.Fatalf("SNATPrefix = %v/%v after Start, want 10.0.100.0/24 enabled", prefix, enabled)
	}
	if err := nat.DisableSNAT(ctx); err != nil {
		t.Fatalf("DisableSNAT: %v", err)
	}
	if _, enabled := nat.SNATPrefix(); enabled {
		t.Fatal("SNAT still reported enabled after DisableSNAT")
	}

	external := mustAddrPort(t, "203.0.113.10:443")
	internal := mustAddrPort(t, "10.0.100.5:8443")
	if err := nat.AddDNAT(ctx, "tcp", external, internal); err != nil {
		t.Fatalf("AddDNAT: %v", err)
	}
	rules := nat.DNATRules()
	if len(rules) != 1 || rules[0].Protocol != "tcp" || rules[0].External != external || rules[0].Internal != internal {
		t.Fatalf("DNATRules = %+v", rules)
	}
	if err := nat.RemoveDNAT(ctx, "tcp", external); err != nil {
		t.Fatalf("RemoveDNAT: %v", err)
	}
	if got := nat.DNATRules(); len(got) != 0 {
		t.Fatalf("DNATRules after remove = %+v", got)
	}
}
