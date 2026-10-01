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
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// update rewrites the golden files: go test ./... -run Golden -update
var update = flag.Bool("update", false, "rewrite NAT golden files")

// dualUplinkConfig is the two-ISP shape the plan targets: ISP A is the
// default, ISP B carries one destination prefix, one static 1:1 host
// sits on each.
func dualUplinkConfig() NATConfig {
	return NATConfig{
		PortRangeStart: 1024,
		PortRangeEnd:   65535,
		InternalCIDR:   "10.4.200.0/24",
		Bridge:         "br-test",
		Uplinks: []NATUplink{
			{Name: "isp-a", Port: "eth6", Addresses: []string{"198.51.100.4"}, Default: true},
			{Name: "isp-b", Port: "eth7", Addresses: []string{"192.0.2.4-192.0.2.5"}, PortRangeStart: 2048, PortRangeEnd: 60000,
				Destinations: []string{"198.51.100.128/25", "192.0.2.128/25"}},
		},
		Static: []StaticNAT{
			{Internal: "10.4.200.10", External: "203.0.113.4"},
			{Internal: "10.4.200.11", External: "192.0.2.6", Uplink: "isp-b"},
		},
	}
}

func TestNATConfig_PlanValidation(t *testing.T) {
	base := dualUplinkConfig()
	cases := map[string]struct {
		mutate  func(*NATConfig)
		wantErr any
	}{
		"valid dual uplink": {mutate: func(*NATConfig) {}},
		"static without uplinks": {mutate: func(c *NATConfig) {
			c.Uplinks = nil
			c.ExternalIP = "203.0.113.10"
		}, wantErr: ErrStaticNeedsUplink},
		"missing uplink name":   {mutate: func(c *NATConfig) { c.Uplinks[0].Name = "" }, wantErr: &ErrInvalidNATUplink{}},
		"duplicate uplink name": {mutate: func(c *NATConfig) { c.Uplinks[1].Name = "isp-a" }, wantErr: &ErrInvalidNATUplink{}},
		"no pool addresses":     {mutate: func(c *NATConfig) { c.Uplinks[0].Addresses = nil }, wantErr: &ErrInvalidNATUplink{}},
		"bad pool address":      {mutate: func(c *NATConfig) { c.Uplinks[0].Addresses = []string{"fd00::1"} }, wantErr: &ErrInvalidNATUplink{}},
		"reversed pool range":   {mutate: func(c *NATConfig) { c.Uplinks[1].Addresses = []string{"192.0.2.5-192.0.2.4"} }, wantErr: &ErrInvalidNATUplink{}},
		"bad uplink port range": {mutate: func(c *NATConfig) { c.Uplinks[1].PortRangeStart = 70; c.Uplinks[1].PortRangeEnd = 60 }, wantErr: &ErrInvalidNATUplink{}},
		"bad destination":       {mutate: func(c *NATConfig) { c.Uplinks[1].Destinations = []string{"not-a-prefix"} }, wantErr: &ErrInvalidNATUplink{}},
		"v6 destination":        {mutate: func(c *NATConfig) { c.Uplinks[1].Destinations = []string{"2001:db8::/32"} }, wantErr: &ErrInvalidNATUplink{}},
		"two defaults":          {mutate: func(c *NATConfig) { c.Uplinks[1].Default = true }, wantErr: &ErrInvalidNATUplink{}},
		"bad static internal":   {mutate: func(c *NATConfig) { c.Static[0].Internal = "nope" }, wantErr: &ErrInvalidStaticNAT{}},
		"bad static external":   {mutate: func(c *NATConfig) { c.Static[0].External = "2001:db8::4" }, wantErr: &ErrInvalidStaticNAT{}},
		"duplicate external":    {mutate: func(c *NATConfig) { c.Static[1].External = c.Static[0].External }, wantErr: &ErrInvalidStaticNAT{}},
		"unknown static uplink": {mutate: func(c *NATConfig) { c.Static[1].Uplink = "starlink" }, wantErr: &ErrInvalidStaticNAT{}},
		"config port range still required": {mutate: func(c *NATConfig) {
			c.PortRangeStart, c.PortRangeEnd = 0, 0
		}, wantErr: ErrInvalidPortRange},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.Uplinks = append([]NATUplink(nil), base.Uplinks...)
			cfg.Static = append([]StaticNAT(nil), base.Static...)
			tc.mutate(&cfg)
			_, _, err := cfg.Validate()
			switch want := tc.wantErr.(type) {
			case nil:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case *ErrInvalidNATUplink:
				var e *ErrInvalidNATUplink
				if !errors.As(err, &e) {
					t.Fatalf("got %T %v, want ErrInvalidNATUplink", err, err)
				}
			case *ErrInvalidStaticNAT:
				var e *ErrInvalidStaticNAT
				if !errors.As(err, &e) {
					t.Fatalf("got %T %v, want ErrInvalidStaticNAT", err, err)
				}
			case error:
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
			}
		})
	}
}

func TestNATConfig_PlanDefaults(t *testing.T) {
	cfg := dualUplinkConfig()
	cfg.Uplinks[0].Default = false
	cfg.Uplinks[0].Port = ""
	plan, err := cfg.plan()
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.defaultIdx != 0 || !plan.uplinks[0].isDefault {
		t.Fatalf("the first uplink is the default when none is marked: %+v", plan.uplinks)
	}
	if plan.uplinks[0].port != "isp-a" {
		t.Fatalf("port defaults to the uplink name, got %q", plan.uplinks[0].port)
	}
	if plan.statics[0].uplink != "isp-a" {
		t.Fatalf("a static with no uplink binds to the default, got %q", plan.statics[0].uplink)
	}
	// uplinkFor: pool member, static external, and the default fallback.
	if got := plan.uplinkFor(mustAddr(t, "192.0.2.5")).name; got != "isp-b" {
		t.Errorf("pool member -> %q, want ispB", got)
	}
	if got := plan.uplinkFor(mustAddr(t, "192.0.2.6")).name; got != "isp-b" {
		t.Errorf("static external -> %q, want ispB", got)
	}
	if got := plan.uplinkFor(mustAddr(t, "8.8.8.8")).name; got != "isp-a" {
		t.Errorf("unknown address -> %q, want the default", got)
	}
	if got := plan.byName("nope").name; got != "isp-a" {
		t.Errorf("unknown name -> %q, want the default", got)
	}
	if got := poolSize(natPool{first: mustAddr(t, "10.0.0.1"), last: mustAddr(t, "10.0.0.4")}); got != 4 {
		t.Errorf("poolSize = %d, want 4", got)
	}
	if _, err := parsePool("10.0.0.1-", 1, 2); err == nil {
		t.Error("a dangling range must fail")
	}
}

// renderRules writes the compiled flow table in a stable textual form.
func renderRules(rules []zoneflows.FlowRule) string {
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "table=%d priority=%d match=%q actions=%q\n", r.Table, r.Priority, r.Match, r.Actions)
	}
	return b.String()
}

// assertGolden compares got against testdata/<name>.golden, rewriting it
// with -update. The zone is fixed by the test so the files are stable.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "nat", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if string(want) != got {
		t.Fatalf("golden %s mismatch\n--- want\n%s--- got\n%s", path, want, got)
	}
}

// fixedZoneNAT builds a NAT whose conntrack zone is deterministic for the
// golden files.
func fixedZoneNAT(t *testing.T, cfg NATConfig) (*NAT, *fakeController, *fakeOVS) {
	t.Helper()
	deps, controller, ovsClient, _ := testDeps()
	ovsClient.ofPorts = map[string]int32{"eth6": 6, "eth7": 7, "eth0": 7}
	nat, err := NewNAT(deps, cfg)
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	nat.ctZone = 4242
	return nat, controller, ovsClient
}

func TestNATGolden_SingleUplinkUnchanged(t *testing.T) {
	nat, _, _ := fixedZoneNAT(t, testNATConfig())
	rules := append(nat.baseRules(), nat.snatFlowRules(nat.internal)...)
	assertGolden(t, "single_uplink", renderRules(rules))
}

func TestNATGolden_DualUplink(t *testing.T) {
	nat, _, _ := fixedZoneNAT(t, dualUplinkConfig())
	rules := nat.snatFlowRules(nat.internal)
	assertGolden(t, "dual_uplink_snat", renderRules(rules))

	// The selector chain: the default loads 1, ISP B's two destination
	// prefixes load 2 at the higher priority, and each pool commits on its
	// own selector.
	var selects, commits int
	for _, r := range rules {
		if r.Priority == prioSNATSelect {
			selects++
			if !strings.Contains(r.Actions, "load:2->NXM_NX_REG0[]") {
				t.Errorf("destination rule loads the wrong selector: %+v", r)
			}
		}
		if r.Priority == prioNATCommitSNAT {
			commits++
		}
	}
	if selects != 2 || commits != 2 {
		t.Fatalf("selects=%d commits=%d, want 2 and 2", selects, commits)
	}
}

func TestNATGolden_StaticAndHairpin(t *testing.T) {
	nat, _, _ := fixedZoneNAT(t, dualUplinkConfig())
	var rules []zoneflows.FlowRule
	for _, st := range nat.plan.statics {
		port := int32(6)
		if st.uplink == "isp-b" {
			port = 7
		}
		rules = append(rules, nat.staticFlowRules(st, port, nat.internal)...)
	}
	assertGolden(t, "static_hairpin", renderRules(rules))

	// Each hairpin commit carries both translations on one conntrack entry.
	hairpins := 0
	for _, r := range rules {
		if r.Priority != prioNATCommitHairpin {
			continue
		}
		hairpins++
		if !strings.Contains(r.Actions, "nat(dst=10.4.200.1") || !strings.Contains(r.Actions, ",nat(src=") {
			t.Errorf("hairpin commit must DNAT and SNAT: %+v", r)
		}
	}
	if hairpins != 2 {
		t.Fatalf("expected one hairpin commit per static, got %d", hairpins)
	}

	// Without an internal prefix there is no hairpin, only the four 1:1 flows.
	noHairpin := nat.staticFlowRules(nat.plan.statics[0], 6, netipInvalidPrefix())
	if len(noHairpin) != 4 {
		t.Fatalf("expected 4 flows without hairpin, got %d", len(noHairpin))
	}
}

func TestNAT_StartDualUplinkInstallsPoolsAndStatics(t *testing.T) {
	nat, controller, ovsClient := fixedZoneNAT(t, dualUplinkConfig())
	ctx := context.Background()
	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	rules := controller.allRules()
	// 6 base (incl. IPv6 pass) + SNAT: 1 default divert + 2 selects + 2 commits + statics: 2 × 6.
	if len(rules) != 6+5+12 {
		t.Fatalf("expected 23 rules, got %d", len(rules))
	}
	wantCookie := fmt.Sprintf("0x%x", CookieNAT)
	for i, r := range rules {
		if r.Cookie != wantCookie {
			t.Fatalf("rule %d not cookie-scoped: %+v", i, r)
		}
	}
	// Static on ISP B resolved eth7 -> 7, static on the default resolved eth6 -> 6.
	var sawIngress6, sawIngress7 bool
	for _, r := range rules {
		if strings.HasPrefix(r.Match, "in_port=6,dl_type=0x0800,nw_dst=203.0.113.4") {
			sawIngress6 = true
		}
		if strings.HasPrefix(r.Match, "in_port=7,dl_type=0x0800,nw_dst=192.0.2.6") {
			sawIngress7 = true
		}
	}
	if !sawIngress6 || !sawIngress7 {
		t.Fatalf("statics not bound to their uplink ports (6=%v 7=%v)", sawIngress6, sawIngress7)
	}
	_ = ovsClient

	h := nat.Health()
	if len(h.Uplinks) != 2 {
		t.Fatalf("health uplinks = %d, want 2", len(h.Uplinks))
	}
	ispA, ispB := h.Uplinks[0], h.Uplinks[1]
	if !ispA.Default || ispA.PoolAddresses != 1 || ispA.Ports != 65535-1024+1 || ispA.Static != 1 {
		t.Errorf("isp-a health: %+v", ispA)
	}
	if ispB.Default || ispB.PoolAddresses != 2 || ispB.Ports != 60000-2048+1 || ispB.Static != 1 || ispB.PoolExhaustion {
		t.Errorf("ispB health: %+v", ispB)
	}
	statics := nat.StaticRules()
	if len(statics) != 2 || statics[1].Uplink != "isp-b" {
		t.Errorf("StaticRules = %+v", statics)
	}

	if err := nat.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if nat.StaticRules() != nil || len(nat.uplinkPorts) != 0 {
		t.Error("stop must clear static state and the port cache")
	}
}

func TestNAT_StartDualUplinkStaticPortFailureIsFatal(t *testing.T) {
	deps, _, ovsClient, _ := testDeps()
	ovsClient.ofPortErr = errors.New("no such port")
	nat, err := NewNAT(deps, dualUplinkConfig())
	if err != nil {
		t.Fatalf("new nat: %v", err)
	}
	err = nat.Start(context.Background())
	var op *OpError
	if !errors.As(err, &op) || op.Op != "resolve-uplink" {
		t.Fatalf("expected a resolve-uplink OpError, got %v", err)
	}
}

func TestNAT_DNATBindsToTheOwningUplink(t *testing.T) {
	nat, controller, _ := fixedZoneNAT(t, dualUplinkConfig())
	ctx := context.Background()
	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	before := len(controller.allRules())

	// External in ISP B's pool -> ISP B's port (7); external nobody
	// owns -> the default uplink's port (6).
	if err := nat.AddDNAT(ctx, "tcp", mustAddrPort(t, "192.0.2.5:443"), mustAddrPort(t, "10.4.200.20:8443")); err != nil {
		t.Fatalf("add dnat ispB: %v", err)
	}
	if err := nat.AddDNAT(ctx, "udp", mustAddrPort(t, "203.0.113.99:53"), mustAddrPort(t, "10.4.200.53:53")); err != nil {
		t.Fatalf("add dnat default: %v", err)
	}
	rules := controller.allRules()[before:]
	if len(rules) != 4 {
		t.Fatalf("expected 4 DNAT rules, got %d", len(rules))
	}
	if !strings.HasPrefix(rules[0].Match, "in_port=7,") {
		t.Errorf("ispB DNAT on wrong port: %+v", rules[0])
	}
	if !strings.HasPrefix(rules[2].Match, "in_port=6,") {
		t.Errorf("default DNAT on wrong port: %+v", rules[2])
	}
	if len(nat.DNATRules()) != 2 {
		t.Errorf("DNATRules = %+v", nat.DNATRules())
	}
}

func TestNAT_SingleUplinkStillRequiresAPort(t *testing.T) {
	cfg := testNATConfig()
	cfg.UplinkPort = ""
	nat, _, _ := fixedZoneNAT(t, cfg)
	ctx := context.Background()
	if err := nat.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	err := nat.AddDNAT(ctx, "tcp", mustAddrPort(t, "203.0.113.10:443"), mustAddrPort(t, "10.0.100.5:443"))
	if !errors.Is(err, ErrEmptyUplink) {
		t.Fatalf("got %v, want ErrEmptyUplink", err)
	}
}

func TestNATErrors_Messages(t *testing.T) {
	if got := (&ErrInvalidNATUplink{Index: 1, Name: "isp-a", Reason: "x"}).Error(); !strings.Contains(got, `"isp-a"`) || !strings.Contains(got, "x") {
		t.Errorf("unexpected message %q", got)
	}
	if got := (&ErrInvalidNATUplink{Index: 1, Reason: "x"}).Error(); !strings.Contains(got, "index 1") {
		t.Errorf("unexpected message %q", got)
	}
	if got := (&ErrInvalidStaticNAT{Index: 2, Reason: "y"}).Error(); !strings.Contains(got, "index 2") || !strings.Contains(got, "y") {
		t.Errorf("unexpected message %q", got)
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// netipInvalidPrefix is the zero prefix: "no internal CIDR configured".
func netipInvalidPrefix() netip.Prefix { return netip.Prefix{} }
