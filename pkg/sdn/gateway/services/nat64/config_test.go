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

package nat64

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validConfig is the smallest configuration that resolves, so each test
// changes exactly the field it is about.
func validConfig() Config {
	return Config{
		Prefix:         "64:ff9b::/96",
		Instance:       "tp-nat64",
		TranslatorPort: "nat640",
		Bridge:         "trusted0",
		Pool4: []Pool4Range{
			{Addresses: "203.0.113.64-203.0.113.71", PortStart: 61001, PortEnd: 65535},
		},
	}
}

func TestParsePrefix_AcceptsEveryRFC6052Length(t *testing.T) {
	// RFC 6052 §2.2 defines exactly these lengths; each embeds the IPv4
	// address at a different offset, and a translator needs to know which.
	for _, spec := range []string{
		"2001:db8::/32",
		"2001:db8:100::/40",
		"2001:db8:1::/48",
		"2001:db8:1:100::/56",
		"2001:db8:1:2::/64",
		"64:ff9b::/96",
	} {
		pfx, err := ParsePrefix(spec)
		if err != nil {
			t.Fatalf("ParsePrefix(%q) = %v, want accepted", spec, err)
		}
		if pfx.String() != spec {
			t.Fatalf("ParsePrefix(%q) round-tripped to %q", spec, pfx.String())
		}
	}
}

func TestParsePrefix_EmptyTakesTheWellKnownPrefix(t *testing.T) {
	pfx, err := ParsePrefix("")
	if err != nil {
		t.Fatalf("ParsePrefix(\"\") = %v", err)
	}
	if pfx.String() != DefaultPrefix {
		t.Fatalf("ParsePrefix(\"\") = %q, want %q", pfx.String(), DefaultPrefix)
	}
}

func TestParsePrefix_RefusesWhatCannotEmbedAnAddress(t *testing.T) {
	tests := []struct {
		name   string
		spec   string
		reason string
	}{
		{"a malformed length", "64:ff9b::/64x", "not an IP prefix"},
		{"an undefined length", "2001:db8::/44", "is not one of"},
		{"an IPv4 prefix", "203.0.113.0/24", "not an IPv6 prefix"},
		{"bits below the prefix length", "64:ff9b::1/96", "bits set below"},
		{"not a prefix at all", "not-a-prefix", "not an IP prefix"},
		{"an address without a length", "64:ff9b::", "not an IP prefix"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrefix(tc.spec)
			if err == nil {
				t.Fatalf("ParsePrefix(%q) accepted an unusable prefix", tc.spec)
			}
			var typed *ErrInvalidNAT64Prefix
			if !errors.As(err, &typed) {
				t.Fatalf("ParsePrefix(%q) = %T, want *ErrInvalidNAT64Prefix", tc.spec, err)
			}
			if !strings.Contains(typed.Error(), tc.reason) {
				t.Fatalf("error %q does not explain %q", typed.Error(), tc.reason)
			}
		})
	}
}

func TestConfigResolve_AcceptsAWholeConfiguration(t *testing.T) {
	cfg := validConfig()
	cfg.ClientZones = []ClientZone{{Name: "iot", VLAN: 300}}
	res, err := cfg.resolve()
	if err != nil {
		t.Fatalf("resolve() = %v", err)
	}
	if res.instance != "tp-nat64" || res.port != "nat640" || res.bridge != "trusted0" {
		t.Fatalf("resolve() lost a field: %+v", res)
	}
	if len(res.pools) != 1 {
		t.Fatalf("resolve() kept %d pools, want 1", len(res.pools))
	}
	if res.timeouts.UDP != DefaultUDPTimeout {
		t.Fatalf("zero UDP timeout = %v, want the RFC 6146 default %v", res.timeouts.UDP, DefaultUDPTimeout)
	}
	if res.timeouts.TCPEstablished != DefaultTCPEstablishedTimeout {
		t.Fatalf("zero tcp-established = %v, want %v", res.timeouts.TCPEstablished, DefaultTCPEstablishedTimeout)
	}
}

func TestConfigResolve_DefaultsTheInstanceAndPrefix(t *testing.T) {
	cfg := validConfig()
	cfg.Instance = ""
	cfg.Prefix = ""
	res, err := cfg.resolve()
	if err != nil {
		t.Fatalf("resolve() = %v", err)
	}
	if res.instance != DefaultInstance {
		t.Fatalf("instance = %q, want %q", res.instance, DefaultInstance)
	}
	if res.prefix.String() != DefaultPrefix {
		t.Fatalf("prefix = %q, want %q", res.prefix.String(), DefaultPrefix)
	}
}

func TestConfigResolve_RefusesAConfigurationThatWouldProgramNothing(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"no bridge", func(c *Config) { c.Bridge = "" }, ErrEmptyBridge},
		{"no translator port", func(c *Config) { c.TranslatorPort = "" }, ErrEmptyTranslatorPort},
		{"no pool4", func(c *Config) { c.Pool4 = nil }, ErrNoPool4},
		{"a whitespace instance name", func(c *Config) { c.Instance = "   " }, ErrEmptyInstance},
		{
			"an inverted pool range",
			func(c *Config) { c.Pool4[0].Addresses = "203.0.113.71-203.0.113.64" },
			ErrInvalidPool4Range,
		},
		{
			"an IPv6 address in pool4",
			func(c *Config) { c.Pool4[0].Addresses = "2001:db8::1" },
			ErrInvalidPool4Range,
		},
		{"a zero port range", func(c *Config) { c.Pool4[0].PortStart = 0 }, ErrInvalidPortRange},
		{
			"an inverted port range",
			func(c *Config) { c.Pool4[0].PortStart, c.Pool4[0].PortEnd = 65535, 61001 },
			ErrInvalidPortRange,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfigResolve_RefusesAZoneTheDivertCannotMatch(t *testing.T) {
	for _, vlan := range []uint16{0, 4095, 4096} {
		cfg := validConfig()
		cfg.ClientZones = []ClientZone{{Name: "iot", VLAN: vlan}}
		err := cfg.Validate()
		var typed *ErrInvalidClientZone
		if !errors.As(err, &typed) {
			t.Fatalf("vlan %d: Validate() = %v, want *ErrInvalidClientZone", vlan, err)
		}
		if typed.Index != 0 {
			t.Fatalf("vlan %d: error names index %d, want 0", vlan, typed.Index)
		}
	}
}

func TestConfigResolve_RefusesTwoPoolsThatWouldAllocateTheSamePair(t *testing.T) {
	cfg := validConfig()
	cfg.Pool4 = append(cfg.Pool4, Pool4Range{
		Addresses: "203.0.113.70-203.0.113.80", PortStart: 61001, PortEnd: 65535,
	})
	err := cfg.Validate()
	var typed *ErrNAT64PoolOverlap
	if !errors.As(err, &typed) {
		t.Fatalf("Validate() = %v, want *ErrNAT64PoolOverlap", err)
	}
}

func TestConfigResolve_AllowsPoolsThatShareAddressesButNotPorts(t *testing.T) {
	// The allocation key is address plus port, so disjoint port ranges on
	// the same addresses is a legitimate way to split a pool.
	cfg := validConfig()
	cfg.Pool4 = []Pool4Range{
		{Addresses: "203.0.113.64", PortStart: 1024, PortEnd: 30000},
		{Addresses: "203.0.113.64", PortStart: 30001, PortEnd: 65535},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want disjoint port ranges accepted", err)
	}
}

func TestSessionTimeouts_RefuseValuesBelowTheRFCFloor(t *testing.T) {
	tests := []struct {
		name  string
		set   func(*SessionTimeouts)
		field string
	}{
		{"udp below 2m", func(t *SessionTimeouts) { t.UDP = time.Minute }, "udp"},
		{"tcp-established below 2h4m", func(t *SessionTimeouts) { t.TCPEstablished = 2 * time.Hour }, "tcp-established"},
		{"tcp-transitory below 4m", func(t *SessionTimeouts) { t.TCPTransitory = time.Minute }, "tcp-transitory"},
		{"icmp below 60s", func(t *SessionTimeouts) { t.ICMP = time.Second }, "icmp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.set(&cfg.Timeouts)
			err := cfg.Validate()
			var typed *ErrSessionTimeoutTooLow
			if !errors.As(err, &typed) {
				t.Fatalf("Validate() = %v, want *ErrSessionTimeoutTooLow", err)
			}
			if typed.Field != tc.field {
				t.Fatalf("error names %q, want %q", typed.Field, tc.field)
			}
		})
	}
}

func TestCheckPoolOverlap_RefusesARangeNAT44AlreadyAllocates(t *testing.T) {
	cfg := validConfig()
	err := cfg.CheckPoolOverlap([]NAT44Range{
		{Uplink: "primary", Addresses: "203.0.113.60-203.0.113.65", PortStart: 61001, PortEnd: 65535},
	})
	var typed *ErrNAT64PoolOverlap
	if !errors.As(err, &typed) {
		t.Fatalf("CheckPoolOverlap() = %v, want *ErrNAT64PoolOverlap", err)
	}
	if typed.Uplink != "primary" {
		t.Fatalf("error names uplink %q, want primary — the operator has to know which one", typed.Uplink)
	}
}

func TestCheckPoolOverlap_AllowsDisjointRanges(t *testing.T) {
	cfg := validConfig()
	err := cfg.CheckPoolOverlap([]NAT44Range{
		// Adjacent addresses, no shared address.
		{Uplink: "primary", Addresses: "203.0.113.72-203.0.113.79", PortStart: 61001, PortEnd: 65535},
		// Shared addresses, disjoint ports.
		{Uplink: "primary", Addresses: "203.0.113.64", PortStart: 1024, PortEnd: 61000},
	})
	if err != nil {
		t.Fatalf("CheckPoolOverlap() = %v, want disjoint ranges accepted", err)
	}
}

func TestCheckPoolOverlap_IgnoresARangeTheNATServiceWillRefuseItself(t *testing.T) {
	// A malformed NAT44 range is the NAT service's error to report; this
	// check must not turn it into a NAT64 refusal that misdirects the
	// operator.
	cfg := validConfig()
	if err := cfg.CheckPoolOverlap([]NAT44Range{{Uplink: "primary", Addresses: "not-an-address"}}); err != nil {
		t.Fatalf("CheckPoolOverlap() = %v, want a malformed NAT44 range ignored", err)
	}
}

func TestCheckPoolOverlap_ReportsItsOwnInvalidConfigurationFirst(t *testing.T) {
	cfg := validConfig()
	cfg.Pool4 = nil
	if err := cfg.CheckPoolOverlap(nil); !errors.Is(err, ErrNoPool4) {
		t.Fatalf("CheckPoolOverlap() = %v, want %v", err, ErrNoPool4)
	}
}

func TestConfig_RefusesAPool4LargerThanTheBound(t *testing.T) {
	cfg := validConfig()
	cfg.Pool4 = []Pool4Range{{Addresses: "10.0.0.0-10.1.0.0", PortStart: 61001, PortEnd: 65535}}
	err := cfg.Validate()
	var typed *ErrPool4TooLarge
	if !errors.As(err, &typed) {
		t.Fatalf("Validate() = %v, want *ErrPool4TooLarge", err)
	}
	if typed.Addresses != 65537 || !strings.Contains(typed.Error(), "65537") {
		t.Fatalf("error = %v, want it to count 65537 addresses", typed)
	}

	cfg.Pool4 = []Pool4Range{{Addresses: "10.0.0.0-10.0.255.255", PortStart: 61001, PortEnd: 65535}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a /16 is within the bound: %v", err)
	}
}
