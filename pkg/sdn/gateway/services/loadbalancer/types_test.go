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

package loadbalancer

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestBackendValidate(t *testing.T) {
	tests := []struct {
		name    string
		backend Backend
		wantErr error
	}{
		{"valid", Backend{Address: netip.MustParseAddr("10.0.0.1"), Port: 80}, nil},
		{"zero address", Backend{Port: 80}, ErrInvalidBackend},
		{"ipv6 address", Backend{Address: netip.MustParseAddr("2001:db8::1"), Port: 80}, ErrInvalidBackend},
		{"zero port", Backend{Address: netip.MustParseAddr("10.0.0.1")}, ErrInvalidBackend},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.backend.Validate(); !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestBackendWeightDefault(t *testing.T) {
	if got := (Backend{}).weight(); got != 1 {
		t.Errorf("zero weight = %d, want 1", got)
	}
	if got := (Backend{Weight: 5}).weight(); got != 5 {
		t.Errorf("weight = %d, want 5", got)
	}
}

func TestVIPValidate(t *testing.T) {
	valid := testVIP()

	tests := []struct {
		name    string
		mutate  func(*VIP)
		max     int
		wantErr error
	}{
		{"valid", func(*VIP) {}, 8, nil},
		{"no limit", func(*VIP) {}, 0, nil},
		{"missing address", func(v *VIP) { v.Address = netip.Addr{} }, 8, ErrInvalidVIPAddress},
		{"ipv6 address", func(v *VIP) { v.Address = netip.MustParseAddr("2001:db8::1") }, 8, ErrInvalidVIPAddress},
		{"zero port", func(v *VIP) { v.Port = 0 }, 8, ErrInvalidVIPPort},
		{"bad protocol", func(v *VIP) { v.Protocol = "sctp" }, 8, ErrInvalidProtocol},
		{"udp ok", func(v *VIP) { v.Protocol = ProtocolUDP }, 8, nil},
		{"least-conn rejected", func(v *VIP) { v.Algorithm = "least-conn" }, 8, ErrAlgorithmUnsupported},
		{"hash ok", func(v *VIP) { v.Algorithm = AlgorithmHash }, 8, nil},
		{"round-robin ok", func(v *VIP) { v.Algorithm = AlgorithmRoundRobin }, 8, nil},
		{"no backends", func(v *VIP) { v.Backends = nil }, 8, ErrNoBackends},
		{"too many backends", func(*VIP) {}, 1, ErrTooManyBackends},
		{"invalid backend", func(v *VIP) { v.Backends[0].Port = 0 }, 8, ErrInvalidBackend},
		{"duplicate backend", func(v *VIP) { v.Backends[1] = v.Backends[0] }, 8, ErrDuplicateBackend},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vip := valid
			vip.Backends = append([]Backend(nil), valid.Backends...)
			tt.mutate(&vip)
			if err := vip.Validate(tt.max); !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVIPKeyString(t *testing.T) {
	key := testVIP().key()
	if got, want := key.String(), "tcp/10.100.0.10:443"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		Bridge:              "br0",
		Algorithm:           AlgorithmRoundRobin,
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  2 * time.Second,
		MaxBackends:         4,
		VIPs:                []VIP{testVIP()},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"empty bridge", func(c *Config) { c.Bridge = "" }, ErrEmptyBridge},
		{"least-conn", func(c *Config) { c.Algorithm = "least-conn" }, ErrAlgorithmUnsupported},
		{"zero timeout", func(c *Config) { c.HealthCheckTimeout = 0 }, ErrInvalidHealthCheck},
		{"interval below timeout", func(c *Config) { c.HealthCheckInterval = time.Second }, ErrInvalidHealthCheck},
		{"negative fall", func(c *Config) { c.Fall = -1 }, ErrInvalidHealthCheck},
		{"negative max backends", func(c *Config) { c.MaxBackends = -1 }, ErrInvalidMaxBackends},
		{"invalid vip", func(c *Config) { c.VIPs = []VIP{{}} }, ErrInvalidVIPAddress},
		{"zero hairpin prefix", func(c *Config) { c.HairpinPrefixes = []netip.Prefix{{}} }, ErrInvalidHairpinPrefix},
		{"ipv6 hairpin prefix", func(c *Config) {
			c.HairpinPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}
		}, ErrInvalidHairpinPrefix},
		{"the same vip twice", func(c *Config) { c.VIPs = []VIP{testVIP(), testVIP()} }, ErrVIPExists},
		{"backend shared by two vips", func(c *Config) {
			other := testVIP()
			other.Address = netip.MustParseAddr("10.100.0.11")
			c.VIPs = []VIP{testVIP(), other}
		}, ErrBackendInUse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigWithDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.Algorithm != AlgorithmHash {
		t.Errorf("Algorithm = %q, want %q", cfg.Algorithm, AlgorithmHash)
	}
	if cfg.Rise != DefaultRise || cfg.Fall != DefaultFall {
		t.Errorf("Rise/Fall = %d/%d, want %d/%d", cfg.Rise, cfg.Fall, DefaultRise, DefaultFall)
	}

	if cfg.MaxBackends != DefaultMaxBackends {
		t.Errorf("MaxBackends = %d, want %d", cfg.MaxBackends, DefaultMaxBackends)
	}

	custom := Config{Algorithm: AlgorithmRoundRobin, Rise: 5, Fall: 7, MaxBackends: 9}.withDefaults()
	if custom.Algorithm != AlgorithmRoundRobin || custom.Rise != 5 || custom.Fall != 7 || custom.MaxBackends != 9 {
		t.Errorf("withDefaults overwrote explicit values: %+v", custom)
	}
}

func TestConfigValidateZeroMaxBackendsDefaults(t *testing.T) {
	cfg := Config{
		Bridge:              "br0",
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  2 * time.Second,
		VIPs:                []VIP{testVIP()},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with zero MaxBackends = %v, want nil (defaults to %d)", err, DefaultMaxBackends)
	}
}

func TestOpErrorWrapping(t *testing.T) {
	cause := errors.New("boom")
	err := &OpError{Op: "install", Err: cause}
	if err.Error() != "loadbalancer: install: boom" {
		t.Errorf("Error = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("OpError does not unwrap to cause")
	}
}

func TestConfigValidateAcceptsHairpinAndDistinctBackends(t *testing.T) {
	udp := testVIP()
	udp.Protocol = ProtocolUDP
	cfg := Config{
		Bridge:              "br0",
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  2 * time.Second,
		HairpinPrefixes:     []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		// The same endpoints under UDP are a different reply tuple.
		VIPs: []VIP{testVIP(), udp},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

// TestStartRefusesADuplicateVIPBeforeProgrammingAnything is the review
// finding on #728: a config naming one VIP twice used to pass validation,
// so Start programmed the first copy and then failed on the second,
// leaving datapath state behind a service that never became active.
func TestStartRefusesADuplicateVIPBeforeProgrammingAnything(t *testing.T) {
	deps, controller, _, groups := testDeps(testVIP(), testVIP())
	if _, err := New(deps); !errors.Is(err, ErrVIPExists) {
		t.Fatalf("New = %v, want ErrVIPExists", err)
	}
	if len(controller.allRules()) != 0 || groups.additions != 0 {
		t.Error("nothing may be programmed for a refused configuration")
	}
}

func TestValidateVIPSet(t *testing.T) {
	if err := ValidateVIPSet(nil, 4); err != nil {
		t.Errorf("an empty set is valid: %v", err)
	}
	other := testVIP()
	other.Port = 8443
	other.Backends = []Backend{{Address: netip.MustParseAddr("10.0.9.9"), Port: 1}}
	if err := ValidateVIPSet([]VIP{testVIP(), other}, 4); err != nil {
		t.Errorf("distinct VIPs with distinct backends: %v", err)
	}
	if err := ValidateVIPSet([]VIP{{}}, 4); !errors.Is(err, ErrInvalidVIPAddress) {
		t.Errorf("an invalid VIP surfaces its own error: %v", err)
	}
}
