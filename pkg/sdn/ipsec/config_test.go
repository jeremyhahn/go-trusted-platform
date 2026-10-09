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

package ipsec

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	return &Config{
		Enabled:         true,
		FabricInterface: "bond0",
		LocalAddress:    "10.20.0.11",
		StaticPeers:     []string{"10.20.0.1", "10.20.0.2"},
		Token:           TokenConfig{Handle: "6970736563"},
	}
}

func TestConfigValidateAccepts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"defaults", func(*Config) {}},
		{"no static peers", func(c *Config) { c.StaticPeers = nil }},
		{"ipv6", func(c *Config) {
			c.LocalAddress = "fd00:20::11"
			c.StaticPeers = []string{"fd00:20::1"}
		}},
		{"lifetime exactly 3x the outage", func(c *Config) {
			c.CPOutageTolerance = 8 * time.Hour
			c.CertLifetime = 24 * time.Hour
		}},
		{"wider replay window", func(c *Config) { c.ReplayWindow = 4096 }},
		{"explicit rate and burst", func(c *Config) { c.IKERate = 50; c.IKEBurst = 50 }},
		{"rate alone scales the burst", func(c *Config) { c.IKERate = 100 }},
		{"explicit socket and module", func(c *Config) {
			c.VICISocket = "/run/charon/charon.vici"
			c.Token.Module = "hsm_2-backup"
		}},
		{"certificate and PIN files", func(c *Config) {
			c.CertificateFile = "/etc/platform/ipsec/tunnel.pem"
			c.Token.PINFile = "/etc/platform/ipsec/token.pin"
		}},
		{"CRL files", func(c *Config) {
			c.CRLFiles = []string{"/etc/platform/ipsec/root.crl", "/etc/platform/ipsec/tunnel.crl"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestConfigValidateDisabledOrAbsent(t *testing.T) {
	var nilConfig *Config
	if err := nilConfig.Validate(); err != nil {
		t.Fatalf("nil section: %v", err)
	}
	// A disabled section is not checked, so it can be staged incomplete.
	if err := (&Config{LocalAddress: "not an address"}).Validate(); err != nil {
		t.Fatalf("disabled section: %v", err)
	}
}

func TestConfigValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
		field  string
		want   error
	}{
		{"missing fabric interface", func(c *Config) { c.FabricInterface = "" }, "fabric-interface", ErrRequired},
		{"interface name too long", func(c *Config) { c.FabricInterface = "a-very-long-ifname" }, "fabric-interface", ErrInvalidInterface},
		{"interface with slash", func(c *Config) { c.FabricInterface = "eth0/1" }, "fabric-interface", ErrInvalidInterface},
		{"missing local address", func(c *Config) { c.LocalAddress = "" }, "local-address", ErrRequired},
		{"local address is a prefix", func(c *Config) { c.LocalAddress = "10.20.0.0/24" }, "local-address", ErrInvalidAddress},
		{"local address unspecified", func(c *Config) { c.LocalAddress = "0.0.0.0" }, "local-address", ErrInvalidAddress},
		{"local address link-local", func(c *Config) { c.LocalAddress = "fe80::1" }, "local-address", ErrInvalidAddress},
		{"local address scoped", func(c *Config) { c.LocalAddress = "fd00::1%eth0" }, "local-address", ErrInvalidAddress},
		{"wildcard peer", func(c *Config) { c.StaticPeers = []string{"0.0.0.0"} }, "static-peers[0]", ErrInvalidAddress},
		{"multicast peer", func(c *Config) { c.StaticPeers = []string{"10.20.0.1", "239.1.1.1"} }, "static-peers[1]", ErrInvalidAddress},
		{"peer is a prefix", func(c *Config) { c.StaticPeers = []string{"10.20.0.0/16"} }, "static-peers[0]", ErrInvalidAddress},
		{"duplicate peer", func(c *Config) { c.StaticPeers = []string{"10.20.0.1", "10.20.0.1"} }, "static-peers[1]", ErrDuplicatePeer},
		{"peer is the local address", func(c *Config) { c.StaticPeers = []string{"10.20.0.11"} }, "static-peers[0]", ErrDuplicatePeer},
		{"mixed families", func(c *Config) { c.StaticPeers = []string{"fd00::1"} }, "static-peers[0]", ErrFamilyMismatch},
		{"relative socket", func(c *Config) { c.VICISocket = "charon.vici" }, "vici-socket", ErrRelativePath},
		{"module given as a path", func(c *Config) { c.Token.Module = "/usr/lib/pkcs11/p11-kit-client.so" }, "token.module", ErrInvalidModule},
		{"module given as a file", func(c *Config) { c.Token.Module = "p11-kit-client.so" }, "token.module", ErrInvalidModule},
		{"module name with a space", func(c *Config) { c.Token.Module = "x kms" }, "token.module", ErrInvalidModule},
		{"module name too long", func(c *Config) { c.Token.Module = strings.Repeat("m", maxModuleName+1) }, "token.module", ErrInvalidModule},
		{"relative certificate file", func(c *Config) { c.CertificateFile = "tunnel.pem" }, "certificate-file", ErrRelativePath},
		{"relative PIN file", func(c *Config) { c.Token.PINFile = "token.pin" }, "token.pin-file", ErrRelativePath},
		{"relative CRL file", func(c *Config) { c.CRLFiles = []string{"/etc/platform/ipsec/root.crl", "tunnel.crl"} }, "crl-files[1]", ErrRelativePath},
		{"missing handle", func(c *Config) { c.Token.Handle = "" }, "token.handle", ErrRequired},
		{"handle not hex", func(c *Config) { c.Token.Handle = "ipsec" }, "token.handle", ErrInvalidHandle},
		{"negative outage tolerance", func(c *Config) { c.CPOutageTolerance = -time.Hour }, "cp-outage-tolerance", ErrNegativeDuration},
		{"negative lifetime", func(c *Config) { c.CertLifetime = -time.Hour }, "cert-lifetime", ErrNegativeDuration},
		{"negative fabric link wait", func(c *Config) { c.FabricLinkWait = -time.Second }, "fabric-link-wait", ErrNegativeDuration},
		{"lifetime under 3x the default outage", func(c *Config) { c.CertLifetime = 71 * time.Hour }, "cert-lifetime", ErrLifetimeTooShort},
		{"lifetime under 3x a configured outage", func(c *Config) {
			c.CPOutageTolerance = 48 * time.Hour
			c.CertLifetime = 100 * time.Hour
		}, "cert-lifetime", ErrLifetimeTooShort},
		{"replay window below 1024", func(c *Config) { c.ReplayWindow = 64 }, "replay-window", ErrReplayWindowTooSmall},
		{"burst below rate", func(c *Config) { c.IKERate = 50; c.IKEBurst = 10 }, "ike-burst", ErrInvalidRate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			err := c.Validate()
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %v, want *ConfigError", err)
			}
			if cfgErr.Field != tt.field || !errors.Is(err, tt.want) {
				t.Fatalf("err = %v (field %q), want %v on %q", err, cfgErr.Field, tt.want, tt.field)
			}
		})
	}
}

func TestConfigEffectiveDefaults(t *testing.T) {
	c := validConfig()
	if got := c.EffectiveVICISocket(); got != DefaultVICISocket {
		t.Errorf("socket = %q, want %q", got, DefaultVICISocket)
	}
	if got := c.EffectiveTokenModule(); got != DefaultTokenModule {
		t.Errorf("module = %q", got)
	}
	if got := c.EffectiveCertLifetime(); got != 72*time.Hour {
		t.Errorf("lifetime = %v, want 3x the 24h default outage", got)
	}
	if got := c.ReauthTime(); got != 36*time.Hour {
		t.Errorf("reauth = %v, want half the lifetime", got)
	}
	if got := c.EffectiveFabricLinkWait(); got != DefaultFabricLinkWait {
		t.Errorf("fabric link wait = %v, want %v", got, DefaultFabricLinkWait)
	}
	if got := c.EffectiveReplayWindow(); got != MinReplayWindow {
		t.Errorf("replay window = %d", got)
	}
	if rate, burst := c.EffectiveIKERate(), c.EffectiveIKEBurst(); rate != DefaultIKERate || burst != 2*DefaultIKERate {
		t.Errorf("ike rate/burst = %d/%d", rate, burst)
	}

	c.CPOutageTolerance = 10 * time.Hour
	if got := c.EffectiveCertLifetime(); got != 30*time.Hour {
		t.Errorf("lifetime = %v, want 3x the configured outage", got)
	}
	c.CertLifetime = 90 * time.Hour
	if got := c.ReauthTime(); got != 45*time.Hour {
		t.Errorf("reauth = %v, want half the configured lifetime", got)
	}
}

func TestConfigLocalAndPeers(t *testing.T) {
	c := validConfig()
	c.LocalAddress = "::ffff:10.20.0.11"
	local, err := c.Local()
	if err != nil {
		t.Fatalf("Local: %v", err)
	}
	if local != netip.MustParseAddr("10.20.0.11") {
		t.Fatalf("Local = %v, want the unmapped IPv4 address", local)
	}
	peers, err := c.Peers()
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.20.0.1"), netip.MustParseAddr("10.20.0.2")}
	if !slices.Equal(peers, want) {
		t.Fatalf("Peers = %v, want %v", peers, want)
	}

	c.LocalAddress = "bogus"
	if _, err := c.Local(); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Local(bogus): err = %v", err)
	}
	c.StaticPeers = []string{"bogus"}
	if _, err := c.Peers(); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Peers(bogus): err = %v", err)
	}
}

func TestConfigErrorString(t *testing.T) {
	err := &ConfigError{Field: "token.handle", Err: ErrRequired}
	if got := err.Error(); got != "overlay.ipsec.token.handle: ipsec: field is required" {
		t.Fatalf("Error() = %q", got)
	}
}
