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

package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ResolverConfig defines how this node resolves DNS queries. All DNS consumers
// (bootstrap, ACME, installer) use this as the platform-wide default. Service-level
// overrides take precedence when explicitly configured.
type ResolverConfig struct {
	Servers        []ResolverServer      `yaml:"servers" json:"servers" mapstructure:"servers"`
	Fallback       []string              `yaml:"fallback" json:"fallback" mapstructure:"fallback"`
	SearchDomains  []string              `yaml:"search-domains" json:"search_domains" mapstructure:"search-domains"`
	LocalForwarder *LocalForwarderConfig `yaml:"local-forwarder" json:"local_forwarder" mapstructure:"local-forwarder"`
}

// ResolverServer represents a DNS server with address and port.
type ResolverServer struct {
	Address string `yaml:"address" json:"address" mapstructure:"address"`
	Port    int    `yaml:"port" json:"port" mapstructure:"port"`
}

// LocalForwarderConfig configures a local DNS forwarder (dnsmasq) for environments
// where the platform DNS server runs on a non-standard port.
type LocalForwarderConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Listen    string `yaml:"listen" json:"listen" mapstructure:"listen"`
	CacheSize int    `yaml:"cache-size" json:"cache_size" mapstructure:"cache-size"`
}

// DefaultResolverConfig returns a ResolverConfig with sensible defaults pointing
// to the local platform DNS server with public DNS fallback.
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		Servers:  []ResolverServer{{Address: "127.0.0.1", Port: DefaultPublicPort}},
		Fallback: []string{"1.1.1.1:53", "8.8.8.8:53"},
		LocalForwarder: &LocalForwarderConfig{
			Listen:    "127.0.0.1:53",
			CacheSize: 1000,
		},
	}
}

// PrimaryServer returns the first resolver server formatted as "address:port".
// PrimaryServer returns an empty string if no servers are configured.
func (r *ResolverConfig) PrimaryServer() string {
	if len(r.Servers) == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", r.Servers[0].Address, r.Servers[0].Port)
}

// PrimaryServerDnsmasq returns the first resolver server formatted as "address#port"
// for use in dnsmasq configuration. PrimaryServerDnsmasq returns an empty string
// if no servers are configured.
func (r *ResolverConfig) PrimaryServerDnsmasq() string {
	if len(r.Servers) == 0 {
		return ""
	}
	return fmt.Sprintf("%s#%d", r.Servers[0].Address, r.Servers[0].Port)
}

// Nameservers returns a list of DNS server addresses suitable for resolv.conf.
// If LocalForwarder is enabled, it returns ["127.0.0.1"] since the local forwarder
// handles port translation. Otherwise it returns the plain IP addresses of all
// configured servers.
func (r *ResolverConfig) Nameservers() []string {
	if r.LocalForwarder != nil && r.LocalForwarder.Enabled {
		return []string{"127.0.0.1"}
	}
	if len(r.Servers) == 0 {
		return nil
	}
	nameservers := make([]string, len(r.Servers))
	for i, s := range r.Servers {
		nameservers[i] = s.Address
	}
	return nameservers
}

// NetResolver creates a *net.Resolver that dials the primary server via UDP.
// NetResolver returns nil if no servers are configured.
func (r *ResolverConfig) NetResolver() *net.Resolver {
	primary := r.PrimaryServer()
	if primary == "" {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "udp", primary)
		},
	}
}

// NeedsLocalForwarder returns true if any configured server uses a non-standard
// port (anything other than 53), indicating that a local forwarder is needed
// for compatibility with resolv.conf-based clients.
func (r *ResolverConfig) NeedsLocalForwarder() bool {
	for _, s := range r.Servers {
		if s.Port != 53 {
			return true
		}
	}
	return false
}

// Validate checks the resolver configuration for errors. Validate returns a typed
// error if no servers are configured, a server has an invalid port, or a server
// has an empty address.
func (r *ResolverConfig) Validate() error {
	if len(r.Servers) == 0 {
		return ErrNoResolverServers{}
	}
	for i, s := range r.Servers {
		if s.Address == "" {
			return ErrInvalidResolverAddress{Index: i}
		}
		if s.Port < 1 || s.Port > 65535 {
			return ErrInvalidResolverPort(s)
		}
	}
	return nil
}
