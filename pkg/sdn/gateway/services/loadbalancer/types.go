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
	"fmt"
	"net/netip"
	"time"
)

// Supported load balancing algorithms. Both map onto an OpenFlow select
// group whose bucket choice OVS derives from the datapath flow hash
// (dp_hash), so selection is per-connection sticky, not per-packet
// round-robin. "round-robin" is accepted as a config alias and documented
// as hash-based selection.
const (
	// AlgorithmHash selects a backend by datapath flow hash.
	AlgorithmHash = "hash"

	// AlgorithmRoundRobin is an accepted alias for hash-based selection.
	AlgorithmRoundRobin = "round-robin"
)

// VIP protocols.
const (
	// ProtocolTCP load-balances TCP connections.
	ProtocolTCP = "tcp"

	// ProtocolUDP load-balances UDP flows. UDP backends are not health
	// probed (there is no protocol-agnostic UDP liveness signal); they are
	// treated as always healthy.
	ProtocolUDP = "udp"
)

// Health-check defaults applied when Config leaves Rise / Fall zero.
const (
	// DefaultRise is the consecutive probe successes required to mark a
	// backend healthy.
	DefaultRise = 2

	// DefaultFall is the consecutive probe failures required to mark a
	// backend unhealthy.
	DefaultFall = 3
)

// DefaultMaxBackends is the per-VIP backend cap applied when Config leaves
// MaxBackends zero.
const DefaultMaxBackends = 64

// algorithms is the set of accepted algorithm names (map-based dispatch for
// O(1) validation).
var algorithms = map[string]struct{}{
	AlgorithmHash:       {},
	AlgorithmRoundRobin: {},
}

// ipProtocols maps VIP protocol names to IP protocol numbers.
var ipProtocols = map[string]uint8{
	ProtocolTCP: 6,
	ProtocolUDP: 17,
}

// Backend is one load-balanced endpoint behind a VIP.
type Backend struct {
	// Address is the backend IPv4 address.
	Address netip.Addr

	// Port is the backend L4 port.
	Port uint16

	// Weight is the relative selection weight. Zero means 1.
	Weight uint16
}

// weight returns the effective bucket weight (zero defaults to 1).
func (b Backend) weight() uint16 {
	if b.Weight == 0 {
		return 1
	}
	return b.Weight
}

// addrPort returns the backend address:port pair.
func (b Backend) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(b.Address, b.Port)
}

// Validate checks the backend address and port.
func (b Backend) Validate() error {
	if !b.Address.IsValid() || !b.Address.Is4() {
		return ErrInvalidBackend
	}
	if b.Port == 0 {
		return ErrInvalidBackend
	}
	return nil
}

// VIP is a virtual IP:port whose traffic is distributed across backends.
type VIP struct {
	// Address is the virtual IPv4 address.
	Address netip.Addr

	// Port is the virtual L4 port.
	Port uint16

	// Protocol is "tcp" or "udp".
	Protocol string

	// Algorithm selects the balancing algorithm ("hash" or "round-robin",
	// both hash-based). Empty inherits the service default.
	Algorithm string

	// Backends are the load-balanced endpoints.
	Backends []Backend
}

// key returns the identity key of the VIP.
func (v VIP) key() vipKey {
	return vipKey{proto: v.Protocol, addr: v.Address, port: v.Port}
}

// Validate checks the VIP definition against the configured backend limit.
// A zero maxBackends disables the limit check.
func (v VIP) Validate(maxBackends int) error {
	if !v.Address.IsValid() || !v.Address.Is4() {
		return ErrInvalidVIPAddress
	}
	if v.Port == 0 {
		return ErrInvalidVIPPort
	}
	if _, ok := ipProtocols[v.Protocol]; !ok {
		return ErrInvalidProtocol
	}
	if v.Algorithm != "" {
		if _, ok := algorithms[v.Algorithm]; !ok {
			return ErrAlgorithmUnsupported
		}
	}
	if len(v.Backends) == 0 {
		return ErrNoBackends
	}
	if maxBackends > 0 && len(v.Backends) > maxBackends {
		return ErrTooManyBackends
	}
	seen := make(map[netip.AddrPort]struct{}, len(v.Backends))
	for _, b := range v.Backends {
		if err := b.Validate(); err != nil {
			return err
		}
		ap := b.addrPort()
		if _, dup := seen[ap]; dup {
			return ErrDuplicateBackend
		}
		seen[ap] = struct{}{}
	}
	return nil
}

// vipKey identifies a VIP by protocol, address, and port.
type vipKey struct {
	proto string
	addr  netip.Addr
	port  uint16
}

// String renders the key as "<proto>/<addr>:<port>", the form used as the
// conntrack zone allocator key and in log messages.
func (k vipKey) String() string {
	return fmt.Sprintf("%s/%s:%d", k.proto, k.addr, k.port)
}

// Config is the load balancer service configuration.
type Config struct {
	// Bridge is the OVS bridge carrying the load balancer tables.
	Bridge string

	// Algorithm is the default balancing algorithm for VIPs that do not
	// set one. Empty defaults to "hash".
	Algorithm string

	// HealthCheckInterval is the probe interval.
	HealthCheckInterval time.Duration

	// HealthCheckTimeout is the per-probe dial timeout. It must be
	// smaller than HealthCheckInterval.
	HealthCheckTimeout time.Duration

	// Rise is the consecutive successes required to mark a backend
	// healthy. Zero defaults to DefaultRise.
	Rise int

	// Fall is the consecutive failures required to mark a backend
	// unhealthy. Zero defaults to DefaultFall.
	Fall int

	// MaxBackends caps the backend count per VIP. Zero defaults to
	// DefaultMaxBackends; negative values are invalid.
	MaxBackends int

	// VIPs are the config-driven virtual IPs installed at Start.
	VIPs []VIP
}

// withDefaults returns a copy of the config with defaults applied.
func (c Config) withDefaults() Config {
	if c.Algorithm == "" {
		c.Algorithm = AlgorithmHash
	}
	if c.Rise == 0 {
		c.Rise = DefaultRise
	}
	if c.Fall == 0 {
		c.Fall = DefaultFall
	}
	if c.MaxBackends == 0 {
		c.MaxBackends = DefaultMaxBackends
	}
	return c
}

// Validate checks the service configuration, including every configured VIP.
// Defaults are applied first so a zero MaxBackends / Rise / Fall validates as
// the defaulted service configuration.
func (c Config) Validate() error {
	c = c.withDefaults()
	if c.Bridge == "" {
		return ErrEmptyBridge
	}
	if c.Algorithm != "" {
		if _, ok := algorithms[c.Algorithm]; !ok {
			return ErrAlgorithmUnsupported
		}
	}
	if c.HealthCheckTimeout <= 0 || c.HealthCheckInterval <= c.HealthCheckTimeout {
		return ErrInvalidHealthCheck
	}
	if c.Rise < 0 || c.Fall < 0 {
		return ErrInvalidHealthCheck
	}
	if c.MaxBackends <= 0 {
		return ErrInvalidMaxBackends
	}
	for _, vip := range c.VIPs {
		if err := vip.Validate(c.MaxBackends); err != nil {
			return err
		}
	}
	return nil
}

// BackendStatus reports one backend and its probed health.
type BackendStatus struct {
	// Backend is the endpoint definition.
	Backend Backend

	// Healthy reports whether the backend currently receives new
	// connections.
	Healthy bool
}

// VIPStatus is a point-in-time snapshot of one VIP.
type VIPStatus struct {
	// VIP is the definition.
	VIP VIP

	// CTZone is the conntrack zone carrying the VIP's connection state.
	CTZone uint16

	// GroupID is the OpenFlow select group distributing the VIP.
	GroupID uint32

	// Backends reports per-backend health.
	Backends []BackendStatus
}

// Health is a point-in-time snapshot of the load balancer service state.
type Health struct {
	// Active reports whether the service is started.
	Active bool

	// VIPCount is the number of installed VIPs.
	VIPCount int

	// HealthyBackends is the number of backends currently receiving new
	// connections.
	HealthyBackends int

	// TotalBackends is the total configured backend count.
	TotalBackends int

	// LastReconcile is when the datapath was last converged.
	LastReconcile time.Time
}
