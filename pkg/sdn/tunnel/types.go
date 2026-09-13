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

package tunnel

import (
	"encoding/base64"
	"net"
	"time"
)

// Default tunnel configuration values.
const (
	// DefaultMTU is the default MTU for GRE tunnels (1500 - 20 IP - 4 GRE = 1476,
	// but 1400 provides headroom for encapsulation + optional GRE key).
	DefaultMTU = 1400

	// DefaultTTL is the default IP TTL for tunnel packets.
	DefaultTTL = 64

	// MinMTU is the minimum valid MTU.
	MinMTU = 68

	// MaxMTU is the maximum valid MTU.
	MaxMTU = 65535

	// MinTTL is the minimum valid TTL.
	MinTTL = 1

	// MaxTTL is the maximum valid TTL.
	MaxTTL = 255

	// TunnelTypeGRE is a GRE tunnel over IPv4.
	TunnelTypeGRE = "gre"

	// TunnelTypeGRE6 is a GRE tunnel over IPv6.
	TunnelTypeGRE6 = "gre6"

	// TunnelTypeIPIP is an IP-in-IP tunnel.
	TunnelTypeIPIP = "ipip"

	// TransportGRE is plain GRE/GRE6/IPIP encapsulation with no protection
	// — the shape the VPS relays speak today. It is the default.
	TransportGRE = "gre"

	// TransportIPsec wraps the carrier tunnel (Type) in ESP through the
	// kernel's XFRM framework: AES-256-GCM (rfc4106), FIPS-approved, keys
	// supplied by a KeyProvider, never by configuration.
	TransportIPsec = "ipsec"

	// TransportWireGuard is a kernel WireGuard interface. Its primitives
	// (Curve25519, ChaCha20-Poly1305, BLAKE2s) are not FIPS-approved, so
	// the transport exists only in non-FIPS builds.
	TransportWireGuard = "wireguard"

	// DefaultReplayWindow is the ESP anti-replay window in packets.
	DefaultReplayWindow = 128

	// DefaultRekeyInterval is how often an IPsec SA is re-keyed.
	DefaultRekeyInterval = 8 * time.Hour

	// DefaultWireGuardKeepalive is the WireGuard persistent keepalive.
	DefaultWireGuardKeepalive = 25 * time.Second

	// esp AES-256-GCM key material: 32-byte key + 4-byte salt (RFC 4106 §8.1).
	espGCMKeyLen = 36
	// espGCMICVBits is the 128-bit ICV rfc4106(gcm(aes)) carries.
	espGCMICVBits = 128
	// espGCMAlgo is the kernel AEAD name for AES-GCM ESP.
	espGCMAlgo = "rfc4106(gcm(aes))"
	// wireGuardKeyLen is a Curve25519 private key.
	wireGuardKeyLen = 32
)

// IPsecConfig protects a carrier tunnel with ESP. Keys are references into
// the platform key store, resolved through a KeyProvider at install time;
// a key value never appears in configuration.
type IPsecConfig struct {
	// KeyRef names the outbound (local → remote) SA key.
	KeyRef string `yaml:"key-ref" json:"key_ref" mapstructure:"key-ref"`

	// PeerKeyRef names the inbound (remote → local) SA key. Empty means the
	// same key as KeyRef with distinct SPIs.
	PeerKeyRef string `yaml:"peer-key-ref,omitempty" json:"peer_key_ref,omitempty" mapstructure:"peer-key-ref"`

	// SPIOut is the outbound SPI; SPIIn the inbound. They must differ.
	SPIOut uint32 `yaml:"spi-out" json:"spi_out" mapstructure:"spi-out"`
	SPIIn  uint32 `yaml:"spi-in" json:"spi_in" mapstructure:"spi-in"`

	// ReplayWindow is the anti-replay window in packets (default 128).
	ReplayWindow int `yaml:"replay-window,omitempty" json:"replay_window,omitempty" mapstructure:"replay-window"`

	// RekeyInterval is how often Rekey should be driven (default 8h). The
	// manager does not run a timer; the reconcile loop calls Rekey.
	RekeyInterval time.Duration `yaml:"rekey-interval,omitempty" json:"rekey_interval,omitempty" mapstructure:"rekey-interval"`
}

// WireGuardConfig describes a kernel WireGuard interface. Non-FIPS builds only.
type WireGuardConfig struct {
	// KeyRef names this node's private key in the platform key store.
	KeyRef string `yaml:"key-ref" json:"key_ref" mapstructure:"key-ref"`

	// PeerPublicKey is the remote peer's public key, base64.
	PeerPublicKey string `yaml:"peer-public-key" json:"peer_public_key" mapstructure:"peer-public-key"`

	// ListenPort is the local UDP port (0 = kernel chooses).
	ListenPort int `yaml:"listen-port,omitempty" json:"listen_port,omitempty" mapstructure:"listen-port"`

	// RemotePort is the peer's UDP port.
	RemotePort int `yaml:"remote-port" json:"remote_port" mapstructure:"remote-port"`

	// PersistentKeepalive keeps NAT state alive (default 25s).
	PersistentKeepalive time.Duration `yaml:"persistent-keepalive,omitempty" json:"persistent_keepalive,omitempty" mapstructure:"persistent-keepalive"`
}

// TunnelConfig holds the configuration for one managed tunnel: a carrier
// (Type) under a Transport, optionally pinned to an uplink.
type TunnelConfig struct {
	// Name is the tunnel interface name (max 15 chars).
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Type is the carrier: "gre", "gre6", or "ipip". Ignored for the
	// wireguard transport, which is its own interface.
	Type string `yaml:"type" json:"type" mapstructure:"type"`

	// Transport is "gre" (default), "ipsec" or "wireguard".
	Transport string `yaml:"transport,omitempty" json:"transport,omitempty" mapstructure:"transport"`

	// Uplink names the UplinkConfig whose routing table carries this
	// tunnel's outer packets. Empty leaves outer routing to the main table.
	Uplink string `yaml:"uplink,omitempty" json:"uplink,omitempty" mapstructure:"uplink"`

	// Local is the local endpoint IP address.
	Local string `yaml:"local" json:"local" mapstructure:"local"`

	// Remote is the remote endpoint IP address.
	Remote string `yaml:"remote" json:"remote" mapstructure:"remote"`

	// TunnelIP is the tunnel interface IPv4 address in CIDR notation.
	TunnelIP string `yaml:"tunnel-ip" json:"tunnel_ip" mapstructure:"tunnel-ip"`

	// TunnelIPv6 is the tunnel interface IPv6 address in CIDR notation (optional).
	TunnelIPv6 string `yaml:"tunnel-ipv6,omitempty" json:"tunnel_ipv6,omitempty" mapstructure:"tunnel-ipv6"`

	// MTU is the tunnel interface MTU (default 1400).
	MTU int `yaml:"mtu,omitempty" json:"mtu,omitempty" mapstructure:"mtu"`

	// TTL is the IP TTL for tunnel packets (default 64).
	TTL int `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl"`

	// Key is the optional GRE key for traffic isolation.
	Key uint32 `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key"`

	// IPsec configures the ipsec transport; required when Transport is ipsec.
	IPsec *IPsecConfig `yaml:"ipsec,omitempty" json:"ipsec,omitempty" mapstructure:"ipsec"`

	// WireGuard configures the wireguard transport; required when Transport is wireguard.
	WireGuard *WireGuardConfig `yaml:"wireguard,omitempty" json:"wireguard,omitempty" mapstructure:"wireguard"`
}

// effectiveTransport returns the configured transport or gre.
func (c *TunnelConfig) effectiveTransport() string {
	if c.Transport == "" {
		return TransportGRE
	}
	return c.Transport
}

// Validate checks if the tunnel configuration is valid.
func (c *TunnelConfig) Validate() error {
	if c.Name == "" {
		return &ErrInvalidTunnelConfig{Reason: "name is required"}
	}
	if len(c.Name) > 15 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "name exceeds 15 characters"}
	}
	transport := c.effectiveTransport()
	if transport != TransportWireGuard {
		if c.Type == "" {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "type is required"}
		}
		if c.Type != TunnelTypeGRE && c.Type != TunnelTypeGRE6 && c.Type != TunnelTypeIPIP {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "type must be gre, gre6, or ipip"}
		}
	}
	if c.Local == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "local endpoint is required"}
	}
	if net.ParseIP(c.Local) == nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "local is not a valid IP address"}
	}
	if c.Remote == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "remote endpoint is required"}
	}
	if net.ParseIP(c.Remote) == nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "remote is not a valid IP address"}
	}
	if c.TunnelIP == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ip is required"}
	}
	if _, _, err := net.ParseCIDR(c.TunnelIP); err != nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ip is not valid CIDR"}
	}
	if c.TunnelIPv6 != "" {
		if _, _, err := net.ParseCIDR(c.TunnelIPv6); err != nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ipv6 is not valid CIDR"}
		}
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "MTU out of range"}
	}
	if c.TTL != 0 && (c.TTL < MinTTL || c.TTL > MaxTTL) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "TTL out of range"}
	}
	return c.ValidateTransport()
}

// ValidateTransport checks the transport section: the transport name, the
// section it requires, and that section's own rules. The wireguard branch
// is build-tag dependent: wireGuardAvailable is false under the fips tag
// and the transport is refused there. Validate calls it last; the gateway
// configuration calls it directly so the transport rules are stated once.
func (c *TunnelConfig) ValidateTransport() error {
	switch c.effectiveTransport() {
	case TransportGRE:
		if c.IPsec != nil || c.WireGuard != nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "gre transport takes no ipsec or wireguard section"}
		}
		return nil
	case TransportIPsec:
		if c.IPsec == nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "ipsec transport requires an ipsec section"}
		}
		if c.WireGuard != nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "ipsec transport takes no wireguard section"}
		}
		return c.IPsec.validate(c.Name)
	case TransportWireGuard:
		if !wireGuardAvailable {
			return &ErrTransportUnavailable{Name: c.Name, Transport: TransportWireGuard, Reason: wireGuardUnavailableReason}
		}
		if c.Type != "" {
			// A WireGuard tunnel has no carrier: the interface is the
			// WireGuard device itself. A type here would be silently
			// ignored, which reads as if the carrier mattered.
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "wireguard transport takes no type"}
		}
		if c.WireGuard == nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "wireguard transport requires a wireguard section"}
		}
		if c.IPsec != nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "wireguard transport takes no ipsec section"}
		}
		return c.WireGuard.validate(c.Name)
	default:
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "transport must be gre, ipsec, or wireguard"}
	}
}

func (c *IPsecConfig) validate(name string) error {
	if c.KeyRef == "" {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "ipsec.key-ref is required"}
	}
	if c.SPIOut == 0 || c.SPIIn == 0 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "ipsec.spi-out and ipsec.spi-in are required and non-zero"}
	}
	if c.SPIOut == c.SPIIn {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "ipsec.spi-out and ipsec.spi-in must differ"}
	}
	if c.ReplayWindow < 0 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "ipsec.replay-window must not be negative"}
	}
	if c.RekeyInterval < 0 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "ipsec.rekey-interval must not be negative"}
	}
	return nil
}

func (c *IPsecConfig) effectiveReplayWindow() int {
	if c.ReplayWindow > 0 {
		return c.ReplayWindow
	}
	return DefaultReplayWindow
}

func (c *IPsecConfig) effectivePeerKeyRef() string {
	if c.PeerKeyRef != "" {
		return c.PeerKeyRef
	}
	return c.KeyRef
}

// EffectiveRekeyInterval is the configured re-key interval or the default.
func (c *IPsecConfig) EffectiveRekeyInterval() time.Duration {
	if c.RekeyInterval > 0 {
		return c.RekeyInterval
	}
	return DefaultRekeyInterval
}

func (c *WireGuardConfig) validate(name string) error {
	if c.KeyRef == "" {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "wireguard.key-ref is required"}
	}
	pub, err := base64.StdEncoding.DecodeString(c.PeerPublicKey)
	if err != nil || len(pub) != wireGuardKeyLen {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "wireguard.peer-public-key must be a base64 32-byte key"}
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "wireguard.listen-port out of range"}
	}
	if c.RemotePort <= 0 || c.RemotePort > 65535 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "wireguard.remote-port is required and must be 1-65535"}
	}
	if c.PersistentKeepalive < 0 {
		return &ErrInvalidTunnelConfig{Name: name, Reason: "wireguard.persistent-keepalive must not be negative"}
	}
	return nil
}

func (c *WireGuardConfig) effectiveKeepalive() time.Duration {
	if c.PersistentKeepalive > 0 {
		return c.PersistentKeepalive
	}
	return DefaultWireGuardKeepalive
}

// effectiveMTU returns the configured MTU or the default.
// rekeyInterval returns how often the transport's key material is rotated,
// or zero for a transport that carries none.
func (c *TunnelConfig) rekeyInterval() time.Duration {
	switch c.effectiveTransport() {
	case TransportIPsec:
		if c.IPsec != nil {
			return c.IPsec.EffectiveRekeyInterval()
		}
		return DefaultRekeyInterval
	case TransportWireGuard:
		return DefaultRekeyInterval
	default:
		return 0
	}
}

func (c *TunnelConfig) effectiveMTU() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return DefaultMTU
}

// effectiveTTL returns the configured TTL or the default.
func (c *TunnelConfig) effectiveTTL() int {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultTTL
}

// TunnelState represents the operational state of a tunnel.
type TunnelState string

const (
	// TunnelStateUp indicates the tunnel interface is up.
	TunnelStateUp TunnelState = "up"

	// TunnelStateDown indicates the tunnel interface is down.
	TunnelStateDown TunnelState = "down"

	// TunnelStateUnknown indicates the tunnel state is unknown.
	TunnelStateUnknown TunnelState = "unknown"
)

// TunnelStatus holds the runtime status of a managed tunnel.
type TunnelStatus struct {
	// Name is the tunnel interface name.
	Name string

	// State is the operational state.
	State TunnelState

	// LocalIP is the local tunnel endpoint.
	LocalIP string

	// RemoteIP is the remote tunnel endpoint.
	RemoteIP string

	// TunnelIP is the tunnel interface address.
	TunnelIP string

	// RxBytes is the number of bytes received.
	RxBytes uint64

	// TxBytes is the number of bytes transmitted.
	TxBytes uint64

	// RxPackets is the number of packets received.
	RxPackets uint64

	// TxPackets is the number of packets transmitted.
	TxPackets uint64

	// Transport is the transport in force: gre, ipsec or wireguard.
	Transport string

	// Uplink is the uplink whose routing table carries the outer packets;
	// empty when the tunnel routes through the main table.
	Uplink string

	// Bound reports whether the outer endpoint pair is currently pinned to
	// Uplink's table. It is false for a tunnel that names no uplink.
	Bound bool

	// RekeyInterval is how often the key material should be rotated; zero
	// for a transport that carries no key material (gre).
	RekeyInterval time.Duration

	// LastRekey is when Rekey last succeeded for this tunnel; zero when it
	// has not been re-keyed since it was created.
	LastRekey time.Time
}

// UplinkStatus describes one programmed WAN uplink: its routing table, the
// next hops installed in it, and the tunnels whose outer endpoints are
// pinned to it.
type UplinkStatus struct {
	// Name is the uplink's identifier.
	Name string

	// Interface is the Linux interface the uplink lives on.
	Interface string

	// Table is the routing table id holding the uplink's default routes.
	Table int

	// GatewayV4 and GatewayV6 are the ISP next hops installed in Table.
	GatewayV4 string
	GatewayV6 string

	// Addresses are the uplink's own addresses whose sourced traffic is
	// steered into Table.
	Addresses []string

	// Priority is the ip rule priority of the source rules.
	Priority int

	// RuleCount is the number of source rules programmed for Addresses.
	RuleCount int

	// Tunnels are the tunnels whose endpoint pair is pinned to this uplink,
	// sorted by name.
	Tunnels []string
}
