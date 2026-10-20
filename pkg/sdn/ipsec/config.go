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

// Package ipsec protects the overlay underlay with host-to-host IPsec. It
// drives strongSwan's charon over VICI: one transport-mode SA per VTEP pair,
// covering VXLAN and the BGP session between them, trapped on demand from
// the admitted EVPN Type-3 routes and kept explicit (no wildcard) toward the
// route reflectors and gateways. Beside charon it owns the fail-closed
// floor that keeps cleartext off the fabric when charon is down: an
// nftables table on the fabric interface and a low-priority XFRM block
// policy.
//
// Configuration and behaviour: docs/sdn/overlay/.
package ipsec

import (
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults and limits for Config.
const (
	// MinReplayWindow is the smallest ESP replay window accepted. VXLAN
	// flows hash across many sender CPUs, so a narrow window drops
	// legitimately reordered packets.
	MinReplayWindow = 1024

	// OutageFactor is how many tolerated control-plane outages a VTEP
	// certificate must outlive: renewal starts at half the lifetime, so a
	// node that misses one renewal window still holds a valid certificate
	// through a full outage.
	OutageFactor = 3

	// DefaultTokenModule names the PKCS#11 module charon holds the IKE key
	// in: the section under pkcs11 { modules { } } in the shipped
	// strongswan.conf (/etc/strongswan.d/charon/pkcs11.conf), whose path
	// is p11-kit's client, forwarding to the node-local xkms token server
	// (charon is musl-linked; the xkms module is not). load-token takes the
	// name, not the path.
	DefaultTokenModule = "xkms"

	// DefaultCPOutageTolerance is the control-plane outage a node rides
	// through on the certificate it holds.
	DefaultCPOutageTolerance = 24 * time.Hour

	// DefaultFabricLinkWait is how long startup waits for a slow fabric link
	// before failing closed.
	DefaultFabricLinkWait = 60 * time.Second

	// DefaultIKERate limits IKE packets per source address on the fabric,
	// in packets per second; the burst defaults to twice the rate.
	DefaultIKERate = 20
)

// Config is the overlay.ipsec section.
//
// YAML form:
//
//	overlay:
//	  ipsec:
//	    enabled: true
//	    fabric-interface: bond0
//	    local-address: 10.20.0.11
//	    static-peers: [10.20.0.1, 10.20.0.2]
//	    token:
//	      handle: 6970736563
//	    certificate-file: /etc/platform/ipsec/tunnel.pem
//	    crl-files: [/etc/platform/ipsec/root.crl, /etc/platform/ipsec/tunnel.crl]
type Config struct {
	// Enabled turns overlay IPsec on. With it on, the fabric interface
	// carries nothing but IKE, ESP, traffic an SA protects and the ICMPv6
	// the link needs -- received, sent or routed through the node.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// FabricInterface is the underlay interface the fail-closed filter
	// guards.
	FabricInterface string `yaml:"fabric-interface" json:"fabric_interface" mapstructure:"fabric-interface"`

	// LocalAddress is this node's VTEP address: the IKE endpoint and the
	// identity its certificate carries.
	LocalAddress string `yaml:"local-address" json:"local_address" mapstructure:"local-address"`

	// StaticPeers are the route reflectors and gateways this node always
	// holds an explicit connection to, independent of EVPN routes. Every
	// entry is a single address; there is no wildcard peer.
	StaticPeers []string `yaml:"static-peers,omitempty" json:"static_peers,omitempty" mapstructure:"static-peers"`

	// VICISocket is charon's control socket, which must be mode 0600 and
	// owned by platformd's user. Default DefaultVICISocket.
	VICISocket string `yaml:"vici-socket,omitempty" json:"vici_socket,omitempty" mapstructure:"vici-socket"`

	// Token locates the IKE private key in the node-local token.
	Token TokenConfig `yaml:"token" json:"token" mapstructure:"token"`

	// CertificateFile is a PEM file holding the tunnel certificate, then
	// the CA certificates peer certificates chain to. FileIdentity loads
	// it; a node whose identity comes from issuance leaves it empty.
	CertificateFile string `yaml:"certificate-file,omitempty" json:"certificate_file,omitempty" mapstructure:"certificate-file"`

	// CRLFiles hold the CRLs peers are checked against, one file per
	// issuer of the tunnel chain: PEM ("X509 CRL") or DER. Service reads
	// them at start and every CRLRefresh, so a CRL replaced on disk is
	// pushed to charon within that.
	CRLFiles []string `yaml:"crl-files,omitempty" json:"crl_files,omitempty" mapstructure:"crl-files"`

	// CertLifetime is the VTEP certificate lifetime. Default and minimum:
	// OutageFactor × CPOutageTolerance.
	CertLifetime time.Duration `yaml:"cert-lifetime,omitempty" json:"cert_lifetime,omitempty" mapstructure:"cert-lifetime"`

	// CPOutageTolerance is the control-plane outage the overlay must ride
	// through without losing a tunnel. Default DefaultCPOutageTolerance.
	CPOutageTolerance time.Duration `yaml:"cp-outage-tolerance,omitempty" json:"cp_outage_tolerance,omitempty" mapstructure:"cp-outage-tolerance"`

	// ReplayWindow is the ESP anti-replay window in packets. Default and
	// minimum MinReplayWindow.
	ReplayWindow uint32 `yaml:"replay-window,omitempty" json:"replay_window,omitempty" mapstructure:"replay-window"`

	// IKERate and IKEBurst limit IKE packets (UDP 500 and 4500) per source
	// address. Defaults DefaultIKERate and twice the rate.
	IKERate  uint32 `yaml:"ike-rate,omitempty" json:"ike_rate,omitempty" mapstructure:"ike-rate"`
	IKEBurst uint32 `yaml:"ike-burst,omitempty" json:"ike_burst,omitempty" mapstructure:"ike-burst"`

	// UnderlaySLAAC also passes ICMPv6 router solicitations and
	// advertisements on the fabric, which an underlay addressed by SLAAC
	// needs. Off by default: an unauthenticated advertisement can readdress
	// or reroute the node.
	UnderlaySLAAC bool `yaml:"underlay-slaac,omitempty" json:"underlay_slaac,omitempty" mapstructure:"underlay-slaac"`

	// FabricLinkWait is how long Service.Install waits for the fabric link to
	// appear before failing closed. Default DefaultFabricLinkWait.
	FabricLinkWait time.Duration `yaml:"fabric-link-wait,omitempty" json:"fabric_link_wait,omitempty" mapstructure:"fabric-link-wait"`
}

// TokenConfig locates the IKE key: a sign-only object in the node-local
// token, reached through p11-kit.
type TokenConfig struct {
	// Module is the name of the strongswan.conf pkcs11 module that holds
	// the key, sent with load-token. Default DefaultTokenModule.
	Module string `yaml:"module,omitempty" json:"module,omitempty" mapstructure:"module"`

	// Slot is the token slot holding the key.
	Slot uint32 `yaml:"slot" json:"slot" mapstructure:"slot"`

	// Handle is the key's CKA_ID in hex, as the KMS set it when the key
	// was created.
	Handle string `yaml:"handle" json:"handle" mapstructure:"handle"`

	// PINFile holds the token PIN on its first line. FileIdentity reads
	// it once into an enclave. Empty when the token needs no PIN.
	PINFile string `yaml:"pin-file,omitempty" json:"pin_file,omitempty" mapstructure:"pin-file"`
}

// Validate checks the section. A disabled or absent section is valid.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if err := validateInterface(c.FabricInterface); err != nil {
		return &ConfigError{Field: "fabric-interface", Err: err}
	}
	local, err := parseUnicast(c.LocalAddress)
	if err != nil {
		return &ConfigError{Field: "local-address", Err: err}
	}
	if err := validatePeers(local, c.StaticPeers); err != nil {
		return err
	}
	if c.VICISocket != "" && !filepath.IsAbs(c.VICISocket) {
		return &ConfigError{Field: "vici-socket", Err: ErrRelativePath}
	}
	if c.CertificateFile != "" && !filepath.IsAbs(c.CertificateFile) {
		return &ConfigError{Field: "certificate-file", Err: ErrRelativePath}
	}
	for i, path := range c.CRLFiles {
		if !filepath.IsAbs(path) {
			return &ConfigError{Field: crlFileField(i), Err: ErrRelativePath}
		}
	}
	if err := c.Token.validate(); err != nil {
		return err
	}
	return c.validateLimits()
}

func (c *Config) validateLimits() error {
	if c.CPOutageTolerance < 0 {
		return &ConfigError{Field: "cp-outage-tolerance", Err: ErrNegativeDuration}
	}
	if c.CertLifetime < 0 {
		return &ConfigError{Field: "cert-lifetime", Err: ErrNegativeDuration}
	}
	if c.FabricLinkWait < 0 {
		return &ConfigError{Field: "fabric-link-wait", Err: ErrNegativeDuration}
	}
	if c.CertLifetime != 0 && c.CertLifetime < OutageFactor*c.EffectiveCPOutageTolerance() {
		return &ConfigError{Field: "cert-lifetime", Err: ErrLifetimeTooShort}
	}
	if c.ReplayWindow != 0 && c.ReplayWindow < MinReplayWindow {
		return &ConfigError{Field: "replay-window", Err: ErrReplayWindowTooSmall}
	}
	if c.EffectiveIKEBurst() < c.EffectiveIKERate() {
		return &ConfigError{Field: "ike-burst", Err: ErrInvalidRate}
	}
	return nil
}

func validatePeers(local netip.Addr, peers []string) error {
	seen := make(map[netip.Addr]struct{}, len(peers)+1)
	seen[local] = struct{}{}
	for i, p := range peers {
		field := "static-peers[" + strconv.Itoa(i) + "]"
		addr, err := parseUnicast(p)
		if err != nil {
			return &ConfigError{Field: field, Err: err}
		}
		if addr.Is4() != local.Is4() {
			return &ConfigError{Field: field, Err: ErrFamilyMismatch}
		}
		if _, dup := seen[addr]; dup {
			return &ConfigError{Field: field, Err: ErrDuplicatePeer}
		}
		seen[addr] = struct{}{}
	}
	return nil
}

func (t *TokenConfig) validate() error {
	if t.Module != "" && !validModuleName(t.Module) {
		return &ConfigError{Field: "token.module", Err: ErrInvalidModule}
	}
	if t.PINFile != "" && !filepath.IsAbs(t.PINFile) {
		return &ConfigError{Field: "token.pin-file", Err: ErrRelativePath}
	}
	if t.Handle == "" {
		return &ConfigError{Field: "token.handle", Err: ErrRequired}
	}
	if _, err := hex.DecodeString(t.Handle); err != nil {
		return &ConfigError{Field: "token.handle", Err: ErrInvalidHandle}
	}
	return nil
}

// maxModuleName bounds a token module name; strongswan.conf section names
// have no limit of their own, a configuration typo should still be caught.
const maxModuleName = 64

// validModuleName reports whether name can be a section under charon's
// pkcs11 { modules { } } in strongswan.conf: letters, digits, '-' and '_'.
// A path, which the field once held, is refused.
func validModuleName(name string) bool {
	if len(name) == 0 || len(name) > maxModuleName {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// parseUnicast parses a single unicast address: not a prefix, not
// unspecified, multicast or link-local, which an SA endpoint cannot be.
func parseUnicast(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, ErrRequired
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, ErrInvalidAddress
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}, ErrInvalidAddress
	}
	return addr, nil
}

// validateInterface accepts a Linux interface name: 1–15 characters, no
// whitespace, slash or NUL.
func validateInterface(name string) error {
	if name == "" {
		return ErrRequired
	}
	if len(name) > 15 || strings.ContainsAny(name, " \t\n/\x00\"") {
		return ErrInvalidInterface
	}
	return nil
}

// Local parses the local address.
func (c *Config) Local() (netip.Addr, error) {
	addr, err := parseUnicast(c.LocalAddress)
	if err != nil {
		return netip.Addr{}, &ConfigError{Field: "local-address", Err: err}
	}
	return addr, nil
}

// enabledLocal checks that the section is present, enabled and valid, and
// returns its local address.
func enabledLocal(cfg *Config) (netip.Addr, error) {
	if cfg == nil || !cfg.Enabled {
		return netip.Addr{}, ErrNotEnabled
	}
	if err := cfg.Validate(); err != nil {
		return netip.Addr{}, err
	}
	return cfg.Local()
}

// crlFileField names the i'th crl-files entry.
func crlFileField(i int) string { return "crl-files[" + strconv.Itoa(i) + "]" }

// Peers parses the static peers.
func (c *Config) Peers() ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(c.StaticPeers))
	for i, p := range c.StaticPeers {
		addr, err := parseUnicast(p)
		if err != nil {
			return nil, &ConfigError{Field: "static-peers[" + strconv.Itoa(i) + "]", Err: err}
		}
		out = append(out, addr)
	}
	return out, nil
}

// EffectiveVICISocket is the configured socket or DefaultVICISocket.
func (c *Config) EffectiveVICISocket() string {
	if c.VICISocket != "" {
		return c.VICISocket
	}
	return DefaultVICISocket
}

// EffectiveTokenModule is the configured module or DefaultTokenModule.
func (c *Config) EffectiveTokenModule() string {
	if c.Token.Module != "" {
		return c.Token.Module
	}
	return DefaultTokenModule
}

// EffectiveCPOutageTolerance is the configured tolerance or
// DefaultCPOutageTolerance.
func (c *Config) EffectiveCPOutageTolerance() time.Duration {
	if c.CPOutageTolerance > 0 {
		return c.CPOutageTolerance
	}
	return DefaultCPOutageTolerance
}

// EffectiveCertLifetime is the configured lifetime or OutageFactor times
// the outage tolerance.
func (c *Config) EffectiveCertLifetime() time.Duration {
	if c.CertLifetime > 0 {
		return c.CertLifetime
	}
	return OutageFactor * c.EffectiveCPOutageTolerance()
}

// ReauthTime is the IKE reauthentication interval: half the certificate
// lifetime, so every SA re-proves its identity — and re-checks revocation
// — with the certificate renewed at the same mark.
func (c *Config) ReauthTime() time.Duration {
	return c.EffectiveCertLifetime() / 2
}

// EffectiveFabricLinkWait is the configured fabric-link wait or
// DefaultFabricLinkWait.
func (c *Config) EffectiveFabricLinkWait() time.Duration {
	if c.FabricLinkWait > 0 {
		return c.FabricLinkWait
	}
	return DefaultFabricLinkWait
}

// EffectiveReplayWindow is the configured window or MinReplayWindow.
func (c *Config) EffectiveReplayWindow() uint32 {
	if c.ReplayWindow > 0 {
		return c.ReplayWindow
	}
	return MinReplayWindow
}

// EffectiveIKERate is the configured per-source IKE rate or DefaultIKERate.
func (c *Config) EffectiveIKERate() uint32 {
	if c.IKERate > 0 {
		return c.IKERate
	}
	return DefaultIKERate
}

// EffectiveIKEBurst is the configured per-source IKE burst or twice the
// effective rate.
func (c *Config) EffectiveIKEBurst() uint32 {
	if c.IKEBurst > 0 {
		return c.IKEBurst
	}
	return 2 * c.EffectiveIKERate()
}
