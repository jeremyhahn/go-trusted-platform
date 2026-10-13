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

package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DesiredConfig is the control plane's intended configuration for one
// gateway — the wire contract of GET /api/v1/gateway/desired-config/{id}
// (#555). It carries only sections a running gateway can apply through a
// live service; a section for a service the gateway does not run is a
// typed, reported refusal on the gateway, never a silent skip.
//
// Version is the control plane's opaque revision of this document. When
// the control plane leaves it empty the gateway derives ContentVersion,
// so an unchanged document is never re-applied and a changed one always
// is.
type DesiredConfig struct {
	GatewayID    string               `json:"gateway_id" yaml:"gateway-id" mapstructure:"gateway-id"`
	Version      string               `json:"version,omitempty" yaml:"version,omitempty" mapstructure:"version"`
	LoadBalancer *DesiredLoadBalancer `json:"load_balancer,omitempty" yaml:"load-balancer,omitempty" mapstructure:"load-balancer"`
	NAT          *DesiredNAT          `json:"nat,omitempty" yaml:"nat,omitempty" mapstructure:"nat"`
	VPN          *DesiredVPN          `json:"vpn,omitempty" yaml:"vpn,omitempty" mapstructure:"vpn"`
}

// DesiredVPN is the control plane's remote-access VPN state for one gateway:
// the enrolled peers and the tenant posture policies (docs/vpn/). The
// gateway admits only enrolled peers, so an empty Peers list admits nobody.
type DesiredVPN struct {
	Peers           []DesiredVPNPeer          `json:"peers,omitempty" yaml:"peers,omitempty" mapstructure:"peers"`
	PosturePolicies []DesiredVPNPosturePolicy `json:"posture_policies,omitempty" yaml:"posture-policies,omitempty" mapstructure:"posture-policies"`
}

// DesiredVPNPeer is one enrolled device of a tenant.
type DesiredVPNPeer struct {
	TenantID string   `json:"tenant_id" yaml:"tenant-id" mapstructure:"tenant-id"`
	DeviceID string   `json:"device_id" yaml:"device-id" mapstructure:"device-id"`
	Zones    []string `json:"zones,omitempty" yaml:"zones,omitempty" mapstructure:"zones"`
}

// DesiredVPNPosturePolicy is one tenant posture policy (a Rego module).
type DesiredVPNPosturePolicy struct {
	TenantID string `json:"tenant_id" yaml:"tenant-id" mapstructure:"tenant-id"`
	Name     string `json:"name" yaml:"name" mapstructure:"name"`
	Module   string `json:"module" yaml:"module" mapstructure:"module"`
}

// validate checks each peer and policy names its tenant and is unique.
func (v *DesiredVPN) validate() error {
	// Keys keep tenant and name apart: a joined "tenant/name" string would
	// make ("a/b", "c") and ("a", "b/c") the same peer.
	peers := map[[2]string]bool{}
	for i, p := range v.Peers {
		field := SectionVPN + ".peers[" + itoa(i) + "]"
		if p.TenantID == "" {
			return &ErrDesiredConfigInvalid{Field: field + ".tenant_id", Reason: "required"}
		}
		if p.DeviceID == "" {
			return &ErrDesiredConfigInvalid{Field: field + ".device_id", Reason: "required"}
		}
		key := [2]string{p.TenantID, p.DeviceID}
		if peers[key] {
			return &ErrDesiredConfigInvalid{Field: field, Reason: "duplicate peer " + strconv.Quote(p.DeviceID) + " of tenant " + strconv.Quote(p.TenantID)}
		}
		peers[key] = true
	}
	policies := map[[2]string]bool{}
	for i, p := range v.PosturePolicies {
		field := SectionVPN + ".posture_policies[" + itoa(i) + "]"
		switch {
		case p.TenantID == "":
			return &ErrDesiredConfigInvalid{Field: field + ".tenant_id", Reason: "required"}
		case p.Name == "":
			return &ErrDesiredConfigInvalid{Field: field + ".name", Reason: "required"}
		case p.Module == "":
			return &ErrDesiredConfigInvalid{Field: field + ".module", Reason: "required"}
		}
		key := [2]string{p.TenantID, p.Name}
		if policies[key] {
			return &ErrDesiredConfigInvalid{Field: field, Reason: "duplicate posture policy " + strconv.Quote(p.Name) + " of tenant " + strconv.Quote(p.TenantID)}
		}
		policies[key] = true
	}
	return nil
}

// DesiredLoadBalancer is the complete set of virtual IPs the gateway's
// load balancer should serve. Reconciliation is declarative: a VIP absent
// here is removed, a present one is added or its backends replaced.
type DesiredLoadBalancer struct {
	VIPs []DesiredVIP `json:"vips" yaml:"vips" mapstructure:"vips"`
}

// DesiredVIP is one load-balanced virtual IP. Its identity is
// (protocol, address, port); the rest is its definition.
type DesiredVIP struct {
	Address   string           `json:"address" yaml:"address" mapstructure:"address"`
	Port      uint16           `json:"port" yaml:"port" mapstructure:"port"`
	Protocol  string           `json:"protocol" yaml:"protocol" mapstructure:"protocol"`
	Algorithm string           `json:"algorithm,omitempty" yaml:"algorithm,omitempty" mapstructure:"algorithm"`
	Backends  []DesiredBackend `json:"backends" yaml:"backends" mapstructure:"backends"`
}

// DesiredBackend is one endpoint behind a VIP.
type DesiredBackend struct {
	Address string `json:"address" yaml:"address" mapstructure:"address"`
	Port    uint16 `json:"port" yaml:"port" mapstructure:"port"`
	Weight  uint16 `json:"weight,omitempty" yaml:"weight,omitempty" mapstructure:"weight"`
}

// DesiredNAT is the NAT state the gateway should hold: an optional SNAT
// source prefix (empty disables SNAT) and the complete list of DNAT
// port-forwards.
type DesiredNAT struct {
	SNATInternalCIDR string        `json:"snat_internal_cidr,omitempty" yaml:"snat-internal-cidr,omitempty" mapstructure:"snat-internal-cidr"`
	DNAT             []DesiredDNAT `json:"dnat,omitempty" yaml:"dnat,omitempty" mapstructure:"dnat"`
}

// DesiredDNAT is one inbound port-forward: traffic to External (an
// "addr:port" on the uplink) is translated to Internal.
type DesiredDNAT struct {
	Protocol string `json:"protocol" yaml:"protocol" mapstructure:"protocol"`
	External string `json:"external" yaml:"external" mapstructure:"external"`
	Internal string `json:"internal" yaml:"internal" mapstructure:"internal"`
}

// DesiredConfigState is the gateway's report of the last desired-config
// reconciliation, carried in the telemetry Snapshot so the control plane
// can see whether what it authored has taken effect.
type DesiredConfigState struct {
	// Version is the revision last applied successfully.
	Version string `json:"version,omitempty"`
	// AppliedAt is when Version took effect.
	AppliedAt time.Time `json:"applied_at,omitempty"`
	// AttemptedAt is the time of the most recent fetch-and-apply attempt,
	// successful or not.
	AttemptedAt time.Time `json:"attempted_at,omitempty"`
	// LastError is the most recent attempt's failure, empty on success.
	LastError string `json:"last_error,omitempty"`
}

// Section names used in errors.
const (
	SectionLoadBalancer = "load_balancer"
	SectionNAT          = "nat"
	SectionVPN          = "vpn"
)

// DecodeDesiredConfig parses the JSON document the control plane served.
// Unknown top-level keys are refused: a section this gateway build does
// not know is a section it cannot apply, and the control plane must be
// told rather than have the key ignored.
func DecodeDesiredConfig(data []byte) (*DesiredConfig, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, &ErrDesiredConfigMalformed{Cause: err}
	}
	for key := range probe {
		if !knownDesiredSections[key] {
			return nil, &ErrDesiredSectionUnsupported{Section: key}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg DesiredConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, &ErrDesiredConfigMalformed{Cause: err}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var knownDesiredSections = map[string]bool{
	"gateway_id":    true,
	"version":       true,
	"load_balancer": true,
	"nat":           true,
	"vpn":           true,
}

// Validate checks every address and identity the document carries, so a
// malformed document is refused before any section is applied.
func (d *DesiredConfig) Validate() error {
	if d == nil {
		return &ErrDesiredConfigInvalid{Field: "document", Reason: "nil"}
	}
	if d.LoadBalancer != nil {
		seen := map[string]bool{}
		for i, vip := range d.LoadBalancer.VIPs {
			if err := vip.validate(i); err != nil {
				return err
			}
			key := vip.Key()
			if seen[key] {
				return &ErrDesiredConfigInvalid{Field: vipField(i, "address"), Reason: "duplicate VIP " + key}
			}
			seen[key] = true
		}
	}
	if d.NAT != nil {
		if d.NAT.SNATInternalCIDR != "" {
			if _, err := netip.ParsePrefix(d.NAT.SNATInternalCIDR); err != nil {
				return &ErrDesiredConfigInvalid{Field: "nat.snat_internal_cidr", Reason: err.Error()}
			}
		}
		seen := map[string]bool{}
		for i, rule := range d.NAT.DNAT {
			if err := rule.validate(i); err != nil {
				return err
			}
			key := rule.Key()
			if seen[key] {
				return &ErrDesiredConfigInvalid{Field: dnatField(i, "external"), Reason: "duplicate DNAT " + key}
			}
			seen[key] = true
		}
	}
	if d.VPN != nil {
		if err := d.VPN.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Key is the VIP's identity: protocol, address and port.
func (v DesiredVIP) Key() string {
	return strings.ToLower(v.Protocol) + "/" + netip.AddrPortFrom(mustAddr(v.Address), v.Port).String()
}

func (v DesiredVIP) validate(i int) error {
	if _, err := netip.ParseAddr(v.Address); err != nil {
		return &ErrDesiredConfigInvalid{Field: vipField(i, "address"), Reason: err.Error()}
	}
	if v.Port == 0 {
		return &ErrDesiredConfigInvalid{Field: vipField(i, "port"), Reason: "must be non-zero"}
	}
	switch strings.ToLower(v.Protocol) {
	case "tcp", "udp":
	default:
		return &ErrDesiredConfigInvalid{Field: vipField(i, "protocol"), Reason: "must be tcp or udp"}
	}
	if len(v.Backends) == 0 {
		return &ErrDesiredConfigInvalid{Field: vipField(i, "backends"), Reason: "at least one backend is required"}
	}
	for j, b := range v.Backends {
		if _, err := netip.ParseAddr(b.Address); err != nil {
			return &ErrDesiredConfigInvalid{Field: vipField(i, "backends") + "[" + itoa(j) + "].address", Reason: err.Error()}
		}
		if b.Port == 0 {
			return &ErrDesiredConfigInvalid{Field: vipField(i, "backends") + "[" + itoa(j) + "].port", Reason: "must be non-zero"}
		}
	}
	return nil
}

// Key is the DNAT rule's identity: protocol and external endpoint.
func (r DesiredDNAT) Key() string {
	return strings.ToLower(r.Protocol) + "/" + r.External
}

func (r DesiredDNAT) validate(i int) error {
	switch strings.ToLower(r.Protocol) {
	case "tcp", "udp":
	default:
		return &ErrDesiredConfigInvalid{Field: dnatField(i, "protocol"), Reason: "must be tcp or udp"}
	}
	if _, err := netip.ParseAddrPort(r.External); err != nil {
		return &ErrDesiredConfigInvalid{Field: dnatField(i, "external"), Reason: err.Error()}
	}
	if _, err := netip.ParseAddrPort(r.Internal); err != nil {
		return &ErrDesiredConfigInvalid{Field: dnatField(i, "internal"), Reason: err.Error()}
	}
	return nil
}

// ContentVersion is the revision of the document derived from its content
// (Version itself excluded), used when the control plane sets none.
func (d *DesiredConfig) ContentVersion() string {
	clone := *d
	clone.Version = ""
	data, err := json.Marshal(&clone)
	if err != nil {
		// Marshalling a struct of strings and integers cannot fail; a
		// zero version forces a re-apply, which is the safe direction.
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EffectiveVersion is Version when the control plane set one, else the
// content-derived revision.
func (d *DesiredConfig) EffectiveVersion() string {
	if d.Version != "" {
		return d.Version
	}
	return d.ContentVersion()
}

func vipField(i int, name string) string {
	return "load_balancer.vips[" + itoa(i) + "]." + name
}

func dnatField(i int, name string) string {
	return "nat.dnat[" + itoa(i) + "]." + name
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// ErrDesiredConfigMalformed reports a document that is not the wire
// contract at all.
type ErrDesiredConfigMalformed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrDesiredConfigMalformed) Error() string {
	return "desired config: malformed document: " + e.Cause.Error()
}

// Unwrap returns the underlying decode error.
func (e *ErrDesiredConfigMalformed) Unwrap() error { return e.Cause }

// ErrDesiredSectionUnsupported reports a top-level key this gateway build
// does not know how to apply.
type ErrDesiredSectionUnsupported struct {
	Section string
}

// Error implements the error interface.
func (e *ErrDesiredSectionUnsupported) Error() string {
	return "desired config: section " + e.Section + " is not supported by this gateway"
}

// ErrDesiredConfigInvalid reports a field whose value cannot be applied.
type ErrDesiredConfigInvalid struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *ErrDesiredConfigInvalid) Error() string {
	return "desired config: " + e.Field + ": " + e.Reason
}

// IsDesiredConfigRejection reports whether err is one of the typed
// refusals a malformed or unsupported document produces, as opposed to a
// transport or apply failure.
func IsDesiredConfigRejection(err error) bool {
	var malformed *ErrDesiredConfigMalformed
	var unsupported *ErrDesiredSectionUnsupported
	var invalid *ErrDesiredConfigInvalid
	return errors.As(err, &malformed) || errors.As(err, &unsupported) || errors.As(err, &invalid)
}
