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

package reporting

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Endpoint is one place the collector may dial a device, with the TLS name
// the device's certificate is expected to carry and where the address came
// from, so a failed dial can be explained.
type Endpoint struct {
	// Address is host:port.
	Address string
	// ServerName is the expected certificate name.
	ServerName string
	// Source names the provenance of the address.
	Source string
}

// AddressResolver finds where to dial a device.
//
// An address is only acceptable when the platform learned it from something
// it authenticated. A self-reported address — one carried in a request body
// — has the same circularity as a self-supplied PCR baseline: whoever can
// speak for the device could point the collector at any machine (#377).
type AddressResolver interface {
	// Endpoints returns the dial candidates in preference order, or an error
	// when the device has no trustworthy address. It never guesses.
	Endpoints(ctx context.Context, deviceID string) ([]Endpoint, error)
}

// Address provenance labels.
const (
	SourcePlatformDNS   = "platform-dns"
	SourceHeartbeatPeer = "heartbeat-peer-address"
	// SourceControlPlaneLoopback is the control plane's own quote endpoint,
	// reached over the loopback interface (#472).
	SourceControlPlaneLoopback = "control-plane-loopback"
)

// DefaultSelfHost is the address the control plane dials itself on when its
// self endpoint names no host.
const DefaultSelfHost = "127.0.0.1"

const (
	maxEndpointsPerDevice = 4
	dnsRecordTypeA        = "A"
	dnsRecordTypeAAAA     = "AAAA"
)

// DeviceAddressRecord is what the resolver needs to know about a device.
type DeviceAddressRecord struct {
	// Hostname is the IDevID Common Name recorded at enrollment.
	Hostname string
	// HeartbeatAddr is the transport peer address of the device's most
	// recent mTLS-authenticated heartbeat (host or host:port). Empty when
	// the device never heartbeated.
	HeartbeatAddr string
	// TLSServerName overrides the certificate name expected of the node,
	// for fleets whose node certificates do not carry the device FQDN. It
	// comes from the device profile.
	TLSServerName string
}

// DeviceRecords looks a device up for address resolution.
type DeviceRecords interface {
	AddressRecord(ctx context.Context, deviceID string) (*DeviceAddressRecord, error)
}

// NameResolver answers from the platform's own authoritative DNS, which is
// populated at enrollment from the connection the device enrolled over.
type NameResolver interface {
	// Resolve returns the record values for name of the given type. An
	// empty result is "no record", not an error.
	Resolve(ctx context.Context, name string, recordType string) ([]string, error)
}

// SelfEndpoint describes the control plane's own quote endpoint.
//
// The control plane is a device in its own registry (#472), so the
// collector must reach it — but a machine registers no platform DNS record
// for itself at enrollment and sends itself no heartbeat, which are the
// only two provenances the resolver otherwise accepts. The loopback address
// is not a guess and it is not something a device claimed: it is a property
// of the process doing the dialling, which is the strongest provenance
// available anywhere in this resolver. It is applied to exactly one device
// id, the one the platform wrote for itself.
//
// ServerName is the name the control plane's own webservice certificate
// carries, read from the running configuration. A profile bound to the
// device still wins, so an operator whose control-plane certificate carries
// a role name configures it the same way as for any node.
type SelfEndpoint struct {
	// DeviceID is the control plane's own device record id.
	DeviceID string
	// Host is the loopback address. Empty selects DefaultSelfHost.
	Host string
	// Port is the port the control plane's own quote endpoint listens on.
	// Zero falls back to the resolver's node port.
	Port int
	// ServerName is the control plane's own certificate name.
	ServerName string
}

// normalised returns the endpoint with its defaults applied, or false when
// it names no device.
func (s *SelfEndpoint) normalised(nodePort int) (SelfEndpoint, bool) {
	if s == nil || strings.TrimSpace(s.DeviceID) == "" {
		return SelfEndpoint{}, false
	}
	out := SelfEndpoint{
		DeviceID:   strings.TrimSpace(s.DeviceID),
		Host:       strings.TrimSpace(s.Host),
		Port:       s.Port,
		ServerName: strings.ToLower(strings.TrimSpace(s.ServerName)),
	}
	if out.Host == "" {
		out.Host = DefaultSelfHost
	}
	if out.Port <= 0 || out.Port > 65535 {
		out.Port = nodePort
	}
	return out, true
}

// DeviceAddressResolverConfig configures DeviceAddressResolver.
type DeviceAddressResolverConfig struct {
	Devices DeviceRecords
	// Names is optional; without it only the heartbeat peer address is used.
	Names NameResolver
	// InternalDomain is the platform's internal zone, appended to the
	// device hostname to form the name the enrollment hook registered.
	InternalDomain string
	// Port is the node's quote port.
	Port int
	// Self is the control plane's own quote endpoint, when this node is a
	// control plane that registered itself as a device. Nil elsewhere.
	Self *SelfEndpoint
}

// DeviceAddressResolver resolves devices from the device record and the
// platform DNS. Order of preference: the platform DNS record for the
// device's FQDN (enrollment-time provenance), then the peer address of the
// device's last authenticated heartbeat. Nothing else.
type DeviceAddressResolver struct {
	devices DeviceRecords
	names   NameResolver
	domain  string
	port    int
	self    SelfEndpoint
	hasSelf bool
}

// NewDeviceAddressResolver fails closed on a missing device source.
func NewDeviceAddressResolver(cfg DeviceAddressResolverConfig) (*DeviceAddressResolver, error) {
	if cfg.Devices == nil {
		return nil, ErrNoDeviceRecords{}
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, ErrInvalidPort{Port: cfg.Port}
	}
	self, hasSelf := cfg.Self.normalised(cfg.Port)
	return &DeviceAddressResolver{
		devices: cfg.Devices,
		names:   cfg.Names,
		domain:  strings.Trim(strings.ToLower(strings.TrimSpace(cfg.InternalDomain)), "."),
		port:    cfg.Port,
		self:    self,
		hasSelf: hasSelf,
	}, nil
}

// Endpoints implements AddressResolver.
func (r *DeviceAddressResolver) Endpoints(ctx context.Context, deviceID string) ([]Endpoint, error) {
	rec, err := r.devices.AddressRecord(ctx, deviceID)
	if err != nil {
		return nil, ErrNoDialableAddress{DeviceID: deviceID, Reason: "device record unavailable: " + err.Error()}
	}
	if rec == nil {
		return nil, ErrNoDialableAddress{DeviceID: deviceID, Reason: "device record unavailable"}
	}
	self := r.isSelf(deviceID)
	fqdn := r.fqdn(rec.Hostname)
	// Precedence for the certificate name: the profile bound to the device
	// first, exactly as for a node; then, for the control plane only, the
	// name its own webservice certificate carries (read from this process's
	// configuration, not from anything a device said); then the FQDN.
	serverName := strings.ToLower(strings.TrimSpace(rec.TLSServerName))
	if serverName == "" && self {
		serverName = r.self.ServerName
	}
	if serverName == "" {
		serverName = fqdn
	}
	if serverName == "" {
		return nil, ErrNoDialableAddress{DeviceID: deviceID,
			Reason: "device has no hostname and its profile sets no tls-server-name; there is no name to verify the node's certificate against"}
	}

	var out []Endpoint
	seen := make(map[string]struct{})
	addPort := func(host, source string, port int) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if _, dup := seen[addr]; dup {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, Endpoint{Address: addr, ServerName: serverName, Source: source})
	}
	add := func(host, source string) { addPort(host, source, r.port) }

	// The control plane's own endpoint comes first: it is the one candidate
	// whose provenance is the running process rather than a record, so it
	// needs neither DNS nor a heartbeat to be trustworthy or reachable.
	if self {
		addPort(r.self.Host, SourceControlPlaneLoopback, r.self.Port)
	}

	if r.names != nil && fqdn != "" {
		for _, rt := range []string{dnsRecordTypeA, dnsRecordTypeAAAA} {
			values, err := r.names.Resolve(ctx, fqdn, rt)
			if err != nil {
				continue
			}
			sort.Strings(values)
			for _, v := range values {
				if net.ParseIP(v) != nil {
					add(v, SourcePlatformDNS)
				}
			}
		}
	}

	if host := heartbeatHost(rec.HeartbeatAddr); host != "" {
		add(host, SourceHeartbeatPeer)
	}

	if len(out) == 0 {
		return nil, ErrNoDialableAddress{DeviceID: deviceID,
			Reason: "no platform DNS record for " + fqdnOrNone(fqdn) + " and no authenticated heartbeat address"}
	}
	if len(out) > maxEndpointsPerDevice {
		out = out[:maxEndpointsPerDevice]
	}
	return out, nil
}

// isSelf reports whether the device id is this control plane's own record.
func (r *DeviceAddressResolver) isSelf(deviceID string) bool {
	return r.hasSelf && strings.TrimSpace(deviceID) == r.self.DeviceID
}

func (r *DeviceAddressResolver) fqdn(hostname string) string {
	h := strings.Trim(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if h == "" {
		return ""
	}
	if r.domain == "" || strings.HasSuffix(h, "."+r.domain) {
		return h
	}
	return h + "." + r.domain
}

// heartbeatHost strips the port from a peer address. A value that is not an
// IP literal is rejected: the heartbeat peer is a transport address, and
// anything else here is a bug upstream, not an address to dial.
func heartbeatHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func fqdnOrNone(fqdn string) string {
	if fqdn == "" {
		return "(no hostname)"
	}
	return fqdn
}
