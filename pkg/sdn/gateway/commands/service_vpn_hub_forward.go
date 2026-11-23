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

package commands

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// vpnHubForwardRule is one rule of the vpn-hub0 ingress chain, compiled from
// the zone matrix (#2093). Every rule but the closing drop (Drop, no Family)
// is bound to a lease's address and a subnet of a zone the matrix opens for
// it.
type vpnHubForwardRule struct {
	// Family is 4 or 6; the closing drop alone has none.
	Family int
	// Source is the lease's address as a host prefix.
	Source netip.Prefix
	// Destination is a subnet of the destination zone.
	Destination netip.Prefix
	// Protocol is "tcp" or "udp" when Port is set.
	Protocol string
	// Port is the destination port; 0 opens every port of Destination.
	Port uint16
	// Reply marks a reply-direction established/related accept from the
	// lease's Source to Destination, never with a Port: replies to
	// connections opened toward the peer, bound to the current lease, so
	// conntrack state that outlives a lease opens nothing.
	Reply bool
	// Drop marks the closing drop for the hub interface.
	Drop bool
	// Comment names the lease's destination zone and service.
	Comment string
}

// text renders the rule in nft syntax.
func (r vpnHubForwardRule) text() string {
	in := fmt.Sprintf("iifname %q", vpnHubInterface)
	if r.Drop {
		return in + " drop"
	}
	ip := "ip"
	if r.Family == 6 {
		ip = "ip6"
	}
	var b strings.Builder
	b.WriteString(in)
	if r.Reply {
		b.WriteString(" ct direction reply ct state established,related")
	}
	fmt.Fprintf(&b, " %s saddr %s %s daddr %s", ip, r.Source, ip, r.Destination)
	if r.Port != 0 {
		fmt.Fprintf(&b, " %s dport %d", r.Protocol, r.Port)
	}
	b.WriteString(" accept")
	if r.Comment != "" {
		fmt.Fprintf(&b, " comment %q", r.Comment)
	}
	return b.String()
}

// vpnHubServicePort is one protocol and port a matrix service name opens.
type vpnHubServicePort struct {
	protocol string
	port     uint16
}

// vpnHubServicePorts are the ports a service-scoped matrix cell opens, the
// values the zone flows use (pkg/sdn/policy/zoneflows generators.go). A
// service name not listed opens nothing.
var vpnHubServicePorts = map[string][]vpnHubServicePort{
	"dns": {
		{"tcp", 53}, {"udp", 53},
		{"tcp", 8053}, {"udp", 8053},
		{"tcp", 9053}, {"udp", 9053},
	},
	"acme": {{"tcp", 443}, {"tcp", 8443}, {"tcp", 9443}},
	"tftp": {{"udp", 69}},
}

// compileVPNHubForwardRules renders the vpn-hub0 forwarding rules for leases
// from the enforcement's matrix: for each lease and each of its zones the
// matrix opens from the management-VPN zone, an accept from the lease's
// address to each subnet of that zone in the lease's family (port rules only
// when the cell names services), led by a reply-direction established/related
// accept from the same address to the same subnet, so conntrack state that
// outlives a lease, or a narrower re-lease of its address, opens nothing the
// current lease does not. A subnet that gets no accept gets no reply accept
// either. Last comes a drop of
// everything else entering on the hub interface. A lease zone with no
// network summary, or with no subnet, is an error: it cannot be enforced.
func compileVPNHubForwardRules(e *vpnHubZoneEnforcement, nets map[zone.Zone]zoneflows.NetworkSummary, leases []*vpn.Lease) ([]vpnHubForwardRule, error) {
	if e == nil {
		return nil, errors.New("no destination-zone enforcement to compile the " + vpnHubInterface + " forwarding rules from")
	}
	rules := []vpnHubForwardRule{}
	for _, lease := range leases {
		if lease == nil {
			continue
		}
		if !lease.Address.IsValid() {
			return nil, fmt.Errorf("lease %s has no address", lease.ID)
		}
		addr := lease.Address.Addr().Unmap()
		family, bits := 4, 32
		if addr.Is6() {
			family, bits = 6, 128
		}
		source := netip.PrefixFrom(addr, bits)
		for _, name := range lease.Zones {
			dst := zone.Zone(name)
			v := e.matrix.Allowed(vpnHubZone, dst)
			if !v.Allowed {
				continue
			}
			summary, ok := nets[dst]
			if !ok {
				return nil, fmt.Errorf("lease zone %s has no network summary", dst)
			}
			if summary.Subnet == "" && summary.Subnet6 == "" {
				return nil, fmt.Errorf("lease zone %s has no subnet", dst)
			}
			for _, s := range []string{summary.Subnet, summary.Subnet6} {
				if s == "" {
					continue
				}
				subnet, err := netip.ParsePrefix(s)
				if err != nil {
					return nil, fmt.Errorf("lease zone %s subnet: %w", dst, err)
				}
				if subnet.Addr().Unmap().Is6() != (family == 6) {
					continue
				}
				base := vpnHubForwardRule{Family: family, Source: source, Destination: subnet.Masked()}
				var accepts []vpnHubForwardRule
				if len(v.Services) == 0 {
					base.Comment = "vpn lease to " + string(dst)
					accepts = append(accepts, base)
				}
				for _, service := range v.Services {
					for _, p := range vpnHubServicePorts[service] {
						r := base
						r.Protocol, r.Port = p.protocol, p.port
						r.Comment = "vpn lease to " + string(dst) + " " + service
						accepts = append(accepts, r)
					}
				}
				if len(accepts) == 0 {
					// A service cell whose services open no port gets
					// neither accepts nor replies.
					continue
				}
				reply := vpnHubForwardRule{Family: family, Source: source, Destination: subnet.Masked(), Reply: true, Comment: "vpn lease replies from " + string(dst)}
				rules = append(rules, reply)
				rules = append(rules, accepts...)
			}
		}
	}
	return append(rules, vpnHubForwardRule{Drop: true, Comment: "everything else from the hub"}), nil
}
