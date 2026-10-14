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

package agent

import (
	"net/netip"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// leaseAddress parses the address the lease assigns the client.
func leaseAddress(kind gwvpn.DataPlaneKind, lease *gwvpn.LeaseWire) (netip.Prefix, error) {
	address, err := netip.ParsePrefix(lease.Address)
	if err != nil {
		return netip.Prefix{}, &ErrLeaseUnusable{Kind: kind, Reason: "address " + lease.Address + " is not a prefix", Cause: err}
	}
	return address, nil
}

// leaseRoutes parses the prefixes a lease routes through the tunnel: the
// zones it reaches. A lease that reaches nothing is unusable.
func leaseRoutes(kind gwvpn.DataPlaneKind, routes []string) ([]netip.Prefix, error) {
	if len(routes) == 0 {
		return nil, &ErrLeaseUnusable{Kind: kind, Reason: "the lease routes nothing"}
	}
	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, &ErrLeaseUnusable{Kind: kind, Reason: "route " + r + " is not a prefix", Cause: err}
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
