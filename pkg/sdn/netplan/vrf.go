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

package netplan

import (
	"fmt"
	"net/netip"
)

// TenantSubnet is one network a tenant asks for in its VRF.
type TenantSubnet struct {
	// Network is the overlay network number the network's L2VNI is built from.
	Network uint32
	// Subnet is the tenant's own (BYO) subnet for the network.
	Subnet netip.Prefix
}

// TenantNetwork is one network of a tenant VRF: an L2VNI with its subnet
// and anycast gateway.
type TenantNetwork struct {
	// Network is the overlay network number.
	Network uint32
	// VNI is the network's L2VNI in this environment.
	VNI uint32
	// Subnet is the tenant's subnet for the network.
	Subnet netip.Prefix
	// Gateway is the network's anycast gateway: the subnet's first host.
	Gateway netip.Addr
}

// TenantVRF is a tenant's IP-VRF in this environment. Its L3VNI routes
// between its networks (symmetric IRB); each network is an L2VNI. The RD
// and the auto-RT are derived from these VNIs by the EVPN speaker, not
// stored here. Tenants' subnets may overlap because each lives in its own
// VRF.
type TenantVRF struct {
	// Tenant is the tenant ID.
	Tenant string
	// L3VNI is the VRF's L3VNI in this environment.
	L3VNI uint32
	// Networks are the VRF's networks, in the order they were given.
	Networks []TenantNetwork
}

// TenantVRF derives tenant's VRF from the plan: the L3VNI of overlay
// network l3 and, for each subnet, its L2VNI and anycast gateway. Each
// subnet must pass CheckTenantSubnet and stay clear of the VRF's other
// subnets; a network number may not repeat or equal l3. A refusal is an
// ErrTenantVRF, or the ErrVNIOutOfRange or ErrTenantSubnet of the check
// that failed.
func (p *Plan) TenantVRF(tenant string, l3 uint32, subnets []TenantSubnet) (TenantVRF, error) {
	refuse := func(reason string) error {
		return ErrTenantVRF{Tenant: tenant, Reason: reason}
	}
	if tenant == "" {
		return TenantVRF{}, refuse("has no tenant ID")
	}
	l3VNI, err := p.VNI(l3)
	if err != nil {
		return TenantVRF{}, err
	}
	networks := make([]TenantNetwork, 0, len(subnets))
	seen := make(map[uint32]bool, len(subnets))
	for _, s := range subnets {
		if s.Network == l3 {
			return TenantVRF{}, refuse(fmt.Sprintf("network %d is the L3VNI", s.Network))
		}
		if seen[s.Network] {
			return TenantVRF{}, refuse(fmt.Sprintf("network %d appears twice", s.Network))
		}
		seen[s.Network] = true
		vni, err := p.VNI(s.Network)
		if err != nil {
			return TenantVRF{}, err
		}
		if err := p.CheckTenantSubnet(s.Subnet); err != nil {
			return TenantVRF{}, err
		}
		for _, prev := range networks {
			if prev.Subnet.Overlaps(s.Subnet) {
				return TenantVRF{}, refuse(fmt.Sprintf("subnet %s overlaps %s", s.Subnet, prev.Subnet))
			}
		}
		gw, err := Gateway(s.Subnet)
		if err != nil {
			return TenantVRF{}, err
		}
		networks = append(networks, TenantNetwork{Network: s.Network, VNI: vni, Subnet: s.Subnet, Gateway: gw})
	}
	return TenantVRF{Tenant: tenant, L3VNI: l3VNI, Networks: networks}, nil
}
