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

// Package netplan derives every number of the reference network
// (docs/architecture/reference-network.md) from an Environment and the
// resolved zone set. It is the only place in the platform where VLAN IDs,
// subnets, VNIs, IPAM pools, port-class VLAN lists and reserved ranges are
// computed; every other package asks a Plan.
//
// The rules, for environment E on the base 10.0.0.0/8:
//
//   - zone at offset n: VLAN E·100+n, IPv4 10.E.n.0/24, IPv6 <ULA /48>:<VLAN
//     digits>::/64 (VLAN 406 → fd12:3456:789a:406::/64);
//   - the lower /17 of 10.E.0.0/16 is VLAN-mapped; the upper /17
//     (10.E.128.0/17) is the IPAM pool, split into tunnel point-to-point
//     links, loopbacks, platform service VIPs, platform-VRF hosts and the
//     tenant default pools;
//   - overlay network n: VNI E·100000+n;
//   - inside a zone subnet: .1 the gateway (the VRRP address of a pair), .2
//     and .3 the gateway nodes, .10–.19 control-plane nodes, .20–.49 other
//     static hosts, .50 and up DHCP;
//   - reserved and never allocatable: 10.E.128.0/31 (gateway HA sync),
//     169.254.169.253 and <ULA>:ffff::/64 (per-VRF host services), and the
//     gateway (anycast) address of every subnet.
//
// A non-reference site overrides a zone's VLAN, IPv4 subnet or IPv6 subnet
// explicitly (Override); growing the fabric past a /24 is a subnet override
// with a shorter prefix.
package netplan
