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

package testenv

import (
	"strconv"

	"github.com/vishvananda/netlink"
)

// VethQueues is the tx and rx queue count of every veth end a test creates.
//
// The kernel gives a veth one queue per possible CPU by default, and every
// queue raises its own uevents when the link is added or removed. On an
// 80-core CI host that is about 450 uevents per pair, enough for test churn
// to start a udev storm (#1178). Every test veth is therefore created through
// NewVeth or VethArgs, which pin both ends to this count; pkg/arch enforces it.
const VethQueues = 1

// NewVeth returns the netlink link that creates a veth pair named name and
// peer, both ends with VethQueues tx and rx queues. Pass it to LinkAdd.
func NewVeth(name, peer string) *netlink.Veth {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	attrs.NumTxQueues = VethQueues
	attrs.NumRxQueues = VethQueues
	return &netlink.Veth{
		LinkAttrs:       attrs,
		PeerName:        peer,
		PeerNumTxQueues: VethQueues,
		PeerNumRxQueues: VethQueues,
	}
}

// VethArgs returns the ip(8) arguments that create a veth pair named name and
// peer in the current network namespace, both ends with VethQueues tx and rx
// queues: exec "ip" with them.
func VethArgs(name, peer string) []string {
	return VethNetnsArgs(name, "", peer, "")
}

// VethNetnsArgs is VethArgs with each end created straight into a network
// namespace: name into netns and peer into peerNetns. An empty namespace
// leaves that end in the current one.
func VethNetnsArgs(name, netns, peer, peerNetns string) []string {
	args := append([]string{"link", "add"}, vethEndArgs(name, netns)...)
	args = append(args, "type", "veth", "peer")
	return append(args, vethEndArgs(peer, peerNetns)...)
}

// vethEndArgs returns the ip(8) arguments that name one veth end, place it in
// netns when one is given, and pin its queue counts.
func vethEndArgs(name, netns string) []string {
	queues := strconv.Itoa(VethQueues)
	args := []string{"name", name}
	if netns != "" {
		args = append(args, "netns", netns)
	}
	return append(args, "numtxqueues", queues, "numrxqueues", queues)
}
