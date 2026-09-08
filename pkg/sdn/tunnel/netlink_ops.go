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
	vnl "github.com/vishvananda/netlink"
)

// netlinkOps abstracts netlink operations for testability.
// Unit tests provide a mock implementation to avoid requiring root/CAP_NET_ADMIN.
type netlinkOps interface {
	LinkAdd(link vnl.Link) error
	LinkDel(link vnl.Link) error
	LinkSetUp(link vnl.Link) error
	LinkSetMTU(link vnl.Link, mtu int) error
	LinkByName(name string) (vnl.Link, error)
	AddrAdd(link vnl.Link, addr *vnl.Addr) error
	AddrList(link vnl.Link, family int) ([]vnl.Addr, error)
	LinkList() ([]vnl.Link, error)

	// IPsec (XFRM) state and policy.
	XfrmStateAdd(state *vnl.XfrmState) error
	XfrmStateUpdate(state *vnl.XfrmState) error
	XfrmStateDel(state *vnl.XfrmState) error
	XfrmPolicyAdd(policy *vnl.XfrmPolicy) error
	XfrmPolicyDel(policy *vnl.XfrmPolicy) error

	// Policy routing: rules and per-table routes.
	RuleAdd(rule *vnl.Rule) error
	RuleDel(rule *vnl.Rule) error
	RuleList(family int) ([]vnl.Rule, error)
	RouteReplace(route *vnl.Route) error
	RouteDel(route *vnl.Route) error
	RouteListFiltered(family int, filter *vnl.Route, mask uint64) ([]vnl.Route, error)
}

// realNetlinkOps calls the real vishvananda/netlink functions.
type realNetlinkOps struct{}

func (r *realNetlinkOps) LinkAdd(link vnl.Link) error {
	return vnl.LinkAdd(link)
}

func (r *realNetlinkOps) LinkDel(link vnl.Link) error {
	return vnl.LinkDel(link)
}

func (r *realNetlinkOps) LinkSetUp(link vnl.Link) error {
	return vnl.LinkSetUp(link)
}

func (r *realNetlinkOps) LinkSetMTU(link vnl.Link, mtu int) error {
	return vnl.LinkSetMTU(link, mtu)
}

func (r *realNetlinkOps) LinkByName(name string) (vnl.Link, error) {
	return vnl.LinkByName(name)
}

func (r *realNetlinkOps) AddrAdd(link vnl.Link, addr *vnl.Addr) error {
	return vnl.AddrAdd(link, addr)
}

func (r *realNetlinkOps) AddrList(link vnl.Link, family int) ([]vnl.Addr, error) {
	return vnl.AddrList(link, family)
}

func (r *realNetlinkOps) LinkList() ([]vnl.Link, error) {
	return vnl.LinkList()
}

func (r *realNetlinkOps) XfrmStateAdd(state *vnl.XfrmState) error {
	return vnl.XfrmStateAdd(state)
}

func (r *realNetlinkOps) XfrmStateUpdate(state *vnl.XfrmState) error {
	return vnl.XfrmStateUpdate(state)
}

func (r *realNetlinkOps) XfrmStateDel(state *vnl.XfrmState) error {
	return vnl.XfrmStateDel(state)
}

func (r *realNetlinkOps) XfrmPolicyAdd(policy *vnl.XfrmPolicy) error {
	return vnl.XfrmPolicyAdd(policy)
}

func (r *realNetlinkOps) XfrmPolicyDel(policy *vnl.XfrmPolicy) error {
	return vnl.XfrmPolicyDel(policy)
}

func (r *realNetlinkOps) RuleAdd(rule *vnl.Rule) error {
	return vnl.RuleAdd(rule)
}

func (r *realNetlinkOps) RuleDel(rule *vnl.Rule) error {
	return vnl.RuleDel(rule)
}

func (r *realNetlinkOps) RuleList(family int) ([]vnl.Rule, error) {
	return vnl.RuleList(family)
}

func (r *realNetlinkOps) RouteReplace(route *vnl.Route) error {
	return vnl.RouteReplace(route)
}

func (r *realNetlinkOps) RouteDel(route *vnl.Route) error {
	return vnl.RouteDel(route)
}

func (r *realNetlinkOps) RouteListFiltered(family int, filter *vnl.Route, mask uint64) ([]vnl.Route, error) {
	return vnl.RouteListFiltered(family, filter, mask)
}
