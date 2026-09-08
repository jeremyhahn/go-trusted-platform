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
	"bytes"
	"context"
	"errors"
	"net"
	"sync"

	vnl "github.com/vishvananda/netlink"
)

// mockNetlinkOps provides a test double for netlink operations.
type mockNetlinkOps struct {
	mu    sync.Mutex
	links map[string]vnl.Link
	addrs map[string][]vnl.Addr

	// Per-method overrides for error injection
	linkAddFn    func(link vnl.Link) error
	linkDelFn    func(link vnl.Link) error
	linkSetUpFn  func(link vnl.Link) error
	linkSetMTUFn func(link vnl.Link, mtu int) error
	linkByNameFn func(name string) (vnl.Link, error)
	addrAddFn    func(link vnl.Link, addr *vnl.Addr) error
	addrListFn   func(link vnl.Link, family int) ([]vnl.Addr, error)
	linkListFn   func() ([]vnl.Link, error)

	// XFRM and policy-routing state (#582)
	xfrmStates   []*vnl.XfrmState
	xfrmPolicies []*vnl.XfrmPolicy
	rules        []vnl.Rule
	routes       []vnl.Route
	xfrmUpdates  int

	xfrmStateAddFn    func(*vnl.XfrmState) error
	xfrmStateUpdateFn func(*vnl.XfrmState) error
	xfrmStateDelFn    func(*vnl.XfrmState) error
	xfrmPolicyAddFn   func(*vnl.XfrmPolicy) error
	xfrmPolicyDelFn   func(*vnl.XfrmPolicy) error
	ruleAddFn         func(*vnl.Rule) error
	ruleDelFn         func(*vnl.Rule) error
	ruleListFn        func(int) ([]vnl.Rule, error)
	routeReplaceFn    func(*vnl.Route) error
	routeDelFn        func(*vnl.Route) error
}

func newMockNetlinkOps() *mockNetlinkOps {
	return &mockNetlinkOps{
		links: make(map[string]vnl.Link),
		addrs: make(map[string][]vnl.Addr),
	}
}

func (m *mockNetlinkOps) LinkAdd(link vnl.Link) error {
	if m.linkAddFn != nil {
		return m.linkAddFn(link)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	if _, ok := m.links[name]; ok {
		return errors.New("file exists")
	}
	m.links[name] = link
	return nil
}

func (m *mockNetlinkOps) LinkDel(link vnl.Link) error {
	if m.linkDelFn != nil {
		return m.linkDelFn(link)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	if _, ok := m.links[name]; !ok {
		return errors.New("Link not found")
	}
	delete(m.links, name)
	delete(m.addrs, name)
	return nil
}

func (m *mockNetlinkOps) LinkSetUp(link vnl.Link) error {
	if m.linkSetUpFn != nil {
		return m.linkSetUpFn(link)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	if existing, ok := m.links[name]; ok {
		attrs := existing.Attrs()
		attrs.Flags |= net.FlagUp
		attrs.OperState = vnl.OperUp
	}
	return nil
}

func (m *mockNetlinkOps) LinkSetMTU(link vnl.Link, mtu int) error {
	if m.linkSetMTUFn != nil {
		return m.linkSetMTUFn(link, mtu)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	if existing, ok := m.links[name]; ok {
		existing.Attrs().MTU = mtu
	}
	return nil
}

func (m *mockNetlinkOps) LinkByName(name string) (vnl.Link, error) {
	if m.linkByNameFn != nil {
		return m.linkByNameFn(name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	link, ok := m.links[name]
	if !ok {
		return nil, errors.New("Link not found")
	}
	return link, nil
}

func (m *mockNetlinkOps) AddrAdd(link vnl.Link, addr *vnl.Addr) error {
	if m.addrAddFn != nil {
		return m.addrAddFn(link, addr)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	m.addrs[name] = append(m.addrs[name], *addr)
	return nil
}

func (m *mockNetlinkOps) AddrList(link vnl.Link, family int) ([]vnl.Addr, error) {
	if m.addrListFn != nil {
		return m.addrListFn(link, family)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	return m.addrs[name], nil
}

func (m *mockNetlinkOps) LinkList() ([]vnl.Link, error) {
	if m.linkListFn != nil {
		return m.linkListFn()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]vnl.Link, 0, len(m.links))
	for _, link := range m.links {
		result = append(result, link)
	}
	return result, nil
}

func (m *mockNetlinkOps) XfrmStateAdd(state *vnl.XfrmState) error {
	if m.xfrmStateAddFn != nil {
		return m.xfrmStateAddFn(state)
	}
	return m.recordState(state)
}

// recordState is the default XfrmStateAdd behaviour, callable from an
// override that wants to succeed for some calls and fail for others.
func (m *mockNetlinkOps) recordState(state *vnl.XfrmState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.xfrmStates {
		if existing.Spi == state.Spi && existing.Dst.Equal(state.Dst) {
			return errors.New("file exists")
		}
	}
	// Copy the key so the test can prove the caller's copy was zeroized
	// without the mock's record going blank too.
	cp := *state
	if state.Aead != nil {
		aead := *state.Aead
		aead.Key = append([]byte(nil), state.Aead.Key...)
		cp.Aead = &aead
	}
	m.xfrmStates = append(m.xfrmStates, &cp)
	return nil
}

func (m *mockNetlinkOps) XfrmStateUpdate(state *vnl.XfrmState) error {
	if m.xfrmStateUpdateFn != nil {
		return m.xfrmStateUpdateFn(state)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.xfrmStates {
		if existing.Spi == state.Spi && existing.Dst.Equal(state.Dst) {
			cp := *state
			if state.Aead != nil {
				aead := *state.Aead
				aead.Key = append([]byte(nil), state.Aead.Key...)
				cp.Aead = &aead
			}
			m.xfrmStates[i] = &cp
			m.xfrmUpdates++
			return nil
		}
	}
	return errors.New("no such state")
}

func (m *mockNetlinkOps) XfrmStateDel(state *vnl.XfrmState) error {
	if m.xfrmStateDelFn != nil {
		return m.xfrmStateDelFn(state)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.xfrmStates {
		if existing.Spi == state.Spi && existing.Dst.Equal(state.Dst) {
			m.xfrmStates = append(m.xfrmStates[:i], m.xfrmStates[i+1:]...)
			return nil
		}
	}
	return errors.New("no such state")
}

func (m *mockNetlinkOps) XfrmPolicyAdd(policy *vnl.XfrmPolicy) error {
	if m.xfrmPolicyAddFn != nil {
		return m.xfrmPolicyAddFn(policy)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.xfrmPolicies = append(m.xfrmPolicies, policy)
	return nil
}

func (m *mockNetlinkOps) XfrmPolicyDel(policy *vnl.XfrmPolicy) error {
	if m.xfrmPolicyDelFn != nil {
		return m.xfrmPolicyDelFn(policy)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.xfrmPolicies {
		if existing.Dir == policy.Dir && existing.Src.String() == policy.Src.String() && existing.Dst.String() == policy.Dst.String() {
			m.xfrmPolicies = append(m.xfrmPolicies[:i], m.xfrmPolicies[i+1:]...)
			return nil
		}
	}
	return errors.New("no such policy")
}

func (m *mockNetlinkOps) RuleAdd(rule *vnl.Rule) error {
	if m.ruleAddFn != nil {
		return m.ruleAddFn(rule)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, *rule)
	return nil
}

func (m *mockNetlinkOps) RuleDel(rule *vnl.Rule) error {
	if m.ruleDelFn != nil {
		return m.ruleDelFn(rule)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rules {
		if rulesEqual(&m.rules[i], rule) {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return errors.New("no such rule")
}

func (m *mockNetlinkOps) RuleList(family int) ([]vnl.Rule, error) {
	if m.ruleListFn != nil {
		return m.ruleListFn(family)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []vnl.Rule
	for _, r := range m.rules {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockNetlinkOps) RouteReplace(route *vnl.Route) error {
	if m.routeReplaceFn != nil {
		return m.routeReplaceFn(route)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.routes {
		if m.routes[i].Table == route.Table && m.routes[i].Dst.String() == route.Dst.String() {
			m.routes[i] = *route
			return nil
		}
	}
	m.routes = append(m.routes, *route)
	return nil
}

func (m *mockNetlinkOps) RouteDel(route *vnl.Route) error {
	if m.routeDelFn != nil {
		return m.routeDelFn(route)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.routes {
		if m.routes[i].Table == route.Table && m.routes[i].Dst.String() == route.Dst.String() {
			m.routes = append(m.routes[:i], m.routes[i+1:]...)
			return nil
		}
	}
	return errors.New("no such route")
}

func (m *mockNetlinkOps) RouteListFiltered(family int, filter *vnl.Route, mask uint64) ([]vnl.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []vnl.Route
	for _, r := range m.routes {
		if filter == nil || mask&vnl.RT_FILTER_TABLE == 0 || r.Table == filter.Table {
			out = append(out, r)
		}
	}
	return out, nil
}

// mockKeys is a KeyProvider test double.
type mockKeys struct {
	keys  map[string][]byte
	err   error
	calls int
}

func (k *mockKeys) Key(_ context.Context, ref string) ([]byte, error) {
	k.calls++
	if k.err != nil {
		return nil, k.err
	}
	v, ok := k.keys[ref]
	if !ok {
		return nil, errors.New("no such key")
	}
	return append([]byte(nil), v...), nil
}

func espKey(b byte) []byte { return bytes.Repeat([]byte{b}, espGCMKeyLen) }
