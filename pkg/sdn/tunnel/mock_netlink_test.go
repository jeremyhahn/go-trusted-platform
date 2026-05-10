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
