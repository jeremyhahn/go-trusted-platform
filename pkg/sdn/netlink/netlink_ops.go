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

package netlink

import (
	vnl "github.com/vishvananda/netlink"
)

// NetlinkOps defines the interface for netlink operations
// This allows for mocking in unit tests
type NetlinkOps interface {
	// LinkByName returns a link by name
	LinkByName(name string) (vnl.Link, error)
	// LinkAdd creates a new link
	LinkAdd(link vnl.Link) error
	// LinkDel deletes a link
	LinkDel(link vnl.Link) error
	// LinkSetUp brings a link up
	LinkSetUp(link vnl.Link) error
	// LinkSetDown brings a link down
	LinkSetDown(link vnl.Link) error
	// LinkSetMTU sets the MTU for a link
	LinkSetMTU(link vnl.Link, mtu int) error
	// LinkList returns all links
	LinkList() ([]vnl.Link, error)
}

// realNetlinkOps implements NetlinkOps using the actual netlink library
type realNetlinkOps struct{}

// defaultOps is the default netlink operations using the real netlink library
var defaultOps NetlinkOps = &realNetlinkOps{}

func (r *realNetlinkOps) LinkByName(name string) (vnl.Link, error) {
	return vnl.LinkByName(name)
}

func (r *realNetlinkOps) LinkAdd(link vnl.Link) error {
	return vnl.LinkAdd(link)
}

func (r *realNetlinkOps) LinkDel(link vnl.Link) error {
	return vnl.LinkDel(link)
}

func (r *realNetlinkOps) LinkSetUp(link vnl.Link) error {
	return vnl.LinkSetUp(link)
}

func (r *realNetlinkOps) LinkSetDown(link vnl.Link) error {
	return vnl.LinkSetDown(link)
}

func (r *realNetlinkOps) LinkSetMTU(link vnl.Link, mtu int) error {
	return vnl.LinkSetMTU(link, mtu)
}

func (r *realNetlinkOps) LinkList() ([]vnl.Link, error) {
	return vnl.LinkList()
}

// SetNetlinkOps allows setting a custom NetlinkOps implementation (for testing)
func SetNetlinkOps(ops NetlinkOps) {
	defaultOps = ops
}

// ResetNetlinkOps resets to the default real netlink operations
func ResetNetlinkOps() {
	defaultOps = &realNetlinkOps{}
}

// getOps returns the current NetlinkOps implementation
func getOps() NetlinkOps {
	return defaultOps
}
