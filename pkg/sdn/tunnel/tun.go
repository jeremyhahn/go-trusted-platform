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
	"net"
	"net/netip"
	"os"
	"sync"

	vnl "github.com/vishvananda/netlink"
)

// defaultTUNMTU is the IPv6 minimum link MTU, which is also the smallest
// tunnel MTU RFC 9484 lets a CONNECT-IP endpoint assume.
const defaultTUNMTU = 1280

// maxInterfaceNameLen is IFNAMSIZ minus the terminating NUL.
const maxInterfaceNameLen = 15

// TUNConfig describes a layer-3 TUN interface whose packets a userspace
// process forwards: the MASQUE data plane's host-side end.
type TUNConfig struct {
	// Name is the interface name (at most 15 characters).
	Name string
	// Addresses are the prefixes configured on the interface; the kernel
	// routes the covered addresses into the device.
	Addresses []netip.Prefix
	// Routes are further prefixes routed into the device. The kernel drops
	// them with the device.
	Routes []netip.Prefix
	// MTU is the link MTU; zero selects defaultTUNMTU.
	MTU int
}

func (c TUNConfig) effectiveMTU() int {
	if c.MTU <= 0 {
		return defaultTUNMTU
	}
	return c.MTU
}

func (c TUNConfig) validate() error {
	if c.Name == "" || len(c.Name) > maxInterfaceNameLen {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "device name must be 1-15 characters"}
	}
	if len(c.Addresses) == 0 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "at least one address is required"}
	}
	for _, p := range c.Addresses {
		if !p.IsValid() {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "address prefix is not valid"}
		}
	}
	for _, p := range c.Routes {
		if !p.IsValid() {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "route prefix is not valid"}
		}
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "MTU out of range"}
	}
	return nil
}

// TUN is an open TUN interface. Packets the kernel routes to the interface
// arrive on Read; Write injects a packet toward the kernel. Close removes
// the interface. The file descriptor is non-blocking and pollable, so Close
// unblocks a pending Read.
type TUN struct {
	name string
	file *os.File
	link vnl.Link
	nl   netlinkOps

	closeOnce sync.Once
	closeErr  error
}

// OpenTUN creates, addresses and brings up a TUN interface. It needs
// CAP_NET_ADMIN.
func OpenTUN(cfg TUNConfig) (*TUN, error) {
	return openTUN(&realNetlinkOps{}, cfg)
}

func openTUN(nl netlinkOps, cfg TUNConfig) (*TUN, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	link := &vnl.Tuntap{
		LinkAttrs:  vnl.LinkAttrs{Name: cfg.Name, MTU: cfg.effectiveMTU()},
		Mode:       vnl.TUNTAP_MODE_TUN,
		Flags:      vnl.TUNTAP_NO_PI | vnl.TUNTAP_ONE_QUEUE,
		Queues:     1,
		NonPersist: true,
	}
	if err := nl.LinkAdd(link); err != nil {
		return nil, &ErrTunnelCreateFailed{Name: cfg.Name, Cause: err}
	}
	if len(link.Fds) == 0 {
		_ = nl.LinkDel(link)
		return nil, &ErrTunnelCreateFailed{Name: cfg.Name, Cause: &ErrDeviceNotUp{Name: cfg.Name}}
	}
	t := &TUN{name: link.Attrs().Name, file: link.Fds[0], link: link, nl: nl}
	if err := t.bringUp(cfg); err != nil {
		_ = t.Close()
		return nil, &ErrTunnelCreateFailed{Name: cfg.Name, Cause: err}
	}
	return t, nil
}

func (t *TUN) bringUp(cfg TUNConfig) error {
	created, err := t.nl.LinkByName(t.name)
	if err != nil {
		return err
	}
	t.link = created
	if err := t.nl.LinkSetMTU(created, cfg.effectiveMTU()); err != nil {
		return err
	}
	for _, p := range cfg.Addresses {
		if err := t.nl.AddrAdd(created, &vnl.Addr{IPNet: prefixToIPNet(p)}); err != nil {
			return err
		}
	}
	if err := t.nl.LinkSetUp(created); err != nil {
		return err
	}
	for _, p := range cfg.Routes {
		route := &vnl.Route{LinkIndex: created.Attrs().Index, Dst: prefixToIPNet(p.Masked()), Scope: vnl.SCOPE_LINK}
		if err := t.nl.RouteReplace(route); err != nil {
			return err
		}
	}
	return nil
}

// Name returns the interface name the kernel assigned.
func (t *TUN) Name() string { return t.name }

// Read reads one packet from the interface.
func (t *TUN) Read(p []byte) (int, error) { return t.file.Read(p) }

// Write injects one packet toward the kernel.
func (t *TUN) Write(p []byte) (int, error) { return t.file.Write(p) }

// Close closes the descriptor and removes the interface. It is idempotent.
func (t *TUN) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.file.Close()
		if err := t.nl.LinkDel(t.link); err != nil && t.closeErr == nil {
			t.closeErr = err
		}
	})
	return t.closeErr
}

// prefixToIPNet converts a netip.Prefix to the net.IPNet netlink expects,
// keeping the address (not the masked network) so an interface address
// such as 10.9.0.1/24 is programmed as given.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	if addr.Is4() {
		a := addr.As4()
		return &net.IPNet{IP: net.IP(a[:]), Mask: net.CIDRMask(p.Bits(), 32)}
	}
	a := addr.As16()
	return &net.IPNet{IP: net.IP(a[:]), Mask: net.CIDRMask(p.Bits(), 128)}
}
