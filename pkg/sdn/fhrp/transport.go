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

package fhrp

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Transport opens the multicast socket a group advertises and listens on.
// The real implementation is a raw IP socket (protocol 112) joined to the
// family's VRRP group on the interface; tests use an in-memory segment.
type Transport interface {
	Open(iface string, family Family, source netip.Addr) (Conn, error)
}

// Conn is one group's socket.
type Conn interface {
	// Send transmits a VRRP payload to dst with TTL / hop limit 255.
	Send(payload []byte, dst netip.Addr) error
	// Receive blocks for the next VRRP payload, returning its source
	// address and the IP TTL / hop limit it arrived with. It returns an
	// error once the connection is closed.
	Receive(ctx context.Context) (payload []byte, src netip.Addr, ttl int, err error)
	Close() error
}

// Programmer puts the virtual addresses on and off the interface and
// announces a takeover. The real implementation is netlink plus an
// AF_PACKET gratuitous ARP / ICMPv6 unsolicited neighbour advertisement.
type Programmer interface {
	// AddAddress programs prefix on iface, using hw as the address's MAC
	// when the programmer places virtual addresses on a virtual-MAC
	// device (§7.3); an implementation that uses the interface's own MAC
	// ignores hw.
	AddAddress(iface string, prefix netip.Prefix, hw net.HardwareAddr) error
	// DeleteAddress removes prefix from iface.
	DeleteAddress(iface string, prefix netip.Prefix, hw net.HardwareAddr) error
	// Announce sends the gratuitous announcement for addr from hw so the
	// segment's neighbour caches move to the new master.
	Announce(iface string, addr netip.Addr, hw net.HardwareAddr) error
}

// AddressReader is optional: a Programmer that implements it lets the
// speaker leave an address it found on the interface in place on release.
// Without it every claimed address counts as the speaker's own.
type AddressReader interface {
	// HasAddress reports whether iface already holds prefix (same address
	// and prefix length).
	HasAddress(iface string, prefix netip.Prefix) (bool, error)
}

// Clock is the time source the speaker's timers run on; tests inject one.
type Clock interface {
	Now() time.Time
	// NewTimer returns a timer that fires once after d.
	NewTimer(d time.Duration) Timer
}

// Timer is the subset of time.Timer the speaker uses.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// wallClock is the production Clock.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) NewTimer(d time.Duration) Timer { return &wallTimer{t: time.NewTimer(d)} }

type wallTimer struct{ t *time.Timer }

func (w *wallTimer) C() <-chan time.Time        { return w.t.C }
func (w *wallTimer) Stop() bool                 { return w.t.Stop() }
func (w *wallTimer) Reset(d time.Duration) bool { return w.t.Reset(d) }
