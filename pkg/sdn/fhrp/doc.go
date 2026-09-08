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

// Package fhrp is the platform's first-hop redundancy speaker: VRRPv3
// (RFC 5798) for IPv4 and IPv6 in one protocol, so a gateway pair can hold
// the shared first-hop addresses a site's hosts point at — the addresses
// the Cisco ASR routers hold with HSRP today (epic #553, ruling R7).
//
// The package is split along the same seam as the rest of pkg/sdn: the
// protocol (packet format, checksum, state machine, timers) is pure Go with
// no privileges and an injected clock, and everything that touches the
// kernel — multicast raw sockets and address programming — sits behind
// two small interfaces (Transport, Programmer) with real implementations
// on Linux and fakes in the tests.
//
// A speaker runs one Group per virtual router ID on an interface. A group
// starts in Initialize, becomes Master immediately when it owns the
// addresses (priority 255) and Backup otherwise, and thereafter follows
// RFC 5798 §6.4: a Backup whose Master_Down_Timer expires claims the
// addresses and advertises; a Master that hears a better advertisement
// releases them. Preemption and accept mode are per group. On the overlay
// segments the EVPN distributed anycast gateway (RFC 9135) is the
// mechanism instead — see docs/gateway/architecture.md.
package fhrp
