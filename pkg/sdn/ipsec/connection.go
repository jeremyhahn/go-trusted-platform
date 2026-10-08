// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/vici"
)

const (
	// connPrefix starts the name of every connection the controller loads.
	// A connection without it belongs to someone else and is left alone.
	connPrefix = "vtep-"

	// childName names the one CHILD_SA of a peer connection.
	childName = "overlay"

	// dpdDelay is how long an idle IKE_SA waits before probing its peer.
	dpdDelay = 30 * time.Second
)

// connName names the connection to peer.
func connName(peer netip.Addr) string {
	return connPrefix + peer.String()
}

// connPeer recovers the peer from a connection name, or reports false for
// a name the controller did not give.
func connPeer(name string) (netip.Addr, bool) {
	rest, ok := strings.CutPrefix(name, connPrefix)
	if !ok {
		return netip.Addr{}, false
	}
	peer, err := netip.ParseAddr(rest)
	if err != nil {
		return netip.Addr{}, false
	}
	return peer, true
}

// connection renders the load-conn section for peer: one IKEv2 connection
// between the two VTEP addresses, both sides authenticated by certificate
// with the identity pinned to the address, and one transport-mode
// CHILD_SA covering every packet between them — VXLAN and the BGP session
// alike. The CHILD_SA is trapped, so it is negotiated by the first packet
// and falls back to the trap, never to cleartext, when it closes or its
// peer goes quiet.
//
// The local certificate and key are not named here: charon picks the
// certificate loaded with load-cert whose subject alternative name is the
// local address, and the key in the loaded token that matches it.
func (s *settings) connection(peer netip.Addr) *vici.Message {
	local := vici.NewMessage()
	local.SetValue("auth", "pubkey")
	local.SetValue("id", s.local.String())

	remote := vici.NewMessage()
	remote.SetValue("auth", "pubkey")
	remote.SetValue("id", peer.String())
	remote.SetValue("revocation", "strict")

	child := vici.NewMessage()
	child.SetValue("mode", "transport")
	child.SetValue("start_action", "trap")
	child.SetValue("dpd_action", "trap")
	child.SetValue("close_action", "trap")
	child.SetList("esp_proposals", espProposal)
	child.SetValue("replay_window", strconv.FormatUint(uint64(s.replayWindow), 10))
	child.SetList("local_ts", "dynamic")
	child.SetList("remote_ts", "dynamic")

	children := vici.NewMessage()
	children.SetSection(childName, child)

	conn := vici.NewMessage()
	conn.SetValue("version", "2")
	conn.SetList("local_addrs", s.local.String())
	conn.SetList("remote_addrs", peer.String())
	conn.SetList("proposals", ikeProposal)
	conn.SetValue("mobike", "no")
	conn.SetValue("unique", "replace")
	conn.SetValue("reauth_time", seconds(s.reauthTime))
	conn.SetValue("dpd_delay", seconds(dpdDelay))
	conn.SetSection("local", local)
	conn.SetSection("remote", remote)
	conn.SetSection("children", children)
	return conn
}

// seconds formats d in whole seconds, the unit strongSwan reads.
func seconds(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + "s"
}
