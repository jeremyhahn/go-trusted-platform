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
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/vici"
)

func TestConnNameRoundTrip(t *testing.T) {
	for _, s := range []string{"10.20.0.1", "fd00:20::1"} {
		peer := netip.MustParseAddr(s)
		got, ok := connPeer(connName(peer))
		if !ok || got != peer {
			t.Fatalf("connPeer(connName(%v)) = %v, %v", peer, got, ok)
		}
	}
	for _, name := range []string{"operator-test", "vtep-", "vtep-not-an-address"} {
		if _, ok := connPeer(name); ok {
			t.Fatalf("connPeer(%q) claimed a connection the controller did not name", name)
		}
	}
}

func TestConnectionRendering(t *testing.T) {
	s := &settings{
		local:        netip.MustParseAddr("10.20.0.11"),
		reauthTime:   36 * time.Hour,
		replayWindow: 4096,
	}
	conn := s.connection(netip.MustParseAddr("10.20.0.30"))

	values := map[string]string{
		"version":     "2",
		"mobike":      "no",
		"unique":      "replace",
		"reauth_time": "129600s",
		"dpd_delay":   "30s",
	}
	for k, want := range values {
		if got, _ := conn.Value(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	lists := map[string][]string{
		"local_addrs":  {"10.20.0.11"},
		"remote_addrs": {"10.20.0.30"},
		"proposals":    {ikeProposal},
	}
	for k, want := range lists {
		if got, _ := conn.List(k); !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}

	local := section(t, conn, "local")
	expectValues(t, "local", local, map[string]string{"auth": "pubkey", "id": "10.20.0.11"})
	remote := section(t, conn, "remote")
	expectValues(t, "remote", remote, map[string]string{"auth": "pubkey", "id": "10.20.0.30", "revocation": "strict"})

	child := section(t, section(t, conn, "children"), childName)
	expectValues(t, "child", child, map[string]string{
		"mode":          "transport",
		"start_action":  "trap",
		"dpd_action":    "trap",
		"close_action":  "trap",
		"replay_window": "4096",
	})
	for k, want := range map[string][]string{
		"esp_proposals": {espProposal},
		"local_ts":      {"dynamic"},
		"remote_ts":     {"dynamic"},
	} {
		if got, _ := child.List(k); !slices.Equal(got, want) {
			t.Errorf("child %s = %v, want %v", k, got, want)
		}
	}

	if _, err := conn.MarshalBinary(); err != nil {
		t.Fatalf("the rendered connection does not encode: %v", err)
	}
}

func section(t *testing.T, m *vici.Message, name string) *vici.Message {
	t.Helper()
	s, ok := m.Section(name)
	if !ok {
		t.Fatalf("section %q missing", name)
	}
	return s
}

func expectValues(t *testing.T, where string, m *vici.Message, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got, _ := m.Value(k); got != v {
			t.Errorf("%s %s = %q, want %q", where, k, got, v)
		}
	}
}
