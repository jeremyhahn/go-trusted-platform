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
	"encoding/pem"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	govici "github.com/strongswan/govici/vici"
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
	root := newTestPKI(t).ca
	conn := s.connection(netip.MustParseAddr("10.20.0.30"), root)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))

	want := &Connection{
		Version:     "2",
		LocalAddrs:  []string{"10.20.0.11"},
		RemoteAddrs: []string{"10.20.0.30"},
		Proposals:   []string{ikeProposal},
		Unique:      "replace",
		ReauthTime:  "129600s",
		DPDDelay:    "30s",
		Local:       ConnAuth{Auth: "pubkey", ID: "10.20.0.11"},
		Remote:      ConnAuth{Auth: "pubkey", ID: "10.20.0.30", Revocation: "strict", CACerts: []string{rootPEM}},
		Children: map[string]ChildSA{childName: {
			Mode:         "transport",
			StartAction:  "trap",
			DPDAction:    "trap",
			CloseAction:  "trap",
			ESPProposals: []string{espProposal},
			ReplayWindow: 4096,
			LocalTS:      []string{"dynamic"},
			RemoteTS:     []string{"dynamic"},
		}},
	}
	if !reflect.DeepEqual(conn, want) {
		t.Fatalf("connection = %+v\nwant %+v", conn, want)
	}
}

// TestConnectionMessage checks the load-conn body charon receives: the
// option names, the yes/no and integer encodings, and that an unset
// option is left out rather than sent empty.
func TestConnectionMessage(t *testing.T) {
	s := &settings{local: netip.MustParseAddr("10.20.0.11"), reauthTime: time.Hour, replayWindow: 1024}
	root := newTestPKI(t).ca
	m, err := govici.MarshalMessage(s.connection(netip.MustParseAddr("10.20.0.30"), root))
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	for k, want := range map[string]string{"version": "2", "mobike": "no", "unique": "replace", "reauth_time": "3600s"} {
		if got := m.Get(k); got != want {
			t.Errorf("%s = %v, want %q", k, got, want)
		}
	}
	if got, _ := m.Get("remote_addrs").([]string); !slices.Equal(got, []string{"10.20.0.30"}) {
		t.Errorf("remote_addrs = %v", got)
	}
	local := section(t, m, "local")
	if local.Get("revocation") != nil {
		t.Error("the unset local revocation option was sent")
	}
	if got := section(t, m, "remote").Get("revocation"); got != "strict" {
		t.Errorf("remote revocation = %v, want strict", got)
	}
	// Only the peer's chain is constrained to the root: the local side
	// names no CA, so charon does not narrow its own certificate choice.
	if local.Get("cacerts") != nil {
		t.Error("a local cacerts constraint was sent")
	}
	wantCA := []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))}
	if got, _ := section(t, m, "remote").Get("cacerts").([]string); !slices.Equal(got, wantCA) {
		t.Errorf("remote cacerts = %v, want the root's PEM", got)
	}
	child := section(t, section(t, m, "children"), childName)
	if got := child.Get("replay_window"); got != "1024" {
		t.Errorf("replay_window = %v", got)
	}
}

func section(t *testing.T, m *govici.Message, name string) *govici.Message {
	t.Helper()
	s, ok := m.Get(name).(*govici.Message)
	if !ok {
		t.Fatalf("section %q missing", name)
	}
	return s
}
