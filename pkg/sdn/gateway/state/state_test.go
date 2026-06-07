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

package state

import (
	"errors"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func TestFileStore_PutGet(t *testing.T) {
	s := newTestStore(t)
	snap := &Snapshot{
		GatewayID: "gw-1",
		Hostname:  "gw-1.example.com",
		Mode:      "edge",
		Health: HealthState{
			Status: "healthy",
			Components: map[string]string{
				"bgp": "up",
				"pxe": "up",
			},
		},
		BGP: BGPState{
			LocalASN:         65001,
			PeerCount:        2,
			EstablishedPeers: 2,
		},
	}
	if err := s.Put(snap); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if snap.ReceivedAt.IsZero() {
		t.Error("Put should stamp ReceivedAt")
	}
	got, err := s.Get("gw-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hostname != "gw-1.example.com" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
	if got.BGP.LocalASN != 65001 {
		t.Errorf("BGP.LocalASN = %d", got.BGP.LocalASN)
	}
}

func TestFileStore_GetMissing(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get("nope")
	if err == nil {
		t.Fatal("expected ErrSnapshotNotFound")
	}
	var nf ErrSnapshotNotFound
	if !errors.As(err, &nf) {
		t.Errorf("expected ErrSnapshotNotFound, got %T", err)
	}
}

func TestFileStore_ListAndDelete(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	older := &Snapshot{GatewayID: "old", ReportedAt: now.Add(-1 * time.Minute)}
	newer := &Snapshot{GatewayID: "new", ReportedAt: now}
	_ = s.Put(older)
	_ = s.Put(newer)
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 || all[0].GatewayID != "new" {
		t.Errorf("expected newest first, got %v", all)
	}
	if err := s.Delete("old"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("old"); err == nil {
		t.Error("expected error after Delete")
	}
}

func TestSanitizeID(t *testing.T) {
	cases := map[string]string{
		"normal":      "normal",
		"with/slash":  "with_slash",
		"with\\back":  "with_back",
		"../escape":   "__escape", // ".." → "_", then "/" → "_" — distinct chars survive as distinct underscores
		"":            "default",
	}
	for in, want := range cases {
		if got := sanitizeID(in); got != want {
			t.Errorf("sanitizeID(%q) = %q, want %q", in, got, want)
		}
	}
}
