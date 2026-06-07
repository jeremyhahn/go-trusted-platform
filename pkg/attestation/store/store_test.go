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

package store

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func testManifest(id, hostID string, ts time.Time) *manifest.HostManifest {
	return &manifest.HostManifest{
		ID:         id,
		HostID:     hostID,
		Timestamp:  ts,
		Nonce:      []byte("nonce"),
		MerkleRoot: []byte("root"),
		Host: &manifest.HostAttestation{
			QuoteData: []byte("quote"),
			Signature: []byte("sig"),
			Nonce:     []byte("nonce"),
			Timestamp: ts,
		},
	}
}

func TestFileStore_ManifestPutGet(t *testing.T) {
	s := newTestStore(t)
	m := testManifest("m1", "host-a", time.Now().UTC())
	if err := s.PutManifest(m); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetManifest("m1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HostID != "host-a" {
		t.Errorf("HostID = %q", got.HostID)
	}
}

func TestFileStore_GetMissing(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetManifest("none")
	if err == nil {
		t.Fatal("expected ErrManifestNotFound")
	}
	var nf ErrManifestNotFound
	if !errors.As(err, &nf) {
		t.Errorf("expected ErrManifestNotFound, got %T", err)
	}
}

func TestFileStore_ListAndFilter(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	_ = s.PutManifest(testManifest("a", "host-1", now.Add(-2*time.Minute)))
	_ = s.PutManifest(testManifest("b", "host-2", now.Add(-1*time.Minute)))
	_ = s.PutManifest(testManifest("c", "host-1", now))

	all, err := s.ListManifests(ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}
	// Newest first.
	if all[0].ID != "c" {
		t.Errorf("expected newest first, got %s", all[0].ID)
	}

	byHost, _ := s.ListManifests(ListFilter{HostID: "host-1"})
	if len(byHost) != 2 {
		t.Errorf("expected 2 host-1 manifests, got %d", len(byHost))
	}
}

func TestFileStore_EventPutList(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutEvent(&Event{Kind: EventKindEnrollSuccess, HostID: "h", CN: "cn-1"}); err != nil {
		t.Fatalf("PutEvent: %v", err)
	}
	if err := s.PutEvent(&Event{Kind: EventKindEnrollFailure, HostID: "h", CN: "cn-2", Reason: "boom"}); err != nil {
		t.Fatalf("PutEvent: %v", err)
	}
	all, err := s.ListEvents(EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 events, got %d", len(all))
	}
	failures, _ := s.ListEvents(EventFilter{Kind: EventKindEnrollFailure})
	if len(failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(failures))
	}
}

func TestFileStore_Delete(t *testing.T) {
	s := newTestStore(t)
	_ = s.PutManifest(testManifest("d", "h", time.Now()))
	if err := s.DeleteManifest("d"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetManifest("d"); err == nil {
		t.Error("expected ErrManifestNotFound after Delete")
	}
}
