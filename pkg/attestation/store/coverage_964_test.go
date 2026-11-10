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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tests in this file cover the persistence surface the
// AttestationService consumes (RFC 9334 §5.1): typed errors for invalid
// input, missing and corrupt records, newest-first ordering and the
// manifest and event filters.

func TestNewFileStore_Errors(t *testing.T) {
	t.Run("empty root", func(t *testing.T) {
		_, err := NewFileStore("")
		var cfgErr errInvalidStoreConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "root" {
			t.Fatalf("err = %v, want errInvalidStoreConfig{Field: root}", err)
		}
		if !strings.Contains(err.Error(), "invalid root") {
			t.Fatalf("Error() = %q, want it to name the field", err.Error())
		}
	})
	t.Run("root under a regular file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewFileStore(filepath.Join(file, "store"))
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) {
			t.Fatalf("err = %v, want *WrappedError", err)
		}
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("err = %v, want it to unwrap to ENOTDIR", err)
		}
		if !strings.Contains(wrapped.Error(), "mkdir") || !strings.Contains(wrapped.Error(), wrapped.Err.Error()) {
			t.Fatalf("Error() = %q, want the message and the cause", wrapped.Error())
		}
	})
}

func TestFileStore_PutManifest_InvalidInput(t *testing.T) {
	s := newTestStore(t)
	cases := []struct {
		name  string
		err   error
		field string
	}{
		{"nil manifest", s.PutManifest(nil), "manifest"},
		{"empty id", s.PutManifest(testManifest("", "host", time.Now())), "manifest.id"},
		{"nil event", s.PutEvent(nil), "event"},
		{"nil report", s.PutReport(nil), "report"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfgErr errInvalidStoreConfig
			if !errors.As(tc.err, &cfgErr) || cfgErr.Field != tc.field {
				t.Fatalf("err = %v, want errInvalidStoreConfig{Field: %s}", tc.err, tc.field)
			}
		})
	}
}

func TestFileStore_WriteFailsWhenDirectoryIsGone(t *testing.T) {
	s := newTestStore(t)
	if err := os.RemoveAll(s.manifests); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(s.events); err != nil {
		t.Fatal(err)
	}
	if err := s.PutManifest(testManifest("m1", "host", time.Now())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PutManifest err = %v, want ErrNotExist", err)
	}
	if err := s.PutEvent(&Event{Kind: EventKindEnrollSuccess}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PutEvent err = %v, want ErrNotExist", err)
	}

	// A store whose directories are gone lists nothing rather than failing.
	manifests, err := s.ListManifests(ListFilter{})
	if err != nil || manifests != nil {
		t.Fatalf("ListManifests = %v, %v; want nil, nil", manifests, err)
	}
	events, err := s.ListEvents(EventFilter{})
	if err != nil || events != nil {
		t.Fatalf("ListEvents = %v, %v; want nil, nil", events, err)
	}
}

func TestFileStore_GetManifest_CorruptRecord(t *testing.T) {
	s := newTestStore(t)
	if err := os.WriteFile(s.manifestPath("bad"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetManifest("bad")
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !strings.Contains(wrapped.Msg, "decode manifest bad") {
		t.Fatalf("err = %v, want *WrappedError naming the manifest", err)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatalf("err = %v, want it to unwrap to *json.SyntaxError", err)
	}
}

func TestFileStore_ReadErrorIsNotNotFound(t *testing.T) {
	s := newTestStore(t)
	// A directory at the manifest path makes the read and the remove fail
	// with an error other than not-found.
	if err := os.MkdirAll(filepath.Join(s.manifestPath("dir"), "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	var notFound ErrManifestNotFound
	if _, err := s.GetManifest("dir"); err == nil || errors.As(err, &notFound) {
		t.Fatalf("GetManifest err = %v, want a non-not-found error", err)
	}
	if err := s.DeleteManifest("dir"); err == nil || errors.As(err, &notFound) {
		t.Fatalf("DeleteManifest err = %v, want a non-not-found error", err)
	}
}

func TestFileStore_DeleteManifest_Missing(t *testing.T) {
	s := newTestStore(t)
	err := s.DeleteManifest("ghost")
	var notFound ErrManifestNotFound
	if !errors.As(err, &notFound) || notFound.ID != "ghost" {
		t.Fatalf("err = %v, want ErrManifestNotFound{ID: ghost}", err)
	}
	if err.Error() != "attestation/store: manifest not found: ghost" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

// writeNoise drops entries every List must skip: a sub-directory, a
// non-JSON file and a corrupt JSON record.
func writeNoise(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileStore_ListManifests_FiltersAndOrder(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, m := range []struct {
		id, host string
		offset   time.Duration
	}{
		{"a", "h1", 0},
		{"b", "h1", time.Hour},
		{"c", "h2", 2 * time.Hour},
		{"d", "h1", 3 * time.Hour},
	} {
		if err := s.PutManifest(testManifest(m.id, m.host, base.Add(m.offset))); err != nil {
			t.Fatal(err)
		}
	}
	writeNoise(t, s.manifests)

	cases := []struct {
		name   string
		filter ListFilter
		want   []string
	}{
		{"all newest first", ListFilter{}, []string{"d", "c", "b", "a"}},
		{"host", ListFilter{HostID: "h1"}, []string{"d", "b", "a"}},
		{"since", ListFilter{Since: base.Add(time.Hour)}, []string{"d", "c", "b"}},
		{"until", ListFilter{Until: base.Add(time.Hour)}, []string{"b", "a"}},
		{"window and host", ListFilter{HostID: "h1", Since: base.Add(30 * time.Minute), Until: base.Add(150 * time.Minute)}, []string{"b"}},
		{"limit", ListFilter{Limit: 2}, []string{"d", "c"}},
		{"limit above count", ListFilter{Limit: 10}, []string{"d", "c", "b", "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListManifests(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, len(got))
			for i, m := range got {
				ids[i] = m.ID
			}
			if strings.Join(ids, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("ids = %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestFileStore_ListEvents_FiltersAndOrder(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, e := range []*Event{
		{ID: "e1", Kind: EventKindManifestCaptured, HostID: "h1", ManifestID: "m1", Timestamp: base},
		{ID: "e2", Kind: EventKindManifestVerified, HostID: "h1", ManifestID: "m1", Timestamp: base.Add(time.Hour)},
		{ID: "e3", Kind: EventKindManifestCaptured, HostID: "h2", ManifestID: "m2", Timestamp: base.Add(2 * time.Hour)},
		{ID: "e4", Kind: EventKindManifestRejected, HostID: "h1", ManifestID: "m3", Timestamp: base.Add(3 * time.Hour)},
	} {
		if err := s.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	writeNoise(t, s.events)

	cases := []struct {
		name   string
		filter EventFilter
		want   []string
	}{
		{"all newest first", EventFilter{}, []string{"e4", "e3", "e2", "e1"}},
		{"kind", EventFilter{Kind: EventKindManifestCaptured}, []string{"e3", "e1"}},
		{"kind with no events", EventFilter{Kind: EventKindCallerRefused}, []string{}},
		{"host", EventFilter{HostID: "h1"}, []string{"e4", "e2", "e1"}},
		{"manifest", EventFilter{ManifestID: "m1"}, []string{"e2", "e1"}},
		{"since", EventFilter{Since: base.Add(2 * time.Hour)}, []string{"e4", "e3"}},
		{"until", EventFilter{Until: base.Add(time.Hour)}, []string{"e2", "e1"}},
		{"host and kind", EventFilter{HostID: "h1", Kind: EventKindManifestCaptured}, []string{"e1"}},
		{"limit", EventFilter{Limit: 1}, []string{"e4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListEvents(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, len(got))
			for i, e := range got {
				ids[i] = e.ID
			}
			if strings.Join(ids, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("ids = %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestFileStore_PutEvent_AssignsIDAndTimestamp(t *testing.T) {
	s := newTestStore(t)
	before := time.Now().UTC()
	e := &Event{Kind: EventKindEnrollFailure, HostID: "h1", Reason: "bad quote"}
	if err := s.PutEvent(e); err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || e.Timestamp.Before(before) {
		t.Fatalf("event = %+v, want a generated ID and a current timestamp", e)
	}
	got, err := s.ListEvents(EventFilter{Kind: EventKindEnrollFailure})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != e.ID || got[0].Reason != "bad quote" || !got[0].Timestamp.Equal(e.Timestamp) {
		t.Fatalf("round trip = %+v, want %+v", got, e)
	}
}
