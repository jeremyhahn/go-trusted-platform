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

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func newTestStore(t *testing.T) *FileSnapshotStore {
	t.Helper()
	store, err := NewFileSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	return store
}

func TestFileSnapshotStore_PutGet(t *testing.T) {
	store := newTestStore(t)
	snap := &Snapshot{
		ID:     "abc",
		Reason: "test",
		Tree:   map[string]interface{}{"a": 1, "b": "two"},
	}
	if err := store.Put(snap); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get("abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Reason != "test" {
		t.Errorf("Reason = %q", got.Reason)
	}
	if v, _ := got.Tree["a"].(float64); v != 1 {
		t.Errorf("Tree[a] = %v", got.Tree["a"])
	}
}

func TestFileSnapshotStore_GetMissing(t *testing.T) {
	store := newTestStore(t)
	_, err := store.Get("nope")
	if err == nil {
		t.Fatal("expected ErrSnapshotNotFound")
	}
	var notFound ErrSnapshotNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrSnapshotNotFound, got %T", err)
	}
}

func TestFileSnapshotStore_List(t *testing.T) {
	store := newTestStore(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := store.Put(&Snapshot{ID: id, Tree: map[string]interface{}{}}); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}
	got, err := store.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 summaries, got %d", len(got))
	}
}

func TestCaptureCurrent(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader([]byte("a: 1\nb: two\n"))); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	store := newTestStore(t)
	snap, err := CaptureCurrent(store, "manual", "tester")
	if err != nil {
		t.Fatalf("CaptureCurrent: %v", err)
	}
	if snap.Reason != "manual" || snap.Actor != "tester" {
		t.Errorf("metadata mismatch: %+v", snap)
	}
	if snap.Tree["a"] != 1 {
		t.Errorf("tree did not capture viper: %+v", snap.Tree)
	}
	got, _ := store.Get(snap.ID)
	if got == nil || got.ID != snap.ID {
		t.Errorf("snapshot did not persist")
	}
}

func TestRollbackTo(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	// Set up an active config file the rollback can rewrite.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	original := []byte("a: 1\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}

	store := newTestStore(t)
	snap, err := CaptureCurrent(store, "before-change", "")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	// Now mutate the live config file and reload.
	mutated := []byte("a: 2\n")
	if err := os.WriteFile(cfgPath, mutated, 0o600); err != nil {
		t.Fatalf("write mutated: %v", err)
	}
	if _, err := ReloadFromDisk(nil); err != nil {
		t.Fatalf("Reload mutated: %v", err)
	}
	if viper.GetInt("a") != 2 {
		t.Fatalf("post-mutation expected a=2, got %d", viper.GetInt("a"))
	}

	// Rollback should restore a=1.
	preID, err := RollbackTo(store, snap.ID, "tester", nil)
	if err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if preID == "" {
		t.Error("RollbackTo should return a pre-rollback snapshot ID")
	}
	if viper.GetInt("a") != 1 {
		t.Errorf("post-rollback expected a=1, got %d", viper.GetInt("a"))
	}
	// Backup file should exist.
	entries, _ := os.ReadDir(dir)
	hasBackup := false
	for _, e := range entries {
		if e.Name() != "config.yaml" {
			hasBackup = true
			break
		}
	}
	if !hasBackup {
		t.Error("expected a .rolled-back-<ts> backup of the mutated config")
	}
}

func TestReloadFromDiskWithSnapshot(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	store := newTestStore(t)
	sections, snapID, snapErr, reloadErr := ReloadFromDiskWithSnapshot(store, nil, "tester")
	if reloadErr != nil {
		t.Fatalf("reload: %v", reloadErr)
	}
	if snapErr != nil {
		t.Errorf("snap err: %v", snapErr)
	}
	if snapID == "" {
		t.Error("expected snapshot id")
	}
	if len(sections) != 1 || sections[0] != "a" {
		t.Errorf("sections = %v", sections)
	}
}
