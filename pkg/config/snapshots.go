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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Snapshot captures the full merged Viper configuration at a point in
// time so an operator can roll back a reload that misbehaved.
//
// The Tree is the raw (non-redacted) Viper.AllSettings. Snapshots are
// stored on the LUKS-encrypted data volume alongside the rest of
// platform state; the on-disk file is mode 0600. Operators that need
// to share a snapshot off-host should use the redacted GetConfig REST
// surface, not the raw snapshot file.
//
// Reason records why the snapshot was taken: "pre-reload" for the
// automatic snapshot the daemon writes before applying a reload, or
// a free-form string supplied by an explicit /snapshots POST.
type Snapshot struct {
	ID         string                 `json:"id"`
	CreatedAt  time.Time              `json:"created_at"`
	Reason     string                 `json:"reason,omitempty"`
	Actor      string                 `json:"actor,omitempty"`
	SourcePath string                 `json:"source_path,omitempty"`
	Tree       map[string]interface{} `json:"tree"`
}

// SnapshotSummary is the listing shape (no Tree). Returned by
// ListSnapshots so callers can show a history without paying the
// cost of streaming every snapshot's full body.
type SnapshotSummary struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Reason     string    `json:"reason,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	SourcePath string    `json:"source_path,omitempty"`
	SizeBytes  int64     `json:"size_bytes"`
}

// SnapshotStore persists Snapshot records. The default implementation
// is file-backed (one JSON file per snapshot under <root>/); a
// cluster-replicated implementation can land later by satisfying this
// interface against pkg/storage/quicbaas.
type SnapshotStore interface {
	Put(s *Snapshot) error
	Get(id string) (*Snapshot, error)
	List(limit int) ([]SnapshotSummary, error)
	Delete(id string) error
}

// FileSnapshotStore is the default SnapshotStore implementation.
// Snapshots live as JSON files under root; the basename is the
// snapshot ID with a .json suffix.
type FileSnapshotStore struct {
	root string
	mu   sync.Mutex
}

// NewFileSnapshotStore prepares the snapshot directory and returns a
// ready store.
func NewFileSnapshotStore(root string) (*FileSnapshotStore, error) {
	if root == "" {
		return nil, ErrInvalidSnapshotConfig{Field: "root", Reason: "cannot be empty"}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("config: mkdir snapshots %s: %w", root, err)
	}
	return &FileSnapshotStore{root: root}, nil
}

func (s *FileSnapshotStore) pathFor(id string) string {
	return filepath.Join(s.root, id+".json")
}

// Put writes a snapshot to disk atomically (temp-file + rename).
func (s *FileSnapshotStore) Put(snap *Snapshot) error {
	if snap == nil || snap.ID == "" {
		return ErrInvalidSnapshotConfig{Field: "snapshot.id", Reason: "cannot be empty"}
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	path := s.pathFor(snap.ID)
	tmp := path + ".tmp"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Get loads a snapshot by ID. Missing returns ErrSnapshotNotFound.
func (s *FileSnapshotStore) Get(id string) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.pathFor(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSnapshotNotFound{ID: id}
		}
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("config: decode snapshot %s: %w", id, err)
	}
	return &snap, nil
}

// List enumerates snapshots newest-first. limit<=0 returns all.
func (s *FileSnapshotStore) List(limit int) ([]SnapshotSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]SnapshotSummary, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.root, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		// Read just the header fields to keep List cheap even when
		// individual snapshots are large.
		summary, err := readSummary(path, info.Size())
		if err != nil {
			continue
		}
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// readSummary parses the JSON envelope header without touching the
// full Tree payload. We rely on the field order produced by
// json.MarshalIndent (id first, then created_at, reason, actor,
// source_path, then tree) — a real schema would use a header file,
// but for the volumes Phase 4.1 ships at, a small decode is fine.
func readSummary(path string, size int64) (SnapshotSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return SnapshotSummary{}, err
	}
	defer f.Close()
	// Read the file but stop early at the "tree" key — we only need
	// the header. For simplicity we decode the whole document; the
	// snapshot files we generate are bounded by the live config size
	// which is well under 1 MiB on real deployments.
	data, err := io.ReadAll(f)
	if err != nil {
		return SnapshotSummary{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return SnapshotSummary{}, err
	}
	return SnapshotSummary{
		ID:         snap.ID,
		CreatedAt:  snap.CreatedAt,
		Reason:     snap.Reason,
		Actor:      snap.Actor,
		SourcePath: snap.SourcePath,
		SizeBytes:  size,
	}, nil
}

// Delete removes a snapshot.
func (s *FileSnapshotStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.pathFor(id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrSnapshotNotFound{ID: id}
		}
		return err
	}
	return nil
}

// CaptureCurrent snaps Viper's current AllSettings into a new
// Snapshot and persists it via the supplied store.
func CaptureCurrent(store SnapshotStore, reason, actor string) (*Snapshot, error) {
	if store == nil {
		return nil, ErrInvalidSnapshotConfig{Field: "store", Reason: "cannot be nil"}
	}
	id, err := newSnapshotID()
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{
		ID:         id,
		CreatedAt:  time.Now().UTC(),
		Reason:     reason,
		Actor:      actor,
		SourcePath: viper.ConfigFileUsed(),
		Tree:       viper.AllSettings(),
	}
	if err := store.Put(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// RollbackTo loads snapshot by ID, writes its Tree as YAML to the
// active Viper config file (saving the current file aside as
// <path>.rolled-back-<ts>), and triggers Viper to re-read it. The
// pre-rollback state is itself captured as a Snapshot so the
// operator can undo a rollback. Returns the new snapshot ID
// representing the pre-rollback state.
//
// target is forwarded to viper.Unmarshal so the running daemon's
// *app.App picks up the rolled-back values.
func RollbackTo(store SnapshotStore, id string, actor string, target interface{}) (string, error) {
	if store == nil {
		return "", ErrInvalidSnapshotConfig{Field: "store", Reason: "cannot be nil"}
	}
	snap, err := store.Get(id)
	if err != nil {
		return "", err
	}
	if snap.SourcePath == "" {
		return "", ErrInvalidSnapshotConfig{Field: "snapshot.source_path", Reason: "snapshot does not record a source path; cannot rollback safely"}
	}
	// Capture the current state first so the rollback is undoable.
	preRollback, err := CaptureCurrent(store, "pre-rollback to "+id, actor)
	if err != nil {
		return "", err
	}
	// Marshal the snapshot Tree to YAML at the source path.
	body, err := yaml.Marshal(snap.Tree)
	if err != nil {
		return preRollback.ID, fmt.Errorf("config: marshal rollback yaml: %w", err)
	}
	backupPath := snap.SourcePath + ".rolled-back-" + time.Now().UTC().Format("20060102T150405Z")
	if data, rerr := os.ReadFile(snap.SourcePath); rerr == nil {
		_ = os.WriteFile(backupPath, data, 0o600)
	}
	if err := os.WriteFile(snap.SourcePath, body, 0o600); err != nil {
		return preRollback.ID, fmt.Errorf("config: write rollback yaml: %w", err)
	}
	// Re-read into Viper + the app struct.
	if _, err := ReloadFromDisk(target); err != nil {
		return preRollback.ID, err
	}
	return preRollback.ID, nil
}

// newSnapshotID returns a short, time-ordered identifier. We use a
// monotonic prefix (RFC3339Nano timestamp) plus 32 bits of randomness
// so concurrent captures don't collide.
func newSnapshotID() (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("20060102T150405.000000000Z")
	return strings.ReplaceAll(ts, ".", "") + "-" + hex.EncodeToString(suffix), nil
}

// ErrSnapshotNotFound is returned when a snapshot ID has no
// corresponding row.
type ErrSnapshotNotFound struct {
	ID string
}

func (e ErrSnapshotNotFound) Error() string {
	return "config: snapshot not found: " + e.ID
}

// ErrInvalidSnapshotConfig is the validation error type for
// snapshot-store construction and capture parameters.
type ErrInvalidSnapshotConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidSnapshotConfig) Error() string {
	return fmt.Sprintf("config: invalid snapshot config: %s: %s", e.Field, e.Reason)
}
