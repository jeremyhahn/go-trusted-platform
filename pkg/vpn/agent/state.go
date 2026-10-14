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

package agent

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// DefaultStatePath is where the agent records the lease it holds. It is on
// tmpfs, so a reboot forgets a lease the reboot also tore down.
const DefaultStatePath = "/run/platformctl/vpn.json"

// Session is what a data plane needs to tear itself down later.
type Session struct {
	Interface string `json:"interface"`
}

// State is the lease the agent holds and the data plane that carries it. It
// holds no secret: the WireGuard private key lives only in the kernel.
type State struct {
	Gateway string          `json:"gateway"`
	Lease   gwvpn.LeaseWire `json:"lease"`
	Session Session         `json:"session"`
	// Factor is the person factor connect presented; a renewal presents
	// it again.
	Factor      gwvpn.PersonFactorKind `json:"factor,omitempty"`
	ConnectedAt time.Time              `json:"connected_at"`
}

// FileStateStore keeps the State in one JSON file, replaced atomically.
type FileStateStore struct {
	Path string
}

// NewFileStateStore returns a store at path, or DefaultStatePath when path
// is empty.
func NewFileStateStore(path string) *FileStateStore {
	if path == "" {
		path = DefaultStatePath
	}
	return &FileStateStore{Path: path}
}

// Load returns the recorded state, or ErrNotConnected when there is none.
func (s *FileStateStore) Load() (*State, error) {
	raw, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &ErrNotConnected{}
	}
	if err != nil {
		return nil, &ErrStateStore{Op: "read", Path: s.Path, Cause: err}
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, &ErrStateStore{Op: "decode", Path: s.Path, Cause: err}
	}
	return &st, nil
}

// Save writes st to a private temporary file beside the state file and
// renames it into place, so a reader never sees a partial record.
func (s *FileStateStore) Save(st *State) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return &ErrStateStore{Op: "encode", Path: s.Path, Cause: err}
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &ErrStateStore{Op: "create directory", Path: dir, Cause: err}
	}
	tmp, err := os.CreateTemp(dir, ".vpn-*.json")
	if err != nil {
		return &ErrStateStore{Op: "create", Path: dir, Cause: err}
	}
	if err := writeAndClose(tmp, raw); err != nil {
		return s.discard(tmp.Name(), &ErrStateStore{Op: "write", Path: tmp.Name(), Cause: err})
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		return s.discard(tmp.Name(), &ErrStateStore{Op: "rename", Path: s.Path, Cause: err})
	}
	return nil
}

// writeAndClose writes raw to f, flushes it to disk and closes it. os.CreateTemp
// already created f with mode 0600.
func writeAndClose(f *os.File, raw []byte) error {
	if _, err := f.Write(raw); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// discard removes a temporary file that never became the state file and
// returns cause, with the removal's failure attached if it failed too.
func (s *FileStateStore) discard(path string, cause *ErrStateStore) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(cause, &ErrStateStore{Op: "remove", Path: path, Cause: err})
	}
	return cause
}

// Remove deletes the state file; a missing file is not an error.
func (s *FileStateStore) Remove() error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &ErrStateStore{Op: "remove", Path: s.Path, Cause: err}
	}
	return nil
}
