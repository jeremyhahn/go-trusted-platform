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

package gateway

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// RevocationJournal is the file that keeps the management VPN's revocations
// whose control-plane DELETE has not landed, each lease ID with the tenant
// that held it. The control plane still records such a lease, so without the
// journal a gateway restart would rebuild it and reinstate a revoked device
// without a fresh admission. It also keeps each admission whose PUT may have
// landed without an answer; a restart treats those as revoked. Every write replaces the whole file through a
// synced temporary file and a rename, so a crash leaves either the old
// journal or the new one.
type RevocationJournal struct {
	path string
}

// NewRevocationJournal is the journal at path. The file and its directory
// are created on the first write.
func NewRevocationJournal(path string) *RevocationJournal {
	return &RevocationJournal{path: path}
}

// load returns the pending revocations. A journal never written holds none.
func (j *RevocationJournal) load() (map[vpn.LeaseID]string, error) {
	data, err := os.ReadFile(j.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[vpn.LeaseID]string{}, nil
	}
	if err != nil {
		return nil, &ErrRevocationJournal{Path: j.path, Op: "read", Cause: err}
	}
	pending := map[vpn.LeaseID]string{}
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, &ErrRevocationJournal{Path: j.path, Op: "parse", Cause: err}
	}
	return pending, nil
}

// save replaces the journal with pending.
func (j *RevocationJournal) save(pending map[vpn.LeaseID]string) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "encode", Cause: err}
	}
	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "write", Cause: err}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(j.path)+".*")
	if err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "write", Cause: err}
	}
	if err := writeSynced(tmp, data); err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "write", Cause: errors.Join(err, os.Remove(tmp.Name()))}
	}
	if err := os.Rename(tmp.Name(), j.path); err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "write", Cause: errors.Join(err, os.Remove(tmp.Name()))}
	}
	if err := syncDir(dir); err != nil {
		return &ErrRevocationJournal{Path: j.path, Op: "write", Cause: err}
	}
	return nil
}

// writeSynced writes data to f, flushes it to disk and closes f.
func writeSynced(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// syncDir flushes dir, so a rename into it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
