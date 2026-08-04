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

package registry

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileStorageClient is a single-node disk-backed QuicBaaSStorageClient
// suitable for Phase 5's first ship. Each entity type maps to a
// subdirectory; each (entityType, key) pair maps to one file whose
// content is the raw value bytes. Operations are protected by a
// process-local mutex.
//
// This is intentionally NOT a cluster-replicated store. When the
// cluster needs replicated image storage, build a QuicBaaSStorage-
// backed implementation against pkg/storage/quicbaas/Storage (which
// has different shape — string keys vs uint64 IDs — and so requires
// its own translation layer). The Registry's persistence contract is
// satisfied either way, so we can swap underneath without touching
// callers.
//
// Keys may contain URL-unsafe characters (e.g. tag references with
// slashes and colons); we percent-encode them to keep the on-disk
// names portable across Linux and macOS.
type FileStorageClient struct {
	root string
	mu   sync.Mutex
}

// NewFileStorageClient ensures root exists and returns a ready
// client. Returns an error if root cannot be created.
func NewFileStorageClient(root string) (*FileStorageClient, error) {
	if root == "" {
		return nil, &MessageError{Msg: "registry: file storage root cannot be empty"}
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: mkdir %s", root), Err: err}
	}
	return &FileStorageClient{root: root}, nil
}

// Put writes a value to <root>/<entityType>/<encodedKey>.
func (f *FileStorageClient) Put(_ context.Context, entityType, key string, value []byte, _ time.Duration) error {
	if entityType == "" || key == "" {
		return &MessageError{Msg: "registry: file storage: entityType and key are required"}
	}
	dir, path := f.path(entityType, key)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, value, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Get reads <root>/<entityType>/<encodedKey>. Missing files return
// (nil, false, nil); errors other than ErrNotExist propagate.
func (f *FileStorageClient) Get(_ context.Context, entityType, key string) ([]byte, bool, error) {
	_, path := f.path(entityType, key)
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

// Delete removes <root>/<entityType>/<encodedKey>. A missing file is
// not an error so callers can issue best-effort deletes.
func (f *FileStorageClient) Delete(_ context.Context, entityType, key string) error {
	_, path := f.path(entityType, key)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// List enumerates keys under <entityType> matching the supplied
// prefix. Results are sorted lexicographically. cursor is a key from
// a previous response; pagination starts strictly after it.
func (f *FileStorageClient) List(_ context.Context, entityType, prefix string, limit int, cursor string) ([]string, string, bool, error) {
	dir := filepath.Join(f.root, entityType)
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}
	all := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		k, err := decodeKey(e.Name())
		if err != nil {
			continue
		}
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		if cursor != "" && k <= cursor {
			continue
		}
		all = append(all, k)
	}
	sort.Strings(all)
	if limit > 0 && len(all) > limit {
		return all[:limit], all[limit-1], true, nil
	}
	return all, "", false, nil
}

func (f *FileStorageClient) path(entityType, key string) (dir, full string) {
	dir = filepath.Join(f.root, entityType)
	full = filepath.Join(dir, encodeKey(key))
	return dir, full
}

// encodeKey makes a key safe for use as a filename by percent-encoding
// every byte that isn't an unreserved URL character. Round-trips
// through decodeKey for List() to surface the original keys.
func encodeKey(k string) string {
	return url.PathEscape(k)
}

func decodeKey(name string) (string, error) {
	return url.PathUnescape(name)
}
