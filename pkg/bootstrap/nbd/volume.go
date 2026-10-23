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

package nbd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const (
	volumeDirMode  = 0o700
	volumeFileMode = 0o600
	volumeSuffix   = ".img"
)

// volumeStore creates and opens the per-device volume files.
type volumeStore struct {
	dir  string
	size int64
	// mu serialises create-or-open, so two first attaches of one identity
	// cannot both see a fresh file before it is sized.
	mu sync.Mutex
}

func newVolumeStore(dir string, size int64) *volumeStore {
	return &volumeStore{dir: dir, size: size}
}

// volume is one open export.
type volume struct {
	file *os.File
	size int64
}

// path returns the volume file for identity. Callers pass only identities
// that passed validIdentity.
func (v *volumeStore) path(identity string) string {
	return filepath.Join(v.dir, identity+volumeSuffix)
}

// open opens identity's volume, creating it at the configured size on the
// first attach. An existing volume keeps its own size.
func (v *volumeStore) open(identity string) (*volume, error) {
	if !validIdentity(identity) {
		return nil, ErrVolume{Identity: identity, Op: "validate", Cause: fs.ErrInvalid}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if err := os.MkdirAll(v.dir, volumeDirMode); err != nil {
		return nil, ErrVolume{Identity: identity, Op: "create directory", Cause: err}
	}

	path := v.path(identity)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, volumeFileMode)
	switch {
	case err == nil:
		if err := file.Truncate(v.size); err != nil {
			return nil, v.discard(identity, file, err)
		}
	case errors.Is(err, fs.ErrExist):
		file, err = os.OpenFile(path, os.O_RDWR, volumeFileMode)
		if err != nil {
			return nil, ErrVolume{Identity: identity, Op: "open", Cause: err}
		}
	default:
		return nil, ErrVolume{Identity: identity, Op: "create", Cause: err}
	}

	info, err := file.Stat()
	if err != nil {
		return nil, closeAfter(identity, file, ErrVolume{Identity: identity, Op: "stat", Cause: err})
	}
	return &volume{file: file, size: info.Size()}, nil
}

// discard removes a volume whose creation failed half-way, so the next
// attach creates it again rather than serving a zero-length file.
func (v *volumeStore) discard(identity string, file *os.File, cause error) error {
	err := closeAfter(identity, file, ErrVolume{Identity: identity, Op: "size", Cause: cause})
	if removeErr := os.Remove(file.Name()); removeErr != nil {
		return errors.Join(err, ErrVolume{Identity: identity, Op: "remove", Cause: removeErr})
	}
	return err
}

// closeAfter closes file and returns err, joined with the close failure if
// there was one.
func closeAfter(identity string, file *os.File, err error) error {
	if closeErr := file.Close(); closeErr != nil {
		return errors.Join(err, ErrVolume{Identity: identity, Op: "close", Cause: closeErr})
	}
	return err
}

// inRange reports whether [offset, offset+length) lies inside the volume.
func (vol *volume) inRange(offset uint64, length uint32) bool {
	end := offset + uint64(length)
	return end >= offset && end <= uint64(vol.size)
}

// trim discards [offset, offset+length) so it reads back as zeros.
func (vol *volume) trim(offset int64, length int64) error {
	if err := punchHole(vol.file, offset, length); err == nil {
		return nil
	}
	return zeroRange(vol.file, offset, length)
}

// zeroRange writes zeros over [offset, offset+length) — the fallback for a
// filesystem that cannot punch holes.
func zeroRange(file *os.File, offset int64, length int64) error {
	zeros := make([]byte, min(length, int64(preferredBlockSize*16)))
	for length > 0 {
		n := min(length, int64(len(zeros)))
		if _, err := file.WriteAt(zeros[:n], offset); err != nil {
			return err
		}
		offset += n
		length -= n
	}
	return nil
}
