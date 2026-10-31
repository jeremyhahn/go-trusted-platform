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
	"io"
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

// VolumeProvider is the store that holds each diskless-nbd node's volume.
// The export server, and the boot server's read of an installed UKI, reach
// a volume only through it, so neither changes with the choice of store.
//
// Implementations validate identity themselves and return ErrVolume for
// every failure.
type VolumeProvider interface {
	// Create makes identity's volume at size bytes if it does not exist.
	// A volume that exists keeps its size and contents.
	Create(identity string, size int64) error
	// Attach returns the path of identity's volume: a regular file or a
	// block device the caller opens. A volume that does not exist is an
	// ErrVolume wrapping fs.ErrNotExist.
	Attach(identity string) (string, error)
}

// LocalVolumes is the VolumeProvider for a single boot node: one sparse
// file per identity, <dir>/<identity>.img. The directory is 0700 and each
// file 0600.
type LocalVolumes struct {
	dir string
	// mu serialises Create, so two first attaches of one identity cannot
	// both see a fresh file before it is sized.
	mu sync.Mutex
}

// NewLocalVolumes returns the local-file store rooted at dir. An empty dir
// is ErrInvalidConfig.
func NewLocalVolumes(dir string) (*LocalVolumes, error) {
	if dir == "" {
		return nil, ErrInvalidConfig{Field: "VolumeDir", Reason: "a volume directory is required"}
	}
	return &LocalVolumes{dir: dir}, nil
}

// path returns the volume file for identity. Callers pass only identities
// that passed validIdentity.
func (l *LocalVolumes) path(identity string) string {
	return filepath.Join(l.dir, identity+volumeSuffix)
}

// Create creates identity's volume file at size bytes on its first call
// and leaves an existing file as it is. A size that is not a positive
// multiple of 512 is refused.
func (l *LocalVolumes) Create(identity string, size int64) error {
	if !validIdentity(identity) {
		return ErrVolume{Identity: identity, Op: "validate", Cause: fs.ErrInvalid}
	}
	if size <= 0 || size%sectorSize != 0 {
		return ErrVolume{Identity: identity, Op: "size", Cause: fs.ErrInvalid}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(l.dir, volumeDirMode); err != nil {
		return ErrVolume{Identity: identity, Op: "create directory", Cause: err}
	}

	file, err := os.OpenFile(l.path(identity), os.O_RDWR|os.O_CREATE|os.O_EXCL, volumeFileMode)
	switch {
	case errors.Is(err, fs.ErrExist):
		return nil
	case err != nil:
		return ErrVolume{Identity: identity, Op: "create", Cause: err}
	}
	if err := file.Truncate(size); err != nil {
		return discard(identity, file, err)
	}
	return closeAfter(identity, file, nil)
}

// Attach returns the path of identity's volume file.
func (l *LocalVolumes) Attach(identity string) (string, error) {
	if !validIdentity(identity) {
		return "", ErrVolume{Identity: identity, Op: "validate", Cause: fs.ErrInvalid}
	}
	path := l.path(identity)
	if _, err := os.Stat(path); err != nil {
		return "", ErrVolume{Identity: identity, Op: "attach", Cause: err}
	}
	return path, nil
}

// volumeStore is the export server's side of the VolumeProvider: it
// creates a volume on its first attach and opens it for transmission.
type volumeStore struct {
	provider VolumeProvider
	size     int64
}

func newVolumeStore(provider VolumeProvider, size int64) *volumeStore {
	return &volumeStore{provider: provider, size: size}
}

// volume is one open export.
type volume struct {
	file *os.File
	size int64
}

// open opens identity's volume, creating it at the configured size on the
// first attach. An existing volume keeps its own size.
func (v *volumeStore) open(identity string) (*volume, error) {
	if err := v.provider.Create(identity, v.size); err != nil {
		return nil, err
	}
	path, err := v.provider.Attach(identity)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrVolume{Identity: identity, Op: "open", Cause: err}
	}
	size, err := volumeSize(identity, file)
	if err != nil {
		return nil, closeAfter(identity, file, err)
	}
	return &volume{file: file, size: size}, nil
}

// volumeSize returns an open volume's size. It seeks to the end rather than
// reading Stat, which reports 0 for a block device.
func volumeSize(identity string, file *os.File) (int64, error) {
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, ErrVolume{Identity: identity, Op: "size", Cause: err}
	}
	return size, nil
}

// discard removes a volume whose creation failed half-way, so the next
// attach creates it again rather than serving a zero-length file.
func discard(identity string, file *os.File, cause error) error {
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
