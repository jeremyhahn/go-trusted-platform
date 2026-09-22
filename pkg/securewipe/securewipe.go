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

// Package securewipe overwrites and deletes regular files that held key
// material: the installer container on the ESP, once the seal it carried
// has been proven. It is shared by firstboot (a failed-seal retry that
// gives up) and platform-initrd (the confirmation wipe), so both destroy
// the container the same way, with direct file operations: every pass is
// written and fsynced, the unlink is fsynced through the parent directory,
// and the filesystem is asked to TRIM so the freed blocks leave the flash
// spare area too.
package securewipe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Pass counts with a name. 1 is NIST SP 800-88 (one random pass, what an
// SSD needs); 3 is DoD 5220.22-M (zeros, ones, random); 7 is DoD ECE
// (zeros, ones, then random). Anything below 1 is treated as 1.
const (
	PassesNIST   = 1
	PassesDoD    = 3
	PassesDoDECE = 7
)

// chunkSize is the write granularity of a pass.
const chunkSize = 1 << 20

// PassError reports which pass of a wipe failed. The file is left as it is
// at that point: partially overwritten, never deleted.
type PassError struct {
	Pass   int
	Passes int
	What   string
	Err    error
}

func (e *PassError) Error() string {
	return fmt.Sprintf("securewipe: pass %d/%d (%s): %v", e.Pass, e.Passes, e.What, e.Err)
}

func (e *PassError) Unwrap() error { return e.Err }

// RemoveError reports that the overwritten file could not be unlinked, or
// that the unlink could not be made durable.
type RemoveError struct {
	Path string
	Err  error
}

func (e *RemoveError) Error() string {
	return fmt.Sprintf("securewipe: removing %s: %v", e.Path, e.Err)
}

func (e *RemoveError) Unwrap() error { return e.Err }

// fill is one overwrite pass's content.
type fill struct {
	what string
	fn   func([]byte) error
}

var (
	fillZeros = fill{"zeros", func(b []byte) error { clear(b); return nil }}
	fillOnes  = fill{"ones", func(b []byte) error {
		for i := range b {
			b[i] = 0xFF
		}
		return nil
	}}
	fillRandom = fill{"random", func(b []byte) error { _, err := io.ReadFull(rand.Reader, b); return err }}
)

// passes returns the pass sequence for a count: random only below the DoD
// threshold, zeros then ones then random from it.
func passes(n int) []fill {
	if n < PassesNIST {
		n = PassesNIST
	}
	if n < PassesDoD {
		out := make([]fill, n)
		for i := range out {
			out[i] = fillRandom
		}
		return out
	}
	out := []fill{fillZeros, fillOnes}
	for len(out) < n {
		out = append(out, fillRandom)
	}
	return out
}

// File overwrites path in passes, deletes it, makes the deletion durable
// and asks the filesystem to TRIM. report, when not nil, receives one line
// per step so the caller can put the progress on whatever console it owns.
// A TRIM the filesystem does not support is reported, not an error: the
// overwrite and the unlink are what the caller needs.
func File(path string, n int, report func(string)) error {
	if report == nil {
		report = func(string) {}
	}
	sequence := passes(n)
	report(fmt.Sprintf("Secure wipe: %d passes", len(sequence)))

	if err := overwrite(path, sequence, report); err != nil {
		return err
	}
	if err := remove(path); err != nil {
		return err
	}
	report("Removed and synced")
	switch err := trim(filepath.Dir(path)); {
	case err == nil:
		report("Filesystem trimmed")
	case IsTrimUnavailable(err):
		report("TRIM not available here: " + err.Error())
	default:
		return &RemoveError{Path: path, Err: err}
	}
	return nil
}

// overwrite writes every pass over the whole file, fsyncing each.
func overwrite(path string, sequence []fill, report func(string)) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return &PassError{Pass: 1, Passes: len(sequence), What: sequence[0].what, Err: err}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return &PassError{Pass: 1, Passes: len(sequence), What: sequence[0].what, Err: err}
	}
	size := info.Size()
	buf := make([]byte, chunkSize)
	defer clear(buf)

	for i, pass := range sequence {
		report(fmt.Sprintf("Pass %d/%d: %s", i+1, len(sequence), pass.what))
		if err := writePass(f, size, pass, buf); err != nil {
			return &PassError{Pass: i + 1, Passes: len(sequence), What: pass.what, Err: err}
		}
	}
	return nil
}

// writePass writes one fill over size bytes from the start and fsyncs.
func writePass(f *os.File, size int64, pass fill, buf []byte) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for remaining := size; remaining > 0; {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if err := pass.fn(buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return f.Sync()
}

// remove unlinks path and fsyncs its directory, so the removal survives a
// reset as surely as the overwrite did.
func remove(path string) error {
	if err := os.Remove(path); err != nil {
		return &RemoveError{Path: path, Err: err}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return &RemoveError{Path: path, Err: err}
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return &RemoveError{Path: path, Err: err}
	}
	return nil
}

// fstrimRange is the kernel's struct fstrim_range.
type fstrimRange struct {
	Start  uint64
	Len    uint64
	Minlen uint64
}

// fitrim is FITRIM, _IOWR('X', 121, struct fstrim_range): the same value on
// every Linux architecture, and not exported by x/sys/unix.
const fitrim = 0xC0185879

// trim asks the filesystem holding dir to discard its free blocks (FITRIM,
// what fstrim does). The ioctl takes a struct, so this is the one place the
// package hands the kernel a pointer.
func trim(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	rng := fstrimRange{Start: 0, Len: ^uint64(0), Minlen: 0}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, d.Fd(), fitrim, uintptr(unsafe.Pointer(&rng)))
	if errno != 0 {
		return errno
	}
	return nil
}

// IsTrimUnavailable reports whether err is FITRIM being declined rather
// than failing: a filesystem without discard (tmpfs, vfat on a loop
// device, ...) or a caller without CAP_SYS_ADMIN (the ioctl needs it; the
// initrd has it, a unit test does not).
func IsTrimUnavailable(err error) bool {
	return errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM)
}
