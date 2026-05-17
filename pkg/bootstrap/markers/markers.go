// Package markers implements a small idempotency primitive for one-shot
// bootstrap work that must not run again after a successful first
// invocation. A marker is a zero-byte sentinel file under <baseDir>/
// containing the timestamp of the first successful run.
//
// Use this for steps that:
//   - have no cheap "is it done?" probe of their own (e.g. "did I create
//     the default tenant?" with no obvious unique identifier to look up),
//     OR
//   - are expensive enough that even a cheap probe is worth skipping on
//     the warm-restart path.
//
// Bootstrap steps that already have a hardware/datastore-level existence
// probe (e.g. "is the EK provisioned at 0x81010001?", or "does the root
// CA load successfully?") should keep their probe and use the marker
// only as a fast-path skip.
//
// Markers are stored on whichever volume holds the platform data dir, so
// they survive across daemon restarts and roll with the LUKS-encrypted
// data partition.
package markers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Markers persists "this step has run successfully" sentinels.
type Markers struct {
	baseDir string
}

// New returns a Markers rooted at baseDir. The directory is created if
// it doesn't already exist; any failure to create it is returned to the
// caller so the daemon can fail loudly instead of silently re-running
// every step on every boot.
func New(baseDir string) (*Markers, error) {
	if baseDir == "" {
		return nil, errors.New("markers: baseDir must not be empty")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("markers: create %s: %w", baseDir, err)
	}
	return &Markers{baseDir: baseDir}, nil
}

// Has reports whether a marker exists for name. A read error other than
// not-exist is returned; callers should treat that as "unable to decide"
// and conservatively NOT skip the work.
func (m *Markers) Has(name string) (bool, error) {
	if err := validateName(name); err != nil {
		return false, err
	}
	_, err := os.Stat(m.path(name))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("markers: stat %s: %w", name, err)
	}
}

// Set creates the marker file for name. Calling Set on an already-set
// marker is a no-op (no error). The file content is the RFC3339 timestamp
// of the FIRST successful Set; subsequent calls do not overwrite it so
// the timestamp remains useful as an audit signal.
func (m *Markers) Set(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	p := m.path(name)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
		return fmt.Errorf("markers: write %s: %w", name, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("markers: rename %s: %w", name, err)
	}
	return nil
}

// DoOnce runs fn iff no marker for name exists. On a successful fn (nil
// return) the marker is created so subsequent calls become no-ops. fn is
// not run if Has returns true; an error from Has propagates without
// running fn so an unreadable marker dir doesn't silently re-execute
// work.
//
// The context is forwarded to fn — Has and Set are quick local file
// ops, so the context is checked only at fn boundaries.
func (m *Markers) DoOnce(ctx context.Context, name string, fn func(context.Context) error) error {
	done, err := m.Has(name)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return m.Set(name)
}

// Clear removes the marker for name. Safe to call when no marker exists.
// Intended for explicit "re-run this step" admin operations, never for
// normal startup paths.
func (m *Markers) Clear(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := os.Remove(m.path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("markers: remove %s: %w", name, err)
	}
	return nil
}

// BaseDir returns the directory holding all marker files. Useful for
// diagnostics and for tests that want to inspect on-disk state.
func (m *Markers) BaseDir() string {
	return m.baseDir
}

func (m *Markers) path(name string) string {
	return filepath.Join(m.baseDir, name+".done")
}

// validateName rejects names that would escape baseDir or otherwise
// produce a surprising filename. Marker names should look like
// "bootstrap.dns.zones" — dotted, lower-case identifiers.
func validateName(name string) error {
	if name == "" {
		return errors.New("markers: name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return fmt.Errorf("markers: invalid name %q", name)
	}
	return nil
}
