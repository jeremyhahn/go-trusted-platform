package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// cov964Store returns a FileStore rooted in a fresh temp directory.
func cov964Store(t *testing.T) (*FileStore, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return store, root
}

// cov964MakeNonEmptyDir creates a directory at path holding one file,
// so os.Remove and os.Rename onto it fail with a non-ErrNotExist error.
func cov964MakeNonEmptyDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write keep: %v", err)
	}
}

func TestCov964WrappedError(t *testing.T) {
	cause := os.ErrPermission
	err := error(&WrappedError{Msg: "gateway/state: mkdir /x", Err: cause})

	if got, want := err.Error(), "gateway/state: mkdir /x: "+cause.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("errors.Is(err, os.ErrPermission) = false, want true")
	}
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Unwrap() != cause {
		t.Fatalf("errors.As did not yield the wrapped cause: %v", err)
	}
}

func TestCov964TypedErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "snapshot not found",
			err:  ErrSnapshotNotFound{GatewayID: "gw-1"},
			want: "gateway/state: snapshot not found for gw-1",
		},
		{
			name: "invalid config",
			err:  errInvalidStateConfig{Field: "root", Reason: "cannot be empty"},
			want: "gateway/state: invalid root: cannot be empty",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCov964NewFileStoreErrors(t *testing.T) {
	t.Run("empty root", func(t *testing.T) {
		store, err := NewFileStore("")
		if store != nil {
			t.Fatalf("store = %v, want nil", store)
		}
		var cfgErr errInvalidStateConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "root" {
			t.Fatalf("err = %v, want errInvalidStateConfig on root", err)
		}
	})

	t.Run("parent is a regular file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent: %v", err)
		}
		store, err := NewFileStore(filepath.Join(parent, "state"))
		if store != nil {
			t.Fatalf("store = %v, want nil", store)
		}
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) {
			t.Fatalf("err = %v, want *WrappedError", err)
		}
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("err = %v, want ENOTDIR cause", err)
		}
	})
}

func TestCov964PutErrors(t *testing.T) {
	t.Run("nil snapshot", func(t *testing.T) {
		store, _ := cov964Store(t)
		var cfgErr errInvalidStateConfig
		if err := store.Put(nil); !errors.As(err, &cfgErr) || cfgErr.Field != "snapshot" {
			t.Fatalf("Put(nil) = %v, want errInvalidStateConfig on snapshot", err)
		}
	})

	t.Run("empty gateway id", func(t *testing.T) {
		store, _ := cov964Store(t)
		var cfgErr errInvalidStateConfig
		if err := store.Put(&Snapshot{}); !errors.As(err, &cfgErr) || cfgErr.Field != "snapshot.gateway_id" {
			t.Fatalf("Put(empty id) = %v, want errInvalidStateConfig on snapshot.gateway_id", err)
		}
	})

	t.Run("temp file path is a directory", func(t *testing.T) {
		store, _ := cov964Store(t)
		cov964MakeNonEmptyDir(t, store.path("gw-1")+".tmp")
		err := store.Put(&Snapshot{GatewayID: "gw-1"})
		if err == nil {
			t.Fatalf("Put = nil, want write error")
		}
		if !errors.Is(err, syscall.EISDIR) {
			t.Fatalf("Put = %v, want EISDIR", err)
		}
	})

	t.Run("target path is a non-empty directory", func(t *testing.T) {
		store, _ := cov964Store(t)
		cov964MakeNonEmptyDir(t, store.path("gw-1"))
		err := store.Put(&Snapshot{GatewayID: "gw-1"})
		var linkErr *os.LinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("Put = %v, want *os.LinkError from rename", err)
		}
	})

	t.Run("stamps received and reported time", func(t *testing.T) {
		store, _ := cov964Store(t)
		snap := &Snapshot{GatewayID: "gw-1"}
		if err := store.Put(snap); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if snap.ReceivedAt.IsZero() || !snap.ReportedAt.Equal(snap.ReceivedAt) {
			t.Fatalf("ReceivedAt=%v ReportedAt=%v, want both stamped equal", snap.ReceivedAt, snap.ReportedAt)
		}
	})
}

func TestCov964GetErrors(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		store, _ := cov964Store(t)
		_, err := store.Get("gw-missing")
		var notFound ErrSnapshotNotFound
		if !errors.As(err, &notFound) || notFound.GatewayID != "gw-missing" {
			t.Fatalf("Get = %v, want ErrSnapshotNotFound for gw-missing", err)
		}
	})

	t.Run("corrupt snapshot", func(t *testing.T) {
		store, _ := cov964Store(t)
		if err := os.WriteFile(store.path("gw-1"), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write corrupt: %v", err)
		}
		snap, err := store.Get("gw-1")
		if snap != nil {
			t.Fatalf("snap = %v, want nil", snap)
		}
		var wrapped *WrappedError
		var syntaxErr *json.SyntaxError
		if !errors.As(err, &wrapped) || !errors.As(err, &syntaxErr) {
			t.Fatalf("Get = %v, want *WrappedError around *json.SyntaxError", err)
		}
	})

	t.Run("snapshot path is a directory", func(t *testing.T) {
		store, _ := cov964Store(t)
		cov964MakeNonEmptyDir(t, store.path("gw-1"))
		_, err := store.Get("gw-1")
		var notFound ErrSnapshotNotFound
		if err == nil || errors.As(err, &notFound) {
			t.Fatalf("Get = %v, want an IO error that is not ErrSnapshotNotFound", err)
		}
		if !errors.Is(err, syscall.EISDIR) {
			t.Fatalf("Get = %v, want EISDIR", err)
		}
	})
}

func TestCov964List(t *testing.T) {
	t.Run("missing root lists nothing", func(t *testing.T) {
		store, root := cov964Store(t)
		if err := os.Remove(root); err != nil {
			t.Fatalf("remove root: %v", err)
		}
		got, err := store.List()
		if err != nil || got != nil {
			t.Fatalf("List = %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("root is a regular file", func(t *testing.T) {
		store, root := cov964Store(t)
		if err := os.Remove(root); err != nil {
			t.Fatalf("remove root: %v", err)
		}
		if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
			t.Fatalf("write root file: %v", err)
		}
		_, err := store.List()
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("List = %v, want ENOTDIR", err)
		}
	})

	t.Run("skips unreadable and foreign entries", func(t *testing.T) {
		store, root := cov964Store(t)
		older := &Snapshot{GatewayID: "gw-old", ReportedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		newer := &Snapshot{GatewayID: "gw-new", ReportedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}
		for _, snap := range []*Snapshot{older, newer} {
			if err := store.Put(snap); err != nil {
				t.Fatalf("Put %s: %v", snap.GatewayID, err)
			}
		}
		writes := map[string]string{
			"corrupt.json": "{not json",
			"notes.txt":    "{}",
		}
		for name, body := range writes {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		cov964MakeNonEmptyDir(t, filepath.Join(root, "dir.json"))
		if err := os.Symlink(filepath.Join(root, "absent"), filepath.Join(root, "dangling.json")); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		got, err := store.List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("List returned %d snapshots, want 2", len(got))
		}
		if got[0].GatewayID != "gw-new" || got[1].GatewayID != "gw-old" {
			t.Fatalf("List order = [%s %s], want [gw-new gw-old]", got[0].GatewayID, got[1].GatewayID)
		}
	})
}

func TestCov964Delete(t *testing.T) {
	t.Run("removes a stored snapshot", func(t *testing.T) {
		store, _ := cov964Store(t)
		if err := store.Put(&Snapshot{GatewayID: "gw-1"}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := store.Delete("gw-1"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := os.Stat(store.path("gw-1")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stat after Delete = %v, want ErrNotExist", err)
		}
	})

	t.Run("missing id", func(t *testing.T) {
		store, _ := cov964Store(t)
		var notFound ErrSnapshotNotFound
		if err := store.Delete("gw-missing"); !errors.As(err, &notFound) || notFound.GatewayID != "gw-missing" {
			t.Fatalf("Delete = %v, want ErrSnapshotNotFound for gw-missing", err)
		}
	})

	t.Run("path cannot be removed", func(t *testing.T) {
		store, _ := cov964Store(t)
		cov964MakeNonEmptyDir(t, store.path("gw-1"))
		err := store.Delete("gw-1")
		var notFound ErrSnapshotNotFound
		if err == nil || errors.As(err, &notFound) {
			t.Fatalf("Delete = %v, want an IO error that is not ErrSnapshotNotFound", err)
		}
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("Delete = %v, want *fs.PathError", err)
		}
	})
}

func TestCov964MustAddr(t *testing.T) {
	tests := []struct {
		in   string
		want netip.Addr
	}{
		{in: "10.0.0.1", want: netip.MustParseAddr("10.0.0.1")},
		{in: "fd00::1", want: netip.MustParseAddr("fd00::1")},
		{in: "not-an-ip", want: netip.Addr{}},
		{in: "", want: netip.Addr{}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := mustAddr(tc.in); got != tc.want {
				t.Fatalf("mustAddr(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
