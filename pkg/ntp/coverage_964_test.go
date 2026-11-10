package ntp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errCoverageCause is the wrapped cause the error-type tests unwrap.
type errCoverageCause struct{}

func (errCoverageCause) Error() string { return "enclave sealed" }

func TestNTSMaterialErrorMessages(t *testing.T) {
	cause := errCoverageCause{}
	tests := []struct {
		name      string
		err       error
		wantText  []string
		wantCause bool
	}{
		{
			name:     "version link quotes its target",
			err:      ErrInvalidNTSVersionLink{Target: "../escape"},
			wantText: []string{"invalid version target", `"../escape"`},
		},
		{
			name:     "rotated material lost without cause",
			err:      ErrRotatedNTSMaterialLost{},
			wantText: []string{"no longer published", "restart the daemon"},
		},
		{
			name:      "rotated material lost carries its cause",
			err:       ErrRotatedNTSMaterialLost{Cause: cause},
			wantText:  []string{"no longer published", ": enclave sealed"},
			wantCause: true,
		},
		{
			name:     "key enclave unavailable without cause",
			err:      ErrNTSKeyEnclaveUnavailable{},
			wantText: []string{"private key enclave is unavailable"},
		},
		{
			name:      "key enclave unavailable carries its cause",
			err:       ErrNTSKeyEnclaveUnavailable{Cause: cause},
			wantText:  []string{"private key enclave is unavailable: enclave sealed"},
			wantCause: true,
		},
		{
			name:     "server name quotes the entry and reason",
			err:      ErrInvalidNTSServerName{Name: "bad name", Reason: "not a DNS name"},
			wantText: []string{`"bad name"`, "is not a DNS name"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, want := range tc.wantText {
				if !strings.Contains(msg, want) {
					t.Fatalf("Error() = %q, want it to contain %q", msg, want)
				}
			}
			if got := errors.Is(tc.err, cause); got != tc.wantCause {
				t.Fatalf("errors.Is(err, cause) = %v, want %v", got, tc.wantCause)
			}
		})
	}
}

func TestErrorsWithoutCauseOmitTheSeparator(t *testing.T) {
	for _, err := range []error{ErrRotatedNTSMaterialLost{}, ErrNTSKeyEnclaveUnavailable{}} {
		if strings.HasSuffix(err.Error(), ": ") || strings.Contains(err.Error(), "unknown cause") {
			t.Fatalf("Error() = %q, a nil cause must not be rendered", err.Error())
		}
	}
}

func TestOSFileSystemLinkLifecycle(t *testing.T) {
	fs := osFileSystem{}
	dir := t.TempDir()
	staged := filepath.Join(dir, "v1.staged")
	version := filepath.Join(dir, "v1")
	current := filepath.Join(dir, "current")

	if err := fs.WriteFile(staged, []byte("pair"), certFileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := fs.Rename(staged, version); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if _, err := fs.ReadFile(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile(staged) error = %v, want os.ErrNotExist after Rename", err)
	}
	if err := fs.Symlink("v1", current); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	target, err := fs.Readlink(current)
	if err != nil || target != "v1" {
		t.Fatalf("Readlink() = %q, %v, want v1", target, err)
	}
	if err := fs.Remove(current); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := fs.Readlink(current); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Readlink() after Remove error = %v, want os.ErrNotExist", err)
	}

	nested := filepath.Join(dir, "tree", "leaf")
	if err := fs.MkdirAll(nested, dirMode); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := fs.RemoveAll(filepath.Join(dir, "tree")); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
	if _, err := os.Stat(nested); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(nested) error = %v, want os.ErrNotExist after RemoveAll", err)
	}
}

func TestOSFileSystemRejectsMissingPaths(t *testing.T) {
	fs := osFileSystem{}
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")

	if err := fs.Rename(missing, filepath.Join(dir, "other")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Rename() error = %v, want os.ErrNotExist", err)
	}
	if err := fs.Symlink("v1", filepath.Join(missing, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Symlink() error = %v, want os.ErrNotExist", err)
	}
	if _, err := fs.Readlink(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Readlink() error = %v, want os.ErrNotExist", err)
	}
	if err := fs.Remove(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Remove() error = %v, want os.ErrNotExist", err)
	}
	if err := fs.WriteFile(filepath.Join(missing, "file"), []byte("x"), configFileMode); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WriteFile() into a missing directory error = %v, want os.ErrNotExist", err)
	}
}

func TestServiceSourcesDelegatesToController(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""}, "restart": {Output: ""}, "status": {Output: "started"},
	})

	t.Run("returns the controller's sources", func(t *testing.T) {
		want := []Source{{Address: "time.example.net"}}
		svc := newTestService(t, consumerConfig(), &fakeController{sources: want}, runner, newMemFS())
		got, err := svc.Sources(ctx)
		if err != nil {
			t.Fatalf("Sources() error = %v", err)
		}
		if len(got) != 1 || got[0].Address != want[0].Address {
			t.Fatalf("Sources() = %+v, want %+v", got, want)
		}
	})

	t.Run("propagates the controller error", func(t *testing.T) {
		ctrlErr := ErrControlUnavailable{}
		svc := newTestService(t, consumerConfig(), &fakeController{sourcesErr: ctrlErr}, runner, newMemFS())
		if _, err := svc.Sources(ctx); !errors.As(err, &ErrControlUnavailable{}) {
			t.Fatalf("Sources() error = %v, want ErrControlUnavailable", err)
		}
	})
}

func TestNewControllerDefaultsToExecRunner(t *testing.T) {
	ctrl, ok := NewController("/run/chrony/chronyd.sock", nil).(*chronyc)
	if !ok {
		t.Fatal("NewController() did not return a *chronyc")
	}
	if _, isExec := ctrl.runner.(execRunner); !isExec {
		t.Fatalf("runner = %T, want execRunner for a nil runner", ctrl.runner)
	}
	if ctrl.socket != "/run/chrony/chronyd.sock" {
		t.Fatalf("socket = %q, want the configured socket", ctrl.socket)
	}
}
