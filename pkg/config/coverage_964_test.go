package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// errCov964Cause is the sentinel cause the typed-error table wraps.
var errCov964Cause = errors.New("cov964 cause")

// cov964ResetViper isolates a test from the process-global viper.
func cov964ResetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

func TestCov964TypedErrorMessages(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		want      string
		wrapsCase bool
	}{
		{"WrappedError", &WrappedError{Msg: "config: op", Err: errCov964Cause}, "config: op: cov964 cause", true},
		{"ErrMergeUnmarshal", &ErrMergeUnmarshal{Cause: errCov964Cause}, "config: failed to unmarshal yaml: cov964 cause", true},
		{"ErrMergeMarshal", &ErrMergeMarshal{Cause: errCov964Cause}, "config: failed to marshal yaml: cov964 cause", true},
		{"ErrMergeReadFile", &ErrMergeReadFile{Path: "/x.yaml", Cause: errCov964Cause}, "config: failed to read file /x.yaml: cov964 cause", true},
		{"ErrDecodeYAML", ErrDecodeYAML{Cause: errCov964Cause}, "config: decode platform config: cov964 cause", true},
		{"ErrApplySectionFailed", ErrApplySectionFailed{Cause: errCov964Cause}, "config: apply section failed: cov964 cause", true},
		{"ErrReloadFailed", ErrReloadFailed{Cause: errCov964Cause}, "config: reload failed: cov964 cause", true},
		{"ErrSnapshotNotFound", ErrSnapshotNotFound{ID: "abc"}, "config: snapshot not found: abc", false},
		{"ErrInvalidSnapshotConfig", ErrInvalidSnapshotConfig{Field: "root", Reason: "cannot be empty"}, "config: invalid snapshot config: root: cannot be empty", false},
		{"ErrInvalidReportingInterval", ErrInvalidReportingInterval{Field: "interval", Reason: "must be positive"}, "config: attestation.reporting.interval: must be positive", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
			if got := errors.Is(tc.err, errCov964Cause); got != tc.wrapsCase {
				t.Fatalf("errors.Is(cause) = %v, want %v", got, tc.wrapsCase)
			}
		})
	}
}

func TestCov964TypedErrorsAs(t *testing.T) {
	wrapped := &WrappedError{Msg: "outer", Err: ErrReloadFailed{Cause: errCov964Cause}}
	var reload ErrReloadFailed
	if !errors.As(wrapped, &reload) {
		t.Fatalf("errors.As(ErrReloadFailed) failed through WrappedError")
	}
	if !errors.Is(reload.Cause, errCov964Cause) {
		t.Fatalf("reload.Cause = %v, want the sentinel", reload.Cause)
	}
	var notFound ErrSnapshotNotFound
	if errors.As(wrapped, &notFound) {
		t.Fatalf("errors.As(ErrSnapshotNotFound) matched an unrelated chain")
	}
}

func TestCov964NewFileSnapshotStoreEmptyRoot(t *testing.T) {
	store, err := NewFileSnapshotStore("")
	if store != nil {
		t.Fatalf("store = %v, want nil", store)
	}
	var cfgErr ErrInvalidSnapshotConfig
	if !errors.As(err, &cfgErr) || cfgErr.Field != "root" {
		t.Fatalf("err = %v, want ErrInvalidSnapshotConfig on root", err)
	}
}

func TestCov964NewFileSnapshotStoreRootIsFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSnapshotStore(dir)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	if err := store.Put(&Snapshot{ID: "file"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// A root below a regular file cannot be created.
	_, err = NewFileSnapshotStore(filepath.Join(store.pathFor("file"), "sub"))
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("err = %v, want *WrappedError", err)
	}
}

func TestCov964PutRejectsMissingID(t *testing.T) {
	store, err := NewFileSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	for name, snap := range map[string]*Snapshot{"nil": nil, "empty id": {}} {
		t.Run(name, func(t *testing.T) {
			var cfgErr ErrInvalidSnapshotConfig
			if err := store.Put(snap); !errors.As(err, &cfgErr) || cfgErr.Field != "snapshot.id" {
				t.Fatalf("Put = %v, want ErrInvalidSnapshotConfig on snapshot.id", err)
			}
		})
	}
}

func TestCov964DeleteExistingThenMissing(t *testing.T) {
	store, err := NewFileSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	if err := store.Put(&Snapshot{ID: "snap-1"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete("snap-1"); err != nil {
		t.Fatalf("Delete existing: %v", err)
	}
	var notFound ErrSnapshotNotFound
	if _, err := store.Get("snap-1"); !errors.As(err, &notFound) {
		t.Fatalf("Get after Delete = %v, want ErrSnapshotNotFound", err)
	}
	err = store.Delete("snap-1")
	if !errors.As(err, &notFound) || notFound.ID != "snap-1" {
		t.Fatalf("Delete missing = %v, want ErrSnapshotNotFound{snap-1}", err)
	}
}

func TestCov964ViperFormat(t *testing.T) {
	tests := []struct {
		name       string
		configType string
		configFile string
		want       string
	}{
		{"unset defaults to yaml", "", "", "yaml"},
		{"config-type wins", "json", "/etc/x.yaml", "json"},
		{"yaml suffix", "", "/cfg/platform.yaml", "yaml"},
		{"yml suffix", "", "/cfg/platform.yml", "yaml"},
		{"json suffix", "", "/cfg/platform.json", "json"},
		{"toml suffix", "", "/cfg/platform.toml", "toml"},
		{"unknown suffix defaults to yaml", "", "/cfg/platform.conf", "yaml"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cov964ResetViper(t)
			if tc.configType != "" {
				viper.Set("config-type", tc.configType)
			}
			if tc.configFile != "" {
				viper.SetConfigFile(tc.configFile)
			}
			if got := viperFormat(); got != tc.want {
				t.Fatalf("viperFormat() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCov964IsEmptyLeaf(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want bool
	}{
		{"nil", nil, true},
		{"empty string", "", true},
		{"empty slice", []interface{}{}, true},
		{"empty map", map[string]interface{}{}, true},
		{"non-empty string", "x", false},
		{"non-empty slice", []interface{}{1}, false},
		{"non-empty map", map[string]interface{}{"k": 1}, false},
		{"zero int is a value", 0, false},
		{"false is a value", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEmptyLeaf(tc.v); got != tc.want {
				t.Fatalf("isEmptyLeaf(%#v) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

func TestCov964ReloadFromDiskMissingFile(t *testing.T) {
	cov964ResetViper(t)
	viper.SetConfigFile(filepath.Join(t.TempDir(), "missing.yaml"))
	sections, err := ReloadFromDisk(nil)
	if sections != nil {
		t.Fatalf("sections = %v, want nil", sections)
	}
	var reload ErrReloadFailed
	if !errors.As(err, &reload) {
		t.Fatalf("err = %v, want ErrReloadFailed", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap fs.ErrNotExist", err)
	}
}
