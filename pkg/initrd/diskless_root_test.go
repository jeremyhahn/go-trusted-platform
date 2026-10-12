package initrd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

const (
	testRootHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testSalt     = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

var (
	testRootFS = bytes.Repeat([]byte("r"), 2*disklessroot.BlockSize)
	testVerity = bytes.Repeat([]byte("v"), disklessroot.BlockSize)
)

type disklessRecorder struct {
	calls []string
	// fail maps a command-line substring to the error the command returns.
	fail map[string]error
}

func (r *disklessRecorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, joined)
	for substr, err := range r.fail {
		if strings.Contains(joined, substr) {
			return []byte("simulated failure"), err
		}
	}
	if name == "losetup" && len(args) > 0 && args[0] == "--find" {
		if strings.HasSuffix(args[len(args)-1], disklessroot.RootFSFile) {
			return []byte("/dev/loop10\n"), nil
		}
		return []byte("/dev/loop11\n"), nil
	}
	return nil, nil
}

// artifactServer serves the two artifacts under their fixed names, or the
// handler a test substitutes for one of them.
func artifactServer(t *testing.T, override map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	bodies := map[string][]byte{
		"/" + disklessroot.RootFSFile: testRootFS,
		"/" + disklessroot.VerityFile: testVerity,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := override[r.URL.Path]; ok {
			handler(w, r)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write %s: %v", r.URL.Path, err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func testDisklessConfig(t *testing.T, server *httptest.Server, rec *disklessRecorder) DisklessRootConfig {
	t.Helper()
	workDir := t.TempDir()
	return DisklessRootConfig{
		Params: disklessroot.BootParams{
			RootFSURL:  server.URL + "/" + disklessroot.RootFSFile,
			VerityURL:  server.URL + "/" + disklessroot.VerityFile,
			RootHash:   testRootHash,
			Salt:       testSalt,
			RootFSSize: int64(len(testRootFS)),
			VeritySize: int64(len(testVerity)),
		},
		WorkDir:   workDir,
		RootMount: filepath.Join(workDir, "sysroot"),
		Client:    server.Client(),
		Runner:    rec.run,
	}
}

func TestMountDisklessRootFetchesVerifiesAndMountsOverlay(t *testing.T) {
	rec := &disklessRecorder{}
	cfg := testDisklessConfig(t, artifactServer(t, nil), rec)
	mount, err := MountDisklessRoot(context.Background(), cfg)
	if err != nil {
		t.Fatalf("MountDisklessRoot: %v", err)
	}
	if mount.DataLoop != "/dev/loop10" || mount.HashLoop != "/dev/loop11" || mount.MapperPath != "/dev/mapper/platform-root" {
		t.Fatalf("unexpected mount result: %#v", mount)
	}
	for path, want := range map[string][]byte{mount.RootFSPath: testRootFS, mount.VerityPath: testVerity} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("fetched %s: %d bytes, %v", path, len(got), err)
		}
	}
	overlay := filepath.Join(cfg.WorkDir, "overlay")
	want := []string{
		"losetup --find --show --read-only " + mount.RootFSPath,
		"losetup --find --show --read-only " + mount.VerityPath,
		"dmsetup create platform-root --readonly --table " +
			"0 16 verity 1 /dev/loop10 /dev/loop11 4096 4096 2 0 sha256 " + testRootHash + " " + testSalt + " 1 panic_on_corruption",
		"mount -t squashfs -o ro /dev/mapper/platform-root " + mount.LowerDir,
		"mount -t tmpfs -o mode=755,size=25% tmpfs " + overlay,
		"mount -t overlay -o lowerdir=" + mount.LowerDir + ",upperdir=" + overlay + "/upper,workdir=" + overlay + "/work overlay " + cfg.RootMount,
	}
	if !slices.Equal(rec.calls, want) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(rec.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestMountDisklessRootUndoesEveryStepNewestFirst(t *testing.T) {
	rec := &disklessRecorder{fail: map[string]error{"-t overlay": errors.New("no overlayfs")}}
	cfg := testDisklessConfig(t, artifactServer(t, nil), rec)
	_, err := MountDisklessRoot(context.Background(), cfg)
	var cmdErr *DisklessCommandError
	if !errors.As(err, &cmdErr) || cmdErr.Step != "mount the root overlay" {
		t.Fatalf("MountDisklessRoot = %v, want the overlay mount error", err)
	}
	want := []string{
		"umount " + filepath.Join(cfg.WorkDir, "overlay"),
		"umount " + filepath.Join(cfg.WorkDir, "lower"),
		"dmsetup remove platform-root",
		"losetup -d /dev/loop11",
		"losetup -d /dev/loop10",
	}
	if got := rec.calls[len(rec.calls)-len(want):]; !slices.Equal(got, want) {
		t.Fatalf("cleanup:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	assertArtifactsRemoved(t, cfg.WorkDir)
}

func TestMountDisklessRootFailsClosedOnVerityMismatch(t *testing.T) {
	rec := &disklessRecorder{fail: map[string]error{"dmsetup create": errors.New("root hash mismatch")}}
	cfg := testDisklessConfig(t, artifactServer(t, nil), rec)
	_, err := MountDisklessRoot(context.Background(), cfg)
	var cmdErr *DisklessCommandError
	if !errors.As(err, &cmdErr) || cmdErr.Step != "open dm-verity" {
		t.Fatalf("MountDisklessRoot = %v, want the dm-verity error", err)
	}
	for _, call := range rec.calls {
		if strings.HasPrefix(call, "mount ") {
			t.Fatalf("a rejected image must never be mounted, got %q", call)
		}
	}
	want := []string{"losetup -d /dev/loop11", "losetup -d /dev/loop10"}
	if got := rec.calls[len(rec.calls)-2:]; !slices.Equal(got, want) {
		t.Fatalf("cleanup = %q, want %q", got, want)
	}
	assertArtifactsRemoved(t, cfg.WorkDir)
}

func TestMountDisklessRootReportsAFailedCleanupAndCarriesOn(t *testing.T) {
	rec := &disklessRecorder{fail: map[string]error{
		"-t squashfs":    errors.New("bad superblock"),
		"dmsetup remove": errors.New("device busy"),
	}}
	cfg := testDisklessConfig(t, artifactServer(t, nil), rec)
	if _, err := MountDisklessRoot(context.Background(), cfg); err == nil {
		t.Fatal("MountDisklessRoot succeeded with a failing squashfs mount")
	}
	want := []string{"dmsetup remove platform-root", "losetup -d /dev/loop11", "losetup -d /dev/loop10"}
	if got := rec.calls[len(rec.calls)-3:]; !slices.Equal(got, want) {
		t.Fatalf("cleanup = %q, want %q", got, want)
	}
}

func TestRemoveDisklessArtifact(t *testing.T) {
	dir := t.TempDir()
	fetched := filepath.Join(dir, disklessroot.RootFSFile)
	if err := os.WriteFile(fetched, testRootFS, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeDisklessArtifact(fetched); err != nil {
		t.Fatalf("remove a fetched artifact: %v", err)
	}
	if _, err := os.Stat(fetched); !os.IsNotExist(err) {
		t.Fatalf("the artifact is still in RAM: %v", err)
	}
	// A fetch that failed before creating its file left nothing to remove.
	if err := removeDisklessArtifact(filepath.Join(dir, disklessroot.VerityFile)); err != nil {
		t.Fatalf("remove an artifact never fetched: %v", err)
	}
}

func TestRemoveDisklessArtifactReportsAFailedRemoval(t *testing.T) {
	// A non-empty directory cannot be removed with os.Remove.
	stuck := filepath.Join(t.TempDir(), disklessroot.RootFSFile)
	if err := os.MkdirAll(filepath.Join(stuck, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := removeDisklessArtifact(stuck)
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !strings.Contains(err.Error(), stuck) {
		t.Fatalf("err = %v, want a WrappedError naming %s", err, stuck)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed removal was reported as an absent artifact: %v", err)
	}
}

func TestRemoveDisklessArtifactsCarriesOnPastAFailure(t *testing.T) {
	dir := t.TempDir()
	stuck := filepath.Join(dir, disklessroot.RootFSFile)
	if err := os.MkdirAll(filepath.Join(stuck, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	fetched := filepath.Join(dir, disklessroot.VerityFile)
	if err := os.WriteFile(fetched, testVerity, 0o600); err != nil {
		t.Fatal(err)
	}
	removeDisklessArtifacts(stuck, fetched)
	if _, err := os.Stat(fetched); !os.IsNotExist(err) {
		t.Fatalf("a failure on the first artifact kept the second in RAM: %v", err)
	}
}

func TestMountDisklessRootDetachesTheDataLoopWhenTheHashLoopFails(t *testing.T) {
	rec := &disklessRecorder{fail: map[string]error{disklessroot.VerityFile: errors.New("no free loop device")}}
	cfg := testDisklessConfig(t, artifactServer(t, nil), rec)
	_, err := MountDisklessRoot(context.Background(), cfg)
	var cmdErr *DisklessCommandError
	if !errors.As(err, &cmdErr) || cmdErr.Step != "attach the hash tree" {
		t.Fatalf("MountDisklessRoot = %v, want the hash tree attach error", err)
	}
	if last := rec.calls[len(rec.calls)-1]; last != "losetup -d /dev/loop10" {
		t.Fatalf("last command = %q, want the data loop detached", last)
	}
}

func TestMountDisklessRootRejectsBadFetches(t *testing.T) {
	rootfsPath := "/" + disklessroot.RootFSFile
	short := testRootFS[:len(testRootFS)-1]
	long := append(bytes.Clone(testRootFS), 'x')
	cases := map[string]struct {
		handler http.HandlerFunc
		check   func(t *testing.T, err error)
	}{
		"non-2xx": {
			handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "gone", http.StatusForbidden) },
			check: func(t *testing.T, err error) {
				var statusErr *DisklessHTTPStatusError
				if !errors.As(err, &statusErr) || !strings.Contains(statusErr.Error(), "403") {
					t.Fatalf("err = %v, want a 403 status error", err)
				}
			},
		},
		"content length differs from the signed size": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(long)))
				writeBody(t, w, long)
			},
			check: wantSizeError(int64(len(long))),
		},
		"truncated body": {
			handler: chunked(t, short),
			check:   wantSizeError(int64(len(short))),
		},
		"oversized body is cut one byte past the signed size": {
			handler: chunked(t, append(long, bytes.Repeat([]byte("x"), 1<<16)...)),
			check:   wantSizeError(int64(len(testRootFS)) + 1),
		},
		"connection dropped mid-body": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(testRootFS)))
				writeBody(t, w, short)
			},
			check: func(t *testing.T, err error) {
				var fetchErr *DisklessFetchError
				if !errors.As(err, &fetchErr) {
					t.Fatalf("err = %v, want a fetch error", err)
				}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &disklessRecorder{}
			cfg := testDisklessConfig(t, artifactServer(t, map[string]http.HandlerFunc{rootfsPath: tc.handler}), rec)
			_, err := MountDisklessRoot(context.Background(), cfg)
			tc.check(t, err)
			if len(rec.calls) != 0 {
				t.Fatalf("a failed fetch ran commands: %q", rec.calls)
			}
			assertArtifactsRemoved(t, cfg.WorkDir)
		})
	}
}

func TestMountDisklessRootRejectsInvalidParamsBeforeFetching(t *testing.T) {
	fetched := false
	server := artifactServer(t, map[string]http.HandlerFunc{
		"/" + disklessroot.RootFSFile: func(http.ResponseWriter, *http.Request) { fetched = true },
	})
	rec := &disklessRecorder{}
	cfg := testDisklessConfig(t, server, rec)
	cfg.Params.RootFSURL = "file:///etc/shadow"
	_, err := MountDisklessRoot(context.Background(), cfg)
	var fieldErr *disklessroot.FieldError
	if !errors.As(err, &fieldErr) || fieldErr.Field != disklessroot.ParamRootFSURL {
		t.Fatalf("MountDisklessRoot = %v, want a rootfs URL field error", err)
	}
	if fetched || len(rec.calls) != 0 {
		t.Fatal("invalid parameters must be rejected before any fetch or command")
	}
}

func TestMountDisklessRootFetchErrors(t *testing.T) {
	server := artifactServer(t, nil)
	t.Run("unreachable server", func(t *testing.T) {
		cfg := testDisklessConfig(t, server, &disklessRecorder{})
		cfg.Params.VerityURL = "http://127.0.0.1:1/" + disklessroot.VerityFile
		var fetchErr *DisklessFetchError
		if _, err := MountDisklessRoot(context.Background(), cfg); !errors.As(err, &fetchErr) || fetchErr.URL != cfg.Params.VerityURL {
			t.Fatalf("MountDisklessRoot = %v, want a verity fetch error", err)
		}
		assertArtifactsRemoved(t, cfg.WorkDir)
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cfg := testDisklessConfig(t, server, &disklessRecorder{})
		var fetchErr *DisklessFetchError
		if _, err := MountDisklessRoot(ctx, cfg); !errors.As(err, &fetchErr) || !errors.Is(err, context.Canceled) {
			t.Fatalf("MountDisklessRoot = %v, want a cancelled fetch", err)
		}
	})
	t.Run("work directory cannot be created", func(t *testing.T) {
		cfg := testDisklessConfig(t, server, &disklessRecorder{})
		blocker := filepath.Join(cfg.WorkDir, "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.WorkDir = filepath.Join(blocker, "work")
		var wrapped *WrappedError
		if _, err := MountDisklessRoot(context.Background(), cfg); !errors.As(err, &wrapped) {
			t.Fatalf("MountDisklessRoot = %v, want a wrapped mkdir error", err)
		}
	})
}

func TestDisklessRootConfigDefaults(t *testing.T) {
	var cfg DisklessRootConfig
	cfg.withDefaults()
	if cfg.WorkDir != defaultDisklessWorkDir || cfg.RootMount != defaultDisklessRootMount ||
		cfg.Mapper != defaultDisklessMapper || cfg.OverlaySize != defaultDisklessOverlaySize || cfg.Runner == nil {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.Client == nil || cfg.Client.Timeout != disklessFetchTimeout {
		t.Fatalf("default client = %+v, want a %s timeout", cfg.Client, disklessFetchTimeout)
	}
	transport, ok := cfg.Client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.ResponseHeaderTimeout != disklessConnectTimeout {
		t.Fatalf("default transport = %+v, want no proxy and a header timeout", cfg.Client.Transport)
	}

	custom := DisklessRootConfig{WorkDir: "/w", RootMount: "/r", Mapper: "m", OverlaySize: "1G"}
	custom.withDefaults()
	if custom.WorkDir != "/w" || custom.RootMount != "/r" || custom.Mapper != "m" || custom.OverlaySize != "1G" {
		t.Fatalf("withDefaults overwrote explicit values: %+v", custom)
	}
}

func TestRunDisklessCommand(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runDisklessCommand(context.Background(), self, "-test.run=^$"); err != nil {
		t.Fatalf("runDisklessCommand(test binary) = %v", err)
	}
	if _, err := runDisklessCommand(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("runDisklessCommand of a missing binary succeeded")
	}
}

func TestDisklessErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	cmdErr := &DisklessCommandError{Step: "open dm-verity", Err: cause, Output: "bad hash"}
	if cmdErr.Error() != "diskless root: open dm-verity: boom: bad hash" || !errors.Is(cmdErr, cause) {
		t.Fatalf("DisklessCommandError = %q", cmdErr.Error())
	}
	if bare := (&DisklessCommandError{Step: "s", Err: cause}).Error(); bare != "diskless root: s: boom" {
		t.Fatalf("DisklessCommandError without output = %q", bare)
	}
	sizeErr := &DisklessSizeError{URL: "http://b/r", Want: 8192, Got: 8193}
	if sizeErr.Error() != "diskless root: http://b/r: got 8193 bytes, the signed size is 8192" {
		t.Fatalf("DisklessSizeError = %q", sizeErr.Error())
	}
	fetchErr := &DisklessFetchError{URL: "http://b/r", Err: cause}
	if fetchErr.Error() != "diskless root: fetch http://b/r: boom" || !errors.Is(fetchErr, cause) {
		t.Fatalf("DisklessFetchError = %q", fetchErr.Error())
	}
}

func wantSizeError(got int64) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var sizeErr *DisklessSizeError
		if !errors.As(err, &sizeErr) || sizeErr.Want != int64(len(testRootFS)) || sizeErr.Got != got {
			t.Fatalf("err = %v, want a size error reporting %d bytes", err, got)
		}
	}
}

// chunked serves body without a Content-Length, so only the reader's own
// bound decides how much of it is accepted.
func chunked(t *testing.T, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer cannot flush")
			return
		}
		flusher.Flush()
		writeBody(t, w, body)
	}
}

func writeBody(t *testing.T, w http.ResponseWriter, body []byte) {
	// The client may hang up once it has read past the signed size.
	if _, err := w.Write(body); err != nil {
		t.Logf("write body: %v", err)
	}
}

func assertArtifactsRemoved(t *testing.T, workDir string) {
	t.Helper()
	for _, name := range []string{disklessroot.RootFSFile, disklessroot.VerityFile} {
		if _, err := os.Stat(filepath.Join(workDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left in RAM after a failed mount: %v", name, err)
		}
	}
}
