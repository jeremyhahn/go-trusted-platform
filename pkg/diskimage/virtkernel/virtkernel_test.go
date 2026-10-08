package virtkernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
)

// repoBuilderDir is build/docker/virt-kernel-builder in this checkout.
func repoBuilderDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "build", "docker", "virt-kernel-builder"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Makefile")); err != nil {
		t.Fatalf("builder directory not found: %v", err)
	}
	return dir
}

// fakeBuilderDir is a builder directory with the inputs the cache key hashes.
// It sits one level down in its own temporary directory so the shared
// kernel configuration (KernelConfigDir, a sibling of the builder) lands
// inside that directory too.
func fakeBuilderDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "virt-kernel-builder")
	for _, rel := range configInputs {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel+" content\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// writeOutput lays out a flavour directory the way the builder does.
func writeOutput(t *testing.T, outputDir, flavor, release, key string) {
	t.Helper()
	dir := filepath.Join(outputDir, flavor)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"vmlinuz-" + flavor:             "kernel",
		"modules-" + flavor + ".tar.gz": "modules",
		"System.map-" + flavor:          "map",
		"config-" + flavor:              "config",
		"kernel-version.txt":            release + "\n",
	}
	var sums string
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		sums += hex.EncodeToString(sum[:]) + "  ./" + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"kernel_version":"` + DefaultVersion + `","kernel_release":"` + release + `","tarball_sha256":"` + DefaultTarballSHA256 + `","cache_key":"` + key + `","flavor":"` + flavor + `","built_at":"now"}`
	if err := os.WriteFile(filepath.Join(outputDir, ManifestName), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCacheKeyMatchesMakeCacheKey(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatal("make is required for this test")
	}
	builder := repoBuilderDir(t)
	got, err := CacheKey(builder, DefaultVersion, DefaultLocalVersion)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("make", "-s", "-C", builder, "cache-key").CombinedOutput()
	if err != nil {
		t.Fatalf("make cache-key: %v\n%s", err, out)
	}
	if want := strings.TrimSpace(string(out)); got != want {
		t.Errorf("CacheKey = %s, make cache-key = %s", got, want)
	}
}

func TestPinsMatchBuilderMakefile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoBuilderDir(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"KERNEL_VERSION ?= " + DefaultVersion,
		"KERNEL_SHA256  ?= " + DefaultTarballSHA256,
		"KERNEL_LOCALVERSION ?= " + DefaultLocalVersion,
		"KERNEL_FLAVOR  ?= " + DefaultFlavor,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("builder Makefile lacks %q", want)
		}
	}
}

func TestCacheKey_ChangesWithEveryInput(t *testing.T) {
	builder := fakeBuilderDir(t)
	base, err := CacheKey(builder, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range configInputs {
		path := filepath.Join(builder, rel)
		original, _ := os.ReadFile(path)
		if err := os.WriteFile(path, append(original, '#'), 0o644); err != nil {
			t.Fatal(err)
		}
		changed, err := CacheKey(builder, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if changed == base {
			t.Errorf("changing %s did not change the cache key", rel)
		}
		if err := os.WriteFile(path, original, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := CacheKey(builder, "6.12.111", "")
	if other == base {
		t.Error("the version is not part of the key")
	}
	if _, err := CacheKey(t.TempDir(), "", ""); err == nil {
		t.Error("a builder directory without inputs must fail")
	} else {
		var input *InputError
		if !errors.As(err, &input) {
			t.Errorf("err = %T", err)
		}
	}
}

func TestLocate(t *testing.T) {
	out := t.TempDir()
	writeOutput(t, out, "virt", "6.12.110-0-virt", "k")

	art, err := Locate(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if art.Release != "6.12.110-0-virt" || art.Flavor != "virt" {
		t.Errorf("artifacts = %+v", art)
	}
	if filepath.Base(art.Kernel) != "vmlinuz-virt" || filepath.Base(art.Modules) != "modules-virt.tar.gz" || filepath.Base(art.Config) != "config-virt" {
		t.Errorf("artifacts = %+v", art)
	}

	// A tampered kernel is a checksum mismatch, not an artifact.
	if err := os.WriteFile(art.Kernel, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mismatch *artifacts.ChecksumMismatchError
	if _, err := Locate(out, "virt"); !errors.As(err, &mismatch) {
		t.Errorf("err = %v", err)
	}

	// A missing flavour names the fix.
	var missing *artifacts.MissingError
	if _, err := Locate(t.TempDir(), "virt"); !errors.As(err, &missing) || missing.Hint != Hint {
		t.Errorf("err = %v", err)
	}
}

func TestReadManifest(t *testing.T) {
	out := t.TempDir()
	writeOutput(t, out, "virt", "6.12.110-0-virt", "key")
	m, err := ReadManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.CacheKey != "key" || m.Release != "6.12.110-0-virt" || m.Version != DefaultVersion {
		t.Errorf("manifest = %+v", m)
	}
	var manifestErr *ManifestError
	if _, err := ReadManifest(t.TempDir()); !errors.As(err, &manifestErr) {
		t.Errorf("missing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, ManifestName), []byte(`{"kernel_version":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(out); !errors.As(err, &manifestErr) {
		t.Errorf("incomplete manifest: %v", err)
	}
}

// recordingRunner records docker invocations and answers with a scripted
// output directory.
type recordingRunner struct {
	calls   [][]string
	onRun   func()
	failAt  int
	failErr error
}

func (r *recordingRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.failErr != nil && len(r.calls) == r.failAt {
		return nil, r.failErr
	}
	if len(args) > 0 && args[0] == "start" && r.onRun != nil {
		r.onRun()
	}
	return nil, nil
}

// verbs is the runtime subcommand of every recorded call.
func verbs(calls [][]string) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call[1])
	}
	return out
}

func TestBuild_UsesTheCacheWhenTheManifestMatches(t *testing.T) {
	builder := fakeBuilderDir(t)
	out := filepath.Join(builder, "output")
	key, _ := CacheKey(builder, "", "")
	writeOutput(t, out, "virt", "6.12.110-0-virt", key)
	rec := &recordingRunner{}

	art, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("docker ran %d times for a cached build", len(rec.calls))
	}
	if art.Release != "6.12.110-0-virt" {
		t.Errorf("artifacts = %+v", art)
	}
}

func TestBuild_RunsTheBuilderAndVerifiesTheManifest(t *testing.T) {
	builder := fakeBuilderDir(t)
	out := filepath.Join(builder, "output")
	key, _ := CacheKey(builder, "", "")
	rec := &recordingRunner{}
	rec.onRun = func() { writeOutput(t, out, "virt", "6.12.110-0-virt", key) }

	art, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, CacheVolume: "my-cache"})
	if err != nil {
		t.Fatal(err)
	}
	if art.Kernel != filepath.Join(out, "virt", "vmlinuz-virt") {
		t.Errorf("kernel = %s", art.Kernel)
	}
	// Image build, then create, start, cp out, rm: nothing to copy in, the
	// Kconfig fragment is baked into the image.
	if got, want := strings.Join(verbs(rec.calls), ","), "build,create,start,cp,rm"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	build := strings.Join(rec.calls[0], " ")
	wantContext := "--build-context kernelconfig=" + filepath.Join(filepath.Dir(builder), "kernel-config")
	if !strings.Contains(build, wantContext) {
		t.Errorf("docker build lacks %q:\n%s", wantContext, build)
	}
	run := strings.Join(rec.calls[1], " ")
	for _, want := range []string{
		"docker create --name builder-",
		"-v my-cache:/build/src",
		"-e KERNEL_VERSION=" + DefaultVersion,
		"-e KERNEL_SHA256=" + DefaultTarballSHA256,
		"-e KERNEL_LOCALVERSION=" + DefaultLocalVersion,
		"-e KERNEL_FLAVOR=virt",
		"-e KERNEL_CACHE_KEY=" + key,
		"trusted-platform-virt-kernel-builder:" + DefaultVersion,
	} {
		if !strings.Contains(run, want) {
			t.Errorf("docker run lacks %q:\n%s", want, run)
		}
	}
	// A bind mount resolves on the daemon's filesystem and arrives empty (or
	// never reaches the checkout) when the build runs in a CI job container:
	// the fragment is baked into the image and the artifacts come out with cp.
	for _, call := range rec.calls {
		for _, arg := range call {
			if strings.HasPrefix(arg, "/") && strings.Contains(arg, ":") {
				t.Errorf("host bind mount %q in %v", arg, call)
			}
		}
	}
	if cp := strings.Join(rec.calls[3], " "); !strings.HasSuffix(cp, ":/output/. "+artifacts.AbsPath(out)) {
		t.Errorf("cp out = %q", cp)
	}
}

func TestBuild_Failures(t *testing.T) {
	boom := errors.New("boom")
	t.Run("image build", func(t *testing.T) {
		builder := fakeBuilderDir(t)
		rec := &recordingRunner{failAt: 1, failErr: boom}
		_, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder})
		var buildErr *BuildError
		if !errors.As(err, &buildErr) || !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("builder run", func(t *testing.T) {
		builder := fakeBuilderDir(t)
		rec := &recordingRunner{failAt: 3, failErr: boom}
		_, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder})
		if !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("stale manifest after a run", func(t *testing.T) {
		builder := fakeBuilderDir(t)
		out := filepath.Join(builder, "output")
		rec := &recordingRunner{}
		rec.onRun = func() { writeOutput(t, out, "virt", "6.12.110-0-virt", "not-the-key") }
		_, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder})
		var manifestErr *ManifestError
		if !errors.As(err, &manifestErr) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no builder inputs", func(t *testing.T) {
		_, err := Build(context.Background(), Options{Runner: (&recordingRunner{}).run, BuilderDir: t.TempDir()})
		var input *InputError
		if !errors.As(err, &input) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestErrorStrings(t *testing.T) {
	cause := errors.New("cause")
	for _, err := range []error{&ManifestError{Path: "p", Err: cause}, &InputError{Path: "p", Err: cause}, &BuildError{Step: "s", Err: cause}} {
		if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "virtkernel: ") {
			t.Errorf("%T: %v", err, err)
		}
	}
	if trimNewline("6.12.110-0-virt\r\n") != "6.12.110-0-virt" {
		t.Error("trimNewline")
	}
}
