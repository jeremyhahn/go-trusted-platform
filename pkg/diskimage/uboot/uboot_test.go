package uboot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoBuilderDir is the real builder directory in this checkout.
func repoBuilderDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "build", "docker", "uboot-builder"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Makefile")); err != nil {
		t.Fatalf("builder directory not found at %s: %v", dir, err)
	}
	return dir
}

// fakeKeys writes three placeholder certificate files (content only matters
// for hashing here).
func fakeKeys(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range certificateFiles {
		if err := writeFile(dir, name, "cert "+name); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeFile(dir, name, body string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
}

func TestPinsMatchBuilderMakefile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoBuilderDir(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"UBOOT_VERSION":    DefaultVersion,
		"UBOOT_SHA256":     DefaultTarballSHA256,
		"UBOOT_OWNER_GUID": DefaultOwnerGUID,
	} {
		re := regexp.MustCompile(`(?m)^` + name + `\s*\?=\s*(\S+)`)
		m := re.FindSubmatch(data)
		if m == nil {
			t.Errorf("builder Makefile does not set %s", name)
			continue
		}
		if string(m[1]) != want {
			t.Errorf("builder Makefile %s = %s, Go default is %s", name, m[1], want)
		}
	}
	// Every hashed input exists in the builder directory.
	for _, rel := range configInputs {
		if _, err := os.Stat(filepath.Join(repoBuilderDir(t), rel)); err != nil {
			t.Errorf("cache key input %s missing: %v", rel, err)
		}
	}
}

func TestCacheKeyMatchesMakeCacheKey(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatal("make is required for this test")
	}
	builder := repoBuilderDir(t)
	keys := fakeKeys(t)
	got, err := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("make", "-s", "-C", builder, "cache-key", "KEYS_DIR="+keys).CombinedOutput()
	if err != nil {
		t.Fatalf("make cache-key: %v\n%s", err, out)
	}
	if want := strings.TrimSpace(string(out)); got != want {
		t.Errorf("CacheKey = %s, make cache-key = %s", got, want)
	}

	// The key changes with any input and with the version.
	if err := os.WriteFile(filepath.Join(keys, "DB.crt"), []byte("rotated"), 0o644); err != nil {
		t.Fatal(err)
	}
	rotated, err := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == got {
		t.Error("CacheKey did not change when DB.crt changed")
	}
	other, err := CacheKey(builder, keys, "2099.01", DefaultOwnerGUID)
	if err != nil {
		t.Fatal(err)
	}
	if other == rotated {
		t.Error("CacheKey did not change with the version")
	}

	// The owner GUID is written into every preseeded signature list, so a
	// different GUID is a different binary: both implementations must
	// include it, and agree on it.
	const fleetGUID = "11111111-2222-3333-4444-555555555555"
	owned, err := CacheKey(builder, keys, DefaultVersion, fleetGUID)
	if err != nil {
		t.Fatal(err)
	}
	if owned == rotated {
		t.Error("CacheKey did not change with the owner GUID")
	}
	out, err = exec.Command("make", "-s", "-C", builder, "cache-key", "KEYS_DIR="+keys, "UBOOT_OWNER_GUID="+fleetGUID).CombinedOutput()
	if err != nil {
		t.Fatalf("make cache-key with an owner GUID: %v\n%s", err, out)
	}
	if want := strings.TrimSpace(string(out)); owned != want {
		t.Errorf("CacheKey with owner GUID = %s, make cache-key = %s", owned, want)
	}
}

// TestCacheKeyCoversTheBuilder pins that the builder's own files are
// inputs: a fix to the build script, the ESL writer or the image recipe
// must miss the cache, or an old u-boot.bin is staged into a new image
// under a manifest that reports a matching key (review finding on #680).
func TestCacheKeyCoversTheBuilder(t *testing.T) {
	for _, name := range []string{"Dockerfile", "build-uboot.sh", "mkesl.py"} {
		found := false
		for _, rel := range configInputs {
			if rel == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not a cache-key input", name)
		}
	}
}

func TestCacheKeyMissingInput(t *testing.T) {
	_, err := CacheKey(repoBuilderDir(t), t.TempDir(), "", "")
	var input *InputError
	if !errors.As(err, &input) || !strings.HasSuffix(input.Path, "PK.crt") {
		t.Errorf("CacheKey without certificates error = %v, want *InputError for PK.crt", err)
	}
}

// writeArtifacts lays out a fake builder output tree with correct checksums.
func writeArtifacts(t *testing.T, out, cacheKey string) {
	t.Helper()
	files := map[string]string{
		"rpi_arm64/u-boot.bin":                 "rpi binary",
		"rpi_arm64/u-boot.config":              "CONFIG_TPM2_TIS_SPI=y\n",
		"rpi_arm64/overlays/tpm-soft-spi.dtbo": "dtbo",
		"qemu_arm64/u-boot.bin":                "qemu binary",
		"qemu_arm64/u-boot.config":             "CONFIG_TPM2_MMIO=y\n",
	}
	for rel, body := range files {
		path := filepath.Join(out, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, board := range Boards {
		dir := filepath.Join(out, string(board))
		var sums strings.Builder
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			data, _ := os.ReadFile(path)
			sum := sha256.Sum256(data)
			sums.WriteString(hex.EncodeToString(sum[:]) + "  ./" + rel + "\n")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := Manifest{Version: DefaultVersion, TarballSHA256: DefaultTarballSHA256, CacheKey: cacheKey, OwnerGUID: DefaultOwnerGUID,
		Boards: []string{"rpi_arm64", "qemu_arm64"}, MeasuredPCRs: []int{0, 1, 2, 4, 5, 7}, BuiltAt: "2026-09-16T00:00:00Z"}
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(out, ManifestName), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLocateVerifiesEveryFile(t *testing.T) {
	out := t.TempDir()
	writeArtifacts(t, out, "key")
	found, err := Locate(out)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	rpi := found[BoardRPiArm64]
	if rpi.Binary != filepath.Join(out, "rpi_arm64", "u-boot.bin") || rpi.OverlaysDir != filepath.Join(out, "rpi_arm64", "overlays") {
		t.Errorf("rpi artifacts = %+v", rpi)
	}
	if found[BoardQEMUArm64].OverlaysDir != "" {
		t.Errorf("qemu artifacts carry an overlays dir: %+v", found[BoardQEMUArm64])
	}

	// A tampered binary is rejected.
	if err := os.WriteFile(rpi.Binary, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mismatch *ChecksumMismatchError
	if _, err := Locate(out); !errors.As(err, &mismatch) || mismatch.Path != rpi.Binary {
		t.Errorf("Locate with a tampered binary error = %v", err)
	}
	writeArtifacts(t, out, "key")

	// A file with no checksum entry is rejected.
	if err := os.WriteFile(filepath.Join(out, "qemu_arm64", "extra.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Locate(out); !errors.As(err, &mismatch) || mismatch.Reason != "no SHA256SUMS entry" {
		t.Errorf("Locate with an unlisted file error = %v", err)
	}
	if err := os.Remove(filepath.Join(out, "qemu_arm64", "extra.bin")); err != nil {
		t.Fatal(err)
	}

	// A missing overlay or board is an ArtifactMissingError that names the fix.
	if err := os.Remove(filepath.Join(out, "rpi_arm64", "overlays", "tpm-soft-spi.dtbo")); err != nil {
		t.Fatal(err)
	}
	var missing *ArtifactMissingError
	if _, err := Locate(out); !errors.As(err, &missing) || !strings.Contains(missing.Hint, "uboot-build") {
		t.Errorf("Locate without the overlay error = %v", err)
	}
	if _, err := Locate(t.TempDir()); !errors.As(err, &missing) {
		t.Errorf("Locate on an empty dir error = %v", err)
	}
}

func TestReadManifest(t *testing.T) {
	out := t.TempDir()
	writeArtifacts(t, out, "abc")
	m, err := ReadManifest(out)
	if err != nil || m.CacheKey != "abc" || m.Version != DefaultVersion || len(m.MeasuredPCRs) != 6 {
		t.Errorf("ReadManifest = %+v, %v", m, err)
	}
	var manifestErr *ManifestError
	if _, err := ReadManifest(t.TempDir()); !errors.As(err, &manifestErr) {
		t.Errorf("missing manifest error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, ManifestName), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(out); !errors.As(err, &manifestErr) {
		t.Errorf("malformed manifest error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, ManifestName), []byte(`{"uboot_version":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(out); !errors.As(err, &manifestErr) {
		t.Errorf("incomplete manifest error = %v", err)
	}
}

// recordingRunner records every invocation and lays out artifacts when the
// builder container is started.
type recordingRunner struct {
	t     *testing.T
	calls [][]string
	out   string
	key   string
	fail  string
}

func (r *recordingRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.fail != "" && args[0] == r.fail {
		return []byte("boom"), errors.New("exit 1")
	}
	if args[0] == "start" {
		writeArtifacts(r.t, r.out, r.key)
	}
	return nil, nil
}

func TestBuildRunsTheBuilderAndVerifies(t *testing.T) {
	builder := repoBuilderDir(t)
	keys := fakeKeys(t)
	out := t.TempDir()
	key, err := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingRunner{t: t, out: out, key: key}
	found, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys, CacheVolume: "my-cache"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(found) != 2 {
		t.Errorf("Build returned %d boards", len(found))
	}
	// Image build, then create, one cp per input in, start, cp out, rm.
	if got, want := strings.Join(verbs(rec.calls), ","), "build,create,cp,cp,cp,start,cp,rm"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	build := strings.Join(rec.calls[0], " ")
	if !strings.Contains(build, "docker build -t trusted-platform-uboot-builder:"+DefaultVersion+" "+builder) {
		t.Errorf("image build argv = %q", build)
	}
	create := strings.Join(rec.calls[1], " ")
	for _, want := range []string{
		"docker create --name builder-",
		"-v my-cache:/build/src",
		"-e UBOOT_VERSION=" + DefaultVersion,
		"-e UBOOT_SHA256=" + DefaultTarballSHA256,
		"-e UBOOT_OWNER_GUID=" + DefaultOwnerGUID,
		"-e UBOOT_CACHE_KEY=" + key,
		" trusted-platform-uboot-builder:" + DefaultVersion,
	} {
		if !strings.Contains(create, want) {
			t.Errorf("create argv %q lacks %q", create, want)
		}
	}
	// No host path is bind-mounted: the daemon may not see this filesystem.
	for _, arg := range rec.calls[1] {
		if strings.HasPrefix(arg, "/") && strings.Contains(arg, ":") {
			t.Errorf("host bind mount %q in %q", arg, create)
		}
	}
	// Inputs are copied in, the artifacts copied out.
	for i, want := range []string{
		absPath(keys) + "/. ",
		absPath(filepath.Join(builder, "configs")) + "/. ",
		absPath(filepath.Join(builder, "patches")) + "/. ",
	} {
		if cp := strings.Join(rec.calls[2+i], " "); !strings.Contains(cp, " cp "+want) {
			t.Errorf("cp in %q lacks %q", cp, want)
		}
	}
	if cp := strings.Join(rec.calls[6], " "); !strings.HasSuffix(cp, ":/output/. "+absPath(out)) {
		t.Errorf("cp out = %q", cp)
	}

	// Second build with the same inputs is a cache hit: no runner calls.
	rec.calls = nil
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys}); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("cache hit still ran %v", rec.calls)
	}

	// Rotated keys miss the cache and rebuild.
	if err := os.WriteFile(filepath.Join(keys, "PK.crt"), []byte("new PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	newKey, _ := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID)
	rec.key = newKey
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys}); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 8 {
		t.Errorf("rotated keys did not rebuild: %v", rec.calls)
	}
}

func TestBuildFailures(t *testing.T) {
	builder := repoBuilderDir(t)
	keys := fakeKeys(t)
	out := t.TempDir()
	key, _ := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID)

	var buildErr *BuildError
	rec := &recordingRunner{t: t, out: out, key: key, fail: "build"}
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys}); !errors.As(err, &buildErr) || buildErr.Step != "building the builder image" {
		t.Errorf("image build failure error = %v", err)
	}
	rec = &recordingRunner{t: t, out: out, key: key, fail: "start"}
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys}); !errors.As(err, &buildErr) || buildErr.Step != "running the builder" {
		t.Errorf("builder run failure error = %v", err)
	}

	// A builder that writes a manifest for other inputs is rejected.
	rec = &recordingRunner{t: t, out: out, key: "stale"}
	var manifestErr *ManifestError
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: keys}); !errors.As(err, &manifestErr) {
		t.Errorf("stale manifest error = %v", err)
	}

	// Missing certificates fail before any container runs.
	rec = &recordingRunner{t: t, out: out, key: key}
	var input *InputError
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: out, KeysDir: t.TempDir()}); !errors.As(err, &input) || len(rec.calls) != 0 {
		t.Errorf("missing keys error = %v, calls = %v", err, rec.calls)
	}
}

func TestErrorMessages(t *testing.T) {
	cases := map[error]string{
		&ArtifactMissingError{Path: "/o/u-boot.bin", Hint: "run make"}: "uboot: artifact /o/u-boot.bin is missing (run make)",
		&ChecksumMismatchError{Path: "/o/x", Reason: "bad"}:            "uboot: /o/x: bad",
		&ManifestError{Path: "/o/m", Err: errors.New("e")}:             "uboot: manifest /o/m: e",
		&InputError{Path: "/k/PK.crt", Err: errors.New("e")}:           "uboot: build input /k/PK.crt: e",
		&BuildError{Step: "s", Err: errors.New("e")}:                   "uboot: s: e",
	}
	for err, want := range cases {
		if err.Error() != want {
			t.Errorf("%T.Error() = %q, want %q", err, err.Error(), want)
		}
	}
	inner := errors.New("inner")
	for _, err := range []error{&ManifestError{Err: inner}, &InputError{Err: inner}, &BuildError{Err: inner}} {
		if !errors.Is(err, inner) {
			t.Errorf("%T does not unwrap", err)
		}
	}
}

func TestVerifyChecksumsRejectsMalformedSums(t *testing.T) {
	out := t.TempDir()
	writeArtifacts(t, out, "key")
	sums := filepath.Join(out, "qemu_arm64", "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("not-a-checksum-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mismatch *ChecksumMismatchError
	if err := verifyChecksums(filepath.Join(out, "qemu_arm64")); !errors.As(err, &mismatch) || !strings.Contains(mismatch.Reason, "malformed") {
		t.Errorf("malformed SHA256SUMS error = %v", err)
	}
	if err := os.Remove(sums); err != nil {
		t.Fatal(err)
	}
	var missing *ArtifactMissingError
	if err := verifyChecksums(filepath.Join(out, "qemu_arm64")); !errors.As(err, &missing) {
		t.Errorf("missing SHA256SUMS error = %v", err)
	}
	// An asterisk (binary mode) marker in the sums file is tolerated.
	writeArtifacts(t, out, "key")
	data, _ := os.ReadFile(sums)
	if err := os.WriteFile(sums, []byte(strings.ReplaceAll(string(data), "  ./", " *./")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyChecksums(filepath.Join(out, "qemu_arm64")); err != nil {
		t.Errorf("binary-mode SHA256SUMS rejected: %v", err)
	}
}

func TestBuildOutputDirectoryErrors(t *testing.T) {
	builder := repoBuilderDir(t)
	keys := fakeKeys(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &recordingRunner{t: t}
	var buildErr *BuildError
	if _, err := Build(context.Background(), Options{Runner: rec.run, BuilderDir: builder, OutputDir: filepath.Join(blocker, "out"), KeysDir: keys}); !errors.As(err, &buildErr) || buildErr.Step != "creating the output directory" {
		t.Errorf("unwritable output dir error = %v", err)
	}
}

// verbs is the runtime subcommand of every recorded call.
func verbs(calls [][]string) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call[1])
	}
	return out
}

func TestOptionsDefaults(t *testing.T) {
	o := (&Options{BuilderDir: "/b"}).withDefaults()
	if o.Runtime != "docker" || o.OutputDir != "/b/output" || o.Version != DefaultVersion ||
		o.TarballSHA256 != DefaultTarballSHA256 || o.OwnerGUID != DefaultOwnerGUID ||
		o.Image != "trusted-platform-uboot-builder:"+DefaultVersion || o.Runner == nil {
		t.Errorf("defaults = %+v", o)
	}
	if got := absPath("relative/path"); !filepath.IsAbs(got) {
		t.Errorf("absPath(relative) = %q", got)
	}
	if _, err := fileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("fileSHA256 of a missing file succeeded")
	}
}
