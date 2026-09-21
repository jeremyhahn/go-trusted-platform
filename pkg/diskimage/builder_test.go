package diskimage

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// writeELF writes a minimal 64-bit ELF header for machine.
func writeELF(t *testing.T, path string, machine elf.Machine) {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(hdr[18:], uint16(machine))
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[58:], 64)
	if err := os.WriteFile(path, hdr, 0o755); err != nil {
		t.Fatal(err)
	}
}

// binariesDir lays out the aarch64 binaries the media staging looks for.
func binariesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"platformd", "platformctl", "platformctl-static", "platform-initrd", "gatewayd"} {
		writeELF(t, filepath.Join(dir, name), elf.EM_AARCH64)
	}
	return dir
}

// ubootOutput lays out verified U-Boot artifacts for both boards.
func ubootOutput(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	files := map[string]string{
		"rpi_arm64/u-boot.bin": "rpi", "rpi_arm64/u-boot.config": "c", "rpi_arm64/overlays/tpm-soft-spi.dtbo": "o",
		"qemu_arm64/u-boot.bin": "qemu", "qemu_arm64/u-boot.config": "c",
	}
	for rel, body := range files {
		p := filepath.Join(out, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, board := range uboot.Boards {
		dir := filepath.Join(out, string(board))
		var sums strings.Builder
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			data, _ := os.ReadFile(p)
			sum := sha256.Sum256(data)
			sums.WriteString(hex.EncodeToString(sum[:]) + "  ./" + rel + "\n")
			return nil
		})
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, _ := json.Marshal(uboot.Manifest{Version: uboot.DefaultVersion, CacheKey: "k", Boards: []string{"rpi_arm64", "qemu_arm64"}})
	if err := os.WriteFile(filepath.Join(out, uboot.ManifestName), m, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// platformConfig writes a minimal platform config carrying seal-pcrs.
func platformConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "platform.yaml")
	if err := os.WriteFile(p, []byte("os:\n  architecture: x86_64\n  hostname: node\ndisk:\n  partition-table: gpt\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// buildRunner records container invocations and fakes a produced image.
type buildRunner struct {
	calls [][]string
	fail  string
}

func (b *buildRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	b.calls = append(b.calls, append([]string{name}, args...))
	if b.fail != "" && len(args) > 0 && args[0] == b.fail {
		return []byte("boom"), errors.New("exit 1")
	}
	if len(args) > 0 && args[0] == "run" {
		for i, a := range args {
			if a == "--output" {
				// the container writes /work/<name>; the host sees <outDir>/<name>
				name := filepath.Base(args[i+1])
				for j, v := range args {
					if v == "-v" && strings.HasSuffix(args[j+1], ":"+containerWorkMount) {
						host := strings.TrimSuffix(args[j+1], ":"+containerWorkMount)
						return nil, os.WriteFile(filepath.Join(host, name), []byte("image"), 0o644)
					}
				}
			}
		}
	}
	return nil, nil
}

// virtKernelOutput is a virt-kernel-builder output directory with a
// manifest and a verified flavour directory.
func virtKernelOutput(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	dir := filepath.Join(out, "virt")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"vmlinuz-virt": "kernel", "modules-virt.tar.gz": "modules", "kernel-version.txt": "6.12.110-0-virt\n", "config-virt": "c"}
	var sums strings.Builder
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		sums.WriteString(hex.EncodeToString(sum[:]) + "  ./" + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"kernel_version":"6.12.110","kernel_release":"6.12.110-0-virt","tarball_sha256":"x","cache_key":"k","flavor":"virt","built_at":"now"}`
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

func buildConfigForTest(t *testing.T, target string, rec *buildRunner) *BuildConfig {
	t.Helper()
	work := t.TempDir()
	bins := binariesDir(t)
	isoCfg := iso.DefaultISOBuildConfig()
	isoCfg.WorkDir = work
	isoCfg.PlatformVersion = "1.0.0-test"
	isoCfg.PlatformdBinary = filepath.Join(bins, "platformd")
	isoCfg.PlatformConfigFile = platformConfig(t)
	isoCfg.PreFetch = false
	isoCfg.SecureBoot = false
	isoCfg.KeysDir = t.TempDir()
	return &BuildConfig{
		ISO: isoCfg, Target: target, SizeMB: 2048, Output: filepath.Join(work, "out", "img.img"),
		BinariesDir: bins, UBootDir: ubootOutput(t), VirtKernelDir: virtKernelOutput(t), Runner: rec.run, Logger: logging.DefaultLogger(),
		SkipPreflight: true, BuilderDir: t.TempDir(), UBootBuilderDir: t.TempDir(), VirtKernelBuilderDir: t.TempDir(),
	}
}

func TestCreateStagesMediaAndRunsTheContainer(t *testing.T) {
	rec := &buildRunner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	res, err := Create(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.Image != cfg.Output || res.SHA256 == "" || res.SizeBytes != 5 || res.UBoot.Board != uboot.BoardQEMUArm64 {
		t.Errorf("result = %+v", res)
	}
	if res.Kernel == nil || res.Kernel.Release != "6.12.110-0-virt" {
		t.Errorf("result kernel = %+v", res.Kernel)
	}
	media := filepath.Join(cfg.ISO.WorkDir, MediaDirName)
	for _, rel := range []string{"platformd-bin/platformd", "platformd-bin/platformctl-static", "platformd-bin/platform-initrd", "configs/installer.yaml", "dracut-platformd/90platformd/module-setup.sh", "boot-firmware",
		"kernel-artifacts/virt/vmlinuz-virt", "kernel-artifacts/virt/modules-virt.tar.gz", "kernel-artifacts/virt/SHA256SUMS", "kernel-artifacts/virt/kernel-version.txt"} {
		if _, err := os.Stat(filepath.Join(media, rel)); err != nil {
			t.Errorf("media lacks %s: %v", rel, err)
		}
	}
	baked, _ := os.ReadFile(filepath.Join(media, "configs", "installer.yaml"))
	for _, want := range []string{"architecture: aarch64", "kernel-package: linux-virt", "kernel-artifacts-dir: /media/cdrom/kernel-artifacts/virt", "device: /dev/vda", "partition-table: mbr", "install-target: image", "firmware: uboot"} {
		if !strings.Contains(string(baked), want) {
			t.Errorf("baked platform config lacks %q:\n%s", want, baked)
		}
	}
	if len(rec.calls) != 2 || rec.calls[0][1] != "build" || rec.calls[1][1] != "run" {
		t.Fatalf("calls = %v", rec.calls)
	}
	build := strings.Join(rec.calls[0], " ")
	if !strings.Contains(build, "--platform linux/arm64 -t "+DefaultBuilderImage) {
		t.Errorf("build argv = %q", build)
	}
	run := strings.Join(rec.calls[1], " ")
	for _, want := range []string{"run --rm --privileged --platform linux/arm64", media + ":/media/cdrom:ro", ":/work",
		"/media/cdrom/platformd-bin/platformctl-static diskimage assemble", "--platform-config /media/cdrom/configs/installer.yaml", "--output /work/img.img", "--size 2048"} {
		if !strings.Contains(run, want) {
			t.Errorf("run argv %q lacks %q", run, want)
		}
	}
	if strings.Contains(run, "--debug") {
		t.Error("debug flag passed without ISO.Debug")
	}
	// Regression check for the 2026-09-16 incident: the container's mdev -s
	// resets the mode of every node in its /dev, so the host's /dev must
	// never be exposed to it.
	if strings.Contains(run, "/dev") {
		t.Errorf("run argv %q exposes a host device path", run)
	}
}

func TestCreateFailures(t *testing.T) {
	var stage *StageError
	if _, err := Create(context.Background(), &BuildConfig{SkipPreflight: true}); !errors.As(err, &stage) {
		t.Errorf("nil ISO config error = %v", err)
	}
	rec := &buildRunner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.SizeMB = 100
	if _, err := Create(context.Background(), cfg); !errors.As(err, &stage) || !strings.Contains(err.Error(), "below the minimum") {
		t.Errorf("small size error = %v", err)
	}
	cfg = buildConfigForTest(t, "nope", rec)
	var unknown *UnknownTargetError
	if _, err := Create(context.Background(), cfg); !errors.As(err, &unknown) || !strings.Contains(err.Error(), "qemu-virt") {
		t.Errorf("unknown target error = %v", err)
	}

	// An x86_64 platformd is rejected for an aarch64 image.
	cfg = buildConfigForTest(t, "qemu-virt", rec)
	writeELF(t, cfg.ISO.PlatformdBinary, elf.EM_X86_64)
	if _, err := Create(context.Background(), cfg); !errors.As(err, &stage) || stage.Step != "staging the install media" {
		t.Errorf("wrong-arch platformd error = %v", err)
	}

	// Missing virt kernel artifacts (the target boots a built kernel).
	cfg = buildConfigForTest(t, "qemu-virt", rec)
	cfg.VirtKernelDir = t.TempDir()
	if _, err := Create(context.Background(), cfg); !errors.As(err, &stage) || stage.Step != "virt kernel" {
		t.Errorf("missing virt kernel error = %v", err)
	}

	// Missing U-Boot artifacts.
	cfg = buildConfigForTest(t, "qemu-virt", rec)
	cfg.UBootDir = t.TempDir()
	if _, err := Create(context.Background(), cfg); !errors.As(err, &stage) || stage.Step != "U-Boot" {
		t.Errorf("missing U-Boot error = %v", err)
	}

	// Container failures.
	var aerr *AssembleError
	rec = &buildRunner{fail: "build"}
	if _, err := Create(context.Background(), buildConfigForTest(t, "qemu-virt", rec)); !errors.As(err, &aerr) || aerr.Step != "building the assemble container image" {
		t.Errorf("image build failure error = %v", err)
	}
	rec = &buildRunner{fail: "run"}
	if _, err := Create(context.Background(), buildConfigForTest(t, "qemu-virt", rec)); !errors.As(err, &aerr) || aerr.Step != "running the assemble container" {
		t.Errorf("container run failure error = %v", err)
	}

	// The rpi target without prefetched firmware packages fails at staging.
	rec = &buildRunner{}
	cfg = buildConfigForTest(t, "rpi", rec)
	if _, err := Create(context.Background(), cfg); !errors.As(err, &stage) || stage.Step != "staging the boot firmware" {
		t.Errorf("rpi without packages error = %v", err)
	}
}

func TestTargetsAndDefaults(t *testing.T) {
	if got := strings.Join(Targets(), ","); got != "qemu-virt,rpi" {
		t.Errorf("Targets() = %s", got)
	}
	if tgt, err := NewTarget("rpi", "cm4"); err != nil || tgt.Name() != "rpi" {
		t.Errorf("NewTarget(rpi,cm4) = %v, %v", tgt, err)
	}
	if _, err := NewTarget("rpi", "rpi2"); err == nil {
		t.Error("NewTarget accepted an unknown model")
	}
	c := (&BuildConfig{}).withDefaults()
	if c.Target != DefaultTarget || c.SizeMB != DefaultSizeMB || c.ContainerRuntime != "docker" || c.BuilderImage != DefaultBuilderImage ||
		c.BuilderDir != DefaultBuilderDir || c.UBootBuilderDir != DefaultUBootBuilderDir || c.UBootOutputDir != filepath.Join(DefaultUBootBuilderDir, "output") || c.Runner == nil || c.Logger == nil {
		t.Errorf("defaults = %+v", c)
	}
}

func TestPreflightHelpers(t *testing.T) {
	if !binfmtHasFixedBinary("enabled\ninterpreter /usr/bin/qemu-aarch64\nflags: POCF\n") || binfmtHasFixedBinary("enabled\nflags: OC\n") || binfmtHasFixedBinary("") {
		t.Error("binfmtHasFixedBinary misreads flags")
	}
	if goArchOf("aarch64") != "arm64" || goArchOf("x86_64") != "amd64" || goArchOf("riscv64") != "riscv64" {
		t.Error("goArchOf mapping")
	}
	// A runtime that cannot answer `version` fails preflight with the remedy.
	failing := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no docker") }
	var pre *PreflightError
	if err := Preflight(context.Background(), failing, "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "docker is not usable") {
		t.Errorf("preflight without docker error = %v", err)
	}
}

// TestPreflightHostChecks drives the binfmt and module checks against fixture
// directories: the binfmt entry is looked up under the QEMU name
// (qemu-aarch64), and each failure names its remedy.
func TestPreflightHostChecks(t *testing.T) {
	ok := func(context.Context, string, ...string) ([]byte, error) { return []byte("28.0"), nil }
	binfmt := t.TempDir()
	modules := t.TempDir()
	origBinfmt, origModules := binfmtDir, sysModuleDir
	binfmtDir, sysModuleDir = binfmt, modules
	t.Cleanup(func() { binfmtDir, sysModuleDir = origBinfmt, origModules })

	var pre *PreflightError
	if err := Preflight(context.Background(), ok, "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "no binfmt handler for aarch64") {
		t.Errorf("missing binfmt entry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binfmt, "qemu-aarch64"), []byte("enabled\nflags: OC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(context.Background(), ok, "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "lacks the F flag") {
		t.Errorf("binfmt without F: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binfmt, "qemu-aarch64"), []byte("enabled\nflags: POCF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(context.Background(), ok, "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "kernel module loop") {
		t.Errorf("missing loop module: %v", err)
	}
	for _, m := range []string{"loop", "dm_crypt"} {
		if err := os.Mkdir(filepath.Join(modules, m), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Preflight(context.Background(), ok, "docker", "aarch64"); err != nil {
		t.Errorf("all checks satisfied: %v", err)
	}
	// A same-architecture request never consults binfmt, so an unregistered
	// handler for the host architecture is not a failure.
	if err := Preflight(context.Background(), ok, "docker", "x86_64"); err != nil {
		t.Errorf("same-arch preflight: %v", err)
	}
}

// TestFileDigest hashes a file and reports a missing one.
func TestFileDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, n, err := fileDigest(path)
	if err != nil || n != 3 || sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("fileDigest = %q, %d, %v", sum, n, err)
	}
	if _, _, err := fileDigest(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file digested")
	}
}

func TestErrorMessages(t *testing.T) {
	inner := errors.New("inner")
	for err, want := range map[error]string{
		&UnknownTargetError{Target: "x", Targets: []string{"a"}}: "diskimage: unknown target x (known: a)",
		&PreflightError{Check: "c", Remedy: "r"}:                 "diskimage: c (r)",
		&StageError{Step: "s", Err: inner}:                       "diskimage: s: inner",
		&AssembleError{Step: "s", Err: inner}:                    "diskimage: assemble: s: inner",
		&InspectError{Path: "p", Reason: "r", Err: inner}:        "diskimage: inspect p: r: inner",
		&InspectError{Path: "p", Reason: "r"}:                    "diskimage: inspect p: r",
		&sizeError{100}:                                          "diskimage: image size 100 MB is below the minimum of 2048 MB",
	} {
		if err.Error() != want {
			t.Errorf("%T.Error() = %q, want %q", err, err.Error(), want)
		}
	}
	for _, err := range []error{&StageError{Err: inner}, &AssembleError{Err: inner}, &InspectError{Err: inner}} {
		if !errors.Is(err, inner) {
			t.Errorf("%T does not unwrap", err)
		}
	}
}
