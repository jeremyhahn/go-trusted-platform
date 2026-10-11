package diskimage

import (
	"context"
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func buildConfigForTest(t *testing.T, target string, rec *diskimagetest.Runner) *BuildConfig {
	t.Helper()
	work := t.TempDir()
	bins := diskimagetest.Binaries(t, elf.EM_AARCH64)
	isoCfg := iso.DefaultISOBuildConfig()
	isoCfg.WorkDir = work
	isoCfg.PlatformVersion = "1.0.0-test"
	isoCfg.PlatformdBinary = filepath.Join(bins, "platformd")
	isoCfg.PlatformConfigFile = diskimagetest.PlatformConfig(t)
	isoCfg.PreFetch = false
	isoCfg.SecureBoot = false
	isoCfg.KeysDir = t.TempDir()
	return &BuildConfig{
		ISO: isoCfg, Target: target, SizeMB: 2048, Output: filepath.Join(work, "out", "img.img"),
		BinariesDir: bins, UBootDir: diskimagetest.UBootOutput(t), VirtKernelDir: diskimagetest.VirtKernelOutput(t), Runner: rec.Run, Logger: logging.DefaultLogger(),
		SkipPreflight: true, BuilderDir: t.TempDir(), UBootBuilderDir: t.TempDir(), VirtKernelBuilderDir: t.TempDir(),
	}
}

// callVerbs is the runtime subcommand of every call rec recorded.
func callVerbs(rec *diskimagetest.Runner) []string {
	verbs := make([]string, 0, len(rec.Calls))
	for _, call := range rec.Calls {
		verbs = append(verbs, call[1])
	}
	return verbs
}

// assertNoHostBindMounts fails when a recorded call bind-mounts a host path.
// A bind mount is resolved on the daemon's filesystem, which is not this
// process's when the build runs in a CI job container: inputs arrive empty and
// outputs never reach the checkout. The fake runtime rejects them too; this
// states the requirement where the argv is asserted.
func assertNoHostBindMounts(t *testing.T, rec *diskimagetest.Runner) {
	t.Helper()
	for _, call := range rec.Calls {
		for i, arg := range call {
			if arg == "-v" && i+1 < len(call) && strings.HasPrefix(call[i+1], "/") && strings.Contains(call[i+1], ":") {
				t.Errorf("host bind mount %q in %v", call[i+1], call)
			}
		}
	}
}

func TestCreateStagesMediaAndRunsTheContainer(t *testing.T) {
	rec := &diskimagetest.Runner{}
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
	// Image build, then create, the media cp'd in, start, the image cp'd out, rm.
	if got, want := strings.Join(callVerbs(rec), ","), "build,create,cp,start,cp,rm"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	build := strings.Join(rec.Calls[0], " ")
	if !strings.Contains(build, "--platform linux/arm64 -t "+DefaultBuilderImage) {
		t.Errorf("build argv = %q", build)
	}
	run := rec.Joined()[1]
	for _, want := range []string{"create --name builder-", "--privileged --platform linux/arm64 -v /work",
		"/media/cdrom/platformd-bin/platformctl-static diskimage assemble", "--platform-config /media/cdrom/configs/installer.yaml", "--output /work/img.img", "--size 2048"} {
		if !strings.Contains(run, want) {
			t.Errorf("run argv %q lacks %q", run, want)
		}
	}
	assertNoHostBindMounts(t, rec)
	if cp := rec.Joined()[2]; !strings.HasPrefix(cp, "docker cp "+media+"/. ") || !strings.HasSuffix(cp, ":/media/cdrom") {
		t.Errorf("media cp in = %q", cp)
	}
	if cp := rec.Joined()[4]; !strings.Contains(cp, ":/work/. ") || !strings.HasSuffix(cp, filepath.Dir(cfg.Output)) {
		t.Errorf("image cp out = %q", cp)
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
	rec := &diskimagetest.Runner{}
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
	diskimagetest.WriteELF(t, cfg.ISO.PlatformdBinary, elf.EM_X86_64)
	var mediaErr *iso.StageMediaError
	if _, err := Create(context.Background(), cfg); !errors.As(err, &mediaErr) || mediaErr.Step != "staging the install media" {
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
	rec = &diskimagetest.Runner{Fail: "build"}
	if _, err := Create(context.Background(), buildConfigForTest(t, "qemu-virt", rec)); !errors.As(err, &aerr) || aerr.Step != "building the assemble container image" {
		t.Errorf("image build failure error = %v", err)
	}
	rec = &diskimagetest.Runner{Fail: "start"}
	if _, err := Create(context.Background(), buildConfigForTest(t, "qemu-virt", rec)); !errors.As(err, &aerr) || aerr.Step != "running the assemble container" {
		t.Errorf("container run failure error = %v", err)
	}

	// The rpi target without prefetched firmware packages fails at staging.
	rec = &diskimagetest.Runner{}
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
	modules := t.TempDir()
	origModules := sysModuleDir
	sysModuleDir = modules
	t.Cleanup(func() { sysModuleDir = origModules })

	// fakeRuntime answers `version` and the binfmt probe `run`; probe is the
	// registration the container sees, probeErr makes the probe container fail.
	var probes [][]string
	fakeRuntime := func(probe string, probeErr error) runnerFunc {
		probes = nil
		return func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[0] == "version" {
				return []byte("28.0"), nil
			}
			probes = append(probes, args)
			return []byte(probe), probeErr
		}
	}

	var pre *PreflightError
	if err := Preflight(context.Background(), fakeRuntime("", errors.New("cat: no such file")), "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "no binfmt handler for aarch64") {
		t.Errorf("absent binfmt handler: %v", err)
	}
	if err := Preflight(context.Background(), fakeRuntime("enabled\nflags: OC\n", nil), "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "lacks the F flag") {
		t.Errorf("binfmt without F: %v", err)
	}
	if err := Preflight(context.Background(), fakeRuntime("enabled\nflags: POCF\n", nil), "docker", "aarch64"); !errors.As(err, &pre) || !strings.Contains(err.Error(), "kernel module loop") {
		t.Errorf("missing loop module: %v", err)
	}
	// The probe is a privileged container that reads the qemu-aarch64 entry.
	if len(probes) != 1 || probes[0][0] != "run" || !strings.Contains(strings.Join(probes[0], " "), "--privileged") || !strings.Contains(strings.Join(probes[0], " "), "binfmt_misc/qemu-aarch64") {
		t.Errorf("probe args = %v", probes)
	}
	for _, m := range []string{"loop", "dm_crypt"} {
		if err := os.Mkdir(filepath.Join(modules, m), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Preflight(context.Background(), fakeRuntime("enabled\nflags: POCF\n", nil), "docker", "aarch64"); err != nil {
		t.Errorf("all checks satisfied: %v", err)
	}
	// A same-architecture request never probes binfmt, so an unregistered
	// handler for the host architecture is not a failure and costs no container.
	if err := Preflight(context.Background(), fakeRuntime("", errors.New("unregistered")), "docker", runtime.GOARCH); err != nil {
		t.Errorf("same-arch preflight: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("same-arch preflight ran a probe: %v", probes)
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

// TestUBootPreseedsTheResolvedCertificates: U-Boot is built from the build's
// resolved Secure Boot certificates (fetched from the KMS for kms://
// references), not from the raw keys directory.
func TestUBootPreseedsTheResolvedCertificates(t *testing.T) {
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "rpi", rec).withDefaults()
	cfg.UBootDir = ""
	cfg.UBootOutputDir = t.TempDir()
	// The real builder context: the cache key hashes its inputs.
	builder, err := filepath.Abs(filepath.Join("..", "..", "build", "docker", "uboot-builder"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.UBootBuilderDir = builder
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
	certDir := t.TempDir()
	for _, role := range []string{"PK", "KEK", "DB"} {
		if err := os.WriteFile(filepath.Join(certDir, role+".crt"), []byte(role), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The fake runner produces no artifacts, so the build itself fails
	// afterwards; the certificates it copied in are what this test is about.
	_, _ = cfg.ubootArtifacts(context.Background(), target, &iso.SecureBootMaterial{CertDir: certDir})

	var copied bool
	for _, call := range rec.Joined() {
		copied = copied || (strings.HasPrefix(call, "docker cp "+certDir+"/. ") && strings.HasSuffix(call, ":/keys"))
	}
	if !copied {
		t.Errorf("U-Boot was not built from the resolved certificates; calls = %v", rec.Calls)
	}
}

// TestStageMediaResolvesSecureBootMaterial: with Secure Boot on, the staged
// media carries the build's resolved certificates and DB signer.
func TestStageMediaResolvesSecureBootMaterial(t *testing.T) {
	cfg := buildConfigForTest(t, "qemu-virt", &diskimagetest.Runner{})
	cfg.ISO.SecureBoot = true
	cfg.ISO.GenerateKeys = false
	authenticodetest.WriteKeyPair(t, cfg.ISO.KeysDir)
	for _, role := range []string{"PK", "KEK"} {
		keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
		_ = keyPath
		data, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.ISO.KeysDir, role+".crt"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	staged, err := StageMedia(context.Background(), cfg)
	if err != nil {
		t.Fatalf("StageMedia: %v", err)
	}
	if staged.SecureBoot == nil || staged.SecureBoot.DB == nil {
		t.Fatalf("staged Secure Boot material = %+v", staged.SecureBoot)
	}
	for _, role := range []string{"PK", "KEK", "DB"} {
		if _, err := os.Stat(filepath.Join(staged.SecureBoot.CertDir, role+".crt")); err != nil {
			t.Errorf("resolved certificates lack %s: %v", role, err)
		}
	}
}
