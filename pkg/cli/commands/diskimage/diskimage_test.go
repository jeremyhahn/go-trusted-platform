package diskimage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

func TestCommandTree(t *testing.T) {
	cmd := NewCommand(nil)
	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = sub.Hidden
	}
	for _, name := range []string{"assemble", "netboot-initfs", "diskless-root"} {
		if hidden, ok := names[name]; !ok || !hidden {
			t.Errorf("%s missing or not hidden: %v", name, names)
		}
	}
	for _, name := range []string{"create", "netboot", "inspect", "test"} {
		if hidden, ok := names[name]; !ok || hidden {
			t.Errorf("%s missing or hidden: %v", name, names)
		}
	}
	boot, _, _ := cmd.Find([]string{"test", "boot"})
	if boot == nil || boot.Name() != "boot" {
		t.Fatalf("test boot missing: %v", boot)
	}
	for _, flag := range []string{"image", "in-place", "uboot", "work-dir", "memory", "cpus", "serial-log", "console-socket", "expect", "timeout", "forward", "debug"} {
		if boot.Flags().Lookup(flag) == nil {
			t.Errorf("test boot lacks --%s", flag)
		}
	}
	if got := boot.Flags().Lookup("uboot").DefValue; !strings.HasSuffix(got, "qemu_arm64/u-boot.bin") {
		t.Errorf("--uboot default = %s", got)
	}
	create, _, _ := cmd.Find([]string{"create"})
	for _, flag := range []string{"target", "model", "size", "output", "binaries-dir", "uboot-dir", "virt-kernel-dir", "virt-kernel-builder-dir", "virt-kernel-output-dir", "virt-kernel-cache-volume", "platform-config", "overrides", "keys-dir", "pre-fetch", "skip-preflight"} {
		if create.Flags().Lookup(flag) == nil {
			t.Errorf("create lacks --%s", flag)
		}
	}
	if !strings.Contains(create.Flags().Lookup("model").Usage, "rpi4") {
		t.Error("--model usage does not list the models")
	}
}

func TestDefaultPlatformConfigPaths(t *testing.T) {
	got := defaultPlatformConfigPaths("rpi", "")
	if len(got) != 2 || !strings.HasSuffix(got[0], filepath.Join("raspberrypi", "rpi4", "default.yaml")) || !strings.HasSuffix(got[1], filepath.Join("single-node", "default.yaml")) {
		t.Errorf("rpi paths = %v", got)
	}
	if got := defaultPlatformConfigPaths("rpi", "cm4"); !strings.Contains(got[0], "cm4") {
		t.Errorf("cm4 path = %v", got)
	}
	if got := defaultPlatformConfigPaths("qemu-virt", ""); len(got) != 1 {
		t.Errorf("qemu paths = %v", got)
	}
}

func TestLoadInstallerConfig(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "install.yaml")
	if err := os.WriteFile(plain, []byte("disk:\n  device: /dev/loop0\nos:\n  architecture: aarch64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	platform := filepath.Join(dir, "platform.yaml")
	if err := os.WriteFile(platform, []byte("install-target: image\nboot:\n  firmware: uboot\nos:\n  architecture: aarch64\n  kernel-package: linux-rpi\ndisk:\n  device: /dev/mmcblk0\nseal-pcrs: [0, 4, 7, 9]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadInstallerConfig(&assembleFlags{config: plain})
	if err != nil || cfg.Disk.Device != "/dev/loop0" || cfg.OS.Architecture != "aarch64" {
		t.Errorf("plain config = %+v, %v", cfg, err)
	}
	cfg, err = loadInstallerConfig(&assembleFlags{platformConfig: platform})
	if err != nil || cfg.Target != installer.InstallTargetImage || cfg.Boot == nil || cfg.Boot.Firmware != installer.BootFirmwareUBoot || cfg.OS.KernelPackage != "linux-rpi" || len(cfg.PCRs) != 4 {
		t.Errorf("platform config = %+v, %v", cfg, err)
	}

	var required ErrConfigRequired
	if _, err := loadInstallerConfig(&assembleFlags{}); !errors.As(err, &required) {
		t.Errorf("neither config error = %v", err)
	}
	if _, err := loadInstallerConfig(&assembleFlags{config: plain, platformConfig: platform}); !errors.As(err, &required) {
		t.Errorf("both configs error = %v", err)
	}
	var loadErr ErrConfigLoadFailed
	if _, err := loadInstallerConfig(&assembleFlags{config: filepath.Join(dir, "missing.yaml")}); !errors.As(err, &loadErr) {
		t.Errorf("missing plain config error = %v", err)
	}
	if _, err := loadInstallerConfig(&assembleFlags{platformConfig: filepath.Join(dir, "missing.yaml")}); !errors.As(err, &loadErr) {
		t.Errorf("missing platform config error = %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("[not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstallerConfig(&assembleFlags{platformConfig: bad}); !errors.As(err, &loadErr) {
		t.Errorf("malformed platform config error = %v", err)
	}
	// An enabled sdn section without an environment cannot yield the
	// network plan the installer needs.
	noEnv := filepath.Join(dir, "no-env.yaml")
	if err := os.WriteFile(noEnv, []byte("sdn:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstallerConfig(&assembleFlags{platformConfig: noEnv}); !errors.As(err, &loadErr) {
		t.Errorf("sdn without environment error = %v", err)
	}
	// A key the sdn schema no longer has fails the load.
	stale := filepath.Join(dir, "stale.yaml")
	if err := os.WriteFile(stale, []byte("sdn:\n  enabled: true\n  environment: {id: 4}\n  transit: {vlan: 10}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var unknown *config.ErrUnknownConfigKeys
	if _, err := loadInstallerConfig(&assembleFlags{platformConfig: stale}); !errors.As(err, &loadErr) || !errors.As(err, &unknown) {
		t.Errorf("stale sdn key error = %v", err)
	}
}

// TestLoadInstallerConfigAcceptsSecretReferences is the regression for #778: a
// platform config whose CA key passwords are kms:// references must load, as it
// does in platformd, instead of failing to decode into secret.SecretValue.
func TestLoadInstallerConfigAcceptsSecretReferences(t *testing.T) {
	platform := filepath.Join("testdata", "platform-secret-refs.yaml")
	cfg, err := loadInstallerConfig(&assembleFlags{platformConfig: platform})
	if err != nil {
		t.Fatalf("platform config with kms:// references: %v", err)
	}
	if cfg.Disk.Device != "/dev/mmcblk0" {
		t.Errorf("disk device = %q", cfg.Disk.Device)
	}
}

func TestBuildConfigResolvesBinariesAndOverrides(t *testing.T) {
	dir := t.TempDir()
	bins := filepath.Join(dir, "aarch64")
	if err := os.MkdirAll(bins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bins, "platformd"), []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	template := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(template, []byte("os:\n  hostname: base\nseal-pcrs: [0, 7, 9]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrides := filepath.Join(dir, "overrides.yaml")
	if err := os.WriteFile(overrides, []byte("os:\n  hostname: pi-01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flags := &createFlags{target: "rpi", binariesDir: bins, platformConfig: template, overrides: overrides, alpineVersion: "3.22.2", mirror: "http://m", platformType: "server", workDir: dir, keyBackend: "file", preFetch: true}
	cfg, err := buildConfig(flags)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.PlatformdBinary != filepath.Join(bins, "platformd") || !cfg.PreFetch || cfg.WorkDir != dir {
		t.Errorf("config = %+v", cfg)
	}
	merged, err := os.ReadFile(cfg.PlatformConfigFile)
	if err != nil || !strings.Contains(string(merged), "hostname: pi-01") || !strings.Contains(string(merged), "seal-pcrs") {
		t.Errorf("merged platform config = %q, %v", merged, err)
	}
	os.Remove(cfg.PlatformConfigFile)

	var notFound ErrBinariesNotFound
	if _, err := buildConfig(&createFlags{target: "rpi", binariesDir: filepath.Join(dir, "empty")}); !errors.As(err, &notFound) {
		t.Errorf("missing binaries error = %v", err)
	}
	if _, err := mergeOverrides("", overrides); err == nil {
		t.Error("overrides without a template accepted")
	}
	if _, err := mergeOverrides(template, filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing overrides file accepted")
	}
}

// The platform apks reach a node only from the image's offline repository, so
// --platform-apk-dir without --pre-fetch is refused before anything is built.
func TestBuildConfigRefusesPlatformAPKDirWithoutPreFetch(t *testing.T) {
	flags := &createFlags{target: "rpi", alpineVersion: "3.22.2", mirror: "http://m", platformType: "server", workDir: t.TempDir(), keyBackend: "file", platformAPKDir: "/builder/output"}

	var unusable *pkgiso.ErrPlatformAPKDirUnusable
	if _, err := buildConfig(flags); !errors.As(err, &unusable) {
		t.Fatalf("buildConfig without pre-fetch = %v, want ErrPlatformAPKDirUnusable", err)
	}

	flags.preFetch = true
	var notFound ErrBinariesNotFound
	if _, err := buildConfig(flags); !errors.As(err, &notFound) {
		t.Errorf("buildConfig with pre-fetch = %v, want it past the check to the binaries", err)
	}
}

// rpiBinaries writes a stand-in aarch64 platformd and returns its directory.
func rpiBinaries(t *testing.T) string {
	t.Helper()
	bins := filepath.Join(t.TempDir(), "aarch64")
	if err := os.MkdirAll(bins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bins, "platformd"), []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bins
}

// The template lookups are relative to the repository root, where
// platformctl diskimage create runs, so these tests run from there and
// resolve the shipped templates.
const repoRoot = "../../../.."

// --role builds the shipped dedicated-profile template for the role, and
// nothing else: the single-node default is not a fallback.
func TestBuildConfigRoleBuildsTheDedicatedTemplate(t *testing.T) {
	t.Chdir(repoRoot)
	// rpi5 is experimental but builds through the same path as rpi4.
	builds := []struct{ model, role string }{
		{"rpi4", "compute"},
		{"rpi5", "compute"},
		{"cm4", "control-plane"},
		{"rpi4", "control-plane"},
	}
	for _, b := range builds {
		t.Run(b.model+"/"+b.role, func(t *testing.T) {
			flags := &createFlags{target: "rpi", model: b.model, role: b.role, binariesDir: rpiBinaries(t)}
			cfg, err := buildConfig(flags)
			if err != nil {
				t.Fatalf("buildConfig: %v", err)
			}
			want := filepath.Join("configs", "platform", "templates", "dedicated", "raspberrypi", b.model, b.role+".yaml")
			if cfg.PlatformConfigFile != want {
				t.Errorf("platform config = %q, want %q", cfg.PlatformConfigFile, want)
			}
		})
	}
}

// Without --role the rpi image stays the single-node one.
func TestBuildConfigWithoutRoleBuildsSingleNode(t *testing.T) {
	t.Chdir(repoRoot)
	cfg, err := buildConfig(&createFlags{target: "rpi", binariesDir: rpiBinaries(t)})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	want := filepath.Join("configs", "platform", "templates", "single-node", "raspberrypi", "rpi4", "default.yaml")
	if cfg.PlatformConfigFile != want {
		t.Errorf("platform config = %q, want %q", cfg.PlatformConfigFile, want)
	}
}

// A role the builder cannot build is refused rather than built as
// single-node: no template for it, a name that is not a host role, a
// target other than rpi, or a --platform-config that already chose the
// template.
func TestBuildConfigRefusesRoleItCannotBuild(t *testing.T) {
	t.Chdir(repoRoot)
	bins := rpiBinaries(t)
	cases := map[string]*createFlags{
		"no template":     {target: "rpi", model: "rpi4", role: "gateway", binariesDir: bins},
		"model without":   {target: "rpi", model: "cm4", role: "compute", binariesDir: bins},
		"unknown model":   {target: "rpi", model: "rpi2", role: "compute", binariesDir: bins},
		"model as a path": {target: "rpi", model: "../supermicro/x10", role: "compute", binariesDir: bins},
		"rpi5 gateway":    {target: "rpi", model: "rpi5", role: "gateway", binariesDir: bins},
		"rpi5 cp":         {target: "rpi", model: "rpi5", role: "control-plane", binariesDir: bins},
		"overrides":       {target: "rpi", model: "cm4", role: "desk-overrides", binariesDir: bins},
		"role as a path":  {target: "rpi", model: "rpi4", role: "../cm4/control-plane", binariesDir: bins},
		"qemu-virt":       {target: "qemu-virt", role: "compute", binariesDir: bins},
		"platform-config": {target: "rpi", role: "compute", binariesDir: bins, mediaFlags: mediaFlags{platformConfig: "node.yaml"}},
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			var refused ErrRoleTemplate
			if _, err := buildConfig(flags); !errors.As(err, &refused) {
				t.Fatalf("buildConfig = %v, want ErrRoleTemplate", err)
			}
			if refused.Role != flags.role {
				t.Errorf("refused role = %q, want %q", refused.Role, flags.role)
			}
		})
	}
}

// The --model help names the experimental boards as such, and only those.
func TestJoinModelsMarksExperimental(t *testing.T) {
	got := joinModels()
	if !strings.Contains(got, "rpi5 (experimental)") {
		t.Errorf("joinModels() = %q, want rpi5 marked experimental", got)
	}
	if strings.Contains(got, "rpi4 (experimental)") {
		t.Errorf("joinModels() = %q, rpi4 is not experimental", got)
	}
}

func TestErrorStrings(t *testing.T) {
	inner := errors.New("inner")
	if got := (ErrConfigLoadFailed{Path: "/p", Err: inner}).Error(); got != "diskimage: failed to load /p: inner" {
		t.Errorf("ErrConfigLoadFailed = %q", got)
	}
	if !errors.Is(ErrConfigLoadFailed{Path: "/p", Err: inner}, inner) {
		t.Error("ErrConfigLoadFailed does not unwrap")
	}
	if got := (ErrBinariesNotFound{Dir: "/b"}).Error(); !strings.Contains(got, "/b") || !strings.Contains(got, "rpi-binaries") {
		t.Errorf("ErrBinariesNotFound = %q", got)
	}
	if got := (ErrBuildFailed{Reason: "r"}).Error(); got != "diskimage build failed: r" {
		t.Errorf("ErrBuildFailed = %q", got)
	}
	if got := (ErrConfigRequired{}).Error(); !strings.Contains(got, "--config") || !strings.Contains(got, "--platform-config") {
		t.Errorf("ErrConfigRequired = %q", got)
	}
}

// TestMergeOverrides deep-merges an overrides file onto the template into a
// temporary file, and rejects a missing template or an unreadable overrides
// file with ErrBuildFailed.
func TestMergeOverrides(t *testing.T) {
	dir := t.TempDir()
	template := filepath.Join(dir, "template.yaml")
	overrides := filepath.Join(dir, "overrides.yaml")
	if err := os.WriteFile(template, []byte("tpm:\n  seal-pcrs: [0, 4, 7]\ndebug: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overrides, []byte("tpm:\n  seal-pcrs: [0, 4, 7, 9]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	merged, err := mergeOverrides(template, overrides)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(merged)
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "- 9") || !strings.Contains(string(data), "debug: false") {
		t.Errorf("merged config = %q", data)
	}

	var build ErrBuildFailed
	if _, err := mergeOverrides("", overrides); !errors.As(err, &build) {
		t.Errorf("empty template error = %v", err)
	}
	if _, err := mergeOverrides(template, filepath.Join(dir, "missing.yaml")); !errors.As(err, &build) {
		t.Errorf("missing overrides error = %v", err)
	}
	// The merged config is a temporary file; a temp dir that cannot hold it
	// is a build failure, not a path to a file that does not exist.
	t.Setenv("TMPDIR", filepath.Join(dir, "no-such-dir"))
	if _, err := mergeOverrides(template, overrides); !errors.As(err, &build) || !strings.Contains(build.Reason, "creating the merged config") {
		t.Errorf("unwritable temp dir error = %v", err)
	}
}

func TestCommandErrorPaths(t *testing.T) {
	run := func(args ...string) error {
		cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
		cmd.SetArgs(args)
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		return cmd.Execute()
	}
	var required ErrConfigRequired
	if err := run("assemble", "--output", filepath.Join(t.TempDir(), "x.img")); !errors.As(err, &required) {
		t.Errorf("assemble without config error = %v", err)
	}
	var notFound ErrBinariesNotFound
	if err := run("create", "--binaries-dir", filepath.Join(t.TempDir(), "none"), "--skip-preflight"); !errors.As(err, &notFound) {
		t.Errorf("create without binaries error = %v", err)
	}
	var inspectErr *pkgdiskimage.InspectError
	if err := run("inspect", filepath.Join(t.TempDir(), "missing.img")); !errors.As(err, &inspectErr) {
		t.Errorf("inspect of a missing image error = %v", err)
	}
	if err := run("inspect"); err == nil {
		t.Error("inspect without an argument accepted")
	}

	// A plain installer config that cannot be assembled (no losetup here,
	// unwritable output) still exercises the assemble path to its error.
	plain := filepath.Join(t.TempDir(), "install.yaml")
	if err := os.WriteFile(plain, []byte("disk:\n  device: /dev/loop0\nos:\n  architecture: aarch64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var aerr *pkgdiskimage.AssembleError
	if err := run("assemble", "--config", plain, "--output", filepath.Join(blocker, "x.img"), "--size", "2048"); !errors.As(err, &aerr) {
		t.Errorf("assemble into an unwritable path error = %v", err)
	}

	// create with binaries present but an unusable target fails in the builder.
	bins := filepath.Join(t.TempDir(), "aarch64")
	if err := os.MkdirAll(bins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bins, "platformd"), []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	var build ErrBuildFailed
	if err := run("create", "--binaries-dir", bins, "--target", "nope", "--skip-preflight", "--work-dir", t.TempDir()); !errors.As(err, &build) || !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("create with an unknown target error = %v", err)
	}
	if err := run("create", "--binaries-dir", bins, "--overrides", filepath.Join(t.TempDir(), "o.yaml"), "--skip-preflight"); !errors.As(err, &build) {
		t.Errorf("create with overrides but no template error = %v", err)
	}

	// netboot refuses an unknown set, and overrides with no template, before
	// it resolves binaries or builds anything.
	var unknown ErrUnknownMediaSet
	if err := run("netboot", "--sets", "nope"); !errors.As(err, &unknown) || unknown.Name != "nope" {
		t.Errorf("netboot with an unknown set error = %v", err)
	}
	build = ErrBuildFailed{}
	if err := run("netboot", "--overrides", filepath.Join(t.TempDir(), "o.yaml"), "--work-dir", t.TempDir()); !errors.As(err, &build) || !strings.Contains(build.Reason, "--overrides requires a --platform-config template") {
		t.Errorf("netboot with overrides but no template error = %v", err)
	}
	if err := run("diskless-root"); !errors.As(err, &required) {
		t.Errorf("diskless-root without config error = %v", err)
	}

	// test boot parses its forwards before it boots, and an --expect deadline
	// does not mask why the boot itself failed.
	var forward ErrInvalidPortForward
	if err := run("test", "boot", "--forward", "8080"); !errors.As(err, &forward) || forward.Spec != "8080" {
		t.Errorf("test boot with a bad forward error = %v", err)
	}
	dir := t.TempDir()
	var bootErr *pkgdiskimage.BootError
	err := run("test", "boot", "--image", filepath.Join(dir, "missing.img"), "--uboot", filepath.Join(dir, "missing.bin"),
		"--work-dir", dir, "--serial-log", filepath.Join(dir, "serial.log"), "--expect", "login:", "--timeout", "1s")
	if !errors.As(err, &bootErr) || bootErr.Step != "opening the image" {
		t.Errorf("test boot --expect of a missing image error = %v", err)
	}
}

func TestParsePortForwards(t *testing.T) {
	got, err := parsePortForwards([]string{"18443:8443", "5353:53/udp", "2222:22/tcp"})
	if err != nil {
		t.Fatal(err)
	}
	want := []qemu.PortForward{
		{HostPort: 18443, GuestPort: 8443, Protocol: "tcp"},
		{HostPort: 5353, GuestPort: 53, Protocol: "udp"},
		{HostPort: 2222, GuestPort: 22, Protocol: "tcp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("forward %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got, err := parsePortForwards(nil); err != nil || len(got) != 0 {
		t.Errorf("nil specs = %v, %v", got, err)
	}
	for _, bad := range []string{"8443", "a:8443", "8443:b", "8443:22/sctp", ""} {
		_, err := parsePortForwards([]string{bad})
		var invalid ErrInvalidPortForward
		if !errors.As(err, &invalid) || invalid.Spec != bad {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestRunTestBoot_RejectsABadForwardBeforeBooting(t *testing.T) {
	err := runTestBoot(nil, &testFlags{image: "nope.img", firmware: "nope.bin", forwards: []string{"bad"}})
	var invalid ErrInvalidPortForward
	if !errors.As(err, &invalid) {
		t.Errorf("err = %v", err)
	}
}

func TestRunTestBoot_ReportsAMissingImage(t *testing.T) {
	dir := t.TempDir()
	err := runTestBoot(nil, &testFlags{image: filepath.Join(dir, "missing.img"), firmware: filepath.Join(dir, "missing.bin"), workDir: dir, timeout: time.Second})
	var bootErr *pkgdiskimage.BootError
	if !errors.As(err, &bootErr) || bootErr.Step != "opening the image" {
		t.Errorf("err = %v", err)
	}
}
