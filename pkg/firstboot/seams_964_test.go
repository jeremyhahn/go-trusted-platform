package firstboot

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// errSeam is the failure the seam fakes return when a test asks them to fail.
var errSeam = errors.New("seam failure")

// swap points a package seam at v for the duration of the test.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// useHostRoot roots every fixed host path under a fresh temporary directory.
func useHostRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	swap(t, &hostRoot, root)
	return root
}

// writeHostFile writes data at the host path p under hostRoot.
func writeHostFile(t *testing.T, p string, data []byte) {
	t.Helper()
	full := hostPath(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// hostFileExists reports whether the host path p exists under hostRoot.
func hostFileExists(p string) bool {
	_, err := os.Stat(hostPath(p))
	return err == nil
}

// fakeCommands records every command the seams run and fails the ones whose
// joined command line starts with a prefix in fail.
type fakeCommands struct {
	calls  []string
	fail   []string
	output map[string]string
}

func (f *fakeCommands) run(name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	out := []byte(f.output[line])
	for _, prefix := range f.fail {
		if strings.HasPrefix(line, prefix) {
			return out, errSeam
		}
	}
	return out, nil
}

func (f *fakeCommands) ran(prefix string) bool {
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

// useCommands installs a fakeCommands on both command seams.
func useCommands(t *testing.T, fail ...string) *fakeCommands {
	t.Helper()
	f := &fakeCommands{fail: fail, output: map[string]string{}}
	swap(t, &hostCommand, commandRunner(f.run))
	swap(t, &hostCommandStdout, commandRunner(f.run))
	return f
}

// fakeLUKS records the LUKS operations and fails the ones named in fail.
type fakeLUKS struct {
	fail     map[string]bool
	locked   []string
	detached []string
	unlocked []string
	killed   []string
	wiped    []luks2.WipeOptions
	isLUKS   bool
}

func (f *fakeLUKS) err(op string) error {
	if f.fail[op] {
		return errSeam
	}
	return nil
}

// useLUKS installs a fakeLUKS on every LUKS seam.
func useLUKS(t *testing.T, fail ...string) *fakeLUKS {
	t.Helper()
	f := &fakeLUKS{fail: map[string]bool{}}
	for _, op := range fail {
		f.fail[op] = true
	}
	swap(t, &luksIsLUKS, func(dev string) (bool, error) { return f.isLUKS, f.err("isluks") })
	swap(t, &luksKillSlot, func(dev string, key []byte, slot int) error {
		f.killed = append(f.killed, dev)
		return f.err("killslot")
	})
	swap(t, &luksSetupLoopDevice, func(path string) (string, error) {
		if err := f.err("setuploop"); err != nil {
			return "", err
		}
		return "/dev/loop7", nil
	})
	swap(t, &luksDetachLoopDevice, func(dev string) error {
		f.detached = append(f.detached, dev)
		return f.err("detach")
	})
	swap(t, &luksUnlock, func(dev string, pass []byte, name string) error {
		f.unlocked = append(f.unlocked, name)
		return f.err("unlock")
	})
	swap(t, &luksLock, func(name string) error {
		f.locked = append(f.locked, name)
		return f.err("lock")
	})
	swap(t, &luksGetMappedDevicePath, func(name string) (string, error) {
		if err := f.err("mapped"); err != nil {
			return "", err
		}
		return "/dev/mapper/" + name, nil
	})
	swap(t, &luksWipe, func(opts luks2.WipeOptions) error {
		f.wiped = append(f.wiped, opts)
		return f.err("wipe")
	})
	return f
}

// installerFiles is the content the fake mount places in the installer.
type installerFiles map[string][]byte

// useMounts installs mount seams. Mounting the installer writes files into
// the target directory; mounts and unmounts are recorded.
func useMounts(t *testing.T, files installerFiles, mountErr error) *[]string {
	t.Helper()
	var calls []string
	swap(t, &hostMount, func(source, target, fstype string, flags uintptr, data string) error {
		calls = append(calls, "mount "+target)
		if mountErr != nil {
			return mountErr
		}
		for name, data := range files {
			full := filepath.Join(target, name)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, data, 0o600); err != nil {
				return err
			}
		}
		return nil
	})
	swap(t, &hostUnmount, func(target string, flags int) error {
		calls = append(calls, "umount "+target)
		return nil
	})
	return &calls
}

// unsealTPM adds Unseal and populated PCR reads to fakeTPM.
type unsealTPM struct {
	*fakeTPM
	unsealKey []byte
	unsealErr error
}

func (u *unsealTPM) Unseal(_ context.Context, _ *xkmssdk.SealedData, _ *xkmssdk.UnsealOptions) ([]byte, error) {
	return u.unsealKey, u.unsealErr
}

func luksKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// runFixture prepares a hardware-TPM firstboot run under a temporary host
// root: a TPM device, an installer container that unlocks to a 32-byte key,
// a recovery key and a platform config.
type runFixture struct {
	exec     *Executor
	tpm      *fakeTPM
	commands *fakeCommands
	luks     *fakeLUKS
	mounts   *[]string
	syncs    int
}

func newRunFixture(t *testing.T, key []byte) *runFixture {
	t.Helper()
	useHostRoot(t)
	swap(t, &hostIsSocket, func(string) bool { return false })
	swap(t, &hostIsDevice, func(p string) bool { return p == "/dev/tpmrm0" })
	swap(t, &hostLookPath, func(string) (string, error) { return "", errSeam })
	swap(t, &gatewaydConfigDir, hostPath("/etc/gatewayd"))
	swap(t, &gatewaydInitScript, hostPath("/etc/init.d/gatewayd"))

	writeHostFile(t, EFIInstallerFile, []byte("luks container"))
	tpm := &fakeTPM{cfg: fullTPMConfig()}
	f := &runFixture{
		tpm:      tpm,
		commands: useCommands(t),
		luks:     useLUKS(t),
		mounts: useMounts(t, installerFiles{
			"luks-key.bin":                     key,
			"recovery-key.txt":                 []byte("recovery-1234"),
			"etc/trusted-platform/config.yaml": []byte("node: {}\n"),
		}, nil),
	}
	// Record host syncs instead of flushing the runner's filesystems.
	swap(t, &hostSync, func() { f.syncs++ })
	f.exec = &Executor{
		tpm:    tpm,
		logger: testLogger(),
		config: &Config{
			PCRSelection:  []uint{0, 7},
			TPMAutoUnseal: true,
			LuksTPMOnly:   true,
			LuksDevice:    "/dev/vda3",
			SwtpmStateDir: hostPath("/var/lib/swtpm"),
			EFIMountPoint: hostPath("/boot/efi"),
			Debug:         true,
		},
	}
	return f
}

func TestRun_HardwareTPMSealsInstallerKey(t *testing.T) {
	f := newRunFixture(t, luksKey())

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.syncs == 0 {
		t.Error("Run sealed the installer key without syncing the host filesystems")
	}

	for _, p := range []string{
		EFISealUpgradePub, EFISealUpgradePriv,
		EFISealPlatformPub, EFISealPlatformPriv,
		EFIPCRBanks, PlatformInitializedMarker,
		"/var/lib/trusted-platform/config.yaml", "/etc/trusted-platform/config.yaml",
		"/etc/trusted-platform/platformd.env", "/etc/systemd/system/platformd.service",
		EFITPMDir + "/boot-env.txt",
	} {
		if !hostFileExists(p) {
			t.Errorf("Run did not write %s", p)
		}
	}
	if hostFileExists(EFIInstallerFile) {
		t.Error("the installer container survived the run")
	}
	if len(f.luks.wiped) != 1 || f.luks.wiped[0].Device != hostPath(EFIInstallerFile) || !f.luks.wiped[0].Trim {
		t.Errorf("wipe = %+v, want one trimmed wipe of the installer", f.luks.wiped)
	}
	if got := strings.Join(f.luks.killed, ","); got != "/dev/vda3" {
		t.Errorf("killed keyslots on %q, want /dev/vda3", got)
	}
	recovery, err := os.ReadFile(hostPath(RecoveryKeyPath))
	if err != nil || string(recovery) != "recovery-1234" {
		t.Errorf("recovery key = %q, %v", recovery, err)
	}
	if !f.commands.ran("systemctl enable platformd.service") {
		t.Errorf("platformd was not enabled: %v", f.commands.calls)
	}
	if !strings.Contains(strings.Join(*f.mounts, ","), "mount "+hostPath("/tmp/installer-mount")) {
		t.Errorf("installer was not mounted: %v", *f.mounts)
	}
	for i, b := range f.tpm.sealedKey {
		if b != 0 {
			t.Fatalf("key byte %d not cleared after Run", i)
		}
	}
}

func TestRun_AlreadySealedSkips(t *testing.T) {
	f := newRunFixture(t, luksKey())
	writeHostFile(t, EFISealPlatformPub, []byte("pub"))
	writeHostFile(t, EFISealPlatformPriv, []byte("priv"))

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.commands.calls) != 0 || f.tpm.sealedKey != nil {
		t.Errorf("an already-sealed system ran %v and sealed %v", f.commands.calls, f.tpm.sealedKey)
	}
}

func TestRun_AutoUnsealDisabledOnlyMarks(t *testing.T) {
	f := newRunFixture(t, luksKey())
	f.exec.config.TPMAutoUnseal = false

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hostFileExists(PlatformInitializedMarker) {
		t.Error("marker not written")
	}
	if f.tpm.sealedKey != nil {
		t.Error("sealed with auto-unseal disabled")
	}
}

func TestRun_AutoUnsealDisabledMarkerFailure(t *testing.T) {
	f := newRunFixture(t, luksKey())
	f.exec.config.TPMAutoUnseal = false
	// A file where the marker directory belongs makes MkdirAll fail.
	writeHostFile(t, filepath.Dir(PlatformInitializedMarker), []byte("file"))

	err := f.exec.Run(context.Background())
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != "failed to create marker file" {
		t.Fatalf("Run error = %v, want the marker WrappedError", err)
	}
}

func TestRun_InitrdSealsOnConfiguredEFISkip(t *testing.T) {
	f := newRunFixture(t, luksKey())
	f.exec.config.EFIMountPoint = t.TempDir()
	tpmDir := filepath.Join(f.exec.config.EFIMountPoint, "tpm2")
	if err := os.MkdirAll(tpmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"seal-platform.pub", "seal-platform.priv"} {
		if err := os.WriteFile(filepath.Join(tpmDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hostFileExists(PlatformInitializedMarker) || f.tpm.sealedKey != nil {
		t.Error("initrd-sealed system was not skipped with a marker")
	}
}

func TestRun_NoInstallerIsErrNoLUKSKey(t *testing.T) {
	f := newRunFixture(t, luksKey())
	if err := os.Remove(hostPath(EFIInstallerFile)); err != nil {
		t.Fatal(err)
	}

	if err := f.exec.Run(context.Background()); !errors.Is(err, ErrNoLUKSKey) {
		t.Fatalf("Run error = %v, want ErrNoLUKSKey", err)
	}
}

func TestRun_ShortKeyIsErrInvalidKeySize(t *testing.T) {
	f := newRunFixture(t, []byte("short"))

	if err := f.exec.Run(context.Background()); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("Run error = %v, want ErrInvalidKeySize", err)
	}
}

func TestRun_StepFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *runFixture)
		msg   string
	}{
		{"efi mount", func(t *testing.T, f *runFixture) {
			f.commands.fail = []string{"mountpoint", "mount "}
		}, "failed to mount EFI partition"},
		{"installer unlock", func(t *testing.T, f *runFixture) {
			f.luks.fail["unlock"] = true
		}, "failed to extract keys from installer"},
		{"upgrade seal", func(t *testing.T, f *runFixture) {
			f.tpm.sealErr = errFakeTPM
		}, "failed to create upgrade sealed objects"},
		{"pcr banks", func(t *testing.T, f *runFixture) {
			f.tpm.cfg.SSRK = nil
		}, "failed to write PCR banks file"},
		{"marker", func(t *testing.T, f *runFixture) {
			writeHostFile(t, filepath.Dir(PlatformInitializedMarker), []byte("file"))
		}, "failed to create marker file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRunFixture(t, luksKey())
			tc.setup(t, f)
			err := f.exec.Run(context.Background())
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tc.msg {
				t.Fatalf("Run error = %v, want WrappedError %q", err, tc.msg)
			}
		})
	}
}

func TestRun_WarningsDoNotFail(t *testing.T) {
	f := newRunFixture(t, luksKey())
	f.luks.fail["wipe"] = true
	f.luks.fail["killslot"] = true
	f.tpm.readPCRsErr = errFakeTPM
	f.commands.fail = []string{"systemctl enable"}
	f.exec.config.Debug = false

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hostFileExists(EFIInstallerFile) {
		t.Error("installer not deleted after the wipe failed")
	}
	if !hostFileExists(PlatformInitializedMarker) {
		t.Error("marker not written")
	}
}

func TestRun_ResealReadsUpgradeSeals(t *testing.T) {
	f := newRunFixture(t, luksKey())
	writeHostFile(t, EFISealUpgradePub, []byte("old-pub"))
	writeHostFile(t, EFISealUpgradePriv, []byte("old-priv"))
	f.exec.tpm = &unsealTPM{fakeTPM: f.tpm, unsealKey: luksKey()}
	f.exec.config.LuksTPMOnly = false

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.luks.unlocked) != 0 {
		t.Error("a reseal opened the installer")
	}
	pub, err := os.ReadFile(hostPath(EFISealUpgradePub))
	if err != nil || string(pub) == "old-pub" {
		t.Errorf("upgrade seal not rewritten: %q, %v", pub, err)
	}
}

func TestRun_ResealUnsealFailure(t *testing.T) {
	f := newRunFixture(t, luksKey())
	writeHostFile(t, EFISealUpgradePub, []byte("old-pub"))
	writeHostFile(t, EFISealUpgradePriv, []byte("old-priv"))
	f.exec.tpm = &unsealTPM{fakeTPM: f.tpm, unsealErr: errFakeTPM}

	err := f.exec.Run(context.Background())
	if !errors.Is(err, errFakeTPM) {
		t.Fatalf("Run error = %v, want the unseal failure", err)
	}
}

// useSwtpm makes the TPM detector find no device and start swtpm as a
// short-lived copy of the test binary that runs no tests.
func useSwtpm(t *testing.T, socketUp bool) {
	t.Helper()
	swap(t, &hostIsDevice, func(string) bool { return false })
	swap(t, &hostIsSocket, func(p string) bool {
		return socketUp && strings.HasSuffix(p, "swtpm.sock") && !strings.HasPrefix(p, hostPath("/var/lib/swtpm"))
	})
	swap(t, &hostStartProcess, func(cmd *exec.Cmd) error {
		cmd.Path = os.Args[0]
		cmd.Args = []string{os.Args[0], "-test.run=^$"}
		cmd.Err = nil
		return cmd.Start()
	})
	writeHostFile(t, "/usr/bin/swtpm", []byte("#!/bin/sh\n"))
}

func TestRun_SoftwareTPMSealsWithoutPCRs(t *testing.T) {
	f := newRunFixture(t, luksKey())
	f.exec.config.SwtpmStateDir = t.TempDir()
	useSwtpm(t, true)
	if err := os.WriteFile(filepath.Join(f.exec.config.SwtpmStateDir, "tpm2-00.permall"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := f.exec.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.commands.ran("swtpm_setup --tpm2") {
		t.Errorf("swtpm_setup not run: %v", f.commands.calls)
	}
	if hostFileExists(EFIPCRBanks) {
		t.Error("a software TPM wrote a pcr-banks file")
	}
	state, err := os.ReadFile(hostPath(EFISwtpmStateDir + "/tpm2-00.permall"))
	if err != nil || string(state) != "state" {
		t.Errorf("swtpm state not copied: %q, %v", state, err)
	}
}

func TestRun_SoftwareTPMFailures(t *testing.T) {
	t.Run("setup", func(t *testing.T) {
		f := newRunFixture(t, luksKey())
		f.exec.config.SwtpmStateDir = t.TempDir()
		useSwtpm(t, true)
		f.commands.fail = []string{"swtpm_setup"}
		err := f.exec.Run(context.Background())
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) || wrapped.Msg != "failed to start swtpm" {
			t.Fatalf("Run error = %v, want failed to start swtpm", err)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		f := newRunFixture(t, luksKey())
		swap(t, &hostIsDevice, func(string) bool { return false })
		err := f.exec.Run(context.Background())
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) || wrapped.Msg != "TPM detection failed" {
			t.Fatalf("Run error = %v, want TPM detection failed", err)
		}
	})
}

func TestStartSwtpm_StartFailure(t *testing.T) {
	useCommands(t)
	swap(t, &hostStartProcess, func(*exec.Cmd) error { return errSeam })
	e := newFakeExecutor(nil, DefaultConfig())

	cmd, err := e.startSwtpm(t.TempDir())
	if cmd != nil || !errors.Is(err, errSeam) {
		t.Fatalf("startSwtpm = %v, %v; want the start failure", cmd, err)
	}
}

func TestStopSwtpm_NilAndExited(t *testing.T) {
	e := newFakeExecutor(nil, DefaultConfig())
	e.stopSwtpm(nil)
	e.stopSwtpm(&exec.Cmd{})

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	e.stopSwtpm(cmd)
	if cmd.ProcessState == nil {
		t.Fatal("stopSwtpm returned before the child was reaped")
	}
}

func TestWaitForSocket(t *testing.T) {
	e := newFakeExecutor(nil, DefaultConfig())
	swap(t, &hostIsSocket, func(string) bool { return true })
	if err := e.waitForSocket("/run/x.sock", time.Second); err != nil {
		t.Fatalf("waitForSocket: %v", err)
	}

	swap(t, &hostIsSocket, func(string) bool { return false })
	var msg *MessageError
	if err := e.waitForSocket("/run/x.sock", 0); !errors.As(err, &msg) {
		t.Fatalf("waitForSocket error = %v, want a timeout MessageError", err)
	}
}

func TestDetectTPMDevice(t *testing.T) {
	logger := testLogger()
	t.Setenv("TPM2TOOLS_TCTI", "")
	useHostRoot(t)

	if _, err := detectTPMDevice(logger); !errors.Is(err, ErrNoTPMDevice) {
		t.Fatalf("no device: err = %v, want ErrNoTPMDevice", err)
	}
	writeHostFile(t, "/dev/tpm0", nil)
	if got, err := detectTPMDevice(logger); err != nil || got != "/dev/tpm0" {
		t.Fatalf("tpm0 = %q, %v", got, err)
	}
	writeHostFile(t, "/dev/tpmrm0", nil)
	if got, err := detectTPMDevice(logger); err != nil || got != "/dev/tpmrm0" {
		t.Fatalf("tpmrm0 = %q, %v", got, err)
	}

	for tcti, want := range map[string]string{
		"device:/dev/tpm1":       "/dev/tpm1",
		"swtpm:path=/run/s.sock": "swtpm:path=/run/s.sock",
		"/dev/tpm2":              "/dev/tpm2",
	} {
		t.Setenv("TPM2TOOLS_TCTI", tcti)
		if got, err := detectTPMDevice(logger); err != nil || got != want {
			t.Errorf("TCTI %q = %q, %v; want %q", tcti, got, err, want)
		}
	}
}

func TestLoadTPMConfig(t *testing.T) {
	logger := testLogger()
	useHostRoot(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(bad, []byte("tpm: [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("tpm:\n  platform-pcr: 23\n  platform-srk:\n    srk-handle: 0x81000010\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	swap(t, &platformConfigPaths, []string{filepath.Join(dir, "missing.yaml"), bad})
	if _, err := loadTPMConfig(logger); !errors.Is(err, ErrNoTPMConfig) {
		t.Fatalf("err = %v, want ErrNoTPMConfig", err)
	}

	swap(t, &platformConfigPaths, []string{bad, good})
	cfg, err := loadTPMConfig(logger)
	if err != nil || cfg.PlatformPCR != 23 || cfg.PlatformSRK.SRKHandle != 0x81000010 {
		t.Fatalf("config file = %+v, %v", cfg, err)
	}

	writeHostFile(t, "/boot/efi/tpm2/pcr-banks", []byte("platform-pcr=16\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n"))
	cfg, err = loadTPMConfig(logger)
	if err != nil || cfg.PlatformPCR != 16 {
		t.Fatalf("pcr-banks = %+v, %v", cfg, err)
	}
}

func TestNewExecutor_OpensTPM(t *testing.T) {
	useHostRoot(t)
	t.Setenv("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")
	swap(t, &platformConfigPaths, nil)
	writeHostFile(t, "/boot/efi/tpm2/pcr-banks", []byte("platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n"))

	tpm := &fakeTPM{cfg: fullTPMConfig()}
	var opened *xkmssdk.TPMParams
	swap(t, &openTPM2, func(p *xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		opened = p
		return tpm, xkmssdk.ErrTPMNotInitialized
	})

	e, err := NewExecutor(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if e.TPM() != tpm || e.Backend() == nil {
		t.Errorf("executor TPM = %v, backend = %v", e.TPM(), e.Backend())
	}
	if opened.Config.Device != "/dev/tpmrm0" || opened.Config.UseSimulator {
		t.Errorf("TPM opened with %+v", opened.Config)
	}
}

func TestNewExecutor_Errors(t *testing.T) {
	t.Run("no device", func(t *testing.T) {
		useHostRoot(t)
		t.Setenv("TPM2TOOLS_TCTI", "")
		if _, err := NewExecutor(context.Background(), DefaultConfig(), testLogger()); !errors.Is(err, ErrNoTPMDevice) {
			t.Fatalf("err = %v, want ErrNoTPMDevice", err)
		}
	})
	t.Run("no config", func(t *testing.T) {
		useHostRoot(t)
		t.Setenv("TPM2TOOLS_TCTI", "/dev/tpm0")
		swap(t, &platformConfigPaths, nil)
		if _, err := NewExecutor(context.Background(), DefaultConfig(), testLogger()); !errors.Is(err, ErrNoTPMConfig) {
			t.Fatalf("err = %v, want ErrNoTPMConfig", err)
		}
	})
	t.Run("open fails every attempt", func(t *testing.T) {
		useHostRoot(t)
		t.Setenv("TPM2TOOLS_TCTI", "/dev/tpm0")
		writeHostFile(t, "/boot/efi/tpm2/pcr-banks", []byte("platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n"))
		swap(t, &tpmRetryDelay, 0)
		attempts := 0
		swap(t, &openTPM2, func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
			attempts++
			return nil, errSeam
		})
		_, err := NewExecutor(context.Background(), DefaultConfig(), testLogger())
		if !errors.Is(err, errSeam) || attempts != 5 {
			t.Fatalf("err = %v after %d attempts, want errSeam after 5", err, attempts)
		}
	})
}

func TestInitializeTPM_SucceedsAfterRetry(t *testing.T) {
	useHostRoot(t)
	swap(t, &tpmRetryDelay, 0)
	tpm := &fakeTPM{}
	attempts := 0
	swap(t, &openTPM2, func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		attempts++
		if attempts < 3 {
			return nil, errSeam
		}
		return tpm, nil
	})

	got, backend, err := initializeTPM(fullTPMConfig(), testLogger())
	if err != nil || got != tpm || backend == nil || attempts != 3 {
		t.Fatalf("initializeTPM = %v, %v, %v after %d attempts", got, backend, err, attempts)
	}
}

func TestExtractKeysFromInstaller_CleansLeftoverMapper(t *testing.T) {
	useHostRoot(t)
	commands := useCommands(t, "losetup -d /dev/loop1")
	commands.output["losetup /dev/loop0"] = "/dev/loop0: (/boot/efi/tpm2/installer.luks)"
	commands.output["losetup /dev/loop1"] = "/dev/loop1: (/boot/efi/tpm2/installer.luks)"
	lk := useLUKS(t, "lock")
	useMounts(t, installerFiles{"luks-key.bin": luksKey(), "config.yaml": []byte("flat: true\n")}, nil)
	writeHostFile(t, "/dev/mapper/installer", nil)
	e := newFakeExecutor(nil, DefaultConfig())

	key, recovery, config, err := e.extractKeysFromInstaller(context.Background(), "/efi/installer.luks")
	if err != nil {
		t.Fatalf("extractKeysFromInstaller: %v", err)
	}
	if len(key) != 32 || recovery != "" || string(config) != "flat: true\n" {
		t.Errorf("got key %d bytes, recovery %q, config %q", len(key), recovery, config)
	}
	if !commands.ran("losetup -d /dev/loop0") {
		t.Errorf("leftover loop device not detached: %v", commands.calls)
	}
	if len(lk.detached) != 1 || lk.detached[0] != "/dev/loop7" {
		t.Errorf("detached %v, want the installer loop device", lk.detached)
	}
}

func TestExtractKeysFromInstaller_Failures(t *testing.T) {
	cases := []struct {
		name     string
		luksFail []string
		mountErr error
		files    installerFiles
		msg      string
	}{
		{"loop", []string{"setuploop"}, nil, nil, "failed to setup loop device"},
		{"unlock", []string{"unlock"}, nil, nil, "failed to unlock installer"},
		{"mount", []string{"mapped"}, errSeam, nil, "failed to mount installer"},
		{"no key", nil, nil, installerFiles{}, "failed to read luks-key.bin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useHostRoot(t)
			useCommands(t)
			lk := useLUKS(t, tc.luksFail...)
			useMounts(t, tc.files, tc.mountErr)
			e := newFakeExecutor(nil, DefaultConfig())

			_, _, _, err := e.extractKeysFromInstaller(context.Background(), "/efi/installer.luks")
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tc.msg {
				t.Fatalf("err = %v, want WrappedError %q", err, tc.msg)
			}
			if tc.name != "loop" && len(lk.detached) != 1 {
				t.Errorf("loop device not released after failure: %v", lk.detached)
			}
		})
	}
}

func TestExtractKeysFromInstaller_MountPointBlocked(t *testing.T) {
	useHostRoot(t)
	useCommands(t)
	lk := useLUKS(t)
	useMounts(t, nil, nil)
	writeHostFile(t, "/tmp", []byte("file"))
	e := newFakeExecutor(nil, DefaultConfig())

	_, _, _, err := e.extractKeysFromInstaller(context.Background(), "/efi/installer.luks")
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != "failed to create mount point" {
		t.Fatalf("err = %v, want the mount point WrappedError", err)
	}
	if len(lk.locked) != 1 {
		t.Errorf("installer not relocked: %v", lk.locked)
	}
}

func TestSecureWipeInstaller(t *testing.T) {
	e := newFakeExecutor(nil, DefaultConfig())
	path := filepath.Join(t.TempDir(), "installer.luks")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	lk := useLUKS(t)
	if err := e.secureWipeInstaller(path); err != nil {
		t.Fatalf("secureWipeInstaller: %v", err)
	}
	if len(lk.wiped) != 1 || lk.wiped[0].Passes != 1 || !lk.wiped[0].Random {
		t.Errorf("wipe options = %+v", lk.wiped)
	}

	var wrapped *WrappedError
	if err := e.secureWipeInstaller(path); !errors.As(err, &wrapped) || wrapped.Msg != "failed to delete installer" {
		t.Fatalf("missing file: err = %v", err)
	}
	lk.fail["wipe"] = true
	if err := e.secureWipeInstaller(path); !errors.Is(err, errSeam) {
		t.Fatalf("wipe failure: err = %v", err)
	}
}

func TestWriteRecoveryKey(t *testing.T) {
	useHostRoot(t)
	e := newFakeExecutor(nil, DefaultConfig())
	if err := e.writeRecoveryKey(""); err != nil {
		t.Fatalf("empty key: %v", err)
	}
	if hostFileExists(RecoveryKeyPath) {
		t.Error("an empty recovery key was written")
	}
	if err := e.writeRecoveryKey("abcd"); err != nil {
		t.Fatalf("writeRecoveryKey: %v", err)
	}
	info, err := os.Stat(hostPath(RecoveryKeyPath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery key %v, %v; want mode 0600", info, err)
	}

	// A directory where the key file belongs makes the write fail.
	if err := os.Remove(hostPath(RecoveryKeyPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(hostPath(RecoveryKeyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	var wrapped *WrappedError
	if err := e.writeRecoveryKey("abcd"); !errors.As(err, &wrapped) || wrapped.Msg != "failed to write recovery key" {
		t.Fatalf("key path is a directory: err = %v", err)
	}

	// A file where the key directory belongs makes MkdirAll fail.
	useHostRoot(t)
	writeHostFile(t, filepath.Dir(RecoveryKeyPath), []byte("file"))
	if err := e.writeRecoveryKey("abcd"); !errors.As(err, &wrapped) || wrapped.Msg != "failed to create recovery key directory" {
		t.Fatalf("key directory blocked: err = %v", err)
	}
}

func TestRemoveLuksPasswordKeyslot(t *testing.T) {
	useHostRoot(t)
	lk := useLUKS(t)
	e := newFakeExecutor(nil, DefaultConfig())

	var msg *MessageError
	if err := e.removeLuksPasswordKeyslot("", luksKey()); !errors.As(err, &msg) {
		t.Fatalf("no device: err = %v, want MessageError", err)
	}

	writeHostFile(t, "/dev/sda3", nil)
	lk.isLUKS = true
	if err := e.removeLuksPasswordKeyslot("", luksKey()); err != nil {
		t.Fatalf("auto-detect: %v", err)
	}
	if strings.Join(lk.killed, ",") != "/dev/sda3" {
		t.Errorf("killed slot on %v, want /dev/sda3", lk.killed)
	}

	lk.fail["killslot"] = true
	if err := e.removeLuksPasswordKeyslot("/dev/vda3", luksKey()); !errors.Is(err, errSeam) {
		t.Fatalf("kill failure: err = %v", err)
	}
}

func TestEnsureEFIMounted(t *testing.T) {
	e := newFakeExecutor(nil, DefaultConfig())

	commands := useCommands(t)
	if err := e.ensureEFIMounted("/boot/efi"); err != nil || commands.ran("mount /boot/efi") {
		t.Fatalf("already mounted: err = %v, calls %v", err, commands.calls)
	}
	commands = useCommands(t, "mountpoint")
	if err := e.ensureEFIMounted("/boot/efi"); err != nil || !commands.ran("mount /boot/efi") {
		t.Fatalf("mount: err = %v, calls %v", err, commands.calls)
	}
	useCommands(t, "mountpoint", "mount ")
	if err := e.ensureEFIMounted("/boot/efi"); !errors.Is(err, errSeam) {
		t.Fatalf("mount failure: err = %v", err)
	}
}

func TestSaveDebugInfo(t *testing.T) {
	useHostRoot(t)
	e := newFakeExecutor(nil, DefaultConfig())
	if err := os.MkdirAll(hostPath(EFITPMDir), 0o755); err != nil {
		t.Fatal(err)
	}

	commands := useCommands(t)
	commands.output["efibootmgr -v"] = "BootOrder: 0001\n"
	writeHostFile(t, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", []byte{1})
	e.saveDebugInfo()
	data, err := os.ReadFile(hostPath(EFITPMDir + "/boot-env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "BootOrder: 0001") || !strings.Contains(string(data), "SecureBoot: 01") {
		t.Errorf("debug info = %q", data)
	}

	useCommands(t, "efibootmgr")
	if err := os.Remove(hostPath("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")); err != nil {
		t.Fatal(err)
	}
	e.saveDebugInfo()
	data, err = os.ReadFile(hostPath(EFITPMDir + "/boot-env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "efibootmgr not available") || !strings.Contains(string(data), "SecureBoot variable not available") {
		t.Errorf("debug info = %q", data)
	}
}

func TestCopySwtpmState(t *testing.T) {
	useHostRoot(t)
	e := newFakeExecutor(nil, DefaultConfig())
	state := t.TempDir()
	for name, data := range map[string]string{"tpm2-00.permall": "p", "swtpm.sock": "s", "swtpm.sock.ctrl": "c"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(state, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := e.copySwtpmState(state); err != nil {
		t.Fatalf("copySwtpmState: %v", err)
	}
	entries, err := os.ReadDir(hostPath(EFISwtpmStateDir))
	if err != nil || len(entries) != 1 || entries[0].Name() != "tpm2-00.permall" {
		t.Fatalf("copied %v, %v; want only the state file", entries, err)
	}

	var wrapped *WrappedError
	if err := e.copySwtpmState(filepath.Join(state, "missing")); !errors.As(err, &wrapped) || wrapped.Msg != "failed to read swtpm state directory" {
		t.Fatalf("missing dir: err = %v", err)
	}
}

func TestDetectInitSystem(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostLookPath, func(string) (string, error) { return "", errSeam })
	if got := detectInitSystem(); got != "unknown" {
		t.Fatalf("bare root = %q, want unknown", got)
	}

	swap(t, &hostLookPath, func(name string) (string, error) {
		if name == "systemctl" {
			return "/usr/bin/systemctl", nil
		}
		return "", errSeam
	})
	if got := detectInitSystem(); got != "systemd" {
		t.Fatalf("systemctl on PATH = %q, want systemd", got)
	}

	writeHostFile(t, "/run/systemd/system/.keep", nil)
	if got := detectInitSystem(); got != "systemd" {
		t.Fatalf("/run/systemd = %q, want systemd", got)
	}

	writeHostFile(t, "/etc/init.d/.keep", nil)
	swap(t, &hostLookPath, func(string) (string, error) { return "/sbin/rc-service", nil })
	if got := detectInitSystem(); got != "openrc" {
		t.Fatalf("rc-service on PATH = %q, want openrc", got)
	}

	writeHostFile(t, "/sbin/openrc-run", nil)
	if got := detectInitSystem(); got != "openrc" {
		t.Fatalf("openrc-run = %q, want openrc", got)
	}
}

func TestInstallPlatformdService_OpenRC(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, "/sbin/openrc-run", nil)
	writeHostFile(t, "/etc/init.d/.keep", nil)
	commands := useCommands(t, "rc-service")
	e := newFakeExecutor(nil, DefaultConfig())

	if err := e.installPlatformdService(true); err != nil {
		t.Fatalf("installPlatformdService: %v", err)
	}
	env, err := os.ReadFile(hostPath("/etc/trusted-platform/platformd.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), `PLATFORMD_DEBUG="--debug"`) {
		t.Errorf("env file = %q", env)
	}
	if !hostFileExists("/etc/init.d/platformd") || !commands.ran("rc-update add platformd default") {
		t.Errorf("OpenRC service not installed: %v", commands.calls)
	}

	useCommands(t, "rc-update")
	var cmdErr *CommandOutputError
	if err := e.installPlatformdService(false); !errors.As(err, &cmdErr) {
		t.Fatalf("rc-update failure: err = %v, want CommandOutputError", err)
	}
}

func TestInstallSystemdService(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, "/lib/systemd/system/.keep", nil)
	commands := useCommands(t, "systemctl daemon-reload", "systemctl start")
	e := newFakeExecutor(nil, DefaultConfig())

	if err := e.installSystemdService(); err != nil {
		t.Fatalf("installSystemdService: %v", err)
	}
	if !hostFileExists("/lib/systemd/system/platformd.service") || !commands.ran("systemctl enable platformd.service") {
		t.Errorf("systemd service not installed: %v", commands.calls)
	}

	useCommands(t, "systemctl enable")
	var cmdErr *CommandOutputError
	if err := e.installSystemdService(); !errors.As(err, &cmdErr) {
		t.Fatalf("enable failure: err = %v, want CommandOutputError", err)
	}
}

func TestInstallPlatformdService_ConfigDirBlocked(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, "/etc/trusted-platform", []byte("file"))
	swap(t, &hostLookPath, func(string) (string, error) { return "", errSeam })
	e := newFakeExecutor(nil, DefaultConfig())

	var wrapped *WrappedError
	if err := e.installPlatformdService(false); !errors.As(err, &wrapped) {
		t.Fatalf("err = %v, want WrappedError", err)
	}
}
