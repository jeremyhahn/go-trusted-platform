package firstboot

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/partition"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// strategyTPM adds what provisioning uses to fakeTPM: the EK certificate
// lookup, the PPI ForceClear, Install, the hierarchy auth change and the raw
// transport tpmowner reads. Without a transport every command fails, so
// tpmowner.Prepare stops provisioning before any key is created.
type strategyTPM struct {
	*fakeTPM
	ekCert          *x509.Certificate
	ekErr           error
	forceClearErr   error
	forceClearCalls int
	transport       transport.TPM
	installErr      error
	installSOPIN    xkmssdk.Password
	installOpts     *xkmssdk.InstallOptions
	setAuthErr      error
	setAuthCalls    int
}

func (s *strategyTPM) EKCertificate() (*x509.Certificate, error) { return s.ekCert, s.ekErr }

func (s *strategyTPM) ForceClear() error {
	s.forceClearCalls++
	return s.forceClearErr
}

func (s *strategyTPM) Transport() transport.TPM {
	if s.transport == nil {
		return failingTransport{}
	}
	return s.transport
}

func (s *strategyTPM) Install(soPIN xkmssdk.Password, opts *xkmssdk.InstallOptions) error {
	s.installSOPIN, s.installOpts = soPIN, opts
	return s.installErr
}

func (s *strategyTPM) SetHierarchyAuth(_, _ xkmssdk.Password, _ *libtpm2.TPMHandle) error {
	s.setAuthCalls++
	return s.setAuthErr
}

// newProvisionableTPM is a TPM fresh from the factory: an in-memory simulator
// answers tpmowner's hierarchy reads with an empty owner auth, it has an EK
// certificate and its Platform KeyStore SRK is already present.
func newProvisionableTPM(t *testing.T) *strategyTPM {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		t.Fatalf("simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := sim.Close(); err != nil {
			t.Errorf("close simulator: %v", err)
		}
	})
	return &strategyTPM{
		fakeTPM:   &fakeTPM{cfg: fullTPMConfig()},
		ekCert:    &x509.Certificate{},
		transport: transport.FromReadWriter(sim),
	}
}

// keyBackend stands in for the executor's key backend; the SRK probe only
// requires one to be present.
type keyBackend struct{ xkmssdk.TPMKeyBackend }

// newProvisioningStrategy is a strategy over tpm whose SO PIN resolves and
// whose executor carries a key backend and a seal PCR selection.
func newProvisioningStrategy(t *testing.T, tpm *strategyTPM, h luks.Handler) *FirstbootSealStrategy {
	t.Helper()
	s := newStrategy(tpm, h)
	s.executor.backend = keyBackend{}
	s.executor.config.PCRSelection = []uint{7}
	s.soPINConfigPaths, s.soPINHandoffFile = soPINSources(t, "123456")
	return s
}

// failingTransport is a TPM transport whose every command fails.
type failingTransport struct{}

func (failingTransport) Send([]byte) ([]byte, error) { return nil, errSeam }

// fakeHandler is the part of luks.Handler Unlock uses: IsOpen and Open. The
// embedded interface is nil, so any other call panics.
type fakeHandler struct {
	luks.Handler
	open    bool
	openErr error
	opened  []string
}

func (f *fakeHandler) IsOpen(_ context.Context, _ string) bool { return f.open }

func (f *fakeHandler) Open(_ context.Context, devicePath, mappingName string, _ []byte, _ *luks.OpenOptions) error {
	f.opened = append(f.opened, devicePath+" "+mappingName)
	return f.openErr
}

// newStrategy builds a FirstbootSealStrategy over an executor whose root
// device is /dev/sda2. A nil tpm leaves the executor without a TPM.
func newStrategy(tpm xkmssdk.TrustedPlatformModule, h luks.Handler) *FirstbootSealStrategy {
	e := &Executor{logger: testLogger(), config: &Config{LuksDevice: "/dev/sda2"}}
	if tpm != nil {
		e.tpm = tpm
	}
	return NewFirstbootSealStrategy(e, h, testLogger())
}

// installerConfigPath is the installer config inside the mounted installer.
const installerConfigPath = strategyInstallerMountPoint + "/etc/trusted-platform/config.yaml"

// writeInstallerConfig writes the installer config the strategy reads.
func writeInstallerConfig(t *testing.T, yaml string) {
	t.Helper()
	writeHostFile(t, installerConfigPath, []byte(yaml))
}

// useESP makes the ESP lookup return dev and err. It returns the root device
// the lookup was asked about.
func useESP(t *testing.T, dev string, err error) *string {
	t.Helper()
	var rootDevice string
	swap(t, &findESP, func(root string, _ ...partition.Option) (string, error) {
		rootDevice = root
		return dev, err
	})
	return &rootDevice
}

// mountEFIDir makes the ESP read as already mounted.
func mountEFIDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(hostPath(strategyEFIMountPoint+"/EFI"), 0o755); err != nil {
		t.Fatalf("mkdir EFI: %v", err)
	}
}

func readHostFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(hostPath(p))
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(data)
}

func requireWrapped(t *testing.T, err error, msg string) *WrappedError {
	t.Helper()
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("err = %v (%T), want *WrappedError", err, err)
	}
	if !strings.HasPrefix(wrapped.Msg, msg) {
		t.Fatalf("WrappedError.Msg = %q, want prefix %q", wrapped.Msg, msg)
	}
	return wrapped
}

func requireMessage(t *testing.T, err error, msg string) {
	t.Helper()
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("err = %v (%T), want *MessageError", err, err)
	}
	if !strings.Contains(msgErr.Msg, msg) {
		t.Fatalf("MessageError.Msg = %q, want it to contain %q", msgErr.Msg, msg)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// eventLogPath is where Unlock polls for the TPM event log.
const eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

// unlockFixture is a first boot whose ESP is mounted and holds the installer
// container, and whose installer is already open: a 32-byte key, a recovery key, an installer config naming a
// direct (non-LVM) root and the destroy strategy, a populated event log and
// the root mapping's device node.
type unlockFixture struct {
	strategy *FirstbootSealStrategy
	handler  *fakeHandler
	luks     *fakeLUKS
	commands *fakeCommands
	mounts   *[]string
	volume   *luks.VolumeConfig
}

func newUnlockFixture(t *testing.T, tpm xkmssdk.TrustedPlatformModule) *unlockFixture {
	t.Helper()
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	swap(t, &firmwareIsAvailable, func() bool { return false })
	mountEFIDir(t)
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyInstallerContainerFile, []byte("container"))
	writeHostFile(t, strategyInstallerMountPoint+"/luks-key.bin", luksKey())
	writeHostFile(t, strategyInstallerMountPoint+"/recovery-key.txt", []byte("recovery-passphrase"))
	writeHostFile(t, strategyInstallerMountPoint+"/etc/trusted-platform/platform.yaml", []byte("platform: {}\n"))
	writeInstallerConfig(t, "disk:\n  root-filesystem: ext4\n  encryption:\n    tpm:\n      recovery-key-strategy: destroy\n")
	writeHostFile(t, eventLogPath, []byte("events"))
	writeHostFile(t, strategyDevMapperDir+"/cryptroot", []byte("root"))

	f := &unlockFixture{
		handler:  &fakeHandler{},
		luks:     useLUKS(t),
		commands: useCommands(t),
		mounts:   useMounts(t, nil, nil),
		volume:   &luks.VolumeConfig{DevicePath: "/dev/sda2", MappingName: "cryptroot"},
	}
	f.strategy = newStrategy(tpm, f.handler)
	return f
}

// Without a TPM, provisioning fails and Unlock falls back to the plain key:
// the root is opened, the installer is copied with a seal-retry marker, the
// recovery key is destroyed, and ErrSealingFallbackUsed reports the downgrade.
func TestStrategyUnlock_NoTPMFallsBackToPlainKey(t *testing.T) {
	f := newUnlockFixture(t, nil)

	err := f.strategy.Unlock(context.Background(), f.volume)
	if !errors.Is(err, ErrSealingFallbackUsed) {
		t.Fatalf("Unlock() = %v, want ErrSealingFallbackUsed", err)
	}
	if !contains(f.handler.opened, "/dev/sda2 cryptroot") {
		t.Errorf("opened = %v, want /dev/sda2 cryptroot", f.handler.opened)
	}
	marker := readHostFile(t, strategyRootMountPoint+"/var/lib/trusted-platform/.seal-retry-needed")
	if !strings.Contains(marker, "reason=provisionInsideInstaller: "+ErrTPMNotAvailable.Error()) {
		t.Errorf("seal-retry marker = %q, want the provisioning failure", marker)
	}
	if got := readHostFile(t, strategyRootMountPoint+"/etc/trusted-platform/platform.yaml"); got != "platform: {}\n" {
		t.Errorf("copied platform.yaml = %q", got)
	}
	if hostFileExists(strategyRootMountPoint + "/var/lib/tpm2/.tpm-sealed") {
		t.Error("a fallback boot must not write the .tpm-sealed marker")
	}
	if !contains(f.luks.killed, "/dev/sda2") {
		t.Errorf("killed = %v, want the recovery slot on /dev/sda2", f.luks.killed)
	}
	if !contains(*f.mounts, "umount "+hostPath(strategyInstallerMountPoint)) {
		t.Errorf("mounts = %v, want the installer unmounted", *f.mounts)
	}
	if !hostFileExists(strategyInstallerMountPoint + "/firstboot-runs/latest") {
		t.Error("the forensic dump was not written")
	}
}

// A seal from an earlier boot skips provisioning and records the idempotent
// skip as the retry reason; an open root mapping is not reopened.
func TestStrategyUnlock_PriorSealSkipsProvisioning(t *testing.T) {
	tpm := &strategyTPM{fakeTPM: &fakeTPM{}}
	f := newUnlockFixture(t, tpm)
	f.handler.open = true
	writeHostFile(t, strategyEFIMountPoint+"/"+strategySealPub, []byte("pub"))

	err := f.strategy.Unlock(context.Background(), f.volume)
	if !errors.Is(err, ErrSealingFallbackUsed) {
		t.Fatalf("Unlock() = %v, want ErrSealingFallbackUsed", err)
	}
	if len(f.handler.opened) != 0 {
		t.Errorf("opened = %v, want an open mapping left alone", f.handler.opened)
	}
	marker := readHostFile(t, strategyRootMountPoint+"/var/lib/trusted-platform/.seal-retry-needed")
	if !strings.Contains(marker, "idempotent skip") {
		t.Errorf("seal-retry marker = %q, want the idempotent skip", marker)
	}
	if tpm.resetCalls+tpm.resetClearCalls != 0 {
		t.Error("the TPM was touched on the idempotent path")
	}
}

func TestStrategyUnlock_OpenFailure(t *testing.T) {
	f := newUnlockFixture(t, nil)
	f.handler.openErr = errSeam

	err := f.strategy.Unlock(context.Background(), f.volume)
	requireWrapped(t, err, "luks unlock failed")
	if !errors.Is(err, errSeam) {
		t.Errorf("Unlock() = %v, want the Open error wrapped", err)
	}
}

func TestStrategyUnlock_InvalidKeySize(t *testing.T) {
	f := newUnlockFixture(t, nil)
	writeHostFile(t, strategyInstallerMountPoint+"/luks-key.bin", []byte("short"))

	err := f.strategy.Unlock(context.Background(), f.volume)
	requireMessage(t, err, "invalid LUKS key size: expected 32, got 5")
	if len(f.handler.opened) != 0 {
		t.Error("the root was opened with an invalid key")
	}
}

func TestStrategyUnlock_InstallerOpenFailure(t *testing.T) {
	f := newUnlockFixture(t, nil)
	if err := os.Remove(hostPath(strategyInstallerMountPoint + "/luks-key.bin")); err != nil {
		t.Fatal(err)
	}
	f.luks.fail["setuploop"] = true

	err := f.strategy.Unlock(context.Background(), f.volume)
	requireWrapped(t, err, "failed to open installer")
	requireWrapped(t, errors.Unwrap(err), "failed to setup loop device")
}

func TestStrategyUnlock_EFIMountFailure(t *testing.T) {
	useHostRoot(t)
	useESP(t, "", errSeam)
	s := newStrategy(nil, &fakeHandler{})

	err := s.Unlock(context.Background(), &luks.VolumeConfig{DevicePath: "/dev/sda2", MappingName: "cryptroot"})
	requireWrapped(t, err, "failed to mount EFI partition")
	requireMessage(t, errors.Unwrap(err), "no EFI partition found")
}

func TestStrategyCanUnlock(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  bool
	}{
		{"first boot", []string{strategyInstallerContainerFile}, true},
		{"no installer", nil, false},
		{"already sealed", []string{strategyInstallerContainerFile, strategySealPub}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHostRoot(t)
			mountEFIDir(t)
			for _, name := range tt.files {
				writeHostFile(t, strategyEFIMountPoint+"/"+name, []byte("x"))
			}
			mounts := useMounts(t, nil, nil)

			if got := newStrategy(nil, nil).CanUnlock(context.Background(), nil); got != tt.want {
				t.Errorf("CanUnlock() = %v, want %v", got, tt.want)
			}
			if len(*mounts) != 0 {
				t.Errorf("mounts = %v, want a mounted ESP left alone", *mounts)
			}
		})
	}
}

// An ESP CanUnlock had to mount itself is unmounted again.
func TestStrategyCanUnlock_MountsAndUnmountsESP(t *testing.T) {
	useHostRoot(t)
	useESP(t, "/dev/sda1", nil)
	mounts := useMounts(t, nil, nil)

	if newStrategy(nil, nil).CanUnlock(context.Background(), nil) {
		t.Error("CanUnlock() = true without an installer")
	}
	efi := hostPath(strategyEFIMountPoint)
	if want := []string{"mount " + efi, "umount " + efi}; strings.Join(*mounts, ",") != strings.Join(want, ",") {
		t.Errorf("mounts = %v, want %v", *mounts, want)
	}
}

func TestStrategyCanUnlock_ESPMountFailure(t *testing.T) {
	useHostRoot(t)
	useESP(t, "", errSeam)

	if newStrategy(nil, nil).CanUnlock(context.Background(), nil) {
		t.Error("CanUnlock() = true when the ESP cannot be mounted")
	}
}

// mountEFI looks the ESP up from the executor's root device and mounts it
// read-only for CanUnlock and read-write for Unlock.
func TestStrategyMountEFI(t *testing.T) {
	useHostRoot(t)
	rootDevice := useESP(t, "/dev/sda1", nil)
	var flags []uintptr
	swap(t, &hostMount, func(source, target, fstype string, f uintptr, data string) error {
		if source != "/dev/sda1" || target != hostPath(strategyEFIMountPoint) || fstype != "vfat" {
			t.Errorf("mount(%s, %s, %s)", source, target, fstype)
		}
		flags = append(flags, f)
		return nil
	})
	s := newStrategy(nil, nil)

	for _, mount := range []func() (bool, error){s.ensureEFIMounted, s.ensureEFIMountedRW} {
		wasMounted, err := mount()
		if err != nil || wasMounted {
			t.Fatalf("mount = (%v, %v), want (false, nil)", wasMounted, err)
		}
	}
	if *rootDevice != "/dev/sda2" {
		t.Errorf("findESP(%q), want the executor's root device", *rootDevice)
	}
	if len(flags) != 2 || flags[0] != syscall.MS_RDONLY || flags[1] != 0 {
		t.Errorf("mount flags = %v, want [MS_RDONLY 0]", flags)
	}
}

func TestStrategyMountEFI_AlreadyMounted(t *testing.T) {
	useHostRoot(t)
	mountEFIDir(t)
	mounts := useMounts(t, nil, errSeam)

	wasMounted, err := newStrategy(nil, nil).mountEFI(0)
	if err != nil || !wasMounted {
		t.Fatalf("mountEFI() = (%v, %v), want (true, nil)", wasMounted, err)
	}
	if len(*mounts) != 0 {
		t.Errorf("mounts = %v, want none", *mounts)
	}
}

func TestStrategyMountEFI_Failures(t *testing.T) {
	t.Run("mount point", func(t *testing.T) {
		useHostRoot(t)
		useESP(t, "/dev/sda1", nil)
		writeHostFile(t, "/boot", []byte("not a directory"))

		_, err := newStrategy(nil, nil).mountEFI(0)
		requireWrapped(t, err, "failed to create mount point")
	})
	t.Run("mount", func(t *testing.T) {
		useHostRoot(t)
		useESP(t, "/dev/sda1", nil)
		useMounts(t, nil, errSeam)

		_, err := newStrategy(nil, nil).mountEFI(0)
		requireWrapped(t, err, "failed to mount /dev/sda1")
		if !errors.Is(err, errSeam) {
			t.Errorf("mountEFI() = %v, want the mount error wrapped", err)
		}
	})
}

func TestStrategyDetectEFIDevice(t *testing.T) {
	rootDevice := useESP(t, "/dev/sda1", nil)
	if got := newStrategy(nil, nil).detectEFIDevice(); got != "/dev/sda1" || *rootDevice != "/dev/sda2" {
		t.Errorf("detectEFIDevice() = %q from %q", got, *rootDevice)
	}
	useESP(t, "/dev/sda1", errSeam)
	if got := newStrategy(nil, nil).detectEFIDevice(); got != "" {
		t.Errorf("detectEFIDevice() = %q, want \"\" on a lookup failure", got)
	}
}

func TestStrategyUnmountEFI(t *testing.T) {
	useHostRoot(t)
	mounts := useMounts(t, nil, nil)

	newStrategy(nil, nil).unmountEFI()
	if want := "umount " + hostPath(strategyEFIMountPoint); len(*mounts) != 1 || (*mounts)[0] != want {
		t.Errorf("mounts = %v, want [%s]", *mounts, want)
	}
}

// A failed ESP unmount is best-effort cleanup: it is logged as a warning that
// names the mount point, and nothing else happens.
func TestStrategyUnmountEFI_LogsFailure(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostUnmount, func(string, int) error { return errSeam })
	var out strings.Builder
	s := NewFirstbootSealStrategy(nil, nil, logging.NewLogger(slog.LevelDebug, &out))

	s.unmountEFI()

	logged := out.String()
	for _, want := range []string{`"level":"WARN"`, "Failed to unmount", hostPath(strategyEFIMountPoint), errSeam.Error()} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
}

func TestStrategyRunCommand(t *testing.T) {
	commands := useCommands(t, "lvm vgscan")
	commands.output["lvm vgscan"] = "no volume groups"
	s := newStrategy(nil, nil)

	if err := s.runCommand("lvm", "pvscan"); err != nil {
		t.Fatalf("runCommand() = %v", err)
	}
	err := s.runCommand("lvm", "vgscan")
	var cmdErr *CommandOutputError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("runCommand() = %v, want *CommandOutputError", err)
	}
	if !errors.Is(err, errSeam) || !strings.Contains(cmdErr.Detail, "no volume groups") {
		t.Errorf("runCommand() = %v, want the command error and its output", err)
	}
}

func TestStrategyOpenInstaller(t *testing.T) {
	useHostRoot(t)
	fl := useLUKS(t)
	var source string
	swap(t, &hostMount, func(src, target, fstype string, flags uintptr, data string) error {
		source = src
		return nil
	})

	loop, err := newStrategy(nil, nil).openInstaller("/boot/efi/tpm2/installer.luks")
	if err != nil || loop != "/dev/loop7" {
		t.Fatalf("openInstaller() = (%q, %v), want (/dev/loop7, nil)", loop, err)
	}
	if source != "/dev/mapper/installer" || !contains(fl.unlocked, "installer") {
		t.Errorf("mounted %q, unlocked %v", source, fl.unlocked)
	}
	if !hostFileExists(strategyInstallerMountPoint) {
		t.Error("the installer mount point was not created")
	}
}

// An installer the initrd hook already mounted is used as it is.
func TestStrategyOpenInstaller_AlreadyMounted(t *testing.T) {
	useHostRoot(t)
	fl := useLUKS(t)
	writeHostFile(t, strategyInstallerMountPoint+"/luks-key.bin", luksKey())

	loop, err := newStrategy(nil, nil).openInstaller("/boot/efi/tpm2/installer.luks")
	if err != nil || loop != "" {
		t.Fatalf("openInstaller() = (%q, %v), want (\"\", nil)", loop, err)
	}
	if len(fl.unlocked) != 0 {
		t.Errorf("unlocked = %v, want nothing opened", fl.unlocked)
	}
}

func TestStrategyOpenInstaller_Failures(t *testing.T) {
	tests := []struct {
		name         string
		fail         []string
		blockMount   bool
		mountErr     error
		wantMsg      string
		wantLocked   bool
		wantDetached bool
	}{
		{name: "loop device", fail: []string{"setuploop"}, wantMsg: "failed to setup loop device"},
		{name: "unlock", fail: []string{"unlock"}, wantMsg: "failed to unlock installer", wantDetached: true},
		{name: "mount point", blockMount: true, wantMsg: "failed to create mount point", wantLocked: true, wantDetached: true},
		{name: "mount", mountErr: errSeam, wantMsg: "failed to mount installer", wantLocked: true, wantDetached: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHostRoot(t)
			fl := useLUKS(t, tt.fail...)
			useMounts(t, nil, tt.mountErr)
			if tt.blockMount {
				writeHostFile(t, "/mnt", []byte("not a directory"))
			}

			loop, err := newStrategy(nil, nil).openInstaller("/boot/efi/tpm2/installer.luks")
			if loop != "" {
				t.Errorf("loop = %q, want \"\" on failure", loop)
			}
			requireWrapped(t, err, tt.wantMsg)
			if got := contains(fl.locked, "installer"); got != tt.wantLocked {
				t.Errorf("locked = %v, want installer locked %v", fl.locked, tt.wantLocked)
			}
			if got := contains(fl.detached, "/dev/loop7"); got != tt.wantDetached {
				t.Errorf("detached = %v, want loop detached %v", fl.detached, tt.wantDetached)
			}
		})
	}
}

// closeInstaller unmounts, closes and detaches the installer; it wipes the
// container only when sealing succeeded.
func TestStrategyCloseInstaller(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		name := "preserved"
		if sealed {
			name = "wiped"
		}
		t.Run(name, func(t *testing.T) {
			useHostRoot(t)
			swap(t, &hostSync, func() {})
			useCommands(t)
			fl := useLUKS(t)
			mounts := useMounts(t, nil, nil)
			container := hostPath(strategyEFIMountPoint + "/" + strategyInstallerContainerFile)
			writeHostFile(t, strategyEFIMountPoint+"/"+strategyInstallerContainerFile, []byte("container"))

			newStrategy(nil, nil).closeInstaller("/dev/loop7", container, 1, sealed)

			if !contains(*mounts, "umount "+hostPath(strategyInstallerMountPoint)) {
				t.Errorf("mounts = %v, want the installer unmounted", *mounts)
			}
			if !contains(fl.locked, "installer") || !contains(fl.detached, "/dev/loop7") {
				t.Errorf("locked %v, detached %v", fl.locked, fl.detached)
			}
			_, err := os.Stat(container)
			if exists := err == nil; exists == sealed {
				t.Errorf("container exists = %v after sealed=%v", exists, sealed)
			}
		})
	}
}

// A lazy unmount that fails falls back to a plain one, and a container the
// wipe cannot handle is still removed.
func TestStrategyCloseInstaller_Fallbacks(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	useCommands(t)
	useLUKS(t)
	var unmountFlags []int
	swap(t, &hostUnmount, func(target string, flags int) error {
		unmountFlags = append(unmountFlags, flags)
		if flags == syscall.MNT_DETACH {
			return errSeam
		}
		return nil
	})
	container := filepath.Join(t.TempDir(), "installer.luks")
	if err := os.Mkdir(container, 0o700); err != nil {
		t.Fatal(err)
	}

	newStrategy(nil, nil).closeInstaller("", container, 1, true)

	if len(unmountFlags) != 2 || unmountFlags[1] != 0 {
		t.Errorf("unmount flags = %v, want [MNT_DETACH 0]", unmountFlags)
	}
	if _, err := os.Stat(container); !os.IsNotExist(err) {
		t.Errorf("container stat = %v, want it removed", err)
	}
}

// An installer that will not unmount or detach is still closed and preserved.
func TestStrategyCloseInstaller_UnmountAndDetachFail(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	useCommands(t)
	fl := useLUKS(t, "detach")
	useMounts(t, nil, nil)
	attempts := 0
	swap(t, &hostUnmount, func(string, int) error {
		attempts++
		return errSeam
	})
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyInstallerContainerFile, []byte("container"))

	newStrategy(nil, nil).closeInstaller("/dev/loop7", hostPath(strategyEFIMountPoint+"/"+strategyInstallerContainerFile), 1, false)

	if attempts != 2 {
		t.Errorf("unmount attempts = %d, want the lazy and the plain unmount", attempts)
	}
	if !contains(fl.locked, "installer") {
		t.Errorf("locked = %v, want the mapping closed", fl.locked)
	}
	if !hostFileExists(strategyEFIMountPoint + "/" + strategyInstallerContainerFile) {
		t.Error("the installer was not preserved")
	}
}

// The production closer force-removes a held mapping with dmsetup and
// reports the command's output when that fails.
func TestDefaultInstallerMappingCloser_ForceRemove(t *testing.T) {
	commands := useCommands(t)
	closer := defaultInstallerMappingCloser()

	if err := closer.forceRemove("installer"); err != nil {
		t.Fatalf("forceRemove() = %v", err)
	}
	if !commands.ran("dmsetup remove --force installer") {
		t.Errorf("commands = %v, want dmsetup remove --force installer", commands.calls)
	}

	commands.fail = []string{"dmsetup remove --force installer"}
	commands.output["dmsetup remove --force installer"] = "device busy"
	err := closer.forceRemove("installer")
	requireWrapped(t, err, "dmsetup remove --force installer: device busy")
	if !errors.Is(err, errSeam) {
		t.Errorf("forceRemove() = %v, want the command error wrapped", err)
	}
}

func TestStrategyProvisionInsideInstaller_NoTPM(t *testing.T) {
	err := newStrategy(nil, nil).provisionInsideInstaller(context.Background())
	if !errors.Is(err, ErrTPMNotAvailable) {
		t.Fatalf("provisionInsideInstaller() = %v, want ErrTPMNotAvailable", err)
	}
}

func TestStrategyProvisionInsideInstaller_SOPINUnresolved(t *testing.T) {
	tpm := &strategyTPM{fakeTPM: &fakeTPM{}, ekCert: &x509.Certificate{}}
	s := newStrategy(tpm, nil)
	s.soPINConfigPaths = []string{filepath.Join(t.TempDir(), "missing.yaml")}

	err := s.provisionInsideInstaller(context.Background())
	requireWrapped(t, err, "SO PIN resolution failed")
	if !errors.Is(err, ErrSOPINConfigNotFound) {
		t.Errorf("provisionInsideInstaller() = %v, want ErrSOPINConfigNotFound", err)
	}
}

// The EK gate refuses the TPM before it is touched.
func TestStrategyProvisionInsideInstaller_EKCertificate(t *testing.T) {
	t.Run("lookup failure", func(t *testing.T) {
		useHostRoot(t)
		tpm := &strategyTPM{fakeTPM: &fakeTPM{}, ekErr: errSeam}
		s := newStrategy(tpm, nil)
		s.soPINConfigPaths, s.soPINHandoffFile = soPINSources(t, "123456")

		err := s.provisionInsideInstaller(context.Background())
		requireWrapped(t, err, "EK certificate lookup failed")
		if tpm.resetCalls+tpm.resetClearCalls != 0 {
			t.Error("the TPM was reset after a failed EK lookup")
		}
	})
	t.Run("missing", func(t *testing.T) {
		useHostRoot(t)
		tpm := &strategyTPM{fakeTPM: &fakeTPM{}}
		s := newStrategy(tpm, nil)
		s.soPINConfigPaths, s.soPINHandoffFile = soPINSources(t, "123456")

		err := s.provisionInsideInstaller(context.Background())
		var missing *EKCertificateMissingError
		if !errors.As(err, &missing) {
			t.Fatalf("provisionInsideInstaller() = %v, want *EKCertificateMissingError", err)
		}
	})
}

// With factory-reset-on-firstboot the TPM is cleared before ownership is
// prepared; a TPM whose commands fail stops at the owner preparation.
func TestStrategyProvisionInsideInstaller_PrepareFailure(t *testing.T) {
	useHostRoot(t)
	writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      factory-reset-on-firstboot: true\n")
	tpm := &strategyTPM{fakeTPM: &fakeTPM{}, ekCert: &x509.Certificate{}}
	s := newStrategy(tpm, nil)
	s.soPINConfigPaths, s.soPINHandoffFile = soPINSources(t, "123456")

	err := s.provisionInsideInstaller(context.Background())
	requireWrapped(t, err, "TPM owner hierarchy preparation failed")
	if !errors.Is(err, errSeam) {
		t.Errorf("provisionInsideInstaller() = %v, want the transport failure", err)
	}
	if tpm.resetClearCalls != 1 || tpm.resetCalls != 0 {
		t.Errorf("reset calls: clear=%d plain=%d, want clear=1 plain=0", tpm.resetClearCalls, tpm.resetCalls)
	}
}

// A software clear refused for stale auth escalates to a PPI ForceClear when
// the operator opted in; a ForceClear that cannot be scheduled leaves the
// loop-guard marker and continues.
func TestStrategyClearTPM_EscalatesToPPI(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	mountEFIDir(t)
	writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      force-clear-via-ppi: true\n")
	tpm := &strategyTPM{
		fakeTPM:       &fakeTPM{resetErr: errors.New("TPM_RC_LOCKOUT")},
		forceClearErr: errSeam,
	}

	newStrategy(tpm, nil).clearTPM()

	if tpm.forceClearCalls != 1 {
		t.Errorf("ForceClear calls = %d, want 1", tpm.forceClearCalls)
	}
	if got := readHostFile(t, strategyEFIMountPoint+"/tpm2/ppi-clear-attempted"); got != "1\n" {
		t.Errorf("PPI marker = %q, want \"1\\n\"", got)
	}
}

func TestStrategyClearTPM(t *testing.T) {
	t.Run("success drops the PPI marker", func(t *testing.T) {
		useHostRoot(t)
		writeHostFile(t, strategyEFIMountPoint+"/tpm2/ppi-clear-attempted", []byte("1\n"))
		tpm := &strategyTPM{fakeTPM: &fakeTPM{}}

		newStrategy(tpm, nil).clearTPM()
		if hostFileExists(strategyEFIMountPoint + "/tpm2/ppi-clear-attempted") {
			t.Error("the PPI marker survived a successful clear")
		}
	})
	t.Run("non-auth failure does not escalate", func(t *testing.T) {
		useHostRoot(t)
		writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      force-clear-via-ppi: true\n")
		tpm := &strategyTPM{fakeTPM: &fakeTPM{resetErr: errSeam}}

		newStrategy(tpm, nil).clearTPM()
		if tpm.forceClearCalls != 0 {
			t.Errorf("ForceClear calls = %d, want 0", tpm.forceClearCalls)
		}
	})
}

// The PPI marker is the reboot-loop guard: an existing marker, or one that
// cannot be written, stops the escalation before ForceClear.
func TestStrategyEscalateToPPIForceClear_LoopGuard(t *testing.T) {
	t.Run("marker exists", func(t *testing.T) {
		useHostRoot(t)
		mountEFIDir(t)
		writeHostFile(t, strategyEFIMountPoint+"/tpm2/ppi-clear-attempted", []byte("1\n"))
		tpm := &strategyTPM{fakeTPM: &fakeTPM{}}

		newStrategy(tpm, nil).escalateToPPIForceClear(errSeam)
		if tpm.forceClearCalls != 0 {
			t.Errorf("ForceClear calls = %d, want 0", tpm.forceClearCalls)
		}
	})
	t.Run("marker unwritable", func(t *testing.T) {
		useHostRoot(t)
		useESP(t, "", errSeam)
		writeHostFile(t, strategyEFIMountPoint+"/tpm2", []byte("not a directory"))
		tpm := &strategyTPM{fakeTPM: &fakeTPM{}}

		newStrategy(tpm, nil).escalateToPPIForceClear(errSeam)
		if tpm.forceClearCalls != 0 {
			t.Errorf("ForceClear calls = %d, want 0", tpm.forceClearCalls)
		}
	})
}

// copyFixture is an open installer with platform state and a direct root.
func copyFixture(t *testing.T, config string) (*[]string, *fakeCommands) {
	t.Helper()
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	writeHostFile(t, strategyInstallerMountPoint+"/var/lib/trusted-platform/ca.pem", []byte("ca"))
	if config != "" {
		writeInstallerConfig(t, config)
	}
	return useMounts(t, nil, nil), useCommands(t)
}

func TestStrategyCopyInstallerToRoot(t *testing.T) {
	t.Run("sealed", func(t *testing.T) {
		mounts, _ := copyFixture(t, "disk:\n  root-filesystem: ext4\n")
		writeHostFile(t, strategyDevMapperDir+"/cryptroot", []byte("root"))

		if err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", ""); err != nil {
			t.Fatalf("copyInstallerToRoot() = %v", err)
		}
		if got := readHostFile(t, strategyRootMountPoint+"/var/lib/trusted-platform/ca.pem"); got != "ca" {
			t.Errorf("copied ca.pem = %q", got)
		}
		if got := readHostFile(t, strategyRootMountPoint+"/var/lib/tpm2/.tpm-sealed"); got != "sealed-by-initrd\n" {
			t.Errorf(".tpm-sealed = %q", got)
		}
		root := hostPath(strategyRootMountPoint)
		if want := []string{"mount " + root, "umount " + root}; strings.Join(*mounts, ",") != strings.Join(want, ",") {
			t.Errorf("mounts = %v, want %v", *mounts, want)
		}
	})
	t.Run("seal retry", func(t *testing.T) {
		copyFixture(t, "disk:\n  root-filesystem: ext4\n")
		writeHostFile(t, strategyDevMapperDir+"/cryptroot", []byte("root"))

		if err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", "sealKeyToTPM: failed"); err != nil {
			t.Fatalf("copyInstallerToRoot() = %v", err)
		}
		marker := readHostFile(t, strategyRootMountPoint+"/var/lib/trusted-platform/.seal-retry-needed")
		if !strings.Contains(marker, "reason=sealKeyToTPM: failed\n") || !strings.Contains(marker, "mapping=cryptroot\n") {
			t.Errorf("seal-retry marker = %q", marker)
		}
		if hostFileExists(strategyRootMountPoint + "/var/lib/tpm2/.tpm-sealed") {
			t.Error("a seal-retry boot wrote the .tpm-sealed marker")
		}
	})
}

// An LVM root is activated by volume group and logical volume name and found
// under /dev/mapper or /dev/<vg>/<lv>.
func TestStrategyCopyInstallerToRoot_LVM(t *testing.T) {
	tests := []struct {
		name   string
		config string
		node   string
		lv     string
	}{
		{"configured mapper node", "disk:\n  root-filesystem: lvm\n  lvm-volume-group: vgx\n  lvm-logical-volume: lvy\n", strategyDevMapperDir + "/vgx-lvy", "vgx/lvy"},
		{"configured vg path", "disk:\n  root-filesystem: lvm\n  lvm-volume-group: vgx\n  lvm-logical-volume: lvy\n", strategyDevDir + "/vgx/lvy", "vgx/lvy"},
		{"default without config", "", strategyDevMapperDir + "/vg0-root", "vg0/root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mounts, commands := copyFixture(t, tt.config)
			commands.fail = []string{"/sbin/lvm pvscan"}
			writeHostFile(t, tt.node, []byte("root"))
			var source string
			swap(t, &hostMount, func(src, target, fstype string, flags uintptr, data string) error {
				source = src
				*mounts = append(*mounts, "mount "+target)
				return nil
			})

			if err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", ""); err != nil {
				t.Fatalf("copyInstallerToRoot() = %v", err)
			}
			if !commands.ran("/sbin/lvm lvchange -ay " + tt.lv) {
				t.Errorf("commands = %v, want lvchange of %s", commands.calls, tt.lv)
			}
			if source != hostPath(tt.node) {
				t.Errorf("mounted %q, want %q", source, hostPath(tt.node))
			}
		})
	}
}

func TestStrategyCopyInstallerToRoot_Failures(t *testing.T) {
	t.Run("root device missing", func(t *testing.T) {
		copyFixture(t, "disk:\n  root-filesystem: ext4\n")

		err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", "")
		requireWrapped(t, err, "root device not found at "+hostPath(strategyDevMapperDir+"/cryptroot"))
	})
	t.Run("mount point", func(t *testing.T) {
		copyFixture(t, "disk:\n  root-filesystem: ext4\n")
		writeHostFile(t, strategyDevMapperDir+"/cryptroot", []byte("root"))
		writeHostFile(t, strategyRootMountPoint, []byte("not a directory"))

		err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", "")
		requireWrapped(t, err, "failed to create root mount point")
	})
	t.Run("every filesystem refused", func(t *testing.T) {
		copyFixture(t, "disk:\n  root-filesystem: ext4\n")
		writeHostFile(t, strategyDevMapperDir+"/cryptroot", []byte("root"))
		var fstypes []string
		swap(t, &hostMount, func(src, target, fstype string, flags uintptr, data string) error {
			fstypes = append(fstypes, fstype)
			return errSeam
		})

		err := newStrategy(nil, nil).copyInstallerToRoot("cryptroot", "", "")
		requireWrapped(t, err, "failed to mount root filesystem")
		if strings.Join(fstypes, ",") != "ext4,xfs,btrfs" {
			t.Errorf("tried %v, want ext4,xfs,btrfs", fstypes)
		}
	})
}

// The installer config's recovery-key strategy decides what happens to the
// recovery passphrase in LUKS slot 2.
func TestStrategyApplyRecoveryKeyStrategy(t *testing.T) {
	t.Run("no key", func(t *testing.T) {
		useHostRoot(t)
		fl := useLUKS(t)

		got, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "")
		if err != nil || got != "escrow" {
			t.Fatalf("applyRecoveryKeyStrategy() = (%q, %v), want (escrow, nil)", got, err)
		}
		if len(fl.killed) != 0 || hostFileExists(firstbootHandoffRecoveryKey) {
			t.Error("an absent recovery key was acted on")
		}
	})
	t.Run("destroy", func(t *testing.T) {
		useHostRoot(t)
		writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      recovery-key-strategy: destroy\n")
		var slot int
		swap(t, &luksKillSlot, func(dev string, key []byte, s int) error {
			slot = s
			return nil
		})

		got, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "recovery")
		if err != nil || got != "destroy" {
			t.Fatalf("applyRecoveryKeyStrategy() = (%q, %v), want (destroy, nil)", got, err)
		}
		if slot != luksSlotRecovery {
			t.Errorf("killed slot %d, want %d", slot, luksSlotRecovery)
		}
	})
	t.Run("destroy failure", func(t *testing.T) {
		useHostRoot(t)
		writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      recovery-key-strategy: destroy\n")
		useLUKS(t, "killslot")

		_, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "recovery")
		requireWrapped(t, err, "luksKillSlot(slot=2)")
	})
	t.Run("escrow", func(t *testing.T) {
		useHostRoot(t)
		writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      recovery-key-strategy: escrow\n")

		got, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "recovery")
		if err != nil || got != "escrow" {
			t.Fatalf("applyRecoveryKeyStrategy() = (%q, %v), want (escrow, nil)", got, err)
		}
		if staged := readHostFile(t, firstbootHandoffRecoveryKey); staged != "recovery" {
			t.Errorf("staged recovery key = %q", staged)
		}
	})
	t.Run("escrow refuses a staged key", func(t *testing.T) {
		useHostRoot(t)
		writeHostFile(t, firstbootHandoffRecoveryKey, []byte("earlier"))

		_, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "recovery")
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("applyRecoveryKeyStrategy() = %v, want os.ErrExist", err)
		}
		if staged := readHostFile(t, firstbootHandoffRecoveryKey); staged != "earlier" {
			t.Errorf("staged recovery key = %q, want the earlier one kept", staged)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		useHostRoot(t)
		writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      recovery-key-strategy: shred\n")

		got, err := newStrategy(nil, nil).applyRecoveryKeyStrategy("/dev/sda2", "recovery")
		requireMessage(t, err, `unknown recovery-key-strategy "shred"`)
		if got != "shred" {
			t.Errorf("strategy = %q, want shred", got)
		}
	})
}

// The install-time passphrase slot is killed; a slot already gone or a kill
// that fails does not stop the boot.
func TestKillInstallerKeyslot(t *testing.T) {
	for _, killErr := range []error{nil, errors.New("keyslot 0 does not exist"), errSeam} {
		var dev string
		slot := -1
		swap(t, &luksKillSlot, func(d string, key []byte, s int) error {
			dev, slot = d, s
			return killErr
		})

		killInstallerKeyslot("/dev/sda2", luksKey())
		if dev != "/dev/sda2" || slot != luksSlotInstaller {
			t.Errorf("killed %s slot %d, want /dev/sda2 slot %d", dev, slot, luksSlotInstaller)
		}
	}
}

func TestStrategyDumpFirstbootForensics(t *testing.T) {
	useHostRoot(t)
	swap(t, &hostSync, func() {})
	commands := useCommands(t, "dmesg")
	commands.output["dmesg"] = "kernel ring"
	writeInstallerConfig(t, "disk: {}\n")

	newStrategy(nil, nil).dumpFirstbootForensics()

	latest := hostPath(strategyInstallerMountPoint + "/firstboot-runs/latest")
	stamp, err := os.Readlink(latest)
	if err != nil {
		t.Fatalf("latest link: %v", err)
	}
	dump := strategyInstallerMountPoint + "/firstboot-runs/" + stamp
	if got := readHostFile(t, dump+"/dmesg.txt"); got != "kernel ring" {
		t.Errorf("dmesg.txt = %q, want the failed command's output kept", got)
	}
	if !hostFileExists(dump + "/date.txt") {
		t.Error("date.txt missing from the dump")
	}
}

func TestStrategyDumpFirstbootForensics_Skipped(t *testing.T) {
	t.Run("installer not mounted", func(t *testing.T) {
		useHostRoot(t)
		commands := useCommands(t)

		newStrategy(nil, nil).dumpFirstbootForensics()
		if len(commands.calls) != 0 || hostFileExists(strategyInstallerMountPoint+"/firstboot-runs") {
			t.Error("a dump was attempted without a mounted installer")
		}
	})
	t.Run("dump directory", func(t *testing.T) {
		useHostRoot(t)
		commands := useCommands(t)
		writeHostFile(t, strategyInstallerMountPoint+"/luks-key.bin", luksKey())
		writeHostFile(t, strategyInstallerMountPoint+"/firstboot-runs", []byte("not a directory"))

		newStrategy(nil, nil).dumpFirstbootForensics()
		if len(commands.calls) != 0 {
			t.Errorf("commands = %v, want none without a dump directory", commands.calls)
		}
	})
}

// After switch_root the marker moves the recovery key to /root, copies the
// installer state to the root filesystem and wipes the installer.
func TestProcessFirstbootMarkers(t *testing.T) {
	useHostRoot(t)
	efi := hostPath(strategyEFIMountPoint)
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyCopyMarker, []byte("1"))
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyInstallerContainerFile, []byte("container"))
	writeHostFile(t, strategyMarkerDir+"/luks-recovery.txt", []byte("recovery"))
	writeHostFile(t, strategyInstallerMountPoint+"/etc/trusted-platform/platform.yaml", []byte("platform"))
	writeHostFile(t, strategyInstallerMountPoint+"/var/lib/trusted-platform/ca.pem", []byte("ca"))
	if err := os.MkdirAll(hostPath("/root"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := ProcessFirstbootMarkers(efi); err != nil {
		t.Fatalf("ProcessFirstbootMarkers() = %v", err)
	}
	if got := readHostFile(t, RecoveryKeyPath); got != "recovery" {
		t.Errorf("recovery key = %q", got)
	}
	if got := readHostFile(t, "/etc/trusted-platform/platform.yaml"); got != "platform" {
		t.Errorf("platform.yaml = %q", got)
	}
	if got := readHostFile(t, "/var/lib/trusted-platform/ca.pem"); got != "ca" {
		t.Errorf("ca.pem = %q", got)
	}
	for _, gone := range []string{
		strategyEFIMountPoint + "/" + strategyCopyMarker,
		strategyEFIMountPoint + "/" + strategyInstallerContainerFile,
		strategyMarkerDir,
	} {
		if hostFileExists(gone) {
			t.Errorf("%s survived marker processing", gone)
		}
	}
}

func TestProcessFirstbootMarkers_NoMarker(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyInstallerContainerFile, []byte("container"))

	if err := ProcessFirstbootMarkers(hostPath(strategyEFIMountPoint)); err != nil {
		t.Fatalf("ProcessFirstbootMarkers() = %v", err)
	}
	if !hostFileExists(strategyEFIMountPoint + "/" + strategyInstallerContainerFile) {
		t.Error("the installer was wiped without a copy marker")
	}
}

// An installer the wipe cannot open is still removed, and a copy that fails
// does not stop the markers from being cleared.
func TestProcessFirstbootMarkers_Fallbacks(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, strategyEFIMountPoint+"/"+strategyCopyMarker, []byte("1"))
	container := hostPath(strategyEFIMountPoint + "/" + strategyInstallerContainerFile)
	if err := os.Mkdir(container, 0o700); err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, strategyInstallerMountPoint+"/etc/trusted-platform/platform.yaml", []byte("platform"))
	writeHostFile(t, "/etc", []byte("not a directory"))

	if err := ProcessFirstbootMarkers(hostPath(strategyEFIMountPoint)); err != nil {
		t.Fatalf("ProcessFirstbootMarkers() = %v", err)
	}
	if hostFileExists(strategyEFIMountPoint+"/"+strategyInstallerContainerFile) ||
		hostFileExists(strategyEFIMountPoint+"/"+strategyCopyMarker) {
		t.Error("the installer or the copy marker survived")
	}
}

// A recovery key /root cannot take stays in the marker directory.
func TestProcessRecoveryKey_WriteFailure(t *testing.T) {
	useHostRoot(t)
	writeHostFile(t, strategyMarkerDir+"/luks-recovery.txt", []byte("recovery"))

	processRecoveryKey()
	if !hostFileExists(strategyMarkerDir + "/luks-recovery.txt") {
		t.Error("the recovery key was removed although it was not written")
	}
	if hostFileExists(RecoveryKeyPath) {
		t.Error("the recovery key was written without a /root directory")
	}
}

func TestCopyInstallerToRootFS_NothingToCopy(t *testing.T) {
	useHostRoot(t)
	if err := copyInstallerToRootFS(); err != nil {
		t.Fatalf("copyInstallerToRootFS() = %v", err)
	}
	if hostFileExists("/var") || hostFileExists("/etc") {
		t.Error("directories were created without an installer to copy from")
	}
}

// A fresh TPM is provisioned in full: the stale handles are evicted, Install
// creates every key without changing the hierarchy auth, and ownership is
// taken last with the SO PIN platformd presents.
func TestStrategyProvisionInsideInstaller_Provisions(t *testing.T) {
	useHostRoot(t)
	tpm := newProvisionableTPM(t)

	if err := newProvisioningStrategy(t, tpm, nil).provisionInsideInstaller(context.Background()); err != nil {
		t.Fatalf("provisionInsideInstaller() = %v", err)
	}
	if tpm.resetCalls != 1 || tpm.resetClearCalls != 0 {
		t.Errorf("reset calls: plain=%d clear=%d, want plain=1 clear=0", tpm.resetCalls, tpm.resetClearCalls)
	}
	opts := tpm.installOpts
	if opts == nil || !opts.EK || !opts.SSRK || !opts.PlatformPolicy || !opts.IAK || !opts.IDevID {
		t.Errorf("Install options = %+v, want EK, SSRK, platform policy, IAK and IDevID", opts)
	}
	if tpm.installSOPIN != nil {
		t.Error("Install was given an SO PIN; it would change the endorsement and lockout auth")
	}
	if tpm.setAuthCalls != 1 || tpm.cfg.SSRK.HierarchyAuth != "123456" {
		t.Errorf("ownership: %d auth changes, presented %q, want 1 and the SO PIN", tpm.setAuthCalls, tpm.cfg.SSRK.HierarchyAuth)
	}
}

func TestStrategyProvisionInsideInstaller_Failures(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		prepare func(*strategyTPM)
		wantMsg string
	}{
		{name: "install", prepare: func(tpm *strategyTPM) { tpm.installErr = errSeam }, wantMsg: "TPM install failed"},
		{
			name:    "install without EK certificate when it is required",
			prepare: func(tpm *strategyTPM) { tpm.installErr = xkmssdk.ErrTPMEndorsementCertNotFound },
			wantMsg: "TPM install failed",
		},
		{name: "platform SRK", prepare: func(tpm *strategyTPM) { tpm.cfg.PlatformSRK = nil }, wantMsg: "Platform KeyStore SRK creation failed"},
		{name: "ownership", prepare: func(tpm *strategyTPM) { tpm.setAuthErr = errSeam }, wantMsg: "TPM ownership failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHostRoot(t)
			tpm := newProvisionableTPM(t)
			tt.prepare(tpm)

			err := newProvisioningStrategy(t, tpm, nil).provisionInsideInstaller(context.Background())
			requireWrapped(t, err, tt.wantMsg)
		})
	}
}

// With allow-missing-ek-certificate, a TPM without an EK certificate is
// provisioned and only IDevID is left out.
func TestStrategyProvisionInsideInstaller_AllowMissingEK(t *testing.T) {
	useHostRoot(t)
	writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      allow-missing-ek-certificate: true\n")
	tpm := newProvisionableTPM(t)
	tpm.ekCert = nil
	tpm.installErr = xkmssdk.ErrTPMEndorsementCertNotFound

	if err := newProvisioningStrategy(t, tpm, nil).provisionInsideInstaller(context.Background()); err != nil {
		t.Fatalf("provisionInsideInstaller() = %v, want a TPM without an EK certificate accepted", err)
	}
	if tpm.setAuthCalls != 1 {
		t.Errorf("auth changes = %d, want ownership taken", tpm.setAuthCalls)
	}
}

func TestStrategyEnsurePlatformSRK(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		tpm := &strategyTPM{fakeTPM: &fakeTPM{cfg: fullTPMConfig()}}
		tpm.cfg.PlatformSRK.CN = ""
		s := newStrategy(tpm, nil)
		s.executor.backend = keyBackend{}

		if err := s.ensurePlatformSRK(); err != nil {
			t.Fatalf("ensurePlatformSRK() = %v", err)
		}
		if tpm.cfg.PlatformSRK.CN != "platform" {
			t.Errorf("CN = %q, want platformd's default", tpm.cfg.PlatformSRK.CN)
		}
		if len(tpm.keyAttrsHandles) != 1 || tpm.keyAttrsHandles[0] != 0x81000010 {
			t.Errorf("probed %v, want the configured SRK handle", tpm.keyAttrsHandles)
		}
	})
	t.Run("no TPM", func(t *testing.T) {
		if err := newStrategy(nil, nil).ensurePlatformSRK(); !errors.Is(err, ErrTPMNotAvailable) {
			t.Fatalf("ensurePlatformSRK() = %v, want ErrTPMNotAvailable", err)
		}
	})
	t.Run("no configuration", func(t *testing.T) {
		tpm := &strategyTPM{fakeTPM: &fakeTPM{cfg: &xkmssdk.TPMConfig{}}}

		requireMessage(t, newStrategy(tpm, nil).ensurePlatformSRK(), "platform-srk")
	})
	t.Run("probe", func(t *testing.T) {
		tpm := &strategyTPM{fakeTPM: &fakeTPM{cfg: fullTPMConfig()}}

		err := newStrategy(tpm, nil).ensurePlatformSRK()
		requireWrapped(t, err, "platform keystore probe failed")
	})
}

// An installer-configured seal handle redirects the LUKS seal parent away
// from the Platform KeyStore SRK.
func TestStrategyGetLUKSSealParentHandle(t *testing.T) {
	useHostRoot(t)
	tpm := &strategyTPM{fakeTPM: &fakeTPM{cfg: fullTPMConfig()}}
	s := newStrategy(tpm, nil)

	if got := s.getLUKSSealParentHandle(); got != 0x81000010 {
		t.Errorf("getLUKSSealParentHandle() = %#x, want the Platform KeyStore SRK", got)
	}
	writeInstallerConfig(t, "disk:\n  encryption:\n    tpm:\n      handle: 0x81000020\n")
	if got := s.getLUKSSealParentHandle(); got != 0x81000020 {
		t.Errorf("getLUKSSealParentHandle() = %#x, want the installer's handle", got)
	}
}

// A first boot that provisions and seals unlocks the root with the sealed key
// in place, kills the install-time passphrase slot, marks the root sealed and
// sets the TRUSTED_PLATFORM variable.
func TestStrategyUnlock_SealsOnFirstProvision(t *testing.T) {
	tpm := newProvisionableTPM(t)
	f := newUnlockFixture(t, tpm)
	f.strategy = newProvisioningStrategy(t, tpm, f.handler)
	swap(t, &firmwareIsAvailable, func() bool { return true })
	trusted := 0
	swap(t, &firmwareSetTrustedPlatform, func() error {
		trusted++
		return errSeam
	})
	var slots []int
	swap(t, &luksKillSlot, func(_ string, _ []byte, slot int) error {
		slots = append(slots, slot)
		return nil
	})

	if err := f.strategy.Unlock(context.Background(), f.volume); err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
	if got := readHostFile(t, strategyEFIMountPoint+"/"+strategySealPub); got != "pub" {
		t.Errorf("seal-platform.pub = %q", got)
	}
	// Seal received the installer's key buffer, which Unlock scrubs on return.
	if string(tpm.sealedKey) != string(make([]byte, len(luksKey()))) {
		t.Errorf("sealed key buffer = %x, want the 32-byte key scrubbed", tpm.sealedKey)
	}
	if got := readHostFile(t, strategyRootMountPoint+"/var/lib/tpm2/.tpm-sealed"); got != "sealed-by-initrd\n" {
		t.Errorf(".tpm-sealed = %q", got)
	}
	if want := []int{luksSlotInstaller, luksSlotRecovery}; len(slots) != 2 || slots[0] != want[0] || slots[1] != want[1] {
		t.Errorf("killed slots %v, want %v", slots, want)
	}
	if trusted != 1 {
		t.Errorf("TRUSTED_PLATFORM set %d times, want 1", trusted)
	}
	if !hostFileExists(strategyEFIMountPoint + "/" + strategyInstallerContainerFile) {
		t.Error("the installer was wiped before the next boot proved the seal")
	}
}

// A seal the TPM refuses leaves the plain-key boot with the seal failure as
// the retry reason.
func TestStrategyUnlock_SealFailure(t *testing.T) {
	tpm := newProvisionableTPM(t)
	tpm.sealErr = errSeam
	f := newUnlockFixture(t, tpm)
	f.strategy = newProvisioningStrategy(t, tpm, f.handler)

	if err := f.strategy.Unlock(context.Background(), f.volume); !errors.Is(err, ErrSealingFallbackUsed) {
		t.Fatalf("Unlock() = %v, want ErrSealingFallbackUsed", err)
	}
	marker := readHostFile(t, strategyRootMountPoint+"/var/lib/trusted-platform/.seal-retry-needed")
	if !strings.Contains(marker, "reason=sealKeyToTPM: failed to seal key") {
		t.Errorf("seal-retry marker = %q, want the seal failure", marker)
	}
	if hostFileExists(strategyEFIMountPoint + "/" + strategySealPub) {
		t.Error("seal-platform.pub written for a refused seal")
	}
}

// Without securityfs, Unlock mounts it to reach the event log. A root
// mapping that is a symlink to a readable LVM physical volume is probed, and
// a recovery-key strategy failure does not stop the boot.
func TestStrategyUnlock_MountsSecurityfs(t *testing.T) {
	f := newUnlockFixture(t, nil)
	if err := os.RemoveAll(hostPath("/sys")); err != nil {
		t.Fatal(err)
	}
	f.mounts = useMounts(t, installerFiles{"tpm0/binary_bios_measurements": []byte("events")}, nil)
	f.commands.fail = []string{"ls -la /dev/dm-*"}
	f.luks.fail["killslot"] = true
	pv := filepath.Join(t.TempDir(), "dm-0")
	if err := os.WriteFile(pv, append([]byte("LABELONE"), make([]byte, 504)...), 0o600); err != nil {
		t.Fatal(err)
	}
	mapping := hostPath(strategyDevMapperDir + "/cryptroot")
	if err := os.Remove(mapping); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pv, mapping); err != nil {
		t.Fatal(err)
	}

	if err := f.strategy.Unlock(context.Background(), f.volume); !errors.Is(err, ErrSealingFallbackUsed) {
		t.Fatalf("Unlock() = %v, want ErrSealingFallbackUsed", err)
	}
	if !contains(*f.mounts, "mount "+hostPath("/sys/kernel/security")) {
		t.Errorf("mounts = %v, want securityfs mounted", *f.mounts)
	}
	if !f.commands.ran("sh -c ls -la /dev/dm-* 2>/dev/null || echo 'No dm-* devices'") {
		t.Errorf("commands = %v, want the shell fallback listing", f.commands.calls)
	}
	if !hostFileExists(strategyRootMountPoint + "/var/lib/trusted-platform/.seal-retry-needed") {
		t.Error("the root was not populated through the symlinked mapping")
	}
}

// A root mapping whose node is gone cannot be copied to; Unlock still
// returns the fallback so the boot is recorded as degraded.
func TestStrategyUnlock_RootCopyFailure(t *testing.T) {
	f := newUnlockFixture(t, nil)
	mapping := hostPath(strategyDevMapperDir + "/cryptroot")
	if err := os.Remove(mapping); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), mapping); err != nil {
		t.Fatal(err)
	}

	if err := f.strategy.Unlock(context.Background(), f.volume); !errors.Is(err, ErrSealingFallbackUsed) {
		t.Fatalf("Unlock() = %v, want ErrSealingFallbackUsed", err)
	}
	if hostFileExists(strategyRootMountPoint + "/var/lib/trusted-platform") {
		t.Error("installer state was copied without a root device")
	}
}
