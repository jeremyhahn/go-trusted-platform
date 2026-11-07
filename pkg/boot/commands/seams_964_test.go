package commands

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	bootconfig "github.com/jeremyhahn/go-trusted-platform/pkg/boot/config"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/securewipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file swap the package's host seams, so none of them
// runs in parallel.

// seamError is the typed error a fake host call returns.
type seamError struct{ op string }

func (e *seamError) Error() string { return e.op + " failed" }

const testPCRBanks = "platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000001\nssrk-handle=0x81000002\n"

// withHostSeams points every host path at a fresh temporary directory and
// every host call at a fake that fails, so a test only reaches the host
// through the seams it sets itself.
func withHostSeams(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	setFlag(t, &installerMountPoint, filepath.Join(dir, "installer"))
	setFlag(t, &rootConfigPath, filepath.Join(dir, "root-config.yaml"))
	setFlag(t, &bootLogPath, filepath.Join(dir, "boot.log"))
	setFlag(t, &pcrBanksConfigPath, filepath.Join(dir, "pcr-banks"))
	setFlag(t, &tpmConfigPaths, []string{filepath.Join(dir, "platformd.yaml")})
	setFlag(t, &platformLogDir, filepath.Join(dir, "log"))
	// The LUKS logger closes its output, so it must not be the test's stdout.
	setFlag[io.Writer](t, &luksLogOutput, &bytes.Buffer{})
	setFlag(t, &setupLoopDevice, func(string) (string, error) { return "", &seamError{op: "losetup"} })
	setFlag(t, &newTPM2, func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		return nil, &seamError{op: "open TPM"}
	})
	return dir
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// fakeTPM is the TPM the newTPM2 seam opens; only Close is reached.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule
	closed int
}

func (f *fakeTPM) Close() error {
	f.closed++
	return nil
}

// withFakeTPM opens a fakeTPM through the seam and records the params.
func withFakeTPM(t *testing.T) (*fakeTPM, **xkmssdk.TPMParams) {
	t.Helper()
	tpm := &fakeTPM{}
	var params *xkmssdk.TPMParams
	setFlag(t, &newTPM2, func(p *xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		params = p
		return tpm, nil
	})
	return tpm, &params
}

func validInitrdConfig(t *testing.T, mode platforminitrd.BootMode) *platforminitrd.Config {
	t.Helper()
	return &platforminitrd.Config{
		Mode:          mode,
		RootDevice:    "/dev/vda2",
		BootDevice:    t.TempDir(),
		XKMSPath:      t.TempDir(),
		PCRBanks:      []string{"sha256"},
		PCRSelection:  []uint{7},
		UnlockTimeout: 30,
		RetryCount:    3,
	}
}

func TestCreateManager_Seams(t *testing.T) {
	t.Run("the pcr-banks file configures the TPM and the manager is built", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, pcrBanksConfigPath, testPCRBanks)
		tpm, params := withFakeTPM(t)

		manager, err := CreateManager(context.Background(), logging.DefaultLogger(), validInitrdConfig(t, platforminitrd.ModeBoot), "/dev/fake-tpm")
		require.NoError(t, err)
		require.NotNil(t, manager)
		require.NotNil(t, *params)
		cfg := (*params).Config
		assert.Equal(t, "/dev/fake-tpm", cfg.Device)
		assert.Equal(t, uint(23), cfg.PlatformPCR)
		assert.Equal(t, uint32(0x81000001), cfg.PlatformSRK.SRKHandle)
		assert.False(t, cfg.UseSimulator)
		assert.Empty(t, cfg.FileIntegrity)
		assert.Zero(t, tpm.closed)
	})

	t.Run("a platform config file is the fallback to the pcr-banks file", func(t *testing.T) {
		dir := withHostSeams(t)
		fallback := filepath.Join(dir, "fallback.yaml")
		writeTestFile(t, fallback, "tpm:\n  platform-pcr: 16\n")
		setFlag(t, &tpmConfigPaths, []string{filepath.Join(dir, "missing.yaml"), fallback})
		_, params := withFakeTPM(t)

		manager, err := CreateManager(context.Background(), logging.DefaultLogger(), validInitrdConfig(t, platforminitrd.ModeBoot), "/dev/fake-tpm")
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, uint(16), (*params).Config.PlatformPCR)
	})

	t.Run("a TPM that does not open fails the manager", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, pcrBanksConfigPath, testPCRBanks)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manager, err := CreateManager(ctx, logging.DefaultLogger(), validInitrdConfig(t, platforminitrd.ModeBoot), "/dev/fake-tpm")
		assert.Nil(t, manager)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "TPM initialization canceled", wrapped.Msg)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("an xkms path that cannot hold a store closes the TPM", func(t *testing.T) {
		dir := withHostSeams(t)
		writeTestFile(t, pcrBanksConfigPath, testPCRBanks)
		tpm, _ := withFakeTPM(t)
		blocker := filepath.Join(dir, "blocker")
		writeTestFile(t, blocker, "a file, not a directory")
		config := validInitrdConfig(t, platforminitrd.ModeBoot)
		config.XKMSPath = filepath.Join(blocker, "xkms")

		manager, err := CreateManager(context.Background(), logging.DefaultLogger(), config, "/dev/fake-tpm")
		assert.Nil(t, manager)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create file storage backend", wrapped.Msg)
		assert.Equal(t, 1, tpm.closed)
	})

	t.Run("an invalid initrd config closes the TPM", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, pcrBanksConfigPath, testPCRBanks)
		tpm, _ := withFakeTPM(t)
		config := validInitrdConfig(t, platforminitrd.ModeBoot)
		config.RootDevice = ""

		manager, err := CreateManager(context.Background(), logging.DefaultLogger(), config, "/dev/fake-tpm")
		assert.Nil(t, manager)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create initrd manager", wrapped.Msg)
		assert.Equal(t, 1, tpm.closed)
	})
}

func TestLoadSealPCRsFromConfig_Seams(t *testing.T) {
	installerConfig := func() string {
		return filepath.Join(installerMountPoint, "etc", "trusted-platform", "config.yaml")
	}

	t.Run("an unparsable installer config falls through to the root config", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, installerConfig(), "seal-pcrs: [unterminated\n")
		writeTestFile(t, rootConfigPath, "seal-pcrs: [7, 9]\n")

		pcrs, err := loadSealPCRsFromConfig(logging.DefaultLogger())
		require.NoError(t, err)
		assert.Equal(t, []uint{7, 9}, pcrs)
	})

	t.Run("a config without seal-pcrs is a typed error naming both paths", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, installerConfig(), "secure-wipe-passes: 3\n")

		pcrs, err := loadSealPCRsFromConfig(logging.DefaultLogger())
		assert.Nil(t, pcrs)
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Msg, installerConfig())
		assert.Contains(t, msgErr.Msg, rootConfigPath)
	})
}

func TestLoadSecureWipePassesFromConfig_Seams(t *testing.T) {
	t.Run("the root config sets the passes", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, filepath.Join(installerMountPoint, "etc", "trusted-platform", "config.yaml"), "secure-wipe-passes: [bad\n")
		writeTestFile(t, rootConfigPath, "secure-wipe-passes: 3\n")
		assert.Equal(t, 3, loadSecureWipePassesFromConfig())
	})

	t.Run("no passes configured is the NIST default", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, rootConfigPath, "seal-pcrs: [7]\n")
		assert.Equal(t, securewipe.PassesNIST, loadSecureWipePassesFromConfig())
	})
}

func TestInitializeLogger_FileModeSeam(t *testing.T) {
	t.Run("recovery logs to a file in the log directory", func(t *testing.T) {
		withHostSeams(t)
		logger, err := InitializeLogger("recovery", true, false)
		require.NoError(t, err)
		require.NotNil(t, logger)
		_, statErr := os.Stat(filepath.Join(platformLogDir, "recovery.log"))
		assert.NoError(t, statErr)
	})

	t.Run("an unwritable log directory falls back to the console", func(t *testing.T) {
		dir := withHostSeams(t)
		blocker := filepath.Join(dir, "blocker")
		writeTestFile(t, blocker, "a file, not a directory")
		setFlag(t, &platformLogDir, filepath.Join(blocker, "log"))

		logger, err := InitializeLogger("recovery", false, true)
		require.NoError(t, err)
		assert.NotNil(t, logger)
	})
}

// fakeMount records the go-luks2 and mount calls tryMountInstaller makes.
type fakeMount struct {
	unlockErr, mappedErr, mountErr error
	unlockPass                     string
	mountSource, mountFSType       string
	locked, detached               []string
}

func withFakeMount(t *testing.T, m *fakeMount) {
	t.Helper()
	setFlag(t, &setupLoopDevice, func(string) (string, error) { return "/dev/loop7", nil })
	setFlag(t, &unlockLUKS, func(_ string, pass []byte, _ string) error {
		m.unlockPass = string(pass)
		return m.unlockErr
	})
	setFlag(t, &mappedDevicePath, func(name string) (string, error) {
		if m.mappedErr != nil {
			return "", m.mappedErr
		}
		return "/dev/mapper/fake-" + name, nil
	})
	setFlag(t, &lockLUKS, func(name string) error {
		m.locked = append(m.locked, name)
		return nil
	})
	setFlag(t, &detachLoopDevice, func(dev string) error {
		m.detached = append(m.detached, dev)
		return nil
	})
	setFlag(t, &mountFS, func(source, _, fstype string, _ uintptr, _ string) error {
		m.mountSource, m.mountFSType = source, fstype
		return m.mountErr
	})
}

func TestTryMountInstaller_Seams(t *testing.T) {
	withContainer := func(t *testing.T) string {
		t.Helper()
		efi := t.TempDir()
		writeTestFile(t, filepath.Join(efi, "tpm2", "installer.luks"), "container")
		return efi
	}

	t.Run("the container is unlocked and mounted", func(t *testing.T) {
		withHostSeams(t)
		m := &fakeMount{}
		withFakeMount(t, m)

		loopDev, mounted := tryMountInstaller(withContainer(t))
		assert.True(t, mounted)
		assert.Equal(t, "/dev/loop7", loopDev)
		assert.Equal(t, bootconfig.InstallerPassword, m.unlockPass)
		assert.Equal(t, "/dev/mapper/fake-installer", m.mountSource)
		assert.Equal(t, "ext4", m.mountFSType)
		assert.DirExists(t, installerMountPoint)
		assert.Empty(t, m.locked)
	})

	t.Run("an unknown mapped path falls back to the mapper default", func(t *testing.T) {
		withHostSeams(t)
		m := &fakeMount{mappedErr: &seamError{op: "mapped path"}}
		withFakeMount(t, m)

		_, mounted := tryMountInstaller(withContainer(t))
		assert.True(t, mounted)
		assert.Equal(t, "/dev/mapper/installer", m.mountSource)
	})

	t.Run("an installer already mounted is left alone", func(t *testing.T) {
		withHostSeams(t)
		writeTestFile(t, filepath.Join(installerMountPoint, "luks-key.bin"), "key")

		loopDev, mounted := tryMountInstaller(withContainer(t))
		assert.False(t, mounted)
		assert.Empty(t, loopDev)
	})

	t.Run("a loop device that cannot be set up is not a mount", func(t *testing.T) {
		withHostSeams(t)
		loopDev, mounted := tryMountInstaller(withContainer(t))
		assert.False(t, mounted)
		assert.Empty(t, loopDev)
	})

	t.Run("a failed unlock detaches the loop device", func(t *testing.T) {
		withHostSeams(t)
		m := &fakeMount{unlockErr: &seamError{op: "unlock"}}
		withFakeMount(t, m)

		_, mounted := tryMountInstaller(withContainer(t))
		assert.False(t, mounted)
		assert.Equal(t, []string{"/dev/loop7"}, m.detached)
		assert.Empty(t, m.locked)
	})

	t.Run("a mount point that cannot be created locks and detaches", func(t *testing.T) {
		dir := withHostSeams(t)
		blocker := filepath.Join(dir, "blocker")
		writeTestFile(t, blocker, "a file, not a directory")
		setFlag(t, &installerMountPoint, filepath.Join(blocker, "installer"))
		m := &fakeMount{}
		withFakeMount(t, m)

		_, mounted := tryMountInstaller(withContainer(t))
		assert.False(t, mounted)
		assert.Equal(t, []string{"installer"}, m.locked)
		assert.Equal(t, []string{"/dev/loop7"}, m.detached)
		assert.Empty(t, m.mountSource)
	})

	t.Run("a failed mount locks and detaches", func(t *testing.T) {
		withHostSeams(t)
		m := &fakeMount{mountErr: &seamError{op: "mount"}}
		withFakeMount(t, m)

		_, mounted := tryMountInstaller(withContainer(t))
		assert.False(t, mounted)
		assert.Equal(t, []string{"installer"}, m.locked)
		assert.Equal(t, []string{"/dev/loop7"}, m.detached)
	})
}

// fakeManager is the platform manager the createManager seam returns.
type fakeManager struct {
	initErr, bootErr, recoveryErr, interactiveErr error
	unlockedWith                                  string
	booted, recovered, interactive, closed        int
}

func (f *fakeManager) Initialize(context.Context) error { return f.initErr }
func (f *fakeManager) DetectMode(context.Context) (platforminitrd.BootMode, error) {
	return platforminitrd.ModeBoot, nil
}
func (f *fakeManager) Install(context.Context, []byte) error { return nil }
func (f *fakeManager) Boot(context.Context) error {
	f.booted++
	return f.bootErr
}
func (f *fakeManager) UnlockedWith() string { return f.unlockedWith }
func (f *fakeManager) Recovery(context.Context) error {
	f.recovered++
	return f.recoveryErr
}
func (f *fakeManager) InteractiveRecovery(context.Context) error {
	f.interactive++
	return f.interactiveErr
}
func (f *fakeManager) RegisterStrategy(platforminitrd.UnlockStrategy) {}
func (f *fakeManager) UnlockVolumes(context.Context) error            { return nil }
func (f *fakeManager) Close() error {
	f.closed++
	return nil
}

// withFakeManager makes createManager return m (or createErr) and records
// the config it was given.
func withFakeManager(t *testing.T, m *fakeManager, createErr error) **platforminitrd.Config {
	t.Helper()
	var got *platforminitrd.Config
	setFlag(t, &createManager, func(_ context.Context, _ *logging.Logger, config *platforminitrd.Config, _ string) (platforminitrd.Manager, error) {
		got = config
		if createErr != nil {
			return nil, createErr
		}
		return m, nil
	})
	return &got
}

// fakeCloser counts the installer close calls; unmountErr fails both the
// normal and the lazy unmount.
type fakeCloser struct {
	unmountErr error
	unmounts   int
}

func (c *fakeCloser) ops() installerCloser {
	return installerCloser{
		unmount: func(string, int) error {
			c.unmounts++
			return c.unmountErr
		},
		lock:   func(string) error { return nil },
		detach: func(string) error { return nil },
		wait:   func() {},
		sync:   func() {},
	}
}

// withBootSeams sets the boot flags of a disk boot with every host seam
// pointed at the test.
func withBootSeams(t *testing.T) *fakeCloser {
	t.Helper()
	withHostSeams(t)
	setFlag(t, &bootDiskless, false)
	setFlag(t, &bootDevice, "/dev/vda2")
	setFlag(t, &bootMappingName, "root")
	setFlag(t, &bootEFIPath, t.TempDir())
	setFlag(t, &bootXKMSDir, t.TempDir())
	setFlag(t, &bootTPMPath, "/dev/fake-tpm")
	setFlag(t, &bootPCRs, []uint{7})
	setFlag(t, &bootEmergency, false)
	setFlag(t, &bootFallbackMode, false)
	closer := &fakeCloser{}
	setFlag(t, &newInstallerCloser, closer.ops)
	return closer
}

func withMountedInstaller(t *testing.T) {
	t.Helper()
	writeTestFile(t, filepath.Join(bootEFIPath, "tpm2", "installer.luks"), "container")
	withFakeMount(t, &fakeMount{})
}

func TestRunBoot_Seams(t *testing.T) {
	t.Run("a disk boot unlocks the root and leaves breadcrumbs", func(t *testing.T) {
		withBootSeams(t)
		m := &fakeManager{}
		config := withFakeManager(t, m, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, 1, m.booted)
		assert.Equal(t, 1, m.closed)
		require.NotNil(t, *config)
		assert.Equal(t, platforminitrd.ModeBoot, (*config).Mode)
		assert.Equal(t, []uint{7}, (*config).PCRSelection)
		assert.Empty(t, (*config).FallbackMethods)
		log, err := os.ReadFile(bootLogPath)
		require.NoError(t, err)
		assert.Contains(t, string(log), "step07: CreateManager")
	})

	t.Run("fallback mode configures every unlock method", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootFallbackMode, true)
		config := withFakeManager(t, &fakeManager{}, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Len(t, (*config).FallbackMethods, 4)
	})

	t.Run("the pcr-banks file selects the PCRs", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootPCRs, []uint(nil))
		writeTestFile(t, filepath.Join(bootEFIPath, "tpm2", "pcr-banks"), "seal-pcrs=0,7\n")
		config := withFakeManager(t, &fakeManager{}, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, []uint{0, 7}, (*config).PCRSelection)
	})

	t.Run("the platform config selects the PCRs without a pcr-banks file", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootPCRs, []uint(nil))
		writeTestFile(t, rootConfigPath, "seal-pcrs: [7, 9]\n")
		config := withFakeManager(t, &fakeManager{}, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, []uint{7, 9}, (*config).PCRSelection)
	})

	t.Run("no PCR source leaves an empty selection the config rejects", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootPCRs, []uint(nil))
		withFakeManager(t, &fakeManager{}, nil)

		err := runBoot(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "invalid configuration", wrapped.Msg)
	})

	t.Run("a missing device is a typed error", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootDevice, "")
		err := runBoot(context.Background())
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, "--device flag is required", msgErr.Msg)
	})

	t.Run("an empty xkms dir is an invalid configuration", func(t *testing.T) {
		withBootSeams(t)
		setFlag(t, &bootXKMSDir, "")
		err := runBoot(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "invalid configuration", wrapped.Msg)
		assert.ErrorIs(t, err, platforminitrd.ErrInvalidConfig)
	})

	failures := []struct {
		name    string
		manager *fakeManager
		create  error
	}{
		{name: "a manager that cannot be created fails the boot", create: &seamError{op: "create manager"}},
		{name: "a platform that does not initialize fails the boot", manager: &fakeManager{initErr: &seamError{op: "initialize"}}},
		{name: "a failed unlock fails the boot", manager: &fakeManager{bootErr: &seamError{op: "boot"}}},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			closer := withBootSeams(t)
			withMountedInstaller(t)
			withFakeManager(t, tt.manager, tt.create)

			err := runBoot(context.Background())
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, "boot failed", wrapped.Msg)
			var cause *seamError
			require.ErrorAs(t, err, &cause)
			assert.Equal(t, 1, closer.unmounts, "the deferred cleanup closes the installer once")
		})
	}

	t.Run("an installer left open on failure is a warning, not a second error", func(t *testing.T) {
		closer := withBootSeams(t)
		closer.unmountErr = &seamError{op: "unmount"}
		withMountedInstaller(t)
		withFakeManager(t, nil, &seamError{op: "create manager"})

		err := runBoot(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "boot failed", wrapped.Msg)
		assert.Equal(t, 2, closer.unmounts, "normal then lazy unmount")
	})

	t.Run("a non TPM-PCR unlock closes the installer and preserves it", func(t *testing.T) {
		closer := withBootSeams(t)
		withMountedInstaller(t)
		m := &fakeManager{unlockedWith: "fido2"}
		withFakeManager(t, m, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, 1, closer.unmounts, "closed once for the confirmation, not again on exit")
		assert.FileExists(t, filepath.Join(bootEFIPath, "tpm2", "installer.luks"))
		log, err := os.ReadFile(bootLogPath)
		require.NoError(t, err)
		assert.Contains(t, string(log), "installer.luks preserved")
	})

	t.Run("an installer that will not close skips the confirmation", func(t *testing.T) {
		closer := withBootSeams(t)
		closer.unmountErr = &seamError{op: "unmount"}
		withMountedInstaller(t)
		withFakeManager(t, &fakeManager{unlockedWith: "fido2"}, nil)

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, 2, closer.unmounts, "the deferred cleanup does not retry")
		log, err := os.ReadFile(bootLogPath)
		require.NoError(t, err)
		assert.Contains(t, string(log), "seal confirmation skipped")
	})

	t.Run("a diskless boot mounts the verified root", func(t *testing.T) {
		withBootSeams(t)
		withBootFlags(t, true, "", disklessTestArgs())
		var got platforminitrd.DisklessRootConfig
		setFlag(t, &mountDisklessRoot, func(_ context.Context, cfg platforminitrd.DisklessRootConfig) (*platforminitrd.DisklessRootMount, error) {
			got = cfg
			return &platforminitrd.DisklessRootMount{RootMount: cfg.RootMount}, nil
		})
		withFakeManager(t, nil, &seamError{op: "a diskless boot builds no manager"})

		require.NoError(t, runBoot(context.Background()))
		assert.Equal(t, bootRootMount, got.RootMount)
	})

	t.Run("a diskless root that does not mount fails the boot", func(t *testing.T) {
		withBootSeams(t)
		withBootFlags(t, true, "", disklessTestArgs())
		setFlag(t, &mountDisklessRoot, func(context.Context, platforminitrd.DisklessRootConfig) (*platforminitrd.DisklessRootMount, error) {
			return nil, &seamError{op: "diskless mount"}
		})

		err := runBoot(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "boot failed", wrapped.Msg)
		var cause *seamError
		require.ErrorAs(t, err, &cause)
		assert.Equal(t, "diskless mount", cause.op)
	})
}

func TestRunRecovery_Seams(t *testing.T) {
	withRecoverySeams := func(t *testing.T) {
		t.Helper()
		withHostSeams(t)
		setFlag(t, &recoveryDevice, "/dev/vda2")
		setFlag(t, &recoveryXKMSDir, t.TempDir())
		setFlag(t, &recoveryEFIPath, t.TempDir())
		setFlag(t, &recoveryInteractive, false)
	}

	t.Run("recovery unlocks the root", func(t *testing.T) {
		withRecoverySeams(t)
		m := &fakeManager{}
		config := withFakeManager(t, m, nil)

		require.NoError(t, runRecovery(context.Background()))
		assert.Equal(t, 1, m.recovered)
		assert.Equal(t, 1, m.closed)
		assert.Equal(t, platforminitrd.ModeRecovery, (*config).Mode)
		assert.FileExists(t, filepath.Join(platformLogDir, "recovery.log"))
	})

	t.Run("interactive recovery runs the menu", func(t *testing.T) {
		withRecoverySeams(t)
		setFlag(t, &recoveryInteractive, true)
		m := &fakeManager{}
		withFakeManager(t, m, nil)

		require.NoError(t, runRecovery(context.Background()))
		assert.Equal(t, 1, m.interactive)
		assert.Zero(t, m.recovered)
	})

	failures := []struct {
		name        string
		interactive bool
		manager     *fakeManager
		wantMsg     string
	}{
		{name: "a platform that does not initialize", manager: &fakeManager{initErr: &seamError{op: "initialize"}}, wantMsg: "failed to initialize platform"},
		{name: "a failed interactive recovery", interactive: true, manager: &fakeManager{interactiveErr: &seamError{op: "menu"}}, wantMsg: "interactive recovery failed"},
		{name: "a failed recovery unlock", manager: &fakeManager{recoveryErr: &seamError{op: "recovery"}}, wantMsg: "recovery failed"},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			withRecoverySeams(t)
			setFlag(t, &recoveryInteractive, tt.interactive)
			withFakeManager(t, tt.manager, nil)

			err := runRecovery(context.Background())
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.wantMsg, wrapped.Msg)
			var cause *seamError
			require.ErrorAs(t, err, &cause)
			assert.Equal(t, 1, tt.manager.closed)
		})
	}
}
