package firstboot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/firstboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// fakeStrategy records the volume runFirstboot hands to the seal strategy.
type fakeStrategy struct {
	canUnlock     bool
	unlockErr     error
	unlockCalls   int
	checkedVolume *storageluks.VolumeConfig
	unlockVolume  *storageluks.VolumeConfig
}

func (f *fakeStrategy) CanUnlock(_ context.Context, volume *storageluks.VolumeConfig) bool {
	f.checkedVolume = volume
	return f.canUnlock
}

func (f *fakeStrategy) Unlock(_ context.Context, volume *storageluks.VolumeConfig) error {
	f.unlockCalls++
	f.unlockVolume = volume
	return f.unlockErr
}

// firstbootSeams holds what the stubbed constructors saw and returns.
type firstbootSeams struct {
	executorErr    error
	luksErr        error
	strategy       *fakeStrategy
	executorConfig *firstboot.Config
	luksCalls      int
	strategyCalls  int
}

// stubFirstbootSeams replaces the host seams for one test and restores them
// with t.Cleanup. Callers must not use t.Parallel.
func stubFirstbootSeams(t *testing.T, seams *firstbootSeams) {
	t.Helper()
	origExecutor, origLUKS, origStrategy := newExecutor, newLUKSHandler, newSealStrategy
	origPCRs, origDevice := firstbootPCRSelection, firstbootLuksDevice
	t.Cleanup(func() {
		newExecutor, newLUKSHandler, newSealStrategy = origExecutor, origLUKS, origStrategy
		firstbootPCRSelection, firstbootLuksDevice = origPCRs, origDevice
	})

	newExecutor = func(_ context.Context, config *firstboot.Config, _ *logging.Logger) (*firstboot.Executor, error) {
		seams.executorConfig = config
		if seams.executorErr != nil {
			return nil, seams.executorErr
		}
		return &firstboot.Executor{}, nil
	}
	newLUKSHandler = func(_ *storageluks.Config, _ interface{}) (storageluks.Handler, error) {
		seams.luksCalls++
		return nil, seams.luksErr
	}
	newSealStrategy = func(_ *firstboot.Executor, _ storageluks.Handler, _ *logging.Logger) sealStrategy {
		seams.strategyCalls++
		return seams.strategy
	}
	firstbootPCRSelection = []uint{0, 7}
	firstbootLuksDevice = "/dev/fake-luks"
}

func TestRunFirstboot_ExecutorError(t *testing.T) {
	seams := &firstbootSeams{executorErr: errSentinel{}, strategy: &fakeStrategy{}}
	stubFirstbootSeams(t, seams)

	err := runFirstboot(context.Background())
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != "failed to create firstboot executor" {
		t.Fatalf("err = %v (%T), want WrappedError for the executor", err, err)
	}
	if !errors.Is(err, errSentinel{}) {
		t.Fatalf("err = %v, want it to wrap the executor error", err)
	}
	if seams.luksCalls != 0 || seams.strategyCalls != 0 {
		t.Fatalf("later steps ran: luks=%d strategy=%d", seams.luksCalls, seams.strategyCalls)
	}
}

func TestRunFirstboot_ExecutorReceivesFlagConfig(t *testing.T) {
	seams := &firstbootSeams{executorErr: errSentinel{}, strategy: &fakeStrategy{}}
	stubFirstbootSeams(t, seams)

	if err := runFirstboot(context.Background()); err == nil {
		t.Fatal("runFirstboot returned nil, want the executor error")
	}
	cfg := seams.executorConfig
	if cfg == nil {
		t.Fatal("executor constructor was not given a config")
	}
	if cfg.LuksDevice != "/dev/fake-luks" {
		t.Fatalf("LuksDevice = %q, want /dev/fake-luks", cfg.LuksDevice)
	}
	if !reflect.DeepEqual(cfg.PCRSelection, []uint{0, 7}) {
		t.Fatalf("PCRSelection = %v, want [0 7]", cfg.PCRSelection)
	}
}

func TestRunFirstboot_PCRsFromConfigReachExecutor(t *testing.T) {
	seams := &firstbootSeams{executorErr: errSentinel{}, strategy: &fakeStrategy{}}
	stubFirstbootSeams(t, seams)
	firstbootPCRSelection = nil
	withConfigFile(t, "seal-pcrs: [4, 11]\n")

	if err := runFirstboot(context.Background()); !errors.Is(err, errSentinel{}) {
		t.Fatalf("err = %v, want the executor error", err)
	}
	if seams.executorConfig == nil || !reflect.DeepEqual(seams.executorConfig.PCRSelection, []uint{4, 11}) {
		t.Fatalf("executor config = %+v, want PCRSelection [4 11]", seams.executorConfig)
	}
}

func TestRunFirstboot_LUKSHandlerError(t *testing.T) {
	seams := &firstbootSeams{luksErr: errSentinel{}, strategy: &fakeStrategy{}}
	stubFirstbootSeams(t, seams)

	err := runFirstboot(context.Background())
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != "failed to initialize LUKS handler" {
		t.Fatalf("err = %v (%T), want WrappedError for the LUKS handler", err, err)
	}
	if !errors.Is(err, errSentinel{}) {
		t.Fatalf("err = %v, want it to wrap the LUKS error", err)
	}
	if seams.strategyCalls != 0 {
		t.Fatalf("strategy built %d times after the LUKS error", seams.strategyCalls)
	}
}

func TestRunFirstboot_NotNeeded(t *testing.T) {
	strategy := &fakeStrategy{canUnlock: false}
	stubFirstbootSeams(t, &firstbootSeams{strategy: strategy})

	if err := runFirstboot(context.Background()); err != nil {
		t.Fatalf("runFirstboot = %v, want nil when sealing is not needed", err)
	}
	if strategy.unlockCalls != 0 {
		t.Fatalf("Unlock called %d times, want 0", strategy.unlockCalls)
	}
	volume := strategy.checkedVolume
	if volume == nil || volume.DevicePath != "/dev/fake-luks" || volume.MappingName != "cryptroot" {
		t.Fatalf("checked volume = %+v", volume)
	}
	if !reflect.DeepEqual(volume.PCRSelection, []uint{0, 7}) || !reflect.DeepEqual(volume.PCRBanks, []string{"sha256"}) {
		t.Fatalf("volume PCRs = %v banks = %v", volume.PCRSelection, volume.PCRBanks)
	}
}

func TestRunFirstboot_Success(t *testing.T) {
	strategy := &fakeStrategy{canUnlock: true}
	stubFirstbootSeams(t, &firstbootSeams{strategy: strategy})

	if err := runFirstboot(context.Background()); err != nil {
		t.Fatalf("runFirstboot = %v, want nil", err)
	}
	if strategy.unlockCalls != 1 {
		t.Fatalf("Unlock called %d times, want 1", strategy.unlockCalls)
	}
	if strategy.unlockVolume != strategy.checkedVolume {
		t.Fatal("Unlock was given a different volume than CanUnlock")
	}
}

func TestRunFirstboot_SealingFallbackReturnedUnwrapped(t *testing.T) {
	strategy := &fakeStrategy{canUnlock: true, unlockErr: firstboot.ErrSealingFallbackUsed}
	stubFirstbootSeams(t, &firstbootSeams{strategy: strategy})

	err := runFirstboot(context.Background())
	if !errors.Is(err, firstboot.ErrSealingFallbackUsed) {
		t.Fatalf("err = %v, want ErrSealingFallbackUsed", err)
	}
	var wrapped *WrappedError
	if errors.As(err, &wrapped) {
		t.Fatalf("err = %v, want the fallback error returned as is, not wrapped", err)
	}
}

func TestRunFirstboot_UnlockError(t *testing.T) {
	strategy := &fakeStrategy{canUnlock: true, unlockErr: errSentinel{}}
	stubFirstbootSeams(t, &firstbootSeams{strategy: strategy})

	err := runFirstboot(context.Background())
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || wrapped.Msg != "firstboot failed" {
		t.Fatalf("err = %v (%T), want WrappedError \"firstboot failed\"", err, err)
	}
	if !errors.Is(err, errSentinel{}) {
		t.Fatalf("err = %v, want it to wrap the Unlock error", err)
	}
}

// withSystemConfigPaths points the host config probes at paths under a
// temporary directory and empties the flag and config-dir probes.
func withSystemConfigPaths(t *testing.T, paths ...string) {
	t.Helper()
	origPaths, origConfig, origConfigDir := systemConfigPaths, firstbootConfig, firstbootConfigDir
	t.Cleanup(func() {
		systemConfigPaths, firstbootConfig, firstbootConfigDir = origPaths, origConfig, origConfigDir
	})
	systemConfigPaths = paths
	firstbootConfig = ""
	firstbootConfigDir = t.TempDir()
}

func TestLoadPCRsFromConfig_NoConfigFile(t *testing.T) {
	dir := t.TempDir()
	withSystemConfigPaths(t, filepath.Join(dir, "config.yaml"), filepath.Join(dir, "install-config.yaml"))

	pcrs, err := loadPCRsFromConfig(initializeLogger(false, false))
	var msgErr *MessageError
	if !errors.As(err, &msgErr) || msgErr.Msg != "no config file found" {
		t.Fatalf("err = %v (%T), want MessageError \"no config file found\"", err, err)
	}
	if pcrs != nil {
		t.Fatalf("pcrs = %v, want nil", pcrs)
	}
}

func TestLoadPCRsFromConfig_SystemConfigPath(t *testing.T) {
	dir := t.TempDir()
	installConfig := filepath.Join(dir, "install-config.yaml")
	if err := os.WriteFile(installConfig, []byte("installer:\n  seal-pcrs: [7]\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	withSystemConfigPaths(t, filepath.Join(dir, "missing.yaml"), installConfig)

	pcrs, err := loadPCRsFromConfig(initializeLogger(false, false))
	if err != nil {
		t.Fatalf("loadPCRsFromConfig = %v", err)
	}
	if !reflect.DeepEqual(pcrs, []uint{7}) {
		t.Fatalf("pcrs = %v, want [7]", pcrs)
	}
}
