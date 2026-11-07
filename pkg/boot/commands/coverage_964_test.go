package commands

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setFlag sets a package flag variable for one test and restores it after.
func setFlag[T any](t *testing.T, flag *T, value T) {
	t.Helper()
	previous := *flag
	*flag = value
	t.Cleanup(func() { *flag = previous })
}

// lookPath resolves a host utility the emergency-shell tests run as the
// "shell"; the tests need its absolute path because the code stats it.
func lookPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	require.NoError(t, err, "the %s utility is required by this test", name)
	return path
}

func TestHandleHexFormatsHandles(t *testing.T) {
	assert.Equal(t, "0x81000001", srkHandleHex(&xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000001}))
	assert.Equal(t, "none", srkHandleHex(nil))
	assert.Equal(t, "0x81000002", ssrkHandleHex(&xkmssdk.SRKConfig{Handle: 0x81000002}))
	assert.Equal(t, "none", ssrkHandleHex(nil))
}

func TestHandleBootFailure(t *testing.T) {
	cause := &MessageError{Msg: "unlock failed"}

	t.Run("without emergency the failure is wrapped", func(t *testing.T) {
		err := handleBootFailure(context.Background(), cause, false)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "boot failed", wrapped.Msg)
		assert.ErrorIs(t, err, cause)
	})

	t.Run("with emergency the shell outcome is returned", func(t *testing.T) {
		setFlag(t, &bootEmergency, true)
		t.Setenv("SHELL", lookPath(t, "true"))
		assert.NoError(t, handleBootFailure(context.Background(), cause, bootEmergency))
	})
}

func TestLaunchEmergencyShell(t *testing.T) {
	tests := []struct {
		name    string
		shell   func(t *testing.T) string
		wantMsg string
		wantIs  error
	}{
		{
			name:  "a shell that exits cleanly returns nil",
			shell: func(t *testing.T) string { return lookPath(t, "true") },
		},
		{
			name:    "a shell that exits non-zero is a failure",
			shell:   func(t *testing.T) string { return lookPath(t, "false") },
			wantMsg: "emergency shell failed",
		},
		{
			name:    "a missing shell is not available",
			shell:   func(t *testing.T) string { return filepath.Join(t.TempDir(), "no-such-shell") },
			wantMsg: "emergency shell not available",
			wantIs:  fs.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SHELL", tt.shell(t))
			err := launchEmergencyShell(context.Background())
			if tt.wantMsg == "" {
				assert.NoError(t, err)
				return
			}
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.wantMsg, wrapped.Msg)
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
		})
	}
}

func TestTryMountInstaller_NoContainerIsNotFirstboot(t *testing.T) {
	loopDev, mounted := tryMountInstaller(t.TempDir())
	assert.False(t, mounted)
	assert.Empty(t, loopDev)
}

func TestLoadSealPCRsFromConfig_NoConfigIsTypedError(t *testing.T) {
	withHostSeams(t)

	pcrs, err := loadSealPCRsFromConfig(logging.DefaultLogger())
	assert.Nil(t, pcrs)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, "seal-pcrs not found in config.yaml")
	assert.Contains(t, msgErr.Msg, installerMountPoint)
	assert.Contains(t, msgErr.Msg, rootConfigPath)
}

func TestDefaultInstallerCloserWaitsTheLockInterval(t *testing.T) {
	closer := defaultInstallerCloser()
	require.NotNil(t, closer.unmount)
	require.NotNil(t, closer.lock)
	require.NotNil(t, closer.detach)
	require.NotNil(t, closer.sync)
	require.NotNil(t, closer.wait)

	start := time.Now()
	closer.wait()
	assert.GreaterOrEqual(t, time.Since(start), installerLockInterval)
}

// CreateManager never falls back to a default TPM configuration: whichever
// source names the TPM device, a host without pcr-banks or a platform
// config is a fatal, typed error before any TPM is opened.
func TestCreateManager_NoTPMConfigurationIsFatal(t *testing.T) {
	tests := []struct {
		name    string
		tcti    string
		tpmPath string
	}{
		{name: "explicit device path", tpmPath: "/nonexistent/tpm0"},
		{name: "TCTI device prefix", tcti: "device:/nonexistent/tpm0", tpmPath: "/dev/tpmrm0"},
		{name: "TCTI swtpm socket", tcti: "swtpm:host=localhost,port=2321", tpmPath: ""},
		{name: "TCTI bare device path", tcti: "/nonexistent/tpmrm0", tpmPath: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withHostSeams(t)
			_, params := withFakeTPM(t)
			t.Setenv("TPM2TOOLS_TCTI", tt.tcti)
			config := &platforminitrd.Config{XKMSPath: t.TempDir()}

			manager, err := CreateManager(context.Background(), logging.DefaultLogger(), config, tt.tpmPath)
			assert.Nil(t, manager)
			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.True(t, strings.HasPrefix(msgErr.Msg, "FATAL: no TPM configuration found"), msgErr.Msg)
			assert.Nil(t, *params, "the missing-configuration guard must stop before the TPM is opened")
		})
	}
}

func TestRunRecovery(t *testing.T) {
	t.Run("device is required", func(t *testing.T) {
		withHostSeams(t)
		setFlag(t, &recoveryDevice, "")
		err := runRecovery(context.Background())
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, "--device flag is required", msgErr.Msg)
	})

	t.Run("an empty xkms dir is an invalid configuration", func(t *testing.T) {
		withHostSeams(t)
		setFlag(t, &recoveryDevice, "/dev/nonexistent2")
		setFlag(t, &recoveryXKMSDir, "")
		err := runRecovery(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "invalid configuration", wrapped.Msg)
		assert.ErrorIs(t, err, platforminitrd.ErrInvalidConfig)
	})

	t.Run("a manager that cannot be created fails recovery", func(t *testing.T) {
		withHostSeams(t)
		setFlag(t, &recoveryDevice, "/dev/nonexistent2")
		setFlag(t, &recoveryXKMSDir, t.TempDir())
		withFakeManager(t, nil, &seamError{op: "create manager"})
		err := runRecovery(context.Background())
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create manager", wrapped.Msg)
		var cause *seamError
		require.True(t, errors.As(wrapped.Err, &cause))
		assert.Equal(t, "create manager", cause.op)
		assert.FileExists(t, filepath.Join(platformLogDir, "recovery.log"))
	})
}

func TestExecute(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })

	rootCmd.SetArgs([]string{"version"})
	assert.NoError(t, Execute())

	rootCmd.SetArgs([]string{"no-such-subcommand"})
	err := Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}
