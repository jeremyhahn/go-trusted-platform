//go:build integration

package diskimage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// ubootTimeout bounds the U-Boot-only session: U-Boot itself boots in
// seconds even under TCG, and an empty disk sends it to the prompt.
const ubootTimeout = 5 * time.Minute

// TestUBootTPMAndSecureBoot boots the qemu_arm64 U-Boot alone, with a
// swtpm behind tpm-tis-device and an empty disk, and asks it at its prompt
// what the image relies on: the TPM is found and is a 2.0 device, and the
// preseeded variables put the firmware in Secure Boot mode.
func TestUBootTPMAndSecureBoot(t *testing.T) {
	in := requireInputs(t)
	workDir := filepath.Join(in.workDir, "uboot")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	ctx, cancel := context.WithTimeout(context.Background(), ubootTimeout)
	defer cancel()
	logger := logging.DefaultLogger()

	cfg := &qemu.Config{
		Arch:              qemu.ArchAArch64,
		Firmware:          in.uboot,
		DiskPath:          filepath.Join(workDir, "empty.img"),
		DiskFormat:        qemu.DiskFormatRaw,
		DiskSize:          "64M",
		Memory:            1024,
		CPUs:              2,
		WorkDir:           workDir,
		EnableKVM:         true,
		NoGraphic:         true,
		NetworkMode:       "none",
		SerialLogFile:     filepath.Join(workDir, "serial.log"),
		ConsoleSocketPath: filepath.Join(workDir, "console.sock"),
	}
	tpm, _, err := harness.StartTPM(ctx, logger, cfg)
	require.NoError(t, err)
	defer harness.StopTPM(logger, tpm)

	vm, err := qemu.NewVM(cfg, logger)
	require.NoError(t, err)
	require.NoError(t, vm.CreateDisk())
	require.NoError(t, vm.Start(ctx, string(qemu.BootModeBoot)))
	defer func() { _ = vm.Stop() }()

	console, err := harness.DialConsole(ctx, cfg.ConsoleSocketPath)
	require.NoError(t, err)
	defer console.Close()

	// The console socket does not replay what U-Boot printed before the
	// client connected (wait=off), so the banner is checked in the serial
	// log at the end; the prompt is what the session waits for. Nothing on
	// the empty disk boots, so the standard boot flow ends there.
	_, err = console.Expect(ctx, "=> ")
	require.NoError(t, err, "U-Boot prompt after the failed autoboot")

	t.Run("tpm2 info finds the TIS device", func(t *testing.T) {
		console.Discard()
		require.NoError(t, console.SendLine("tpm2 autostart"))
		_, err := console.Expect(ctx, "=> ")
		require.NoError(t, err)
		console.Discard()
		require.NoError(t, console.SendLine("tpm2 info"))
		out, err := console.Expect(ctx, "=> ")
		require.NoError(t, err)
		assert.Contains(t, out, "v2.0", "a TPM 2.0 device is bound (tpm-tis-device via TPM2_MMIO): %q", out)
		assert.NotContains(t, out, "Unable to find TPM", "%q", out)
	})

	t.Run("SecureBoot is on from the preseeded variables", func(t *testing.T) {
		console.Discard()
		require.NoError(t, console.SendLine("printenv -e SecureBoot"))
		out, err := console.Expect(ctx, "=> ")
		require.NoError(t, err)
		assert.Contains(t, out, "SecureBoot:", "%q", out)
		assert.Contains(t, out, "00000000: 01", "SecureBoot=1 (PK is enrolled): %q", out)

		console.Discard()
		require.NoError(t, console.SendLine("printenv -e -n db"))
		out, err = console.Expect(ctx, "=> ")
		require.NoError(t, err)
		assert.NotContains(t, out, "not found", "the preseeded db is present: %q", out)
	})

	t.Run("the banner and the transcript are in the serial log", func(t *testing.T) {
		require.NoError(t, vm.Stop(), "stopping the VM flushes the chardev log")
		for _, needle := range []string{"U-Boot 20", "tpm2 info", "=> "} {
			found, err := harness.SerialContains(cfg.SerialLogFile, needle)
			require.NoError(t, err)
			assert.True(t, found, "serial log lacks %q", needle)
		}
	})
}
