//go:build integration

package diskimage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// Serial milestones of a first boot, in order, as the guest prints them
// (read from a real transcript on 2026-09-20). Each one names the stage
// that produced it, so a timeout says where the chain stopped.
var firstBootMilestones = []string{
	"U-Boot 20",        // U-Boot banner
	"Booting bootflow", // U-Boot's standard boot found the ESP's bootflow (efi_mgr)
	"EFI stub: Measured initrd data into PCR 9",                         // the kernel inside the UKI verified; its EFI stub runs
	"EFI stub: UEFI Secure Boot is enabled.",                            // the stub sees the preseeded Secure Boot state
	"Linux version",                                                     // the kernel
	"dracut: PLATFORMD: Detected FIRSTBOOT mode",                        // platform-initrd found installer.luks on the ESP
	"Installer unlocked successfully",                                   // go-luks2 opened the installer container
	"Successfully unlocked with strategy",                               // the root volume is open
	"Starting firstboot TPM sealing workflow",                           // platformctl firstboot, after switch_root (ttyAMA0 is /dev/console on the stand-in)
	"Platform provisioned inside encrypted installer",                   // EK, SSRK, platform policy, IAK and the Platform SRK exist
	"LUKS key sealed to TPM with PCR policy",                            // the sealed blobs are on the ESP
	"installer container preserved pending next-boot unseal validation", // the seal-confirmation handshake (docs/bootstrap/architecture.md)
	"Seal staged on EFI partition",                                      // the seal service wrote its flags after platformctl firstboot returned
	"login:",                                                            // OpenRC's default runlevel finished, platformd included; the disk is quiescent
}

// secondBootMilestones prove the second boot unseals against the PCRs
// the first boot sealed to, without any fallback — TPM-PCR is attempt 1
// and it succeeds — and that this proof consumes the seal-confirmation
// handshake: installer.luks was still on the ESP (FIRSTBOOT mode is
// detected once more), and platform-initrd wipes it before switch_root.
// What must not happen is the keyfile being the strategy that unlocked.
var secondBootMilestones = []string{
	"U-Boot 20",
	"Booting bootflow",
	"Linux version",
	"Detected FIRSTBOOT mode",
	"Successfully unlocked with strategy: TPM-PCR",
	"Attempt 1: TPM-PCR - SUCCESS",
	"Boot sequence completed",
	"Seal confirmed by TPM-PCR unlock",
	"installer.luks securely wiped",
	"login:", // the system is up and the ESP quiescent before the disk is reused
}

// thirdBootMilestones prove the lifecycle is complete: no installer
// container, so no FIRSTBOOT mode, and the root still unlocks with
// TPM-PCR from the seal alone.
var thirdBootMilestones = []string{
	"U-Boot 20",
	"Linux version",
	"installer.luks not present",
	"Successfully unlocked with strategy: TPM-PCR",
	"Boot sequence completed",
}

// Timeouts under TCG emulation on a development host. The first boot
// provisions the TPM and seals; the second only unseals.
const (
	firstBootTimeout  = 45 * time.Minute
	secondBootTimeout = 20 * time.Minute
)

// TestFirstBoot boots the qemu-virt image once through firstboot sealing
// and then boots the same disk with the same TPM state a second time and
// expects the PCR-sealed unlock. It fails at the first milestone the guest
// does not print, and the failure carries the tail of the transcript.
func TestFirstBoot(t *testing.T) {
	in := requireInputs(t)
	workDir := filepath.Join(in.workDir, "firstboot")
	logger := logging.DefaultLogger()

	firstLog := filepath.Join(workDir, "boot1.log")
	t.Run("first boot provisions and seals", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), firstBootTimeout)
		defer cancel()
		last := firstBootMilestones[len(firstBootMilestones)-1]
		result, err := pkgdiskimage.Boot(ctx, pkgdiskimage.BootOptions{
			Image:        in.image,
			Firmware:     in.uboot,
			WorkDir:      workDir,
			SerialLog:    firstLog,
			Expect:       last,
			PortForwards: []qemu.PortForward{{HostPort: 18443, GuestPort: 8443, Protocol: "tcp"}},
			Logger:       logger,
		})
		if err != nil {
			t.Fatalf("first boot: %v\n%s", err, harness.MissingMilestone(firstLog, firstBootMilestones))
		}
		require.True(t, result.Expected)
		assert.Equal(t, harness.TPMStateInitialized, result.TPMState, "the first boot starts from fresh TPM state")
		for _, m := range firstBootMilestones {
			found, err := harness.SerialContains(firstLog, m)
			require.NoError(t, err)
			assert.True(t, found, "milestone %q missing from the first boot", m)
		}
		for _, bad := range []string{"Image not authenticated", "Security violation", "Synchronous Abort", "Kernel panic", "falling back to manual entry"} {
			found, err := harness.SerialContains(firstLog, bad)
			require.NoError(t, err)
			assert.False(t, found, "the first boot printed %q", bad)
		}
	})

	t.Run("second boot unseals against the PCRs", func(t *testing.T) {
		if t.Failed() {
			t.Fatal("the first boot did not complete; the second cannot unseal")
		}
		ctx, cancel := context.WithTimeout(context.Background(), secondBootTimeout)
		defer cancel()
		secondLog := filepath.Join(workDir, "boot2.log")
		result, err := pkgdiskimage.Boot(ctx, pkgdiskimage.BootOptions{
			Image:     filepath.Join(workDir, "disk.img"),
			InPlace:   true, // the disk the first boot sealed
			Firmware:  in.uboot,
			WorkDir:   workDir, // the same TPM state
			SerialLog: secondLog,
			Expect:    secondBootMilestones[len(secondBootMilestones)-1],
			Logger:    logger,
		})
		if err != nil {
			t.Fatalf("second boot: %v\n%s", err, harness.MissingMilestone(secondLog, secondBootMilestones))
		}
		require.True(t, result.Expected)
		assert.Equal(t, harness.TPMStatePreserved, result.TPMState, "the second boot must reuse the first boot's TPM state")
		for _, m := range secondBootMilestones {
			found, err := harness.SerialContains(secondLog, m)
			require.NoError(t, err)
			assert.True(t, found, "milestone %q missing from the second boot", m)
		}
		found, err := harness.SerialContains(secondLog, "Successfully unlocked with strategy: Keyfile")
		require.NoError(t, err)
		assert.False(t, found, "the second boot must not fall back to the installer keyfile")
	})

	t.Run("third boot has no installer container and still unseals", func(t *testing.T) {
		if t.Failed() {
			t.Fatal("the second boot did not complete; the third proves nothing")
		}
		ctx, cancel := context.WithTimeout(context.Background(), secondBootTimeout)
		defer cancel()
		thirdLog := filepath.Join(workDir, "boot3.log")
		result, err := pkgdiskimage.Boot(ctx, pkgdiskimage.BootOptions{
			Image:     filepath.Join(workDir, "disk.img"),
			InPlace:   true,
			Firmware:  in.uboot,
			WorkDir:   workDir,
			SerialLog: thirdLog,
			Expect:    thirdBootMilestones[len(thirdBootMilestones)-1],
			Logger:    logger,
		})
		if err != nil {
			t.Fatalf("third boot: %v\n%s", err, harness.MissingMilestone(thirdLog, thirdBootMilestones))
		}
		require.True(t, result.Expected)
		for _, m := range thirdBootMilestones {
			found, err := harness.SerialContains(thirdLog, m)
			require.NoError(t, err)
			assert.True(t, found, "milestone %q missing from the third boot", m)
		}
		found, err := harness.SerialContains(thirdLog, "Detected FIRSTBOOT mode")
		require.NoError(t, err)
		assert.False(t, found, "installer.luks must be gone after the confirmed seal")
	})
}
