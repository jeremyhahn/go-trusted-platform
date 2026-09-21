//go:build integration

package diskimage

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
)

// Partition types and machine codes the images must carry.
const (
	mbrTypeFAT32LBA  = 0x0c
	mbrTypeLinux     = 0x83
	peMachineAArch64 = 0xaa64
)

// TestImageLayout checks what both images put on disk, before anything
// boots: the MBR the Raspberry Pi firmware reads, the FAT boot partition,
// the LUKS2 root, the signed aarch64 UKI, and the first-boot material.
func TestImageLayout(t *testing.T) {
	in := requireInputs(t)
	ctx := context.Background()

	t.Run("qemu-virt", func(t *testing.T) {
		report, err := pkgdiskimage.Inspect(ctx, in.image, nil)
		require.NoError(t, err)
		assertPlatformImage(t, report)
		assert.Empty(t, report.ConfigTxt, "the virt image has no Raspberry Pi config.txt")
	})

	t.Run("rpi", func(t *testing.T) {
		report, err := pkgdiskimage.Inspect(ctx, in.rpiImage, nil)
		require.NoError(t, err)
		assertPlatformImage(t, report)

		// The Raspberry Pi firmware reads these from the first FAT partition.
		for _, name := range []string{"config.txt", "kernel8.img", "start4.elf", "fixup4.dat", "bcm2711-rpi-4-b.dtb", "overlays/tpm-soft-spi.dtbo"} {
			assert.Contains(t, report.ESPFiles, name, "boot partition lacks %s", name)
		}
		for _, line := range []string{"arm_64bit=1", "enable_uart=1", "kernel=kernel8.img", "dtoverlay=tpm-soft-spi"} {
			assert.Contains(t, report.ConfigTxt, line)
		}
	})
}

// assertPlatformImage holds for every factory image regardless of target.
func assertPlatformImage(t *testing.T, r *pkgdiskimage.Report) {
	t.Helper()
	require.Len(t, r.Partitions, 2, "one boot partition and one root partition")
	assert.Equal(t, byte(mbrTypeFAT32LBA), r.Partitions[0].Type, "p1 is FAT32 (LBA) for the Raspberry Pi firmware")
	assert.True(t, r.Partitions[0].Bootable, "p1 carries the boot flag")
	assert.Equal(t, byte(mbrTypeLinux), r.Partitions[1].Type)
	assert.Greater(t, r.Partitions[0].SizeBytes(), int64(500<<20), "the boot partition holds the UKI and the firmware")
	require.NotNil(t, r.ESP)
	assert.True(t, r.LUKS2, "p2 is a LUKS2 volume")

	assert.Equal(t, "EFI/BOOT/BOOTAA64.EFI", r.UKIPath)
	assert.Equal(t, uint16(peMachineAArch64), r.UKIMachine)
	assert.True(t, r.UKISigned, "the UKI carries an Authenticode signature for the preseeded db")

	assert.True(t, r.InstallerLUKS, "tpm2/installer.luks is present until the first boot seals")
	assert.True(t, r.Provisioned, "the uboot firmware seam wrote the provisioned sentinel")
	assert.Contains(t, r.ESPFiles, "tpm2/pcr-banks")
	assert.NotContains(t, strings.Join(r.ESPFiles, "\n"), "luks-key", "no plaintext LUKS key may sit on the boot partition")
}
