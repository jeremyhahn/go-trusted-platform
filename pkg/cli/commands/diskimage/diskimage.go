// Package diskimage is the `platformctl diskimage` command group: build,
// assemble (inside the builder container) and inspect factory disk images
// of the trusted platform, starting with the Raspberry Pi SD-card image.
package diskimage

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the diskimage root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diskimage",
		Short: "Factory disk images (Raspberry Pi SD card, QEMU virt)",
		Long: `Build factory disk images of the Trusted Platform.

Unlike the ISO, which installs the platform on the machine it boots on, a
factory image is produced on a build host: the installer runs inside an
arm64 container against a loop-mounted image, and the device's first boot
is the same first-boot provisioning the ISO install produces (TPM
provisioning, LUKS sealing, platformd enrollment and attestation).

  create   - build an image (U-Boot, media staging, container assemble)
  inspect  - report an image's partitions, EFI partition and UKI
  test     - boot an image under QEMU with a software TPM
  assemble - the in-container step create runs (not for direct use)

Targets:
  rpi        Raspberry Pi SD-card image (models: rpi4, rpi400, cm4, rpi3b+, rpi5)
  qemu-virt  the QEMU virt stand-in the integration tests boot`,
	}
	cmd.AddCommand(newCreateCommand(getFlags))
	cmd.AddCommand(newInspectCommand(getFlags))
	cmd.AddCommand(newTestCommand(getFlags))
	cmd.AddCommand(newAssembleCommand(getFlags))
	return cmd
}
