package diskimage

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
)

func newInspectCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect IMAGE",
		Short: "Report an image's partitions, EFI partition contents and UKI",
		Long: `Inspect a factory disk image without mounting it.

Reads the MBR and the LUKS2 header in Go and lists the EFI partition with
mtools (mdir/mcopy must be installed), reporting the UKI's machine type and
whether it carries an Authenticode signature, whether tpm2/installer.luks is
still present (first boot not yet taken), and the Raspberry Pi config.txt.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := pkgdiskimage.Inspect(context.Background(), args[0], nil)
			if err != nil {
				return err
			}
			fmt.Print(report.String())
			return nil
		},
	}
}
