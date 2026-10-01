package diskimage

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
)

type netbootInitfsFlags struct {
	modules, release, flavour, output string
}

// newNetbootInitfsCommand is the in-container step of a netboot media build
// for a platform-built kernel: it runs in the arm64 builder container
// (pkg/diskimage StagedMedia.BuildNetbootInitfs), never on the host.
func newNetbootInitfsCommand(_ func() *cli.CommonFlags) *cobra.Command {
	flags := &netbootInitfsFlags{}
	cmd := &cobra.Command{
		Use:    "netboot-initfs",
		Short:  "Generate a netboot initramfs and modloop for a platform-built kernel (in-container step of the netboot media build)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNetbootInitfs(cmd.Context(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.modules, "modules", "", "The kernel's modules tarball (lib/modules/<release>)")
	f.StringVar(&flags.release, "release", "", "The kernel release")
	f.StringVar(&flags.flavour, "flavour", "", "The kernel flavour, naming initramfs-<flavour> and modloop-<flavour>")
	f.StringVar(&flags.output, "output", "", "Directory receiving both")
	return cmd
}

func runNetbootInitfs(ctx context.Context, flags *netbootInitfsFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := pkgdiskimage.GenerateNetbootInitfs(ctx, pkgdiskimage.NetbootInitfsOptions{
		Modules:   flags.modules,
		Release:   flags.release,
		Flavour:   flags.flavour,
		OutputDir: flags.output,
	}); err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}
	return nil
}
