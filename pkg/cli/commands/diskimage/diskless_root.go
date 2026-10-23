package diskimage

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
)

type disklessRootFlags struct {
	assembleFlags
	workDir         string
	salt            string
	sourceDateEpoch int64
}

// newDisklessRootCommand is the in-container step of a diskless netboot media
// build: it runs in the builder container, never on the host. It installs the
// media's platform onto a scratch image and packs the installed root into the
// squashfs and dm-verity hash tree; the host signs the manifest.
func newDisklessRootCommand(_ func() *cli.CommonFlags) *cobra.Command {
	flags := &disklessRootFlags{}
	cmd := &cobra.Command{
		Use:    "diskless-root",
		Short:  "Build the diskless squashfs root and dm-verity hash tree (in-container step of the netboot media build)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDisklessRoot(cmd.Context(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.config, "config", "", "Installer configuration YAML")
	f.StringVar(&flags.platformConfig, "platform-config", "", "Platform config YAML whose installer section configures the install")
	f.IntVar(&flags.sizeMB, "size", 0, "Scratch image size in MB")
	f.StringVar(&flags.workDir, "work-dir", "", "Directory for the scratch image and its mount point")
	f.StringVar(&flags.output, "output", "", "Directory receiving rootfs.squashfs, rootfs.verity and rootfs.roothash")
	f.Int64Var(&flags.sourceDateEpoch, "source-date-epoch", 0, "SOURCE_DATE_EPOCH: every timestamp in the squashfs")
	f.StringVar(&flags.salt, "salt", "", "dm-verity salt (64 hex characters)")
	f.BoolVar(&flags.debug, "debug", false, "Install a debug build")
	return cmd
}

func runDisklessRoot(ctx context.Context, flags *disklessRootFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadInstallerConfig(&flags.assembleFlags)
	if err != nil {
		return err
	}
	cfg.Debug = cfg.Debug || flags.debug
	root, err := pkgdiskimage.GenerateDisklessRoot(ctx, pkgdiskimage.DisklessRootOptions{
		Config:          cfg,
		SizeMB:          flags.sizeMB,
		WorkDir:         flags.workDir,
		OutputDir:       flags.output,
		SourceDateEpoch: flags.sourceDateEpoch,
		Salt:            flags.salt,
		Logger:          newLogger(true, flags.debug),
	})
	if err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}
	fmt.Printf("Diskless root %s (root hash %s)\n", root.RootFS, root.Manifest.RootHash)
	return nil
}
