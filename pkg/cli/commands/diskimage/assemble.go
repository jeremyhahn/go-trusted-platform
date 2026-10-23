package diskimage

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

type assembleFlags struct {
	config         string
	platformConfig string
	output         string
	sizeMB         int
	debug          bool
}

func newAssembleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &assembleFlags{}
	cmd := &cobra.Command{
		Use:    "assemble",
		Short:  "Run the installer against a loop-mounted image (in-container step of create)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAssemble(getFlags(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.config, "config", "", "Installer configuration YAML (installer.Config)")
	f.StringVar(&flags.platformConfig, "platform-config", "", "Platform configuration YAML, converted the way the live installer converts it")
	f.StringVar(&flags.output, "output", "", "Image path to create")
	f.IntVar(&flags.sizeMB, "size", pkgdiskimage.DefaultSizeMB, "Image size in MB")
	f.BoolVar(&flags.debug, "debug", false, "Enable debug output")
	return cmd
}

// loadInstallerConfig loads exactly one of the two configuration forms.
func loadInstallerConfig(flags *assembleFlags) (*installer.Config, error) {
	switch {
	case flags.config != "" && flags.platformConfig != "", flags.config == "" && flags.platformConfig == "":
		return nil, ErrConfigRequired{}
	case flags.config != "":
		cfg, err := installer.LoadConfig(flags.config)
		if err != nil {
			return nil, ErrConfigLoadFailed{Path: flags.config, Err: err}
		}
		return cfg, nil
	default:
		data, err := os.ReadFile(flags.platformConfig)
		if err != nil {
			return nil, ErrConfigLoadFailed{Path: flags.platformConfig, Err: err}
		}
		if err := app.CheckPlatformConfigYAML(data); err != nil {
			return nil, ErrConfigLoadFailed{Path: flags.platformConfig, Err: err}
		}
		var platform app.App
		if err := config.DecodeYAML(data, &platform); err != nil {
			return nil, ErrConfigLoadFailed{Path: flags.platformConfig, Err: err}
		}
		cfg, err := platform.GetInstallerConfig()
		if err != nil {
			return nil, ErrConfigLoadFailed{Path: flags.platformConfig, Err: err}
		}
		return cfg, nil
	}
}

func runAssemble(_ *cli.CommonFlags, flags *assembleFlags) error {
	cfg, err := loadInstallerConfig(flags)
	if err != nil {
		return err
	}
	cfg.Debug = cfg.Debug || flags.debug
	result, err := pkgdiskimage.Assemble(context.Background(), pkgdiskimage.AssembleOptions{
		Config: cfg,
		Output: flags.output,
		SizeMB: flags.sizeMB,
		Logger: newLogger(true, flags.debug),
	})
	if err != nil {
		return err
	}
	fmt.Printf("Assembled %s (%d MB) via %s\n", result.Image, result.SizeBytes/(1024*1024), result.LoopDevice)
	return nil
}
