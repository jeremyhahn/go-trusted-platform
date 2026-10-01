package diskimage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/netboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// DefaultARM64IPXE is where `make ipxe-build` leaves the arm64 iPXE.
const DefaultARM64IPXE = "build/docker/ipxe-builder/output/bin-arm64-efi/snponly.efi"

type netbootFlags struct {
	mediaFlags
	output           string
	cacheDir         string
	x86BinariesDir   string
	arm64BinariesDir string
	ipxe             string
	model            string
	sets             []string
}

func newNetbootCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &netbootFlags{}
	cmd := &cobra.Command{
		Use:   "netboot",
		Short: "Build the netboot media the bootstrap container serves",
		Long: `Build a netboot media build (container.NetbootMedia) for the bootstrap
container: one media set per architecture and board — the x86_64 installer,
the Raspberry Pi installer and the arm64 (QEMU virt) installer — each its
install media, payload list and db-signed kernel, plus the Raspberry Pi TFTP
tree and the db-signed arm64 iPXE. Point bootstrap.yaml's
deployer.netboot_media_dir at the output.

The sets are served over the network, so they never carry a private key:
with Secure Boot on, the DB key must live in the control plane's KMS
(secure-boot.resign-mode: remote, kms:// references), which the build
reaches through the platform context (--context).

Examples:
  platformctl diskimage netboot --output bin/netboot-media
  platformctl diskimage netboot --sets aarch64-rpi --uboot-dir build/docker/uboot-builder/output`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNetboot(getFlags(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.output, "output", "", "Output directory, replaced (default <work-dir>/netboot-media)")
	f.StringVar(&flags.cacheDir, "cache-dir", "", "Alpine netboot release cache (default <output>.cache/alpine)")
	f.StringVar(&flags.x86BinariesDir, "x86-binaries-dir", "", "x86_64 platformd, platformctl, platformctl-static, platform-initrd, gatewayd (default: next to this binary)")
	f.StringVar(&flags.arm64BinariesDir, "arm64-binaries-dir", "", "arm64 binaries (default: aarch64/ next to this binary)")
	f.StringVar(&flags.ipxe, "ipxe", DefaultARM64IPXE, "The arm64 iPXE to sign (make ipxe-build)")
	f.StringVar(&flags.model, "model", rpi.DefaultModel, "Raspberry Pi board the TFTP tree's config.txt is written for: "+joinModels())
	f.StringSliceVar(&flags.sets, "sets", nil, "Media sets to build (default all: "+strings.Join(setNames(netboot.DefaultSets), ", ")+")")
	addMediaFlags(f, &flags.mediaFlags)
	return cmd
}

func setNames(sets []netboot.Set) []string {
	names := make([]string, 0, len(sets))
	for _, s := range sets {
		names = append(names, s.Name)
	}
	return names
}

// selectSets picks the named sets from the defaults, in their order.
func selectSets(names []string) ([]netboot.Set, error) {
	if len(names) == 0 {
		return netboot.DefaultSets, nil
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var sets []netboot.Set
	for _, s := range netboot.DefaultSets {
		if wanted[s.Name] {
			sets = append(sets, s)
			delete(wanted, s.Name)
		}
	}
	for n := range wanted {
		return nil, ErrUnknownMediaSet{Name: n, Known: setNames(netboot.DefaultSets)}
	}
	return sets, nil
}

func runNetboot(common *cli.CommonFlags, flags *netbootFlags) (err error) {
	logger := newLogger(flags.verbose, flags.debug)
	platformClient := cli.NewLazyClient(common)
	defer func() {
		if closeErr := platformClient.Close(); closeErr != nil && err == nil {
			err = ErrBuildFailed{Reason: "closing the platform connection: " + closeErr.Error()}
		}
	}()
	sets, err := selectSets(flags.sets)
	if err != nil {
		return err
	}
	isoBuild, err := flags.isoConfig("", "")
	if err != nil {
		return err
	}
	cfg := &netboot.Config{
		Build:     flags.imageBuild(isoBuild, platformClient, logger),
		Model:     flags.model,
		IPXEFile:  flags.ipxe,
		CacheDir:  flags.cacheDir,
		OutputDir: flags.output,
		Sets:      sets,
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = filepath.Join(flags.workDir, "netboot-media")
	}
	for _, s := range sets {
		switch s.Architecture {
		case ipxe.ArchitectureX86_64:
			if cfg.X86BinariesDir == "" {
				if cfg.X86BinariesDir, err = binariesDir(flags.x86BinariesDir, ""); err != nil {
					return err
				}
			}
		case ipxe.ArchitectureARM64:
			if cfg.ARM64BinariesDir == "" {
				if cfg.ARM64BinariesDir, err = binariesDir(flags.arm64BinariesDir, "aarch64"); err != nil {
					return err
				}
			}
		}
	}
	fmt.Printf("Building netboot media (%s) into %s\n  platform config: %s\n", strings.Join(setNames(sets), ", "), cfg.OutputDir, isoBuild.PlatformConfigFile)

	result, err := netboot.Build(context.Background(), cfg)
	if err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}
	fmt.Printf("\nNetboot media: %s\n  sets: %s\n", result.Dir, strings.Join(result.Sets, ", "))
	return nil
}
