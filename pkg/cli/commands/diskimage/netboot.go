package diskimage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	diskless         bool
	fleetKey         string
	fleetCert        string
	sourceDateEpoch  int64
	targetSoC        string
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

--diskless also packs the installed root of each installer set into a
dm-verity squashfs for nodes with boot_model: diskless, and signs its
manifest (root hash, salt, sizes) with the DB key; Secure Boot is required.
Every timestamp derives from --source-date-epoch (or SOURCE_DATE_EPOCH), so
two builds of the same inputs carry the same root hash.

With --fleet-key the build also makes the Raspberry Pi's HTTP boot files: boot.img
(the Pi boot partition as a FAT ramdisk), boot.sig (signed by the fleet key, an
RSA-2048 key held in the KMS, which is sent only a digest) and pubkey.bin. It
prints the OTP customer key hash to burn and the EEPROM's HTTP_HOST/HTTP_PATH.
Burning the hash into OTP is irreversible: see docs/factory-image/user.md.

Examples:
  platformctl diskimage netboot --output bin/netboot-media
  SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) platformctl diskimage netboot --diskless
  platformctl diskimage netboot --sets aarch64-rpi --uboot-dir build/docker/uboot-builder/output
  platformctl diskimage netboot --sets aarch64-rpi --fleet-key kms://rpi/fleet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNetboot(getFlags(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.output, "output", "", "Output directory, replaced (default <work-dir>/netboot-media)")
	f.StringVar(&flags.cacheDir, "cache-dir", "", "Alpine netboot release cache (default <output>.cache/alpine)")
	f.StringVar(&flags.x86BinariesDir, "x86-binaries-dir", "", "x86_64 platformd, platformctl, platform-initrd, gatewayd (default: next to this binary)")
	f.StringVar(&flags.arm64BinariesDir, "arm64-binaries-dir", "", "arm64 binaries (default: aarch64/ next to this binary)")
	f.StringVar(&flags.ipxe, "ipxe", DefaultARM64IPXE, "The arm64 iPXE to sign (make ipxe-build)")
	f.StringVar(&flags.model, "model", rpi.DefaultModel, "Raspberry Pi board the TFTP tree's config.txt is written for: "+joinModels())
	f.StringSliceVar(&flags.sets, "sets", nil, "Media sets to build (default all: "+strings.Join(setNames(netboot.DefaultSets), ", ")+")")
	f.BoolVar(&flags.diskless, "diskless", false, "Also build the signed dm-verity squashfs root diskless nodes boot (needs Secure Boot)")
	f.StringVar(&flags.fleetKey, "fleet-key", "", "kms:// reference of the RSA-2048 fleet key that signs the Raspberry Pi's HTTP boot.sig (turns HTTP boot on)")
	f.StringVar(&flags.fleetCert, "fleet-cert", "", "kms:// reference of the fleet key's certificate (default: the --fleet-key id); append #sha256=<fingerprint> to pin it")
	f.Int64Var(&flags.sourceDateEpoch, "source-date-epoch", -1, "Build time, as a Unix time: every timestamp of the diskless root (default: SOURCE_DATE_EPOCH) and boot.sig's ts (default: now)")
	f.StringVar(&flags.targetSoC, "target-soc", "", "optional boot.sig target-soc line (2711 or 2712); omitted by default")
	addMediaFlags(f, &flags.mediaFlags)
	return cmd
}

// resolveSourceDateEpoch is the diskless root's timestamp: the flag when
// given (>= 0), else the SOURCE_DATE_EPOCH environment value.
func resolveSourceDateEpoch(flag int64, env string) (int64, error) {
	if flag >= 0 {
		return flag, nil
	}
	if env == "" {
		return 0, ErrSourceDateEpoch{}
	}
	epoch, err := strconv.ParseInt(env, 10, 64)
	if err != nil || epoch < 0 {
		return 0, ErrSourceDateEpoch{Value: env}
	}
	return epoch, nil
}

// httpBootConfig is the HTTP boot configuration the flags ask for; nil without
// --fleet-key. --source-date-epoch also serves --diskless, so only without
// either does it need the fleet key.
func (f *netbootFlags) httpBootConfig() (*netboot.HTTPBoot, error) {
	if f.fleetKey == "" {
		needFleetKey := map[string]bool{
			"fleet-cert":        f.fleetCert != "",
			"source-date-epoch": f.sourceDateEpoch >= 0 && !f.diskless,
			"target-soc":        f.targetSoC != "",
		}
		for flag, set := range needFleetKey {
			if set {
				return nil, ErrHTTPBootFlags{Flag: flag}
			}
		}
		return nil, nil
	}
	h := &netboot.HTTPBoot{FleetKey: f.fleetKey, FleetCert: f.fleetCert, TargetSoC: f.targetSoC}
	if f.sourceDateEpoch >= 0 {
		h.Timestamp = time.Unix(f.sourceDateEpoch, 0)
	}
	return h, nil
}

func setNames(sets []netboot.Set) []string {
	names := make([]string, 0, len(sets))
	for _, s := range sets {
		names = append(names, s.Name)
	}
	return names
}

// selectSets picks the named sets from the defaults, in their order. With no
// names it returns none and leaves the default to netboot.Config.SetsToBuild,
// which drops the sets a --diskless build cannot produce.
func selectSets(names []string) ([]netboot.Set, error) {
	if len(names) == 0 {
		return nil, nil
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
	httpBoot, err := flags.httpBootConfig()
	if err != nil {
		return err
	}
	isoBuild, err := flags.isoConfig("", "")
	if err != nil {
		return err
	}
	cfg := &netboot.Config{
		HTTPBoot:  httpBoot,
		Build:     flags.imageBuild(isoBuild, platformClient, logger),
		Model:     flags.model,
		IPXEFile:  flags.ipxe,
		CacheDir:  flags.cacheDir,
		OutputDir: flags.output,
		Sets:      sets,
		Diskless:  flags.diskless,
		Version:   isoBuild.PlatformVersion,
	}
	sets = cfg.SetsToBuild()
	cfg.Sets = sets
	if flags.diskless {
		if cfg.SourceDateEpoch, err = resolveSourceDateEpoch(flags.sourceDateEpoch, os.Getenv("SOURCE_DATE_EPOCH")); err != nil {
			return err
		}
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
	if result.HTTPBoot != nil {
		fmt.Print(httpBootSummary(result))
	}
	return nil
}

// httpBootSummary is what an operator takes from an HTTP boot build: the OTP
// hash to burn and the EEPROM settings that find the files.
func httpBootSummary(result *netboot.Result) string {
	return fmt.Sprintf(`
HTTP boot (%s/%s):
  OTP customer key hash: %s
    Burning it into OTP is IRREVERSIBLE; see docs/factory-image/user.md first.
  EEPROM: HTTP_HOST=<the container's address> HTTP_PATH=%s SIGNED_BOOT=1
  boot.img: %d bytes
`, result.Dir, netboot.HTTPBootDir, result.HTTPBoot.KeyHashHex(), result.HTTPBootPath, result.HTTPBoot.ImageSize)
}
