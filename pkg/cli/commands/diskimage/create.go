package diskimage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mediaFlags are the inputs every image build shares — `create` and
// `netboot` alike: the ISO pipeline's media settings, the builder
// containers, and the U-Boot and virt-kernel builds.
type mediaFlags struct {
	builderImage          string
	builderDir            string
	containerRuntime      string
	ubootDir              string
	ubootBuilderDir       string
	ubootOutputDir        string
	ubootCacheVolume      string
	virtKernelDir         string
	virtKernelBuilderDir  string
	virtKernelOutputDir   string
	virtKernelCacheVolume string
	skipPreflight         bool

	platformVersion string
	alpineVersion   string
	mirror          string
	apkMirror       string
	platformAPKDir  string
	platformConfig  string
	overrides       string
	platformType    string
	secureBoot      bool
	tpmUnseal       bool
	luks            bool
	fido2           bool
	keysDir         string
	generateKeys    bool
	keyBackend      string
	caBundle        string
	caKeyAlgorithm  string
	webUI           string
	workDir         string
	preFetch        bool
	debug           bool
	verbose         bool
}

type createFlags struct {
	mediaFlags
	target      string
	model       string
	role        string
	sizeMB      int
	output      string
	binariesDir string
}

// defaultPlatformConfigPaths mirror `iso create`: the single-node template
// first. The Raspberry Pi template under templates/single-node/raspberrypi
// is preferred for the rpi target when it exists.
func defaultPlatformConfigPaths(target, model string) []string {
	paths := []string{}
	if target == rpi.Name {
		if model == "" {
			model = rpi.DefaultModel
		}
		paths = append(paths, filepath.Join("configs", "platform", "templates", "single-node", "raspberrypi", model, "default.yaml"))
	}
	return append(paths, "configs/platform/templates/single-node/default.yaml")
}

func newCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &createFlags{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Build a factory disk image",
		Long: `Build a factory disk image for a target device.

The build reuses the ISO pipeline for the install media (Alpine packages
pre-fetched for the target architecture, platform binaries, platform
configuration, Secure Boot keys, CA bundle) and runs the installer inside
an arm64 container against a loop-mounted image. U-Boot is built (or
located with --uboot-dir) with the Secure Boot keys preseeded.

Examples:
  # Raspberry Pi 4 image with the defaults
  platformctl diskimage create --target rpi --model rpi4 --output bin/trusted-platform-rpi.img

  # Raspberry Pi 4 compute node of the dedicated profile
  platformctl diskimage create --target rpi --model rpi4 --role compute --overrides node.yaml

  # QEMU virt stand-in for the integration tests
  platformctl diskimage create --target qemu-virt --output bin/trusted-platform-qemu.img

  # Reuse a U-Boot build and a custom platform config with overrides
  platformctl diskimage create --uboot-dir build/docker/uboot-builder/output \
    --platform-config configs/platform/templates/single-node/default.yaml --overrides node.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(getFlags(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.target, "target", pkgdiskimage.DefaultTarget, "Image target: rpi or qemu-virt")
	f.StringVar(&flags.model, "model", "", "Board model for the rpi target (default "+rpi.DefaultModel+"): "+joinModels())
	f.StringVar(&flags.role, "role", "", "Dedicated-profile role for the rpi target, built from dedicated/raspberrypi/<model>/<role>.yaml (compute on rpi4 and rpi5); empty builds the single-node image")
	f.IntVar(&flags.sizeMB, "size", pkgdiskimage.DefaultSizeMB, "Image size in MB")
	f.StringVar(&flags.output, "output", "", "Output image path (default <work-dir>/trusted-platform-<target>.img)")
	f.StringVar(&flags.binariesDir, "binaries-dir", "", "Directory holding the target-architecture platformd, platformctl, platformctl-static, platform-initrd and gatewayd (default: aarch64/ next to this binary)")
	addMediaFlags(f, &flags.mediaFlags)
	return cmd
}

// addMediaFlags registers the flags every image build shares.
func addMediaFlags(f *pflag.FlagSet, flags *mediaFlags) {
	f.StringVar(&flags.builderImage, "builder-image", pkgdiskimage.DefaultBuilderImage, "Builder (assemble) container image tag")
	f.StringVar(&flags.builderDir, "builder-dir", pkgdiskimage.DefaultBuilderDir, "Builder (assemble) container build context")
	f.StringVar(&flags.containerRuntime, "container-runtime", pkgdiskimage.DefaultContainerRuntime, "Container runtime binary")
	f.StringVar(&flags.ubootDir, "uboot-dir", "", "Prebuilt U-Boot artifacts (skips the U-Boot build)")
	f.StringVar(&flags.ubootBuilderDir, "uboot-builder-dir", pkgdiskimage.DefaultUBootBuilderDir, "U-Boot builder build context")
	f.StringVar(&flags.ubootOutputDir, "uboot-output-dir", "", "U-Boot builder output directory (default <uboot-builder-dir>/output)")
	f.StringVar(&flags.ubootCacheVolume, "uboot-cache-volume", "", "docker volume caching the U-Boot tarball (default trusted-platform-uboot-src)")
	f.StringVar(&flags.virtKernelDir, "virt-kernel-dir", "", "Prebuilt virt kernel artifacts for the qemu-virt target (skips the kernel build)")
	f.StringVar(&flags.virtKernelBuilderDir, "virt-kernel-builder-dir", pkgdiskimage.DefaultVirtKernelBuilderDir, "Virt kernel builder build context")
	f.StringVar(&flags.virtKernelOutputDir, "virt-kernel-output-dir", "", "Virt kernel builder output directory (default <virt-kernel-builder-dir>/output)")
	f.StringVar(&flags.virtKernelCacheVolume, "virt-kernel-cache-volume", "", "docker volume caching the kernel tarball (default trusted-platform-virt-kernel-src)")
	f.BoolVar(&flags.skipPreflight, "skip-preflight", false, "Skip the build-host checks (binfmt, container runtime, kernel modules)")

	f.StringVar(&flags.platformVersion, "platform-version", "", "Platform version baked into the media (default: the VERSION file, else dev)")
	f.StringVar(&flags.alpineVersion, "alpine-version", "3.22.2", "Alpine Linux version")
	f.StringVar(&flags.mirror, "mirror", "http://mirror.cs.odu.edu/alpine", "Alpine Linux mirror URL (build-time pre-fetch source)")
	f.StringVar(&flags.apkMirror, "apk-mirror", "", "Install-time APK mirror base URL baked into the kernel cmdline")
	f.StringVar(&flags.platformAPKDir, "platform-apk-dir", "", "strongSwan builder output (make strongswan-build) whose apks the media carries and installs for the overlay's IPsec transport")
	f.StringVar(&flags.platformConfig, "platform-config", "", "Path to the platform config template baked into the media (auto-detected)")
	f.StringVar(&flags.overrides, "overrides", "", "Path to override YAML (deep-merged onto --platform-config)")
	f.StringVar(&flags.platformType, "platform-type", "server", "Platform type: 'server' or 'client'")
	f.BoolVar(&flags.secureBoot, "secure-boot", true, "Enable Secure Boot (keys are preseeded into U-Boot)")
	f.BoolVar(&flags.tpmUnseal, "tpm-unseal", true, "Enable TPM auto-unseal")
	f.BoolVar(&flags.luks, "luks", true, "Enable LUKS encryption")
	f.BoolVar(&flags.fido2, "fido2", false, "Enable FIDO2 security key support")
	f.StringVar(&flags.keysDir, "keys-dir", "", "Secure Boot keys directory (PK/KEK/DB) for references that are not kms://")
	f.BoolVar(&flags.generateKeys, "generate-keys", true, "Generate Secure Boot keys if they don't exist")
	f.StringVar(&flags.keyBackend, "key-backend", "file", "Secure Boot key backend: file, software, pkcs11, tpm2, awskms, azurekv, gcpkms, vault")
	f.StringVar(&flags.caBundle, "ca-bundle", "", "CA bundle PEM to embed for the client trust store")
	f.StringVar(&flags.caKeyAlgorithm, "ca-key-algorithm", "", "CA key algorithm filter (rsa, ecdsa, ed25519); empty = all")
	f.StringVar(&flags.webUI, "webui", "", "Path to the web UI directory or tarball")
	f.StringVar(&flags.workDir, "work-dir", "work", "Working directory")
	f.BoolVar(&flags.preFetch, "pre-fetch", true, "Pre-download every package into the media (required: the container installs offline)")
	f.BoolVar(&flags.debug, "debug", false, "Enable debug output")
	f.BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")
}

func joinModels() string {
	out := ""
	for i, name := range rpi.Models() {
		if i > 0 {
			out += ", "
		}
		out += name
		if m, err := rpi.LookupModel(name); err == nil && m.Experimental {
			out += " (experimental)"
		}
	}
	return out
}

func newLogger(verbose, debug bool) *logging.Logger {
	level := slog.LevelWarn
	if debug {
		level = slog.LevelDebug
	} else if verbose {
		level = slog.LevelInfo
	}
	return logging.NewLogger(level, nil)
}

// isoConfig turns the shared flags into the ISO build configuration; the
// platform config defaults to the template for target and model.
func (m *mediaFlags) isoConfig(target, model string) (*pkgiso.ISOBuildConfig, error) {
	cfg := pkgiso.DefaultISOBuildConfig()
	cfg.PlatformVersion = m.platformVersion
	if cfg.PlatformVersion == "" {
		cfg.PlatformVersion = pkgiso.ReadVersionFile()
	}
	cfg.AlpineVersion = m.alpineVersion
	cfg.AlpineMirror = m.mirror
	cfg.APKMirror = m.apkMirror
	cfg.PlatformAPKDir = m.platformAPKDir
	cfg.PlatformType = pkgiso.PlatformType(m.platformType)
	cfg.SecureBoot = m.secureBoot
	cfg.GenerateKeys = m.generateKeys
	cfg.KeyBackend = m.keyBackend
	cfg.TPMAutoUnseal = m.tpmUnseal
	cfg.LUKSTPMOnly = m.luks
	cfg.EnableFIDO2 = m.fido2
	cfg.Debug = m.debug
	cfg.PreFetch = m.preFetch
	cfg.WorkDir = m.workDir
	cfg.KeysDir = m.keysDir
	cfg.CABundlePath = m.caBundle
	cfg.CAKeyAlgorithm = m.caKeyAlgorithm
	cfg.WebUIPath = m.webUI
	if err := cfg.ValidatePlatformAPKDir(); err != nil {
		return nil, err
	}

	platformConfig := m.platformConfig
	if platformConfig == "" {
		for _, p := range defaultPlatformConfigPaths(target, model) {
			if _, err := os.Stat(p); err == nil {
				platformConfig = p
				break
			}
		}
	}
	if m.overrides != "" {
		merged, err := mergeOverrides(platformConfig, m.overrides)
		if err != nil {
			return nil, err
		}
		platformConfig = merged
	}
	cfg.PlatformConfigFile = platformConfig
	return cfg, nil
}

// imageBuild is the image build configuration the shared flags describe.
func (m *mediaFlags) imageBuild(iso *pkgiso.ISOBuildConfig, platformClient *cli.LazyClient, logger *logging.Logger) *pkgdiskimage.BuildConfig {
	return &pkgdiskimage.BuildConfig{
		ISO:                   iso,
		VirtKernelDir:         m.virtKernelDir,
		VirtKernelBuilderDir:  m.virtKernelBuilderDir,
		VirtKernelOutputDir:   m.virtKernelOutputDir,
		VirtKernelCacheVolume: m.virtKernelCacheVolume,
		ContainerRuntime:      m.containerRuntime,
		BuilderImage:          m.builderImage,
		BuilderDir:            m.builderDir,
		UBootBuilderDir:       m.ubootBuilderDir,
		UBootOutputDir:        m.ubootOutputDir,
		UBootDir:              m.ubootDir,
		UBootCacheVolume:      m.ubootCacheVolume,
		KMSClients:            kmsClients(platformClient),
		Logger:                logger,
		SkipPreflight:         m.skipPreflight,
	}
}

// binariesDir resolves a binaries directory: dir when given, else sub next
// to this binary ("" for the directory itself). It must hold platformd.
func binariesDir(dir, sub string) (string, error) {
	if dir == "" {
		self, err := os.Executable()
		if err != nil {
			return "", ErrBuildFailed{Reason: "cannot resolve the running binary: " + err.Error()}
		}
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		dir = filepath.Join(filepath.Dir(self), sub)
	}
	if _, err := os.Stat(filepath.Join(dir, "platformd")); err != nil {
		return "", ErrBinariesNotFound{Dir: dir}
	}
	return dir, nil
}

// buildConfig turns create's flags into the ISO build configuration with
// its target-architecture binaries.
// hostInstallerBinary is the host-architecture platformctl-static that sits
// beside the running platformctl; a foreign-architecture image build runs the
// installer with it so LUKS and the filesystems are native (#802).
func hostInstallerBinary() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", ErrBuildFailed{Reason: "cannot resolve the running binary: " + err.Error()}
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	path := filepath.Join(filepath.Dir(self), "platformctl-static")
	if _, err := os.Stat(path); err != nil {
		// Only a foreign-architecture build needs it; Create reports it then.
		return "", nil
	}
	return path, nil
}

func buildConfig(flags *createFlags) (*pkgiso.ISOBuildConfig, error) {
	if flags.role != "" {
		path, err := roleTemplate(flags.target, flags.model, flags.role, flags.platformConfig)
		if err != nil {
			return nil, err
		}
		flags.platformConfig = path
	}
	cfg, err := flags.isoConfig(flags.target, flags.model)
	if err != nil {
		return nil, err
	}
	binDir, err := binariesDir(flags.binariesDir, "aarch64")
	if err != nil {
		return nil, err
	}
	cfg.PlatformdBinary = filepath.Join(binDir, "platformd")
	return cfg, nil
}

// roleTemplate returns the dedicated-profile template a --role build uses,
// dedicated/raspberrypi/<model>/<role>.yaml. Unlike the single-node default
// there is no fallback: a role without a template is refused, never built
// as a single-node image.
func roleTemplate(target, model, role, platformConfig string) (string, error) {
	if model == "" {
		model = rpi.DefaultModel
	}
	refuse := func(reason string) (string, error) {
		return "", ErrRoleTemplate{Target: target, Model: model, Role: role, Reason: reason}
	}
	if platformConfig != "" {
		return refuse("--platform-config already chooses the template; pass one of them")
	}
	if target != rpi.Name {
		return refuse("dedicated roles are built for the " + rpi.Name + " target only")
	}
	// The model names the template directory, so only a board the image
	// builder knows may reach the path.
	if _, err := rpi.LookupModel(model); err != nil {
		return refuse(err.Error())
	}
	path := filepath.Join("configs", "platform", "templates", "dedicated", "raspberrypi", model, role+".yaml")
	if _, err := os.Stat(path); err != nil {
		return refuse("no template: " + err.Error())
	}
	return path, nil
}

func runCreate(common *cli.CommonFlags, flags *createFlags) (err error) {
	logger := newLogger(flags.verbose, flags.debug)
	platformClient := cli.NewLazyClient(common)
	defer func() {
		if closeErr := platformClient.Close(); closeErr != nil && err == nil {
			err = ErrBuildFailed{Reason: "closing the platform connection: " + closeErr.Error()}
		}
	}()
	cfg, err := buildConfig(flags)
	if err != nil {
		return err
	}
	fmt.Printf("Building %s image (model %q, %d MB)\n", flags.target, flags.model, flags.sizeMB)
	fmt.Printf("  platform config: %s\n  binaries: %s\n  work dir: %s\n", cfg.PlatformConfigFile, filepath.Dir(cfg.PlatformdBinary), cfg.WorkDir)

	build := flags.imageBuild(cfg, platformClient, logger)
	build.Target = flags.target
	build.Model = flags.model
	build.SizeMB = flags.sizeMB
	build.Output = flags.output
	build.BinariesDir = filepath.Dir(cfg.PlatformdBinary)
	if build.HostInstallerBinary, err = hostInstallerBinary(); err != nil {
		return err
	}
	result, err := pkgdiskimage.Create(context.Background(), build)
	if err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}
	fmt.Printf("\nImage: %s\n  SHA256: %s\n  Size: %d MB\n  U-Boot: %s\n  Media: %s\n", result.Image, result.SHA256, result.SizeBytes/(1024*1024), result.UBoot.Binary, result.MediaDir)
	return nil
}

// kmsClients reaches kms:// Secure Boot references through the operator's
// platform client, connecting only when a build needs one.
func kmsClients(client *cli.LazyClient) pkgiso.KMSClientsFunc {
	return func() (*pkgiso.KMSClients, error) {
		cl, err := client.Client()
		if err != nil {
			return nil, err
		}
		return &pkgiso.KMSClients{KMS: cl.KMS(), CA: cl.CA()}, nil
	}
}
