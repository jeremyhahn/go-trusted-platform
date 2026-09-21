package diskimage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type createFlags struct {
	target               string
	model                string
	sizeMB               int
	output               string
	binariesDir          string
	builderImage         string
	builderDir           string
	containerRuntime     string
	ubootDir             string
	ubootBuilderDir      string
	ubootOutputDir       string
	virtKernelDir        string
	virtKernelBuilderDir string
	virtKernelOutputDir  string
	virtKernelCacheDir   string
	ubootCacheDir        string
	skipPreflight        bool

	platformVersion string
	alpineVersion   string
	mirror          string
	apkMirror       string
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
	f.IntVar(&flags.sizeMB, "size", pkgdiskimage.DefaultSizeMB, "Image size in MB")
	f.StringVar(&flags.output, "output", "", "Output image path (default <work-dir>/trusted-platform-<target>.img)")
	f.StringVar(&flags.binariesDir, "binaries-dir", "", "Directory holding the target-architecture platformd, platformctl, platformctl-static, platform-initrd and gatewayd (default: aarch64/ next to this binary)")
	f.StringVar(&flags.builderImage, "builder-image", pkgdiskimage.DefaultBuilderImage, "Assemble container image tag")
	f.StringVar(&flags.builderDir, "builder-dir", pkgdiskimage.DefaultBuilderDir, "Assemble container build context")
	f.StringVar(&flags.containerRuntime, "container-runtime", pkgdiskimage.DefaultContainerRuntime, "Container runtime binary")
	f.StringVar(&flags.ubootDir, "uboot-dir", "", "Prebuilt U-Boot artifacts (skips the U-Boot build)")
	f.StringVar(&flags.ubootBuilderDir, "uboot-builder-dir", pkgdiskimage.DefaultUBootBuilderDir, "U-Boot builder build context")
	f.StringVar(&flags.ubootOutputDir, "uboot-output-dir", "", "U-Boot builder output directory (default <uboot-builder-dir>/output)")
	f.StringVar(&flags.ubootCacheDir, "uboot-cache-dir", "", "U-Boot tarball cache directory")
	f.StringVar(&flags.virtKernelDir, "virt-kernel-dir", "", "Prebuilt virt kernel artifacts for the qemu-virt target (skips the kernel build)")
	f.StringVar(&flags.virtKernelBuilderDir, "virt-kernel-builder-dir", pkgdiskimage.DefaultVirtKernelBuilderDir, "Virt kernel builder build context")
	f.StringVar(&flags.virtKernelOutputDir, "virt-kernel-output-dir", "", "Virt kernel builder output directory (default <virt-kernel-builder-dir>/output)")
	f.StringVar(&flags.virtKernelCacheDir, "virt-kernel-cache-dir", "", "Kernel tarball cache directory")
	f.BoolVar(&flags.skipPreflight, "skip-preflight", false, "Skip the build-host checks (binfmt, container runtime, kernel modules)")

	f.StringVar(&flags.platformVersion, "platform-version", "", "Platform version baked into the image (default: the VERSION file, else dev)")
	f.StringVar(&flags.alpineVersion, "alpine-version", "3.22.2", "Alpine Linux version")
	f.StringVar(&flags.mirror, "mirror", "http://mirror.cs.odu.edu/alpine", "Alpine Linux mirror URL (build-time pre-fetch source)")
	f.StringVar(&flags.apkMirror, "apk-mirror", "", "Install-time APK mirror base URL baked into the kernel cmdline")
	f.StringVar(&flags.platformConfig, "platform-config", "", "Path to the platform config template baked into the image (auto-detected)")
	f.StringVar(&flags.overrides, "overrides", "", "Path to override YAML (deep-merged onto --platform-config)")
	f.StringVar(&flags.platformType, "platform-type", "server", "Platform type: 'server' or 'client'")
	f.BoolVar(&flags.secureBoot, "secure-boot", true, "Enable Secure Boot (keys are preseeded into U-Boot)")
	f.BoolVar(&flags.tpmUnseal, "tpm-unseal", true, "Enable TPM auto-unseal")
	f.BoolVar(&flags.luks, "luks", true, "Enable LUKS encryption")
	f.BoolVar(&flags.fido2, "fido2", false, "Enable FIDO2 security key support")
	f.StringVar(&flags.keysDir, "keys-dir", "", "Secure Boot keys directory (PK/KEK/DB)")
	f.BoolVar(&flags.generateKeys, "generate-keys", true, "Generate Secure Boot keys if they don't exist")
	f.StringVar(&flags.keyBackend, "key-backend", "file", "Secure Boot key backend: file, software, pkcs11, tpm2, awskms, azurekv, gcpkms, vault")
	f.StringVar(&flags.caBundle, "ca-bundle", "", "CA bundle PEM to embed for the client trust store")
	f.StringVar(&flags.caKeyAlgorithm, "ca-key-algorithm", "", "CA key algorithm filter (rsa, ecdsa, ed25519); empty = all")
	f.StringVar(&flags.webUI, "webui", "", "Path to the web UI directory or tarball")
	f.StringVar(&flags.workDir, "work-dir", "work", "Working directory")
	f.BoolVar(&flags.preFetch, "pre-fetch", true, "Pre-download every package into the media (required: the container installs offline)")
	f.BoolVar(&flags.debug, "debug", false, "Enable debug output")
	f.BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")
	return cmd
}

func joinModels() string {
	out := ""
	for i, m := range rpi.Models() {
		if i > 0 {
			out += ", "
		}
		out += m
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

// buildConfig turns the flags into the shared ISO build configuration.
func buildConfig(flags *createFlags) (*pkgiso.ISOBuildConfig, error) {
	cfg := pkgiso.DefaultISOBuildConfig()
	cfg.PlatformVersion = flags.platformVersion
	if cfg.PlatformVersion == "" {
		cfg.PlatformVersion = pkgiso.ReadVersionFile()
	}
	cfg.AlpineVersion = flags.alpineVersion
	cfg.AlpineMirror = flags.mirror
	cfg.APKMirror = flags.apkMirror
	cfg.PlatformType = pkgiso.PlatformType(flags.platformType)
	cfg.SecureBoot = flags.secureBoot
	cfg.GenerateKeys = flags.generateKeys
	cfg.KeyBackend = flags.keyBackend
	cfg.TPMAutoUnseal = flags.tpmUnseal
	cfg.LUKSTPMOnly = flags.luks
	cfg.EnableFIDO2 = flags.fido2
	cfg.Debug = flags.debug
	cfg.PreFetch = flags.preFetch
	cfg.WorkDir = flags.workDir
	cfg.KeysDir = flags.keysDir
	cfg.CABundlePath = flags.caBundle
	cfg.CAKeyAlgorithm = flags.caKeyAlgorithm
	cfg.WebUIPath = flags.webUI

	platformConfig := flags.platformConfig
	if platformConfig == "" {
		for _, p := range defaultPlatformConfigPaths(flags.target, flags.model) {
			if _, err := os.Stat(p); err == nil {
				platformConfig = p
				break
			}
		}
	}
	if flags.overrides != "" {
		merged, err := mergeOverrides(platformConfig, flags.overrides)
		if err != nil {
			return nil, err
		}
		platformConfig = merged
	}
	cfg.PlatformConfigFile = platformConfig

	binDir := flags.binariesDir
	if binDir == "" {
		self, err := os.Executable()
		if err != nil {
			return nil, ErrBuildFailed{Reason: "cannot resolve the running binary: " + err.Error()}
		}
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		binDir = filepath.Join(filepath.Dir(self), "aarch64")
	}
	if _, err := os.Stat(filepath.Join(binDir, "platformd")); err != nil {
		return nil, ErrBinariesNotFound{Dir: binDir}
	}
	cfg.PlatformdBinary = filepath.Join(binDir, "platformd")
	return cfg, nil
}

func runCreate(_ *cli.CommonFlags, flags *createFlags) error {
	logger := newLogger(flags.verbose, flags.debug)
	cfg, err := buildConfig(flags)
	if err != nil {
		return err
	}
	fmt.Printf("Building %s image (model %q, %d MB)\n", flags.target, flags.model, flags.sizeMB)
	fmt.Printf("  platform config: %s\n  binaries: %s\n  work dir: %s\n", cfg.PlatformConfigFile, filepath.Dir(cfg.PlatformdBinary), cfg.WorkDir)

	result, err := pkgdiskimage.Create(context.Background(), &pkgdiskimage.BuildConfig{
		ISO:                  cfg,
		Target:               flags.target,
		VirtKernelDir:        flags.virtKernelDir,
		VirtKernelBuilderDir: flags.virtKernelBuilderDir,
		VirtKernelOutputDir:  flags.virtKernelOutputDir,
		VirtKernelCacheDir:   flags.virtKernelCacheDir,
		Model:                flags.model,
		SizeMB:               flags.sizeMB,
		Output:               flags.output,
		BinariesDir:          filepath.Dir(cfg.PlatformdBinary),
		ContainerRuntime:     flags.containerRuntime,
		BuilderImage:         flags.builderImage,
		BuilderDir:           flags.builderDir,
		UBootBuilderDir:      flags.ubootBuilderDir,
		UBootOutputDir:       flags.ubootOutputDir,
		UBootDir:             flags.ubootDir,
		UBootCacheDir:        flags.ubootCacheDir,
		Logger:               logger,
		SkipPreflight:        flags.skipPreflight,
	})
	if err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}
	fmt.Printf("\nImage: %s\n  SHA256: %s\n  Size: %d MB\n  U-Boot: %s\n  Media: %s\n", result.Image, result.SHA256, result.SizeBytes/(1024*1024), result.UBoot.Binary, result.MediaDir)
	return nil
}
