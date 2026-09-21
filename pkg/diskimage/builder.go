package diskimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/virtkernel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// bakedPlatformConfigName is the platform config StageMedia bakes onto the
// media (pkg/iso CopyPlatformConfig); the container installs from it exactly
// as the live ISO does.
const bakedPlatformConfigName = "installer.yaml"

// Result describes a built image.
type Result struct {
	// Image is the output path.
	Image string
	// SHA256 is the image's digest.
	SHA256 string
	// SizeBytes is the image's declared size.
	SizeBytes int64
	// MediaDir is the staged media root, kept for inspection.
	MediaDir string
	// UBoot is the U-Boot build the image carries.
	UBoot uboot.Artifacts
	// Kernel is the platform-built kernel the image carries, nil for a
	// target on a packaged kernel.
	Kernel *virtkernel.Artifacts
}

// Create builds an image end to end: preflight, target resolution, Secure
// Boot keys, U-Boot, media staging, boot firmware, and the assemble step
// inside the arm64 container.
func Create(ctx context.Context, cfg *BuildConfig) (*Result, error) {
	c := cfg.withDefaults()
	if c.ISO == nil {
		return nil, &StageError{Step: "configuration", Err: errMissingISOConfig}
	}
	if c.SizeMB < minimumSizeMB {
		return nil, &StageError{Step: "configuration", Err: &sizeError{c.SizeMB}}
	}
	target, err := NewTarget(c.Target, c.Model)
	if err != nil {
		return nil, err
	}
	if !c.SkipPreflight {
		if err := Preflight(ctx, c.Runner, c.ContainerRuntime, string(target.Architecture())); err != nil {
			return nil, err
		}
	}

	// The build config is shared with the ISO; the target decides the
	// architecture and the binaries directory decides the platformd path.
	c.ISO.Architecture = string(target.Architecture())
	if c.BinariesDir != "" {
		c.ISO.PlatformdBinary = filepath.Join(c.BinariesDir, "platformd")
	}
	if err := c.ISO.Validate(); err != nil {
		return nil, &StageError{Step: "validating the build configuration", Err: err}
	}
	if err := c.ISO.ResolveBinaries(); err != nil {
		return nil, &StageError{Step: "resolving the target binaries", Err: err}
	}
	workDir, err := c.ISO.ResolveWorkDir()
	if err != nil {
		return nil, &StageError{Step: "resolving the work directory", Err: err}
	}

	decision, err := iso.EnsureSecureBootKeys(ctx, c.Logger, c.ISO)
	if err != nil {
		return nil, &StageError{Step: "Secure Boot keys", Err: err}
	}
	c.Logger.Info("[DISKIMAGE] Secure Boot keys", "decision", string(decision), "dir", c.ISO.KeysDir)

	art, err := c.ubootArtifacts(ctx, target)
	if err != nil {
		return nil, err
	}
	kernel, err := c.kernelArtifacts(ctx, target)
	if err != nil {
		return nil, err
	}

	mediaDir := filepath.Join(workDir, MediaDirName)
	platformCfg := iso.NewPlatformISOConfig(c.ISO, workDir)
	platformCfg.Directories.ISO = mediaDir
	platformCfg.Installer = target.InstallerOverrides()
	if err := platformCfg.Validate(); err != nil {
		return nil, &StageError{Step: "validating the media configuration", Err: err}
	}
	customizer := iso.NewCustomizer(platformCfg, c.Logger)
	if err := customizer.StageMedia(ctx); err != nil {
		return nil, &StageError{Step: "staging the install media", Err: err}
	}
	prefetchDir := filepath.Join(mediaDir, "apks-prefetch", string(target.Architecture()))
	if err := target.StageBootFirmware(ctx, mediaDir, prefetchDir, art); err != nil {
		return nil, &StageError{Step: "staging the boot firmware", Err: err}
	}
	if kernel != nil {
		if err := target.StageKernel(ctx, mediaDir, kernel); err != nil {
			return nil, &StageError{Step: "staging the kernel", Err: err}
		}
	}

	output := c.Output
	if output == "" {
		output = filepath.Join(workDir, "trusted-platform-"+target.Name()+".img")
	}
	if err := c.assembleInContainer(ctx, mediaDir, output, target); err != nil {
		return nil, err
	}

	sum, size, err := fileDigest(output)
	if err != nil {
		return nil, &AssembleError{Step: "reading the finished image", Err: err}
	}
	return &Result{Image: output, SHA256: sum, SizeBytes: size, MediaDir: mediaDir, UBoot: art, Kernel: kernel}, nil
}

// kernelArtifacts builds or locates the platform-built kernel for a target
// that boots one; nil for a target on a packaged kernel.
func (c *BuildConfig) kernelArtifacts(ctx context.Context, target Target) (*virtkernel.Artifacts, error) {
	if !target.BuiltKernel() {
		return nil, nil
	}
	var kernel *virtkernel.Artifacts
	var err error
	if c.VirtKernelDir != "" {
		kernel, err = virtkernel.Locate(c.VirtKernelDir, "")
	} else {
		kernel, err = virtkernel.Build(ctx, virtkernel.Options{
			Runner:     c.Runner,
			Runtime:    c.ContainerRuntime,
			BuilderDir: c.VirtKernelBuilderDir,
			OutputDir:  c.VirtKernelOutputDir,
			CacheDir:   c.VirtKernelCacheDir,
		})
	}
	if err != nil {
		return nil, &StageError{Step: "virt kernel", Err: err}
	}
	c.Logger.Info("[DISKIMAGE] Platform-built kernel", "release", kernel.Release, "kernel", kernel.Kernel)
	return kernel, nil
}

// ubootArtifacts builds or locates the target's U-Boot.
func (c *BuildConfig) ubootArtifacts(ctx context.Context, target Target) (uboot.Artifacts, error) {
	var all map[uboot.Board]uboot.Artifacts
	var err error
	if c.UBootDir != "" {
		all, err = uboot.Locate(c.UBootDir)
	} else {
		all, err = uboot.Build(ctx, uboot.Options{
			Runner:     c.Runner,
			Runtime:    c.ContainerRuntime,
			BuilderDir: c.UBootBuilderDir,
			OutputDir:  c.UBootOutputDir,
			KeysDir:    c.ISO.KeysDir,
			CacheDir:   c.UBootCacheDir,
		})
	}
	if err != nil {
		return uboot.Artifacts{}, &StageError{Step: "U-Boot", Err: err}
	}
	art, ok := all[target.UBootBoard()]
	if !ok {
		return uboot.Artifacts{}, &StageError{Step: "U-Boot", Err: &uboot.ArtifactMissingError{Path: string(target.UBootBoard()), Hint: "run `make uboot-build`"}}
	}
	return art, nil
}

// assembleInContainer runs `platformctl diskimage assemble` from the staged
// media inside the arm64 builder container, privileged for loop devices and
// device-mapper, with the media read-only and the image directory writable.
// The container keeps its own private /dev: the host's /dev is never
// bind-mounted, because the installer's `mdev -s` (which creates the
// partition nodes) resets the mode of every node it walks, and on the
// host that took /dev/null away from every unprivileged process.
func (c *BuildConfig) assembleInContainer(ctx context.Context, mediaDir, output string, target Target) error {
	outDir, err := filepath.Abs(filepath.Dir(output))
	if err != nil {
		return &AssembleError{Step: "resolving the output directory", Err: err}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return &AssembleError{Step: "creating the output directory", Err: err}
	}
	if _, err := c.Runner(ctx, c.ContainerRuntime, "build", "--platform", "linux/"+goArchOf(string(target.Architecture())), "-t", c.BuilderImage, c.BuilderDir); err != nil {
		return &AssembleError{Step: "building the assemble container image", Err: err}
	}
	absMedia, err := filepath.Abs(mediaDir)
	if err != nil {
		return &AssembleError{Step: "resolving the media directory", Err: err}
	}
	args := []string{"run", "--rm", "--privileged",
		"--platform", "linux/" + goArchOf(string(target.Architecture())),
		"-v", absMedia + ":" + containerMediaMount + ":ro",
		"-v", outDir + ":" + containerWorkMount,
		c.BuilderImage,
		containerMediaMount + "/platformd-bin/platformctl-static", "diskimage", "assemble",
		"--platform-config", containerMediaMount + "/configs/" + bakedPlatformConfigName,
		"--output", containerWorkMount + "/" + filepath.Base(output),
		"--size", strconv.Itoa(c.SizeMB),
	}
	if c.ISO.Debug {
		args = append(args, "--debug")
	}
	if _, err := c.Runner(ctx, c.ContainerRuntime, args...); err != nil {
		return &AssembleError{Step: "running the assemble container", Err: err}
	}
	return nil
}

// Preflight checks the host can run the assemble container: the runtime is
// present, a foreign-architecture container can exec (binfmt with the F
// flag, so chroot inside it works), and the loop and dm-crypt modules the
// installer relies on are loaded.
func Preflight(ctx context.Context, run runnerFunc, containerRuntime, arch string) error {
	if _, err := run(ctx, containerRuntime, "version", "--format", "{{.Server.Version}}"); err != nil {
		return &PreflightError{Check: containerRuntime + " is not usable", Remedy: "install and start " + containerRuntime + " and make sure this user can talk to it"}
	}
	hostArch := runtime.GOARCH
	if goArchOf(arch) != hostArch {
		// binfmt_misc entries are registered under the QEMU architecture
		// name (qemu-aarch64), which is the Alpine name, not GOARCH.
		flags, err := os.ReadFile(binfmtDir + "/qemu-" + arch)
		if err != nil {
			return &PreflightError{Check: "no binfmt handler for " + arch + " containers", Remedy: "run `make init` (registers multiarch/qemu-user-static --reset -p yes)"}
		}
		if !binfmtHasFixedBinary(string(flags)) {
			return &PreflightError{Check: "the qemu-" + arch + " binfmt handler lacks the F flag, so chroot inside the container cannot exec", Remedy: "re-register with `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes`"}
		}
	}
	for _, module := range []string{"loop", "dm_crypt"} {
		if _, err := os.Stat(sysModuleDir + "/" + module); err != nil {
			return &PreflightError{Check: "kernel module " + module + " is not loaded", Remedy: "modprobe " + module}
		}
	}
	return nil
}

// binfmtDir is where the kernel exposes binfmt_misc registrations. It is a
// variable so tests can point Preflight at a fixture directory.
var binfmtDir = "/proc/sys/fs/binfmt_misc"

// sysModuleDir is where the kernel lists loaded modules; overridable in tests.
var sysModuleDir = "/sys/module"

// runnerFunc is runner.Runner without the import cycle in the signature.
type runnerFunc = func(ctx context.Context, name string, args ...string) ([]byte, error)

// binfmtHasFixedBinary reports whether a binfmt_misc entry carries the F
// (fix binary) flag.
func binfmtHasFixedBinary(entry string) bool {
	for _, line := range strings.Split(entry, "\n") {
		if strings.HasPrefix(line, "flags:") {
			return strings.Contains(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), "F")
		}
	}
	return false
}

// goArchOf maps an Alpine architecture name to GOARCH.
func goArchOf(arch string) string {
	switch arch {
	case "aarch64":
		return "arm64"
	case "x86_64":
		return "amd64"
	default:
		return arch
	}
}

// fileDigest returns the hex sha256 and size of a file.
func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// errMissingISOConfig is returned when BuildConfig.ISO is nil.
var errMissingISOConfig = &configError{"ISO build configuration is required"}

// configError is a configuration defect.
type configError struct{ msg string }

func (e *configError) Error() string { return "diskimage: " + e.msg }

// sizeError reports an image size below the minimum.
type sizeError struct{ mb int }

func (e *sizeError) Error() string {
	return "diskimage: image size " + strconv.Itoa(e.mb) + " MB is below the minimum of " + strconv.Itoa(minimumSizeMB) + " MB"
}
