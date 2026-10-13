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

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
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

// StagedMedia is a target's install media staged on disk: the layout the
// installer reads as /media/cdrom (packages, the platform binaries, the
// board's boot firmware, a platform-built kernel), before any image is
// assembled from it. The image build assembles it; the netboot media build
// serves it to an installer booted over the network.
type StagedMedia struct {
	Target   Target
	WorkDir  string
	MediaDir string
	// UBoot is the U-Boot build the media's boot firmware carries.
	UBoot uboot.Artifacts
	// Kernel is the platform-built kernel, nil for a target on a packaged
	// kernel.
	Kernel *virtkernel.Artifacts
	// SecureBoot is the build's resolved Secure Boot certificates and DB
	// signer; nil when Secure Boot is off.
	SecureBoot *iso.SecureBootMaterial
	// config is the resolved build configuration, for Create.
	config *BuildConfig
	// install is the staged installer media, for InstallerInitramfs.
	install *iso.InstallMedia
}

// InstallerInitramfs rewrites a netboot initramfs at path as the installer's
// for this target's media (iso.InstallMedia.InstallerInitramfs).
func (s *StagedMedia) InstallerInitramfs(ctx context.Context, path string) error {
	return s.install.InstallerInitramfs(ctx, path)
}

// StageMedia stages a target's install media: the Secure Boot keys, U-Boot
// and (for a target that boots one) the platform-built kernel, then the
// media tree the installer reads, with the target's installer overrides,
// boot firmware and kernel.
func StageMedia(ctx context.Context, cfg *BuildConfig) (*StagedMedia, error) {
	c := cfg.withDefaults()
	if c.ISO == nil {
		return nil, &StageError{Step: "configuration", Err: errMissingISOConfig}
	}
	target, err := NewTarget(c.Target, c.Model)
	if err != nil {
		return nil, err
	}
	// The build config is shared with the ISO; the target decides the
	// architecture and the binaries directory decides the platformd path.
	c.ISO.Architecture = string(target.Architecture())
	if c.BinariesDir != "" {
		c.ISO.PlatformdBinary = filepath.Join(c.BinariesDir, "platformd")
	}
	media, err := iso.StageInstallMedia(ctx, c.ISO, MediaDirName, target.InstallerOverrides(), c.KMSClients, c.Logger)
	if err != nil {
		return nil, &StageError{Step: "install media", Err: err}
	}
	workDir, mediaDir, material := media.WorkDir, media.Dir, media.SecureBoot

	art, err := c.ubootArtifacts(ctx, target, material)
	if err != nil {
		return nil, err
	}
	kernel, err := c.kernelArtifacts(ctx, target)
	if err != nil {
		return nil, err
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

	return &StagedMedia{Target: target, WorkDir: workDir, MediaDir: mediaDir, UBoot: art, Kernel: kernel, SecureBoot: material, config: c, install: media}, nil
}

// Create builds an image end to end: preflight, target resolution, Secure
// Boot keys, U-Boot, media staging, boot firmware, and the assemble step
// inside the arm64 container.
func Create(ctx context.Context, cfg *BuildConfig) (*Result, error) {
	if cfg == nil || cfg.ISO == nil {
		return nil, &StageError{Step: "configuration", Err: errMissingISOConfig}
	}
	resolved := cfg.withDefaults()
	if resolved.SizeMB < minimumSizeMB {
		return nil, &StageError{Step: "configuration", Err: &sizeError{resolved.SizeMB}}
	}
	if err := validateBuilderImage(resolved.BuilderImage); err != nil {
		return nil, &StageError{Step: "configuration", Err: err}
	}
	if !resolved.SkipPreflight {
		target, err := NewTarget(resolved.Target, resolved.Model)
		if err != nil {
			return nil, err
		}
		if err := Preflight(ctx, resolved.Runner, resolved.ContainerRuntime, string(target.Architecture())); err != nil {
			return nil, err
		}
	}
	staged, err := StageMedia(ctx, cfg)
	if err != nil {
		return nil, err
	}
	c, target, workDir, mediaDir, art, kernel := staged.config, staged.Target, staged.WorkDir, staged.MediaDir, staged.UBoot, staged.Kernel

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
			Runner:      c.Runner,
			Runtime:     c.ContainerRuntime,
			BuilderDir:  c.VirtKernelBuilderDir,
			OutputDir:   c.VirtKernelOutputDir,
			CacheVolume: c.VirtKernelCacheVolume,
		})
	}
	if err != nil {
		return nil, &StageError{Step: "virt kernel", Err: err}
	}
	c.Logger.Info("[DISKIMAGE] Platform-built kernel", "release", kernel.Release, "kernel", kernel.Kernel)
	return kernel, nil
}

// ubootArtifacts builds or locates the target's U-Boot.
func (c *BuildConfig) ubootArtifacts(ctx context.Context, target Target, material *iso.SecureBootMaterial) (uboot.Artifacts, error) {
	// U-Boot preseeds the PK/KEK/db it enforces: the resolved certificates,
	// wherever the keys live (a KMS, or the keys directory).
	keysDir := c.ISO.KeysDir
	if material != nil {
		keysDir = material.CertDir
	}
	var all map[uboot.Board]uboot.Artifacts
	var err error
	if c.UBootDir != "" {
		all, err = uboot.Locate(c.UBootDir)
	} else {
		all, err = uboot.Build(ctx, uboot.Options{
			Runner:      c.Runner,
			Runtime:     c.ContainerRuntime,
			BuilderDir:  c.UBootBuilderDir,
			OutputDir:   c.UBootOutputDir,
			KeysDir:     keysDir,
			CacheVolume: c.UBootCacheVolume,
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
// media inside the builder container at the HOST platform, privileged for
// loop devices and device-mapper. Under qemu-user there are no keyring
// syscalls, so go-luks2 cannot open the volume in a foreign-architecture
// container (#802); the target's packages are laid down by the installer's
// chroot steps, which run under binfmt.
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
	platform := "linux/" + c.HostArch
	image := c.builderImageFor(c.HostArch)
	if _, err := c.Runner(ctx, c.ContainerRuntime, "build", "--platform", platform, "-t", image, c.BuilderDir); err != nil {
		return &AssembleError{Step: "building the assemble container image", Err: err}
	}
	absMedia, err := filepath.Abs(mediaDir)
	if err != nil {
		return &AssembleError{Step: "resolving the media directory", Err: err}
	}
	in := []runner.Copy{{Host: absMedia, Container: containerMediaMount}}
	// The media's platformctl-static is the target's. It runs here only when
	// the target is the host; otherwise the host-architecture installer does,
	// so partitioning, LUKS and mkfs are native and only the chroot steps
	// run under binfmt.
	installer := containerMediaMount + "/platformd-bin/platformctl-static"
	if targetArch := goArchOf(string(target.Architecture())); targetArch != c.HostArch {
		if c.HostInstallerBinary == "" {
			return &HostInstallerMissingError{HostArch: c.HostArch, TargetArch: targetArch}
		}
		installerDir, cleanup, err := stageHostInstaller(c.HostInstallerBinary)
		if err != nil {
			return &AssembleError{Step: "staging the host installer", Err: err}
		}
		defer cleanup()
		in = append(in, runner.Copy{Host: installerDir, Container: containerInstallerMount})
		installer = containerInstallerMount + "/" + hostInstallerName
	}
	command := []string{
		installer, "diskimage", "assemble",
		"--platform-config", containerMediaMount + "/configs/" + bakedPlatformConfigName,
		"--output", containerWorkMount + "/" + filepath.Base(output),
		"--size", strconv.Itoa(c.SizeMB),
	}
	if c.ISO.Debug {
		command = append(command, "--debug")
	}
	// The media goes in and the image comes out with cp, not bind mounts: the
	// daemon may not share this process's filesystem (CI job container).
	container := runner.Container{
		Image:      image,
		CreateArgs: []string{"--privileged", "--platform", platform, "-v", containerWorkMount},
		Command:    command,
		In:         in,
		Out:        []runner.Copy{{Host: outDir, Container: containerWorkMount}},
	}
	if err := container.Run(ctx, c.Runner, c.ContainerRuntime); err != nil {
		return &AssembleError{Step: "running the assemble container", Err: err}
	}
	return nil
}

// stageHostInstaller copies the host-architecture installer binary into a
// fresh directory (the container copy moves directories) and returns it with
// its cleanup.
func stageHostInstaller(binary string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "host-installer-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	src, err := os.Open(binary)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, hostInstallerName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		cleanup()
		return "", nil, err
	}
	if err := dst.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
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
		// name (qemu-aarch64), which is the Alpine name, not GOARCH. The
		// registration belongs to the container runtime's kernel, not to this
		// process's /proc (a CI job container has no binfmt_misc mount), so
		// ask a short-lived native container.
		entry, err := run(ctx, containerRuntime, "run", "--rm", "--privileged", binfmtProbeImage,
			"sh", "-c", "mountpoint -q "+binfmtMount+" || mount -t binfmt_misc none "+binfmtMount+"; cat "+binfmtMount+"/qemu-"+arch)
		if err != nil {
			return &PreflightError{Check: "no binfmt handler for " + arch + " containers", Remedy: "run `make binfmt` (registers the pinned tonistiigi/binfmt handler with the F flag)"}
		}
		if !binfmtHasFixedBinary(string(entry)) {
			return &PreflightError{Check: "the qemu-" + arch + " binfmt handler lacks the F flag, so chroot inside the container cannot exec", Remedy: "re-register with `make binfmt` (the pinned tonistiigi/binfmt handler, with the F flag)"}
		}
	}
	for _, module := range []string{"loop", "dm_crypt"} {
		if _, err := os.Stat(sysModuleDir + "/" + module); err != nil {
			return &PreflightError{Check: "kernel module " + module + " is not loaded", Remedy: "modprobe " + module}
		}
	}
	return nil
}

const (
	// binfmtProbeImage is the builder image's base, so the probe pulls nothing
	// the build does not already need.
	binfmtProbeImage = "alpine:3.22"
	// binfmtMount is where binfmt_misc is mounted inside the probe container.
	binfmtMount = "/proc/sys/fs/binfmt_misc"
)

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

// builderImageError reports a --builder-image that is not a bare repository.
type builderImageError struct{ value string }

func (e *builderImageError) Error() string {
	return "diskimage: --builder-image " + strconv.Quote(e.value) +
		" must be an image repository without a tag or digest (for example trusted-platform-diskimage-builder or registry:5000/builder); the tag is the architecture"
}

// validateBuilderImage rejects a repository that already carries a tag or a
// digest: builderImageFor appends the architecture tag. A registry port
// (host:5000/foo) is not a tag, so only the last path segment is checked.
func validateBuilderImage(image string) error {
	last := image[strings.LastIndex(image, "/")+1:]
	if strings.Contains(image, "@") || strings.Contains(last, ":") {
		return &builderImageError{image}
	}
	return nil
}

// sizeError reports an image size below the minimum.
type sizeError struct{ mb int }

func (e *sizeError) Error() string {
	return "diskimage: image size " + strconv.Itoa(e.mb) + " MB is below the minimum of " + strconv.Itoa(minimumSizeMB) + " MB"
}
