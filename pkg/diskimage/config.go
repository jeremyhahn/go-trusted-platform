package diskimage

import (
	"path/filepath"
	"runtime"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Defaults for BuildConfig.
const (
	DefaultTarget           = "rpi"
	DefaultSizeMB           = 4096
	DefaultContainerRuntime = "docker"
	// DefaultBuilderImage is the builder image repository; the image tag is
	// the architecture it is built for (see BuildConfig.builderImageFor).
	DefaultBuilderImage = "trusted-platform-diskimage-builder"
	// DefaultBuilderDir is the assemble container's build context, relative
	// to the repository root.
	DefaultBuilderDir = "build/docker/diskimage-builder"
	// DefaultUBootBuilderDir is the U-Boot builder, relative to the
	// repository root.
	DefaultUBootBuilderDir = "build/docker/uboot-builder"
	// DefaultVirtKernelBuilderDir is the virt kernel builder, relative to
	// the repository root.
	DefaultVirtKernelBuilderDir = "build/docker/virt-kernel-builder"
	// MediaDirName is the media root under the work directory; it is
	// bind-mounted at /media/cdrom in the assemble container.
	MediaDirName = "media"
	// containerMediaMount is where the installer reads the media.
	containerMediaMount = "/media/cdrom"
	// containerInstallerMount is where the host-architecture installer binary
	// lands in a foreign-architecture build; hostInstallerName is its name.
	containerInstallerMount = "/installer"
	hostInstallerName       = "platformctl-static"
	// containerWorkMount is where the image is written inside the container.
	containerWorkMount = "/work"
	// minimumSizeMB is the smallest image that fits the installer's 538 MB
	// boot partition plus an Alpine root with the platform binaries.
	minimumSizeMB = 2048
)

// BuildConfig drives Create.
type BuildConfig struct {
	// ISO carries everything the ISO build shares with the image build:
	// Alpine version and mirror, platform config, Secure Boot keys, CA
	// bundle, web UI, pre-fetch. Its Architecture is set from the target.
	ISO *iso.ISOBuildConfig
	// Target is rpi (default) or qemu-virt; Model is the target's board.
	Target string
	Model  string
	// SizeMB is the image size (default 4096, minimum 2048).
	SizeMB int
	// Output is the image path.
	Output string
	// BinariesDir holds the target-architecture platformd, platformctl,
	// platformctl-static, platform-initrd and gatewayd.
	BinariesDir string
	// HostArch is the Go architecture of the build host (default
	// runtime.GOARCH). The assemble container runs at this platform, so
	// partitioning, LUKS and mkfs run natively; only the target chroot steps
	// run under binfmt.
	HostArch string
	// HostInstallerBinary is a static platformctl built for HostArch. It runs
	// the installer in the assemble container when the target is a foreign
	// architecture (the media's platformctl-static is the target's, and is
	// what the finished image carries). Unused when the target is the host.
	HostInstallerBinary string
	// ContainerRuntime is docker (default); BuilderImage the assemble
	// image repository (tagged per architecture); BuilderDir its build context.
	ContainerRuntime string
	BuilderImage     string
	BuilderDir       string
	// UBootBuilderDir is the U-Boot builder context; UBootOutputDir where
	// its artifacts live (default <UBootBuilderDir>/output); UBootDir, when
	// set, names prebuilt artifacts and skips the U-Boot build entirely.
	UBootBuilderDir string
	UBootOutputDir  string
	UBootDir        string
	// UBootCacheVolume names the docker volume that caches the U-Boot
	// tarball between builds (default uboot.DefaultCacheVolume).
	UBootCacheVolume string
	// VirtKernelBuilderDir is the virt kernel builder context;
	// VirtKernelOutputDir where its artifacts live (default
	// <VirtKernelBuilderDir>/output); VirtKernelDir, when set, names
	// prebuilt artifacts and skips the build; VirtKernelCacheVolume names the
	// docker volume that caches the kernel tarball. Only targets whose BuiltKernel is true use them.
	VirtKernelBuilderDir  string
	VirtKernelOutputDir   string
	VirtKernelDir         string
	VirtKernelCacheVolume string
	// KMSClients opens the operator's platform clients for kms:// Secure
	// Boot references in the platform config; nil when the build only signs
	// with file keys.
	KMSClients iso.KMSClientsFunc
	// Runner runs docker and other host commands; nil means runner.Exec.
	Runner runner.Runner
	// Logger receives progress; nil means the default logger.
	Logger *logging.Logger
	// SkipPreflight disables the host checks (binfmt, container runtime,
	// kernel modules); tests use it.
	SkipPreflight bool
}

// builderImageFor is the builder image tag for a Go architecture. The assemble
// step (host) and netboot-initfs (target) build different platforms, so each
// gets its own tag and neither can run the other's image.
func (c *BuildConfig) builderImageFor(arch string) string {
	return c.BuilderImage + ":" + arch
}

// withDefaults fills the zero fields.
func (c *BuildConfig) withDefaults() *BuildConfig {
	out := *c
	if out.Target == "" {
		out.Target = DefaultTarget
	}
	if out.SizeMB == 0 {
		out.SizeMB = DefaultSizeMB
	}
	if out.HostArch == "" {
		out.HostArch = runtime.GOARCH
	}
	if out.ContainerRuntime == "" {
		out.ContainerRuntime = DefaultContainerRuntime
	}
	if out.BuilderImage == "" {
		out.BuilderImage = DefaultBuilderImage
	}
	if out.BuilderDir == "" {
		out.BuilderDir = DefaultBuilderDir
	}
	if out.UBootBuilderDir == "" {
		out.UBootBuilderDir = DefaultUBootBuilderDir
	}
	if out.UBootOutputDir == "" {
		out.UBootOutputDir = filepath.Join(out.UBootBuilderDir, "output")
	}
	if out.VirtKernelBuilderDir == "" {
		out.VirtKernelBuilderDir = DefaultVirtKernelBuilderDir
	}
	if out.VirtKernelOutputDir == "" {
		out.VirtKernelOutputDir = filepath.Join(out.VirtKernelBuilderDir, "output")
	}
	if out.Runner == nil {
		out.Runner = runner.Exec
	}
	if out.Logger == nil {
		out.Logger = logging.DefaultLogger()
	}
	return &out
}
