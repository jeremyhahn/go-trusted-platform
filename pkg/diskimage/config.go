package diskimage

import (
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Defaults for BuildConfig.
const (
	DefaultTarget           = "rpi"
	DefaultSizeMB           = 4096
	DefaultContainerRuntime = "docker"
	DefaultBuilderImage     = "trusted-platform-diskimage-builder:arm64"
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
	// ContainerRuntime is docker (default); BuilderImage the assemble
	// image tag; BuilderDir its build context.
	ContainerRuntime string
	BuilderImage     string
	BuilderDir       string
	// UBootBuilderDir is the U-Boot builder context; UBootOutputDir where
	// its artifacts live (default <UBootBuilderDir>/output); UBootDir, when
	// set, names prebuilt artifacts and skips the U-Boot build entirely.
	UBootBuilderDir string
	UBootOutputDir  string
	UBootDir        string
	// UBootCacheDir caches the U-Boot tarball between builds.
	UBootCacheDir string
	// VirtKernelBuilderDir is the virt kernel builder context;
	// VirtKernelOutputDir where its artifacts live (default
	// <VirtKernelBuilderDir>/output); VirtKernelDir, when set, names
	// prebuilt artifacts and skips the build; VirtKernelCacheDir caches the
	// kernel tarball. Only targets whose BuiltKernel is true use them.
	VirtKernelBuilderDir string
	VirtKernelOutputDir  string
	VirtKernelDir        string
	VirtKernelCacheDir   string
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

// withDefaults fills the zero fields.
func (c *BuildConfig) withDefaults() *BuildConfig {
	out := *c
	if out.Target == "" {
		out.Target = DefaultTarget
	}
	if out.SizeMB == 0 {
		out.SizeMB = DefaultSizeMB
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
