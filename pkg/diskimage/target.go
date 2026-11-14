// Package diskimage builds factory disk images of the trusted platform: the
// installer's Phase A runs on the build host, inside an arm64 container
// against a loop-mounted image, and the device's first boot is the
// unchanged Phase B (platform-initrd, firstboot provisioning and sealing,
// platformd enrollment and attestation).
//
// The builder reuses the ISO pipeline for everything that is not the boot
// chain: iso.Customizer.StageMedia lays out the media root the installer
// reads from /media/cdrom, and pkg/installer does the partitioning, LUKS,
// OS install and UKI. A Target supplies what differs per device: the
// architecture, kernel package, extra packages, installer overrides and
// the boot firmware files that go onto the EFI partition.
package diskimage

import (
	"context"
	"sort"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/qemuvirt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/virtkernel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Target is one kind of device image.
type Target interface {
	// Name is the --target value.
	Name() string
	// ModelName is the board the image is for, the --model value resolved
	// to the target's name for it ("rpi4", "virt"). Name()/ModelName() is
	// the measurement manifest's model.
	ModelName() string
	// Architecture is the CPU architecture of the image.
	Architecture() uki.Architecture
	// KernelPackage is the apk kernel to install and prefetch.
	KernelPackage() string
	// ExtraPackages are prefetched in addition to the platform's set.
	ExtraPackages() []string
	// UBootBoard is the U-Boot build the image boots with.
	UBootBoard() uboot.Board
	// InstallerOverrides adjusts the generated installer configuration.
	InstallerOverrides() iso.InstallerOverrides
	// StageBootFirmware fills <mediaDir>/boot-firmware with what the
	// installer's uboot firmware seam copies onto the EFI partition.
	StageBootFirmware(ctx context.Context, mediaDir, prefetchDir string, art uboot.Artifacts) error
	// BuiltKernel reports whether the image boots a platform-built kernel
	// (pkg/diskimage/virtkernel) instead of the apk kernel package. The
	// builder then produces or locates the kernel and calls StageKernel.
	BuiltKernel() bool
	// StageKernel copies the built kernel's artifact directory onto the
	// media where InstallerOverrides.KernelArtifactsDir points.
	StageKernel(ctx context.Context, mediaDir string, kernel *virtkernel.Artifacts) error
}

// targetFactory builds a Target for a --model value.
type targetFactory func(model string) (Target, error)

// targets dispatches a --target name to its factory.
var targets = map[string]targetFactory{
	rpi.Name:      func(model string) (Target, error) { return rpi.New(model) },
	qemuvirt.Name: func(string) (Target, error) { return qemuvirt.New(), nil },
}

// Targets lists the known target names, sorted.
func Targets() []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewTarget resolves a --target / --model pair.
func NewTarget(name, model string) (Target, error) {
	factory, ok := targets[name]
	if !ok {
		return nil, &UnknownTargetError{Target: name, Targets: Targets()}
	}
	return factory(model)
}
