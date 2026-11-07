// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package netboot

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Layout of a netboot media build (container.NetbootMedia).
const (
	// CDROMDir is a set's install-media tree, laid under /media/cdrom by
	// the autoinstall from the set's payload list.
	CDROMDir = "cdrom"
	// TFTPTreeDir is the Raspberry Pi TFTP tree.
	TFTPTreeDir = "rpi-tftp"
	// ARM64IPXEFile is the db-signed arm64 iPXE, served as snponly-aarch64.efi.
	ARM64IPXEFile = "firmware/snponly-aarch64.efi"
)

// Set is one media set a netboot build produces.
type Set struct {
	// Name is the set's name (container.MediaSet).
	Name string
	// Architecture is the iPXE ${buildarch} the set boots on.
	Architecture string
	// Target is the diskimage target whose media, overrides and boot
	// firmware the set installs; empty for the x86_64 installer, which
	// stages the installer media alone.
	Target string
	// Flavour is the Alpine netboot kernel flavour the set boots.
	Flavour string
	// KernelArgs are the flavour's own kernel arguments.
	KernelArgs string
	// Default makes the set its architecture's default.
	Default bool
}

// X86_64Set boots Alpine's lts kernel and installs an x86_64 machine: the
// installer media alone, the machine's own UEFI firmware. It is x86_64's
// default (and i386 BIOS iPXE's, which chains to it).
var X86_64Set = Set{
	Name:         container.MediaSetX86_64,
	Architecture: ipxe.ArchitectureX86_64,
	Flavour:      "lts",
	// modules=: the modloop and live squashfs, then the NIC drivers (igb …
	// bnxt_en) loaded early so the initramfs can DHCP before it fetches the
	// modloop over HTTP; earlycon / console=: the x86 serial consoles, so
	// SOL captures show the boot; loglevel=7 for the diagnostics.
	KernelArgs: "modules=loop,squashfs,sd-mod,usb-storage,igb,igc,ixgbe,i40e,ice,e1000,e1000e,mlx5_core,bnxt_en,af_packet " +
		"earlyprintk=efi,keep earlycon=uart8250,io,0x3f8,115200n8 " +
		"console=tty0 console=ttyS1,115200n8 console=ttyS0,115200n8 " +
		"loglevel=7 console=tty1",
	Default: true,
}

// RaspberryPiSet boots Alpine's rpi kernel — bcmgenet built in, the SPI TPM
// as a module — and installs a Raspberry Pi: its media carries the rpi
// target's overrides, boot firmware and packages.
var RaspberryPiSet = Set{
	Name:         container.MediaSetRaspberryPi,
	Architecture: ipxe.ArchitectureARM64,
	Target:       "rpi",
	Flavour:      "rpi",
	// modules=: mount the modloop and live squashfs, then af_packet for
	// the initramfs DHCP; consoles: the PL011 (ttyAMA0 once Bluetooth is
	// moved off it) and the framebuffer.
	KernelArgs: "modules=loop,squashfs,sd-mod,usb-storage,af_packet console=ttyAMA0,115200 console=tty1",
}

// ARM64VirtSet boots the QEMU virt stand-in's platform-built kernel (the TPM
// driver Alpine's aarch64 kernels lack) with an initramfs and modloop
// generated for it, and installs the virt target. It is arm64's default: a
// generic arm64 machine boots it.
var ARM64VirtSet = Set{
	Name:         container.MediaSetARM64Virt,
	Architecture: ipxe.ArchitectureARM64,
	Target:       "qemu-virt",
	Flavour:      "virt",
	// modules=: the modloop and live squashfs, virtio_net and af_packet for
	// the initramfs DHCP; console: the virt machine's PL011.
	KernelArgs: "modules=loop,squashfs,virtio_net,af_packet console=ttyAMA0,115200",
	Default:    true,
}

// DefaultSets are the sets a build produces unless told otherwise.
var DefaultSets = []Set{X86_64Set, RaspberryPiSet, ARM64VirtSet}

// Config configures a netboot media build.
type Config struct {
	// Build is every set's image build: the ISO build config (Alpine
	// release and mirror, platform config, Secure Boot keys, pre-fetch),
	// U-Boot and virt-kernel inputs, runner, logger and KMS clients. Each
	// set gets its own copy with its target, model, binaries and work
	// directory.
	Build *diskimage.BuildConfig
	// ARM64BinariesDir and X86BinariesDir hold each architecture's
	// platformd, platformctl, platform-initrd and
	// gatewayd.
	ARM64BinariesDir string
	X86BinariesDir   string
	// Model is the Raspberry Pi board the TFTP tree's config.txt is
	// written for (default rpi4).
	Model string
	// IPXEFile is the arm64 iPXE the build signs (the ipxe-builder's
	// bin-arm64-efi/snponly.efi, verified against its SHA256SUMS).
	IPXEFile string
	// CacheDir caches the pinned Alpine netboot tarballs.
	CacheDir string
	// OutputDir receives the build; it is replaced.
	OutputDir string
	// Sets are the sets to build (default DefaultSets).
	Sets []Set
	// Diskless adds the diskless root to every set with a diskimage target:
	// the squashfs and its dm-verity hash tree beside the kernel, and the
	// manifest, signed with the Secure Boot DB key, in the install media.
	// It needs Secure Boot and a Version. A set serves it only to the nodes
	// whose boot_model is diskless; every other node installs to its disk.
	Diskless bool
	// SourceDateEpoch and Version fix the diskless root's timestamps and its
	// verity salt, so the same release builds the same root hash.
	SourceDateEpoch int64
	Version         string
	// HTTPBoot, when set, also builds the signed boot.img and boot.sig the
	// Raspberry Pi bootloader EEPROM fetches over HTTP, from the Pi set's
	// boot partition; nil builds none.
	HTTPBoot *HTTPBoot
}

// Result is a finished netboot media build.
type Result struct {
	// Dir is the build's root: netboot-media.yaml, SHA256SUMS, media/.
	Dir string
	// Sets names the media sets built.
	Sets []string
	// HTTPBoot describes the HTTP boot files when the build made them.
	HTTPBoot *HTTPBootFiles
	// HTTPBootPath is the EEPROM's HTTP_PATH for them, under the HTTP_HOST
	// the container is reached at; empty without HTTP boot.
	HTTPBootPath string
}

// Build produces a netboot media build: one media set per Set, the
// Raspberry Pi TFTP tree and the signed arm64 iPXE when the Pi set is built,
// the index and the checksums. The result is loaded back through the
// container's own loaders before Build returns, so a build the container
// would refuse is a build error.
func Build(ctx context.Context, cfg *Config) (*Result, error) {
	c, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(c.OutputDir); err != nil {
		return nil, &BuildError{Step: "clearing " + c.OutputDir, Err: err}
	}
	work := filepath.Join(c.OutputDir, ".work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, &BuildError{Step: "creating the work directory", Err: err}
	}

	index := container.NetbootMedia{}
	var httpBoot *HTTPBootFiles
	for _, set := range c.Sets {
		staged, err := c.buildSet(ctx, set, work)
		if err != nil {
			return nil, err
		}
		index.MediaSets = append(index.MediaSets, set.Name)
		if set.Name != container.MediaSetRaspberryPi {
			continue
		}
		if err := c.piBootFiles(ctx, staged); err != nil {
			return nil, err
		}
		index.TFTPTree = TFTPTreeDir
		index.ARM64IPXE = ARM64IPXEFile
		if c.HTTPBoot == nil {
			continue
		}
		if httpBoot, err = c.httpBootFiles(ctx); err != nil {
			return nil, &BuildError{Set: set.Name, Step: "the HTTP boot files", Err: err}
		}
		index.HTTPBoot = HTTPBootDir
	}
	if err := os.RemoveAll(work); err != nil {
		return nil, &BuildError{Step: "removing the work directory", Err: err}
	}
	sort.Strings(index.MediaSets)
	if err := writeIndex(c.OutputDir, &index); err != nil {
		return nil, err
	}
	if err := writeChecksums(c.OutputDir); err != nil {
		return nil, err
	}
	if _, err := container.LoadNetbootMedia(c.OutputDir); err != nil {
		return nil, &BuildError{Step: "loading the build back", Err: err}
	}
	if _, err := container.LoadMediaSets(filepath.Join(c.OutputDir, container.NetbootMediaSetsDir), "/data/"+container.NetbootMediaSetsDir); err != nil {
		return nil, &BuildError{Step: "loading the media sets back", Err: err}
	}
	result := &Result{Dir: c.OutputDir, Sets: index.MediaSets}
	if httpBoot != nil {
		if err := readBackHTTPBoot(c.OutputDir, httpBoot); err != nil {
			return nil, err
		}
		result.HTTPBoot = httpBoot
		result.HTTPBootPath = (&container.NetbootMedia{HTTPBoot: HTTPBootDir}).HTTPBootPath()
	}
	return result, nil
}

// readBackHTTPBoot reads the HTTP boot files staged under outputDir back as
// the EEPROM reads them, against the key hash they were staged for. Build's
// last step: what fails here is never served.
func readBackHTTPBoot(outputDir string, files *HTTPBootFiles) error {
	if _, err := VerifyHTTPBoot(filepath.Join(outputDir, HTTPBootDir), files.KeyHash); err != nil {
		return &BuildError{Step: "loading the HTTP boot files back", Err: err}
	}
	return nil
}

// resolve checks the configuration and fills its defaults.
func (cfg *Config) resolve() (*Config, error) {
	if cfg == nil || cfg.Build == nil || cfg.Build.ISO == nil {
		return nil, &BuildError{Step: "configuration", Err: &MissingFileError{File: "an image build configuration"}}
	}
	c := *cfg
	if c.OutputDir == "" {
		return nil, &BuildError{Step: "configuration", Err: &MissingFileError{File: "an output directory"}}
	}
	if c.CacheDir == "" {
		c.CacheDir = filepath.Join(c.OutputDir+".cache", "alpine")
	}
	if c.Model == "" {
		c.Model = "rpi4"
	}
	c.Sets = c.SetsToBuild()
	if c.Diskless {
		if !c.Build.ISO.SecureBoot {
			return nil, &BuildError{Step: "configuration", Err: &MissingFileError{File: "Secure Boot, whose DB key signs the diskless root manifest"}}
		}
		if c.Version == "" {
			return nil, &BuildError{Step: "configuration", Err: &MissingFileError{File: "a version for the diskless root"}}
		}
	}
	for _, set := range c.Sets {
		if c.binariesDir(set) == "" {
			return nil, &BuildError{Set: set.Name, Step: "configuration", Err: &MissingFileError{File: "the " + set.Architecture + " binaries directory"}}
		}
		if set.Target == "" && set.Architecture != ipxe.ArchitectureX86_64 {
			return nil, &BuildError{Set: set.Name, Step: "configuration", Err: &MissingFileError{File: "a diskimage target for an " + set.Architecture + " set"}}
		}
		if set.Name == container.MediaSetRaspberryPi && c.IPXEFile == "" {
			return nil, &BuildError{Set: set.Name, Step: "configuration", Err: &MissingFileError{File: "the arm64 iPXE"}}
		}
	}
	if c.HTTPBoot != nil {
		if err := c.resolveHTTPBoot(); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// disklessDefaultSets is DefaultSets without the sets that have no diskless
// image (no diskimage target, the x86_64 installer), logging each one left
// out. A set named explicitly is never filtered: it fails with
// UnsupportedDisklessSetError.
func (cfg *Config) disklessDefaultSets() []Set {
	logger := logging.DefaultLogger()
	if cfg.Build != nil && cfg.Build.Logger != nil {
		logger = cfg.Build.Logger
	}
	sets := make([]Set, 0, len(DefaultSets))
	for _, set := range DefaultSets {
		if set.Target == "" {
			logger.Infof("[NETBOOT] --diskless: leaving the %s set out of the default sets, it has no diskless image; name it in --sets to make this an error", set.Name)
			continue
		}
		sets = append(sets, set)
	}
	return sets
}

// SetsToBuild returns the sets a build of this configuration produces: Sets
// when any are named, otherwise DefaultSets, less the sets with no diskless
// image when Diskless is set. A caller that prepares per-set inputs (binaries
// directories) asks here rather than starting from DefaultSets, so a default
// diskless build never needs inputs for a set it leaves out.
func (cfg *Config) SetsToBuild() []Set {
	if len(cfg.Sets) > 0 {
		return cfg.Sets
	}
	if cfg.Diskless {
		return cfg.disklessDefaultSets()
	}
	return DefaultSets
}

// setMedia is a set's staged install media and what staging it produced.
type setMedia struct {
	// dir is the media tree (cdrom/ once the set is in place).
	dir string
	// arch is the Alpine architecture (x86_64, aarch64).
	arch string
	// secureBoot is the build's resolved certificates and DB signer; nil
	// when Secure Boot is off.
	secureBoot *iso.SecureBootMaterial
	// image is the target's image staging (U-Boot, its kernel, its boot
	// firmware); nil for a set with no diskimage target (x86_64).
	image *diskimage.StagedMedia
	// installerInitramfs rewrites the set's netboot initramfs as the
	// installer's, running this media's autoinstall.
	installerInitramfs func(ctx context.Context, path string) error
}

// stagedSet is a built media set.
type stagedSet struct {
	dir   string
	media *setMedia
}

// buildSet stages one set: its install media (moved into place as cdrom/),
// the flavour's kernel — db-signed when Secure Boot is on — the installer
// initramfs made from the flavour's, its modloop, the payload list and the
// descriptor.
func (c *Config) buildSet(ctx context.Context, set Set, work string) (*stagedSet, error) {
	fail := func(step string, err error) error { return &BuildError{Set: set.Name, Step: step, Err: err} }

	isoBuild := *c.Build.ISO
	isoBuild.WorkDir = filepath.Join(work, set.Name)
	// The set is served over HTTP: no private key material, ever.
	isoBuild.NetworkServed = true
	media, err := c.stageMedia(ctx, set, &isoBuild)
	if err != nil {
		return nil, fail("staging the install media", err)
	}
	if c.Diskless && media.image == nil {
		return nil, fail("validating the diskless root", &UnsupportedDisklessSetError{Set: set.Name})
	}

	setDir := filepath.Join(c.OutputDir, container.NetbootMediaSetsDir, set.Name)
	if err := os.MkdirAll(setDir, 0o755); err != nil {
		return nil, fail("creating the set directory", err)
	}
	cdrom := filepath.Join(setDir, CDROMDir)
	if err := os.Rename(media.dir, cdrom); err != nil {
		return nil, fail("moving the media into the set", err)
	}
	media.dir = cdrom
	if media.image != nil {
		media.image.MediaDir = cdrom
	}
	if err := refusePrivateKeys(cdrom); err != nil {
		return nil, fail("checking the media for key material", err)
	}

	unpacked := filepath.Join(work, set.Name+"-boot")
	files, err := c.bootFiles(ctx, set, media, &isoBuild, unpacked)
	if err != nil {
		return nil, fail("the "+set.Flavour+" kernel, initramfs and modloop", err)
	}
	// The release's initramfs boots a live system; the installer's runs the
	// autoinstall (alpine_start=autoinstall) with this set as its payload.
	if err := media.installerInitramfs(ctx, filepath.Join(unpacked, files.Initrd)); err != nil {
		return nil, fail("making the installer initramfs", err)
	}
	if err := placeKernel(filepath.Join(unpacked, files.Kernel), filepath.Join(setDir, files.Kernel), media.secureBoot); err != nil {
		return nil, fail("placing the kernel", err)
	}
	for _, name := range []string{files.Initrd, files.Modloop} {
		if err := os.Rename(filepath.Join(unpacked, name), filepath.Join(setDir, name)); err != nil {
			return nil, fail("placing "+name, err)
		}
	}

	// The diskless root is built before the payload list, so the signed
	// manifest under cdrom/ reaches the installer with the rest of the media.
	diskless := c.Diskless
	if diskless {
		if _, err := media.image.BuildDisklessRoot(ctx, setDir, filepath.Join(cdrom, disklessroot.Dir), c.SourceDateEpoch, c.Version); err != nil {
			return nil, fail("building the diskless root", err)
		}
	}
	if err := writePayloadList(setDir); err != nil {
		return nil, fail("writing the payload list", err)
	}
	descriptor := container.MediaSet{
		Name:         set.Name,
		Architecture: set.Architecture,
		Kernel:       files.Kernel,
		Initrd:       files.Initrd,
		Modloop:      files.Modloop,
		KernelArgs:   set.KernelArgs,
		Default:      set.Default,
		Diskless:     diskless,
	}
	if err := writeDescriptor(setDir, descriptor); err != nil {
		return nil, fail("writing the descriptor", err)
	}
	return &stagedSet{dir: setDir, media: media}, nil
}

// stageMedia stages the set's install media: through its diskimage target
// (overrides, U-Boot, boot firmware, kernel) when it has one, otherwise the
// installer media alone (the x86_64 set, whose firmware is the machine's).
func (c *Config) stageMedia(ctx context.Context, set Set, isoBuild *iso.ISOBuildConfig) (*setMedia, error) {
	if set.Target == "" {
		isoBuild.Architecture = alpineArch(set.Architecture)
		isoBuild.UseBinariesDir(c.binariesDir(set))
		logger := c.Build.Logger
		if logger == nil {
			logger = logging.DefaultLogger()
		}
		media, err := iso.StageInstallMedia(ctx, isoBuild, diskimage.MediaDirName, iso.InstallerOverrides{}, c.Build.KMSClients, logger)
		if err != nil {
			return nil, err
		}
		return &setMedia{dir: media.Dir, arch: isoBuild.Architecture, secureBoot: media.SecureBoot, installerInitramfs: media.InstallerInitramfs}, nil
	}
	build := *c.Build
	build.ISO = isoBuild
	build.Target = set.Target
	build.Model = c.Model
	build.BinariesDir = c.binariesDir(set)
	staged, err := diskimage.StageMedia(ctx, &build)
	if err != nil {
		return nil, err
	}
	return &setMedia{dir: staged.MediaDir, arch: string(staged.Target.Architecture()), secureBoot: staged.SecureBoot, image: staged, installerInitramfs: staged.InstallerInitramfs}, nil
}

// binariesDir is the platform binaries directory for the set's architecture.
func (c *Config) binariesDir(set Set) string {
	if set.Architecture == ipxe.ArchitectureX86_64 {
		return c.X86BinariesDir
	}
	return c.ARM64BinariesDir
}

// alpineArch is Alpine's name for an iPXE architecture.
func alpineArch(ipxeArch string) string {
	if ipxeArch == ipxe.ArchitectureARM64 {
		return "aarch64"
	}
	return ipxeArch
}

// bootFiles puts the set's kernel, initramfs and modloop in dir. A target on
// a platform-built kernel (the QEMU virt stand-in's, with the TPM driver
// Alpine's aarch64 kernels lack) boots that kernel, with an initramfs and
// modloop generated for it; any other set boots Alpine's netboot flavour from
// the digest-pinned release.
func (c *Config) bootFiles(ctx context.Context, set Set, media *setMedia, isoBuild *iso.ISOBuildConfig, dir string) (flavourFiles, error) {
	if media.image == nil || media.image.Kernel == nil {
		tarball, err := fetchAlpineNetboot(ctx, isoBuild.AlpineVersion, media.arch, isoBuild.AlpineMirror, c.CacheDir)
		if err != nil {
			return flavourFiles{}, err
		}
		return extractFlavour(tarball, set.Flavour, dir)
	}
	kernel := media.image.Kernel
	initfs, err := media.image.BuildNetbootInitfs(ctx, dir)
	if err != nil {
		return flavourFiles{}, err
	}
	files := flavourFiles{
		Kernel:  filepath.Base(kernel.Kernel),
		Initrd:  filepath.Base(initfs.Initramfs),
		Modloop: filepath.Base(initfs.Modloop),
	}
	data, err := os.ReadFile(kernel.Kernel)
	if err != nil {
		return flavourFiles{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, files.Kernel), data, 0o644); err != nil {
		return flavourFiles{}, err
	}
	return files, nil
}

// placeKernel installs the kernel at dst: db-signed when the build has Secure
// Boot material (U-Boot verifies what it loads), as released otherwise.
func placeKernel(src, dst string, material *iso.SecureBootMaterial) error {
	if material == nil {
		return os.Rename(src, dst)
	}
	return uki.SignKernel(src, dst, material.DB)
}

// piBootFiles stages what a Raspberry Pi fetches before the installer: the
// TFTP tree (firmware, device trees, config.txt, U-Boot as kernel8.img) from
// the Pi set's own packages and U-Boot build, and the arm64 iPXE U-Boot
// chains, db-signed.
func (c *Config) piBootFiles(ctx context.Context, set *stagedSet) error {
	fail := func(step string, err error) error {
		return &BuildError{Set: container.MediaSetRaspberryPi, Step: step, Err: err}
	}
	image := set.media.image
	prefetch := filepath.Join(image.MediaDir, "apks-prefetch", string(image.Target.Architecture()))
	if err := Stage(ctx, Inputs{Model: c.Model, PrefetchDir: prefetch, UBoot: image.UBoot}, filepath.Join(c.OutputDir, TFTPTreeDir)); err != nil {
		return fail("staging the TFTP tree", err)
	}

	if err := artifacts.VerifyChecksums(filepath.Dir(c.IPXEFile), "run `make ipxe-build`"); err != nil {
		return fail("verifying the arm64 iPXE", err)
	}
	dst := filepath.Join(c.OutputDir, filepath.FromSlash(ARM64IPXEFile))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fail("creating the firmware directory", err)
	}
	if set.media.secureBoot == nil {
		data, err := os.ReadFile(c.IPXEFile)
		if err != nil {
			return fail("reading the arm64 iPXE", err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fail("placing the arm64 iPXE", err)
		}
		return nil
	}
	if err := set.media.secureBoot.DB.SignFile(c.IPXEFile, dst); err != nil {
		return fail("signing the arm64 iPXE", err)
	}
	return nil
}

// refusePrivateKeys fails when the media carries anything under
// secure-boot-keys/ that is not positively public enrollment material: a
// netboot set is served over HTTP, so it must never hold a private key. A
// build whose DB key is a staged file (media signing) cannot be netbooted;
// its keys belong in the KMS (resign-mode remote).
func refusePrivateKeys(cdrom string) error {
	dir := filepath.Join(cdrom, iso.SecureBootKeysISODirName)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if e.IsDir() || !iso.IsSecureBootPublicArtifact(e.Name(), data) {
			return &PrivateKeyMaterialError{File: path.Join(iso.SecureBootKeysISODirName, e.Name())}
		}
	}
	return nil
}

// writePayloadList writes the set's payload list: every file of its media
// tree, laid under /media/cdrom at its path.
func writePayloadList(setDir string) error {
	entries, err := container.PayloadFromTree(filepath.Join(setDir, CDROMDir), CDROMDir)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(setDir, container.PayloadListName))
	if err != nil {
		return err
	}
	if err := container.WritePayloadList(f, entries); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeDescriptor writes the set's media-set.yaml.
func writeDescriptor(setDir string, set container.MediaSet) error {
	data, err := yaml.Marshal(&set)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(setDir, container.MediaSetDescriptor), data, 0o644)
}

// writeIndex writes netboot-media.yaml.
func writeIndex(root string, index *container.NetbootMedia) error {
	data, err := yaml.Marshal(index)
	if err != nil {
		return &BuildError{Step: "encoding the index", Err: err}
	}
	if err := os.WriteFile(filepath.Join(root, container.NetbootMediaIndex), data, 0o644); err != nil {
		return &BuildError{Step: "writing the index", Err: err}
	}
	return nil
}

// writeChecksums writes SHA256SUMS over every file of the build, relative to
// its root in sha256sum's format, so the deployer's `sha256sum -c` checks the
// copy it staged.
func writeChecksums(root string) error {
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == container.NetbootMediaSums {
			return nil
		}
		sum, err := artifacts.FileSHA256(p)
		if err != nil {
			return err
		}
		lines = append(lines, sum+"  "+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return &BuildError{Step: "hashing the build", Err: err}
	}
	sort.Strings(lines)
	if err := os.WriteFile(filepath.Join(root, container.NetbootMediaSums), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return &BuildError{Step: "writing " + container.NetbootMediaSums, Err: err}
	}
	return nil
}

// BuildError is a step of a netboot media build that failed, for a set or
// for the build as a whole.
type UnsupportedDisklessSetError struct {
	Set string
}

func (e *UnsupportedDisklessSetError) Error() string {
	return "diskless root is not available for media set " + e.Set
}

type BuildError struct {
	Set  string
	Step string
	Err  error
}

func (e *BuildError) Error() string {
	where := "diskimage/netboot: "
	if e.Set != "" {
		where += e.Set + ": "
	}
	return where + e.Step + ": " + e.Err.Error()
}

func (e *BuildError) Unwrap() error { return e.Err }

// PrivateKeyMaterialError is a netboot set whose media carries a file under
// secure-boot-keys/ that is not public enrollment material.
type PrivateKeyMaterialError struct {
	File string
}

func (e *PrivateKeyMaterialError) Error() string {
	return "diskimage/netboot: " + e.File + " is not public enrollment material, and a netboot set is served over HTTP; " +
		"keep the Secure Boot DB key in the KMS (secure-boot.resign-mode: remote, kms:// references)"
}
