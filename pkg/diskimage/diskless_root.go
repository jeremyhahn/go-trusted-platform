package diskimage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// DisklessRootHashFile carries the root hash veritysetup printed, from the
	// in-container step to the host, which signs it into the manifest.
	DisklessRootHashFile = "rootfs.roothash"
	// disklessImageFile is the scratch image the installer lays the root on.
	disklessImageFile = "rootfs.img"
	// disklessRootPartition is the root partition of an unencrypted ext4
	// install: partition 1 is the ESP, partition 2 the root.
	disklessRootPartition = 2
	// disklessFstab replaces the installer's fstab: the installed one mounts
	// the disk's partitions by UUID, and a diskless node has no disk.
	disklessFstab = "# Diskless node: / is a dm-verity squashfs under a tmpfs overlay.\n" +
		"# There is no local disk to mount.\n"
)

// disklessDebugReason is why --debug cannot build a diskless root: debug mode
// enables SSH root login and generates SSH host keys, and the root is one
// public image every node boots.
const disklessDebugReason = "debug mode (SSH root login, host keys) cannot be baked into the shared public root"

// disklessRequiredPaths are what makes the squashfs a bootable platform root:
// the init the initramfs switches to and the daemon it starts. They are checked
// in the mounted tree and again in the finished image's listing.
var disklessRequiredPaths = []string{"sbin/init", "usr/bin/platformd"}

// DisklessRootOptions configures the in-container diskless root build.
type DisklessRootOptions struct {
	// Config is the installer configuration the media was built for. The
	// build installs it unencrypted onto ext4: the root is read-only and
	// integrity-protected by dm-verity, but public, so the build refuses a
	// platform config whose secret fields hold plaintext rather than secret
	// references (refuseRootConfigSecrets).
	Config *installer.Config
	// SizeMB is the scratch image the install is laid onto.
	SizeMB int
	// WorkDir holds the scratch image and its mount point.
	WorkDir string
	// OutputDir receives rootfs.squashfs, rootfs.verity and rootfs.roothash.
	OutputDir string
	// SourceDateEpoch is every timestamp in the squashfs.
	SourceDateEpoch int64
	// Salt is the verity salt (disklessroot.DeriveSalt).
	Salt string
	// Runner runs losetup, mount, mksquashfs, unsquashfs and veritysetup; nil
	// means runner.Exec.
	Runner runner.Runner
	// Logger receives the installer's log; nil means the default logger.
	Logger *logging.Logger
	// assemble installs onto the scratch image; nil means Assemble.
	assemble func(ctx context.Context, opts AssembleOptions) (*AssembleResult, error)
	// allocateLoop returns a free loop device; nil means loop-control.
	allocateLoop func() (string, error)
}

// DisklessRoot is the generated squashfs root and its dm-verity hash tree.
type DisklessRoot struct {
	RootFS string
	Verity string
	// Manifest is what the build states about them; the host signs it.
	Manifest disklessroot.Manifest
}

// DisklessRootInputError reports a missing or invalid diskless root input.
type DisklessRootInputError struct {
	Field  string
	Reason string
}

func (e DisklessRootInputError) Error() string {
	if e.Reason == "" {
		return "diskless root: missing " + e.Field
	}
	return "diskless root: " + e.Field + ": " + e.Reason
}

// DisklessRootHashError reports veritysetup output without a valid root hash.
type DisklessRootHashError struct {
	Output string
	Err    error
}

func (e DisklessRootHashError) Error() string {
	if e.Err == nil {
		return "diskless root: veritysetup output did not include a root hash"
	}
	return "diskless root: invalid verity root hash " + strconv.Quote(e.Output) + ": " + e.Err.Error()
}

func (e DisklessRootHashError) Unwrap() error { return e.Err }

// DisklessRootContentError reports a root that would not boot: a path the
// node needs is missing from the installed tree or from the squashfs.
type DisklessRootContentError struct {
	Where string
	Path  string
}

func (e DisklessRootContentError) Error() string {
	return "diskless root: " + e.Where + " has no /" + e.Path
}

// validate checks the options GenerateDisklessRoot cannot default.
func (opts *DisklessRootOptions) validate() error {
	switch {
	case opts.Config == nil:
		return DisklessRootInputError{Field: "installer configuration"}
	case opts.WorkDir == "":
		return DisklessRootInputError{Field: "work directory"}
	case opts.OutputDir == "":
		return DisklessRootInputError{Field: "output directory"}
	case opts.SourceDateEpoch < 0:
		return DisklessRootInputError{Field: "source date epoch", Reason: "must not be negative"}
	case opts.Config.Debug:
		return DisklessRootInputError{Field: "debug", Reason: disklessDebugReason}
	}
	return disklessroot.ValidateSalt(opts.Salt)
}

// GenerateDisklessRoot builds the diskless root inside the builder container.
// It installs the platform onto a scratch image, the same install a disk node
// gets but unencrypted, takes the root partition's tree, and packs it into a
// reproducible squashfs with a dm-verity hash tree. The verity parameters are
// disklessroot's constants and the salt is derived from the release, so two
// builds of the same tree produce the same root hash.
func GenerateDisklessRoot(ctx context.Context, opts DisklessRootOptions) (*DisklessRoot, error) {
	if err := opts.validate(); err != nil {
		return nil, &StageError{Step: "diskless root", Err: err}
	}
	run := opts.Runner
	if run == nil {
		run = runner.Exec
	}
	logger := opts.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	assemble := opts.assemble
	if assemble == nil {
		assemble = Assemble
	}
	allocateLoop := opts.allocateLoop
	if allocateLoop == nil {
		allocateLoop = func() (string, error) { return allocateLoopDevice(loopControlPath) }
	}
	for _, dir := range []string{opts.WorkDir, opts.OutputDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, &StageError{Step: "creating " + dir, Err: err}
		}
	}

	image := filepath.Join(opts.WorkDir, disklessImageFile)
	if _, err := assemble(ctx, AssembleOptions{
		Config: disklessInstallConfig(opts.Config),
		Output: image,
		SizeMB: opts.SizeMB,
		Runner: run,
		Logger: logger,
	}); err != nil {
		return nil, &StageError{Step: "installing the diskless root", Err: err}
	}
	out := &DisklessRoot{
		RootFS: filepath.Join(opts.OutputDir, disklessroot.RootFSFile),
		Verity: filepath.Join(opts.OutputDir, disklessroot.VerityFile),
	}
	if err := squashImageRoot(ctx, run, allocateLoop, image, filepath.Join(opts.WorkDir, "root"), out.RootFS, opts.SourceDateEpoch); err != nil {
		return nil, err
	}
	if err := os.Remove(image); err != nil {
		return nil, &StageError{Step: "removing the scratch image", Err: err}
	}
	if err := checkSquashfsListing(ctx, run, out.RootFS); err != nil {
		return nil, err
	}
	rootHash, err := formatVerity(ctx, run, out.RootFS, out.Verity, opts.Salt)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(opts.OutputDir, DisklessRootHashFile), []byte(rootHash+"\n"), 0o644); err != nil {
		return nil, &StageError{Step: "writing the verity root hash", Err: err}
	}
	manifest, err := disklessManifest(out, rootHash, opts.Salt)
	if err != nil {
		return nil, err
	}
	out.Manifest = manifest
	return out, nil
}

// disklessInstallConfig is the installer configuration for the diskless root:
// the media's, with the disk unencrypted ext4 and no TPM sealing, because the
// root is never a disk and holds no secret to seal. Secure Boot is off: the
// install signs nothing the root carries (the UKI is on the ESP, which is not
// packed), and with it on the installer would generate a DB key onto the root
// it is about to publish. A diskless node's UKI is signed when the node is
// installed, never from this image.
func disklessInstallConfig(base *installer.Config) *installer.Config {
	cfg := *base
	disk := installer.DiskConfig{}
	if base.Disk != nil {
		disk = *base.Disk
	}
	disk.Encryption = nil
	disk.RootFilesystem = installer.FilesystemExt4
	cfg.Disk = &disk
	cfg.EnableTPMSealing = false
	if base.SecureBoot != nil {
		sb := *base.SecureBoot
		sb.Enabled = false
		sb.Enforce = false
		cfg.SecureBoot = &sb
	}
	return &cfg
}

// squashImageRoot attaches the image's root partition, makes the installed
// tree diskless, checks it boots, and packs it into rootfs. The partition is
// unmounted and detached whatever happens.
func squashImageRoot(ctx context.Context, run runner.Runner, allocateLoop func() (string, error), image, mountDir, rootfs string, epoch int64) error {
	offset, size, err := rootPartitionExtent(image)
	if err != nil {
		return &StageError{Step: "reading the scratch image's partition table", Err: err}
	}
	loop, err := allocateLoop()
	if err != nil {
		return &StageError{Step: "allocating a loop device", Err: err}
	}
	if _, err := run(ctx, "losetup", "--offset", strconv.FormatInt(offset, 10), "--sizelimit", strconv.FormatInt(size, 10), loop, image); err != nil {
		return &StageError{Step: "attaching the root partition", Err: err}
	}
	err = squashMountedRoot(ctx, run, loop, mountDir, rootfs, epoch)
	if _, detachErr := run(context.WithoutCancel(ctx), "losetup", "--detach", loop); detachErr != nil && err == nil {
		err = &StageError{Step: "detaching the root partition", Err: detachErr}
	}
	return err
}

// squashMountedRoot mounts the attached root partition and packs it.
func squashMountedRoot(ctx context.Context, run runner.Runner, loop, mountDir, rootfs string, epoch int64) error {
	if err := os.MkdirAll(mountDir, 0o755); err != nil {
		return &StageError{Step: "creating the root mount point", Err: err}
	}
	if _, err := run(ctx, "mount", "-t", "ext4", loop, mountDir); err != nil {
		return &StageError{Step: "mounting the root partition", Err: err}
	}
	err := lockRootAccounts(mountDir)
	if err != nil {
		err = &StageError{Step: "locking the installed root's accounts", Err: err}
	} else {
		err = packRoot(ctx, run, mountDir, rootfs, epoch)
	}
	if _, umountErr := run(context.WithoutCancel(ctx), "umount", mountDir); umountErr != nil && err == nil {
		err = &StageError{Step: "unmounting the root partition", Err: umountErr}
	}
	return err
}

// packRoot makes the mounted tree diskless, checks it boots and holds no
// private key, and runs mksquashfs over it. -reproducible with fixed mkfs and file times makes the
// image a function of the tree alone; mksquashfs sorts directory entries
// itself. Ownership is kept: the tree is the installed system's.
func packRoot(ctx context.Context, run runner.Runner, root, rootfs string, epoch int64) error {
	if err := os.WriteFile(filepath.Join(root, "etc", "fstab"), []byte(disklessFstab), 0o644); err != nil {
		return &StageError{Step: "writing the diskless fstab", Err: err}
	}
	for _, p := range disklessRequiredPaths {
		if _, err := os.Lstat(filepath.Join(root, p)); err != nil {
			return &StageError{Step: "checking the installed root", Err: DisklessRootContentError{Where: "the installed root", Path: p}}
		}
	}
	if err := refuseRootPrivateKeys(root); err != nil {
		return &StageError{Step: "checking the installed root for private keys", Err: err}
	}
	if err := refuseRootCredentials(root); err != nil {
		return &StageError{Step: "checking the installed root for passwords", Err: err}
	}
	if err := refuseRootConfigSecrets(root); err != nil {
		return &StageError{Step: "checking the installed root's platform config for plaintext secrets", Err: err}
	}
	stamp := strconv.FormatInt(epoch, 10)
	if _, err := run(ctx, "mksquashfs", root, rootfs,
		"-noappend", "-comp", "xz", "-reproducible",
		"-mkfs-time", stamp, "-all-time", stamp); err != nil {
		return &StageError{Step: "mksquashfs", Err: err}
	}
	return nil
}

// checkSquashfsListing lists the finished squashfs and requires every path
// the node boots from: what is checked is the artifact, not the tree it came
// from.
func checkSquashfsListing(ctx context.Context, run runner.Runner, rootfs string) error {
	listing, err := run(ctx, "unsquashfs", "-l", rootfs)
	if err != nil {
		return &StageError{Step: "listing the squashfs", Err: err}
	}
	entries := map[string]bool{}
	for _, line := range strings.Split(string(listing), "\n") {
		entries[strings.TrimSpace(line)] = true
	}
	for _, p := range disklessRequiredPaths {
		if !entries["squashfs-root/"+p] {
			return &StageError{Step: "checking the squashfs", Err: DisklessRootContentError{Where: "the squashfs", Path: p}}
		}
	}
	return nil
}

// formatVerity formats the hash tree with the pinned parameters and no
// superblock, so nothing on the network can choose them, and returns the root
// hash it printed.
func formatVerity(ctx context.Context, run runner.Runner, rootfs, verity, salt string) (string, error) {
	info, err := os.Stat(rootfs)
	if err != nil {
		return "", &StageError{Step: "reading the squashfs", Err: err}
	}
	if info.Size() == 0 || info.Size()%disklessroot.BlockSize != 0 {
		return "", &StageError{Step: "reading the squashfs", Err: DisklessRootInputError{Field: "squashfs size", Reason: "must be a positive multiple of " + strconv.Itoa(disklessroot.BlockSize)}}
	}
	block := strconv.Itoa(disklessroot.BlockSize)
	output, err := run(ctx, "veritysetup", "format", "--no-superblock",
		"--hash", disklessroot.HashAlgorithm,
		"--data-block-size", block, "--hash-block-size", block,
		"--salt", salt, rootfs, verity)
	if err != nil {
		return "", &StageError{Step: "veritysetup format", Err: err}
	}
	rootHash, err := parseVerityRootHash(string(output))
	if err != nil {
		return "", &StageError{Step: "reading the verity root hash", Err: err}
	}
	return rootHash, nil
}

// disklessManifest states the built artifacts: the root hash, the salt and
// both sizes.
func disklessManifest(out *DisklessRoot, rootHash, salt string) (disklessroot.Manifest, error) {
	m := disklessroot.Manifest{Version: disklessroot.ManifestVersion, RootHash: rootHash, Salt: salt}
	for _, f := range []struct {
		path string
		size *int64
	}{{out.RootFS, &m.RootFSSize}, {out.Verity, &m.VeritySize}} {
		info, err := os.Stat(f.path)
		if err != nil {
			return disklessroot.Manifest{}, &StageError{Step: "reading the diskless root output", Err: err}
		}
		*f.size = info.Size()
	}
	if err := m.Validate(); err != nil {
		return disklessroot.Manifest{}, &StageError{Step: "validating the diskless root manifest", Err: err}
	}
	return m, nil
}

// rootPartitionExtent is the byte offset and size of the image's root
// partition, from its MBR: U-Boot targets partition with MBR.
func rootPartitionExtent(image string) (int64, int64, error) {
	f, err := os.Open(image)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sector := make([]byte, sectorSize)
	if _, err := io.ReadFull(f, sector); err != nil {
		return 0, 0, err
	}
	parts, err := ParseMBR(sector)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range parts {
		if p.Index == disklessRootPartition {
			return int64(p.StartLBA) * sectorSize, int64(p.Sectors) * sectorSize, nil
		}
	}
	return 0, 0, DisklessRootInputError{Field: "scratch image", Reason: "has no partition " + strconv.Itoa(disklessRootPartition)}
}

// parseVerityRootHash finds the "Root hash:" line veritysetup format prints.
func parseVerityRootHash(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Root hash") {
			continue
		}
		hash := strings.TrimSpace(value)
		if err := disklessroot.ValidateRootHash(hash); err != nil {
			return "", DisklessRootHashError{Output: hash, Err: err}
		}
		return hash, nil
	}
	return "", DisklessRootHashError{}
}

// BuildDisklessRoot runs the diskless-root step in the builder container and
// signs its manifest on the host with the Secure Boot DB key: the container
// never holds a key. The artifacts land in outDir, the set's directory the
// boot server serves; the signed manifest in manifestDir, inside the install
// media, where the installer verifies it against the DB certificate. Inputs
// and outputs move by copy through the container runtime, never by host bind
// mount.
func (s *StagedMedia) BuildDisklessRoot(ctx context.Context, outDir, manifestDir string, sourceDateEpoch int64, version string) (*DisklessRoot, error) {
	if s.Target == nil || s.config == nil || s.MediaDir == "" {
		return nil, &StageError{Step: "diskless root", Err: DisklessRootInputError{Field: "staged media"}}
	}
	if s.SecureBoot == nil || s.SecureBoot.DBKey == nil {
		return nil, &StageError{Step: "diskless root", Err: DisklessRootInputError{Field: "Secure Boot DB key", Reason: "the manifest is signed with it; build with Secure Boot on"}}
	}
	if version == "" {
		return nil, &StageError{Step: "diskless root", Err: DisklessRootInputError{Field: "version"}}
	}
	if sourceDateEpoch < 0 {
		return nil, &StageError{Step: "diskless root", Err: DisklessRootInputError{Field: "source date epoch", Reason: "must not be negative"}}
	}
	c := s.config
	if c.ISO.Debug {
		return nil, &StageError{Step: "diskless root", Err: DisklessRootInputError{Field: "debug", Reason: disklessDebugReason}}
	}
	salt := disklessroot.DeriveSalt(sourceDateEpoch, version)
	targetArch := goArchOf(string(s.Target.Architecture()))
	arch := "linux/" + targetArch
	image := c.builderImageFor(targetArch)
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return nil, &StageError{Step: "resolving the diskless root output directory", Err: err}
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return nil, &StageError{Step: "creating the diskless root output directory", Err: err}
	}
	absMedia, err := filepath.Abs(s.MediaDir)
	if err != nil {
		return nil, &StageError{Step: "resolving the media directory", Err: err}
	}
	if _, err := c.Runner(ctx, c.ContainerRuntime, "build", "--platform", arch, "-t", image, c.BuilderDir); err != nil {
		return nil, &StageError{Step: "building the builder container image", Err: err}
	}
	command := []string{
		containerMediaMount + "/platformd-bin/platformctl-static", "diskimage", "diskless-root",
		"--platform-config", containerMediaMount + "/configs/" + bakedPlatformConfigName,
		"--size", strconv.Itoa(c.SizeMB),
		"--work-dir", containerWorkMount,
		"--output", containerOutputMount,
		"--source-date-epoch", strconv.FormatInt(sourceDateEpoch, 10),
		"--salt", salt,
	}
	// Privileged for the loop device and the mounts, as the assemble step.
	container := runner.Container{
		Image:      image,
		CreateArgs: []string{"--privileged", "--platform", arch, "-v", containerWorkMount, "-v", containerOutputMount},
		Command:    command,
		In:         []runner.Copy{{Host: absMedia, Container: containerMediaMount}},
		Out:        []runner.Copy{{Host: absOut, Container: containerOutputMount}},
	}
	if err := container.Run(ctx, c.Runner, c.ContainerRuntime); err != nil {
		return nil, &StageError{Step: "running the diskless root step", Err: err}
	}
	out := &DisklessRoot{
		RootFS: filepath.Join(absOut, disklessroot.RootFSFile),
		Verity: filepath.Join(absOut, disklessroot.VerityFile),
	}
	hashFile := filepath.Join(absOut, DisklessRootHashFile)
	hashBytes, err := os.ReadFile(hashFile)
	if err != nil {
		return nil, &StageError{Step: "reading the verity root hash", Err: err}
	}
	// The hash file is the container's hand-off, not a served artifact: the
	// signed manifest is the only place the root hash is published.
	if err := os.Remove(hashFile); err != nil {
		return nil, &StageError{Step: "removing the verity root hash hand-off", Err: err}
	}
	manifest, err := disklessManifest(out, string(bytes.TrimSpace(hashBytes)), salt)
	if err != nil {
		return nil, err
	}
	if err := disklessroot.WriteSigned(manifestDir, manifest, s.SecureBoot.DBKey); err != nil {
		return nil, &StageError{Step: "signing the diskless root manifest", Err: err}
	}
	out.Manifest = manifest
	return out, nil
}
