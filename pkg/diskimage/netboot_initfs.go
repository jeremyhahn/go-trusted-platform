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

package diskimage

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
)

// NetbootInitfsFeatures are the mkinitfs features of Alpine's own netboot
// initramfs (aports scripts/mkimg.netboot.sh, every architecture but s390x):
// enough to bring the network up, fetch the modloop and mount the live
// root over HTTP.
const NetbootInitfsFeatures = "base network squashfs usb virtio"

// Where the netboot initfs step reads the kernel artifacts and writes its
// output inside the builder container.
const (
	containerKernelMount = "/kernel"
	containerOutputMount = "/out"
)

// NetbootInitfsOptions configure GenerateNetbootInitfs, the in-container
// step that builds a netboot initramfs and modloop for a platform-built
// kernel.
type NetbootInitfsOptions struct {
	// Modules is the kernel's modules tarball (lib/modules/<release>).
	Modules string
	// Release is the kernel release (the modules directory's name).
	Release string
	// Flavour names the outputs: initramfs-<flavour>, modloop-<flavour>.
	Flavour string
	// OutputDir receives both.
	OutputDir string
	// Root is the filesystem root the modules are installed under for
	// mkinitfs (default "/", the container's).
	Root string
	// Runner runs mkinitfs and mksquashfs; nil means runner.Exec.
	Runner runner.Runner
}

// NetbootInitfs names the generated files.
type NetbootInitfs struct {
	Initramfs, Modloop string
}

// GenerateNetbootInitfs builds, inside the arm64 builder container, what
// Alpine's netboot release carries for its own kernels but not for the
// platform's: an initramfs with Alpine's netboot features for the kernel's
// modules, and the modloop — a squashfs with modules/<release>/ at its root,
// the layout Alpine's init mounts. Neither is signed: like the initramfs,
// the modloop is fetched over the provisioning network, the boundary the
// netboot install already assumes.
func GenerateNetbootInitfs(ctx context.Context, opts NetbootInitfsOptions) (*NetbootInitfs, error) {
	if opts.Modules == "" || opts.Release == "" || opts.Flavour == "" || opts.OutputDir == "" {
		return nil, &StageError{Step: "netboot initfs", Err: errMissingInitfsInput}
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}
	run := opts.Runner
	if run == nil {
		run = runner.Exec
	}
	prefix := "lib/modules/" + opts.Release + "/"
	all := func(string) bool { return true }
	modulesDir := filepath.Join(root, "lib", "modules", opts.Release)
	if _, err := artifacts.ExtractTarGz(opts.Modules, prefix, modulesDir, all); err != nil {
		return nil, &StageError{Step: "installing the kernel modules", Err: err}
	}
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, &StageError{Step: "creating the output directory", Err: err}
	}

	out := &NetbootInitfs{
		Initramfs: filepath.Join(opts.OutputDir, "initramfs-"+opts.Flavour),
		Modloop:   filepath.Join(opts.OutputDir, "modloop-"+opts.Flavour),
	}
	if _, err := run(ctx, "mkinitfs", "-b", root, "-F", NetbootInitfsFeatures, "-o", out.Initramfs, opts.Release); err != nil {
		return nil, &StageError{Step: "mkinitfs", Err: err}
	}

	if err := buildModloop(ctx, run, opts.Modules, prefix, opts.Release, out.Modloop); err != nil {
		return nil, err
	}
	return out, nil
}

// buildModloop squashes the modules into modloop: modules/<release>/ at the
// squashfs root, from a scratch tree that is removed afterwards.
func buildModloop(ctx context.Context, run runner.Runner, modules, prefix, release, modloop string) (err error) {
	tree, err := os.MkdirTemp("", "modloop-")
	if err != nil {
		return &StageError{Step: "creating the modloop tree", Err: err}
	}
	defer func() {
		if rmErr := os.RemoveAll(tree); rmErr != nil && err == nil {
			err = &StageError{Step: "removing the modloop tree", Err: rmErr}
		}
	}()
	if _, err := artifacts.ExtractTarGz(modules, prefix, filepath.Join(tree, "modules", release), func(string) bool { return true }); err != nil {
		return &StageError{Step: "laying out the modloop", Err: err}
	}
	if _, err := run(ctx, "mksquashfs", tree, modloop, "-comp", "xz", "-noappend", "-all-root"); err != nil {
		return &StageError{Step: "mksquashfs", Err: err}
	}
	return nil
}

// BuildNetbootInitfs generates the netboot initramfs and modloop for the
// staged media's platform-built kernel into outDir, running
// GenerateNetbootInitfs in the arm64 builder container (the kernel builder
// cross-compiles on the host, so its container cannot run the target's
// mkinitfs). It is an error for a target on a packaged kernel.
func (s *StagedMedia) BuildNetbootInitfs(ctx context.Context, outDir string) (*NetbootInitfs, error) {
	if s.Kernel == nil {
		return nil, &StageError{Step: "netboot initfs", Err: errNoBuiltKernel}
	}
	c := s.config
	arch := "linux/" + goArchOf(string(s.Target.Architecture()))
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return nil, &StageError{Step: "resolving the output directory", Err: err}
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return nil, &StageError{Step: "creating the output directory", Err: err}
	}
	absMedia, err := filepath.Abs(s.MediaDir)
	if err != nil {
		return nil, &StageError{Step: "resolving the media directory", Err: err}
	}
	absKernel, err := filepath.Abs(s.Kernel.Dir)
	if err != nil {
		return nil, &StageError{Step: "resolving the kernel directory", Err: err}
	}
	if _, err := c.Runner(ctx, c.ContainerRuntime, "build", "--platform", arch, "-t", c.BuilderImage, c.BuilderDir); err != nil {
		return nil, &StageError{Step: "building the builder container image", Err: err}
	}
	flavour := s.Kernel.Flavor
	// Inputs go in and the initramfs and modloop come out with cp, not bind
	// mounts: the daemon may not share this process's filesystem (CI job
	// container).
	container := runner.Container{
		Image:      c.BuilderImage,
		CreateArgs: []string{"--platform", arch, "-v", containerOutputMount},
		Command: []string{
			containerMediaMount + "/platformd-bin/platformctl-static", "diskimage", "netboot-initfs",
			"--modules", containerKernelMount + "/" + filepath.Base(s.Kernel.Modules),
			"--release", s.Kernel.Release,
			"--flavour", flavour,
			"--output", containerOutputMount,
		},
		In: []runner.Copy{
			{Host: absMedia, Container: containerMediaMount},
			{Host: absKernel, Container: containerKernelMount},
		},
		Out: []runner.Copy{{Host: absOut, Container: containerOutputMount}},
	}
	if err := container.Run(ctx, c.Runner, c.ContainerRuntime); err != nil {
		return nil, &StageError{Step: "running the netboot initfs step", Err: err}
	}
	out := &NetbootInitfs{
		Initramfs: filepath.Join(absOut, "initramfs-"+flavour),
		Modloop:   filepath.Join(absOut, "modloop-"+flavour),
	}
	for _, p := range []string{out.Initramfs, out.Modloop} {
		if _, err := os.Stat(p); err != nil {
			return nil, &StageError{Step: "reading the netboot initfs output", Err: err}
		}
	}
	return out, nil
}

// errMissingInitfsInput is a netboot initfs step without its modules,
// release, flavour or output directory.
var errMissingInitfsInput = &configError{"the netboot initfs step needs the modules tarball, the kernel release, the flavour and an output directory"}

// errNoBuiltKernel is a netboot initfs request for a target on a packaged
// kernel: its initramfs and modloop come with the kernel's package.
var errNoBuiltKernel = &configError{"the target boots a packaged kernel; only a platform-built kernel needs a generated netboot initfs"}
