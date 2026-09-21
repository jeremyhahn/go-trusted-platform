// Package virtkernel drives and verifies the virt kernel builder container
// (build/docker/virt-kernel-builder) that produces the aarch64 kernel the
// QEMU virt stand-in of the Raspberry Pi factory image boots.
//
// Alpine's aarch64 kernels carry no memory-mapped TIS driver, and the only
// TPM QEMU attaches to the virt machine is memory-mapped, so the emulated
// first boot needs a kernel of the platform's own: Alpine's version with
// CONFIG_TCG_TIS, signed modules and the lockdown LSM. Like pkg/diskimage/uboot,
// this package owns the cache key that ties an output to its inputs, the
// container invocation (through the runner seam) and the verification of
// what came back before it is staged onto install media.
package virtkernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
)

// Pinned upstream release; build/docker/virt-kernel-builder/Makefile carries
// the same values and TestPinsMatchBuilderMakefile keeps them equal. The
// version is Alpine 3.22's linux-lts version, so the stand-in boots the same
// kernel sources the Pi's linux-lts sibling ships.
const (
	DefaultVersion       = "6.12.110"
	DefaultTarballSHA256 = "8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c"
	// DefaultLocalVersion follows Alpine's flavour naming
	// (6.12.110-0-virt), so /lib/modules/<release> and vmlinuz-<flavor>
	// look exactly like a packaged kernel to the installer.
	DefaultLocalVersion = "-0-virt"
	// DefaultFlavor is the kernel flavour: vmlinuz-virt, modules-virt.tar.gz.
	DefaultFlavor = "virt"
	// Hint is the command that produces the artifacts.
	Hint = "run `make virt-kernel-build`"
)

// configInputs are the builder inputs, relative to the builder directory,
// in the order the cache key hashes them.
var configInputs = []string{
	"configs/virt.config",
	"build-virt-kernel.sh",
	"Dockerfile",
}

// ManifestName is the file the builder writes beside the flavour directory.
const ManifestName = "manifest.json"

// Manifest is build/docker/virt-kernel-builder/output/manifest.json.
type Manifest struct {
	Version       string `json:"kernel_version"`
	Release       string `json:"kernel_release"`
	TarballSHA256 string `json:"tarball_sha256"`
	CacheKey      string `json:"cache_key"`
	Flavor        string `json:"flavor"`
	BuiltAt       string `json:"built_at"`
}

// Artifacts is the verified build output.
type Artifacts struct {
	// Dir is the flavour's output directory.
	Dir string
	// Flavor is the kernel flavour (virt).
	Flavor string
	// Release is the kernel release string (6.12.110-0-virt), the name of
	// the modules directory.
	Release string
	// Kernel is the gzip-compressed Image the UKI wraps (vmlinuz-<flavor>).
	Kernel string
	// Modules is the tarball that unpacks at the target root
	// (lib/modules/<release>).
	Modules string
	// Config is the .config the kernel was built from.
	Config string
}

// Options configures Build.
type Options struct {
	// Runner runs docker; nil means runner.Exec.
	Runner runner.Runner
	// Runtime is the container runtime binary (default docker).
	Runtime string
	// BuilderDir is build/docker/virt-kernel-builder.
	BuilderDir string
	// OutputDir receives the artifacts (default <BuilderDir>/output).
	OutputDir string
	// CacheDir caches the upstream tarball between builds (optional).
	CacheDir string
	// Version, TarballSHA256, LocalVersion and Flavor pin the build; empty
	// means the defaults.
	Version       string
	TarballSHA256 string
	LocalVersion  string
	Flavor        string
	// Image is the builder image tag; empty means
	// trusted-platform-virt-kernel-builder:<version>.
	Image string
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.Runner == nil {
		out.Runner = runner.Exec
	}
	if out.Runtime == "" {
		out.Runtime = "docker"
	}
	if out.OutputDir == "" {
		out.OutputDir = filepath.Join(out.BuilderDir, "output")
	}
	if out.Version == "" {
		out.Version = DefaultVersion
	}
	if out.TarballSHA256 == "" {
		out.TarballSHA256 = DefaultTarballSHA256
	}
	if out.LocalVersion == "" {
		out.LocalVersion = DefaultLocalVersion
	}
	if out.Flavor == "" {
		out.Flavor = DefaultFlavor
	}
	if out.Image == "" {
		out.Image = "trusted-platform-virt-kernel-builder:" + out.Version
	}
	return out
}

// CacheKey derives the key that identifies a build by its inputs: the
// release version with its local version, then the Kconfig fragment, the
// build script and the Dockerfile. It is byte-for-byte the value
// `make cache-key` prints in the builder directory:
// "virt-kernel:<version><localversion>" then the hex sha256 of each input
// in configInputs order, one per line, hashed with sha256.
func CacheKey(builderDir, version, localVersion string) (string, error) {
	if version == "" {
		version = DefaultVersion
	}
	if localVersion == "" {
		localVersion = DefaultLocalVersion
	}
	h := sha256.New()
	if _, err := io.WriteString(h, "virt-kernel:"+version+localVersion+"\n"); err != nil {
		return "", err
	}
	for _, rel := range configInputs {
		path := filepath.Join(builderDir, rel)
		sum, err := artifacts.FileSHA256(path)
		if err != nil {
			return "", &InputError{Path: path, Err: err}
		}
		if _, err := io.WriteString(h, sum+"\n"); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Build produces the kernel artifacts unless the output directory already
// carries a manifest for exactly these inputs, then verifies and returns
// them. It builds the container image first so a changed Dockerfile or
// script is never masked by a stale image.
func Build(ctx context.Context, opts Options) (*Artifacts, error) {
	o := opts.withDefaults()
	key, err := CacheKey(o.BuilderDir, o.Version, o.LocalVersion)
	if err != nil {
		return nil, err
	}
	if manifest, err := ReadManifest(o.OutputDir); err == nil && manifest.CacheKey == key {
		if art, err := Locate(o.OutputDir, o.Flavor); err == nil {
			return art, nil
		}
	}
	if _, err := o.Runner(ctx, o.Runtime, "build", "-t", o.Image, o.BuilderDir); err != nil {
		return nil, &BuildError{Step: "building the builder image", Err: err}
	}
	if err := os.MkdirAll(o.OutputDir, 0o755); err != nil {
		return nil, &BuildError{Step: "creating the output directory", Err: err}
	}
	args := []string{"run", "--rm",
		"-v", artifacts.AbsPath(o.OutputDir) + ":/output",
		"-v", artifacts.AbsPath(filepath.Join(o.BuilderDir, "configs")) + ":/configs:ro",
	}
	if o.CacheDir != "" {
		if err := os.MkdirAll(o.CacheDir, 0o755); err != nil {
			return nil, &BuildError{Step: "creating the tarball cache directory", Err: err}
		}
		args = append(args, "-v", artifacts.AbsPath(o.CacheDir)+":/build/src")
	}
	args = append(args,
		"-e", "KERNEL_VERSION="+o.Version,
		"-e", "KERNEL_SHA256="+o.TarballSHA256,
		"-e", "KERNEL_LOCALVERSION="+o.LocalVersion,
		"-e", "KERNEL_FLAVOR="+o.Flavor,
		"-e", "KERNEL_CACHE_KEY="+key,
		o.Image,
	)
	if _, err := o.Runner(ctx, o.Runtime, args...); err != nil {
		return nil, &BuildError{Step: "running the builder", Err: err}
	}
	manifest, err := ReadManifest(o.OutputDir)
	if err != nil {
		return nil, err
	}
	if manifest.CacheKey != key {
		return nil, &ManifestError{Path: filepath.Join(o.OutputDir, ManifestName),
			Err: errors.New("cache key " + manifest.CacheKey + " does not match the inputs (" + key + ")")}
	}
	return Locate(o.OutputDir, o.Flavor)
}

// ReadManifest parses <outputDir>/manifest.json.
func ReadManifest(outputDir string) (*Manifest, error) {
	path := filepath.Join(outputDir, ManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ManifestError{Path: path, Err: err}
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &ManifestError{Path: path, Err: err}
	}
	if m.Version == "" || m.CacheKey == "" || m.Release == "" {
		return nil, &ManifestError{Path: path, Err: errors.New("kernel_version, kernel_release and cache_key are required")}
	}
	return &m, nil
}

// Locate finds the flavour's artifacts under outputDir and verifies every
// file against SHA256SUMS before returning them.
func Locate(outputDir, flavor string) (*Artifacts, error) {
	if flavor == "" {
		flavor = DefaultFlavor
	}
	dir := filepath.Join(outputDir, flavor)
	kernel := filepath.Join(dir, "vmlinuz-"+flavor)
	if _, err := os.Stat(kernel); err != nil {
		return nil, &artifacts.MissingError{Path: kernel, Hint: Hint}
	}
	if err := artifacts.VerifyChecksums(dir, Hint); err != nil {
		return nil, err
	}
	release, err := os.ReadFile(filepath.Join(dir, "kernel-version.txt"))
	if err != nil {
		return nil, &artifacts.MissingError{Path: filepath.Join(dir, "kernel-version.txt"), Hint: Hint}
	}
	modules := filepath.Join(dir, "modules-"+flavor+".tar.gz")
	if _, err := os.Stat(modules); err != nil {
		return nil, &artifacts.MissingError{Path: modules, Hint: Hint}
	}
	return &Artifacts{
		Dir:     dir,
		Flavor:  flavor,
		Release: trimNewline(string(release)),
		Kernel:  kernel,
		Modules: modules,
		Config:  filepath.Join(dir, "config-"+flavor),
	}, nil
}

// trimNewline drops the trailing newline kernel-version.txt carries.
func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
