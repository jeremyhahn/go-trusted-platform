// Package uboot drives and verifies the U-Boot builder container
// (build/docker/uboot-builder) that produces the boot firmware of the
// Raspberry Pi factory image and of its QEMU stand-in.
//
// The builder is a Makefile-driven container; this package owns the parts a
// Go caller needs: the cache key that ties an output to its inputs, the
// container invocation (through the runner seam so it is unit-testable), and
// the verification of what came back before any of it is staged onto an EFI
// partition.
package uboot

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
)

// Board is a U-Boot board configuration the builder produces.
type Board string

const (
	// BoardRPiArm64 is loaded by the Raspberry Pi firmware as kernel8.img.
	BoardRPiArm64 Board = "rpi_arm64"
	// BoardQEMUArm64 is the QEMU virt machine firmware for emulated boots.
	BoardQEMUArm64 Board = "qemu_arm64"
)

// Boards lists every board the builder produces, in build order.
var Boards = []Board{BoardRPiArm64, BoardQEMUArm64}

// Pinned upstream release; build/docker/uboot-builder/Makefile carries the
// same values and TestPinsMatchBuilderMakefile keeps them equal.
const (
	DefaultVersion       = "2026.07"
	DefaultTarballSHA256 = "78e8bfc382fe388f9b55aa1daf8c563522a037779b5d4c349d1415e381f1243e"
	// DefaultOwnerGUID is the SignatureOwner written into the preseeded
	// PK/KEK/db lists.
	DefaultOwnerGUID = "7e5a1c6e-0b3f-4a5e-9c2d-3f1a2b4c5d6e"
	// DefaultCacheVolume is the docker volume holding the upstream tarball;
	// it is the CACHE_VOLUME default of build/docker/uboot-builder/Makefile,
	// so `make` and this package share one cache.
	DefaultCacheVolume = "trusted-platform-uboot-src"
)

// Certificate file names the builder reads from the keys directory: the
// same names pkg/iso stages on the install media.
var certificateFiles = []string{"PK.crt", "KEK.crt", "DB.crt"}

// configInputs are the builder inputs, relative to the builder directory,
// in the order the cache key hashes them.
var configInputs = []string{
	"configs/common-efi.config",
	"configs/rpi_arm64-tpm.config",
	"configs/qemu_arm64-tpm.config",
	"configs/tpm-soft-spi.dts",
	"patches/0001-mbedtls-glue-return-errno-for-parse-failures.patch",
	// The builder itself: a change to the image recipe, the build script
	// or the ESL writer changes the binary as surely as a fragment does.
	"Dockerfile",
	"build-uboot.sh",
	"mkesl.py",
}

// ManifestName is the file the builder writes beside the board directories.
const ManifestName = "manifest.json"

// Manifest is build/docker/uboot-builder/output/manifest.json.
type Manifest struct {
	Version       string   `json:"uboot_version"`
	TarballSHA256 string   `json:"tarball_sha256"`
	CacheKey      string   `json:"cache_key"`
	OwnerGUID     string   `json:"owner_guid"`
	Boards        []string `json:"boards"`
	MeasuredPCRs  []int    `json:"measured_pcrs"`
	BuiltAt       string   `json:"built_at"`
}

// Artifacts is one board's verified build output.
type Artifacts struct {
	Board Board
	// Dir is the board's output directory.
	Dir string
	// Binary is u-boot.bin.
	Binary string
	// Config is the resolved .config the binary was built from.
	Config string
	// OverlaysDir holds the compiled device-tree overlays (rpi_arm64 only).
	OverlaysDir string
}

// Options configures Build.
type Options struct {
	// Runner runs docker; nil means runner.Exec.
	Runner runner.Runner
	// Runtime is the container runtime binary (default docker).
	Runtime string
	// BuilderDir is build/docker/uboot-builder.
	BuilderDir string
	// OutputDir receives the artifacts (default <BuilderDir>/output).
	OutputDir string
	// KeysDir holds PK.crt, KEK.crt and DB.crt.
	KeysDir string
	// CacheVolume is the named docker volume that caches the upstream
	// tarball between builds; empty means DefaultCacheVolume, the volume
	// `make build` in the builder directory uses.
	CacheVolume string
	// Version and TarballSHA256 pin the upstream release; empty means the
	// defaults.
	Version       string
	TarballSHA256 string
	// OwnerGUID is the SignatureOwner of the preseeded lists; empty means
	// DefaultOwnerGUID.
	OwnerGUID string
	// Image is the builder image tag; empty means
	// trusted-platform-uboot-builder:<version>.
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
	if out.CacheVolume == "" {
		out.CacheVolume = DefaultCacheVolume
	}
	if out.Version == "" {
		out.Version = DefaultVersion
	}
	if out.TarballSHA256 == "" {
		out.TarballSHA256 = DefaultTarballSHA256
	}
	if out.OwnerGUID == "" {
		out.OwnerGUID = DefaultOwnerGUID
	}
	if out.Image == "" {
		out.Image = "trusted-platform-uboot-builder:" + out.Version
	}
	return out
}

// CacheKey derives the key that identifies a build by its inputs: the
// release version, the Kconfig fragments, the overlay source and the three
// certificates. It is byte-for-byte the value `make cache-key` prints in
// the builder directory: "uboot:<version>" then the hex sha256 of each input
// in configInputs order followed by certificateFiles order, one per line,
// hashed with sha256.
func CacheKey(builderDir, keysDir, version, ownerGUID string) (string, error) {
	if version == "" {
		version = DefaultVersion
	}
	if ownerGUID == "" {
		ownerGUID = DefaultOwnerGUID
	}
	h := sha256.New()
	if _, err := io.WriteString(h, "uboot:"+version+"\nowner:"+ownerGUID+"\n"); err != nil {
		return "", err
	}
	var inputs []string
	for _, rel := range configInputs {
		inputs = append(inputs, filepath.Join(builderDir, rel))
	}
	for _, name := range certificateFiles {
		inputs = append(inputs, filepath.Join(keysDir, name))
	}
	for _, path := range inputs {
		sum, err := fileSHA256(path)
		if err != nil {
			return "", &InputError{Path: path, Err: err}
		}
		if _, err := io.WriteString(h, sum+"\n"); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Build produces the U-Boot artifacts unless the output directory already
// carries a manifest for exactly these inputs, then verifies and returns
// them. It builds the container image first so a changed Dockerfile or
// script is never masked by a stale image.
func Build(ctx context.Context, opts Options) (map[Board]Artifacts, error) {
	o := opts.withDefaults()
	key, err := CacheKey(o.BuilderDir, o.KeysDir, o.Version, o.OwnerGUID)
	if err != nil {
		return nil, err
	}
	if manifest, err := ReadManifest(o.OutputDir); err == nil && manifest.CacheKey == key {
		if artifacts, err := Locate(o.OutputDir); err == nil {
			return artifacts, nil
		}
	}

	if _, err := o.Runner(ctx, o.Runtime, "build", "-t", o.Image, o.BuilderDir); err != nil {
		return nil, &BuildError{Step: "building the builder image", Err: err}
	}
	if err := os.MkdirAll(o.OutputDir, 0o755); err != nil {
		return nil, &BuildError{Step: "creating the output directory", Err: err}
	}
	// Inputs go in and artifacts come out with cp, not bind mounts: the daemon
	// may not share this process's filesystem (CI job container). The tarball
	// cache is a named volume the daemon owns.
	container := runner.Container{
		Image: o.Image,
		CreateArgs: []string{
			"-v", o.CacheVolume + ":/build/src",
			"-e", "UBOOT_VERSION=" + o.Version,
			"-e", "UBOOT_SHA256=" + o.TarballSHA256,
			"-e", "UBOOT_OWNER_GUID=" + o.OwnerGUID,
			"-e", "UBOOT_CACHE_KEY=" + key,
		},
		In: []runner.Copy{
			{Host: absPath(o.KeysDir), Container: "/keys"},
			{Host: absPath(filepath.Join(o.BuilderDir, "configs")), Container: "/configs"},
			{Host: absPath(filepath.Join(o.BuilderDir, "patches")), Container: "/patches"},
		},
		Out: []runner.Copy{{Host: absPath(o.OutputDir), Container: "/output"}},
	}
	if err := container.Run(ctx, o.Runner, o.Runtime); err != nil {
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
	return Locate(o.OutputDir)
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
	if m.Version == "" || m.CacheKey == "" {
		return nil, &ManifestError{Path: path, Err: errors.New("uboot_version and cache_key are required")}
	}
	return &m, nil
}

// Locate finds every board's artifacts under outputDir and verifies each
// file against the board's SHA256SUMS before returning it. A board directory
// that is missing, a file without a checksum entry, or a mismatching digest
// is an error: nothing unverified reaches an EFI partition.
func Locate(outputDir string) (map[Board]Artifacts, error) {
	found := make(map[Board]Artifacts, len(Boards))
	for _, board := range Boards {
		dir := filepath.Join(outputDir, string(board))
		binary := filepath.Join(dir, "u-boot.bin")
		if _, err := os.Stat(binary); err != nil {
			return nil, &ArtifactMissingError{Path: binary, Hint: "run `make uboot-build`"}
		}
		if err := verifyChecksums(dir); err != nil {
			return nil, err
		}
		a := Artifacts{Board: board, Dir: dir, Binary: binary, Config: filepath.Join(dir, "u-boot.config")}
		if board == BoardRPiArm64 {
			a.OverlaysDir = filepath.Join(dir, "overlays")
			if _, err := os.Stat(filepath.Join(a.OverlaysDir, "tpm-soft-spi.dtbo")); err != nil {
				return nil, &ArtifactMissingError{Path: filepath.Join(a.OverlaysDir, "tpm-soft-spi.dtbo"), Hint: "run `make uboot-build`"}
			}
		}
		found[board] = a
	}
	return found, nil
}

// verifyChecksums checks every regular file under dir (except SHA256SUMS)
// against the SHA256SUMS the builder wrote there.
func verifyChecksums(dir string) error {
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	f, err := os.Open(sumsPath)
	if err != nil {
		return &ArtifactMissingError{Path: sumsPath, Hint: "run `make uboot-build`"}
	}
	defer f.Close()
	expected := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return &ChecksumMismatchError{Path: sumsPath, Reason: "malformed line " + scanner.Text()}
		}
		expected[filepath.Clean(strings.TrimPrefix(fields[1], "*"))] = fields[0]
	}
	if err := scanner.Err(); err != nil {
		return &ChecksumMismatchError{Path: sumsPath, Reason: err.Error()}
	}
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) == "SHA256SUMS" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		want, ok := expected[rel]
		if !ok {
			return &ChecksumMismatchError{Path: path, Reason: "no SHA256SUMS entry"}
		}
		got, err := fileSHA256(path)
		if err != nil {
			return &ChecksumMismatchError{Path: path, Reason: err.Error()}
		}
		if got != want {
			return &ChecksumMismatchError{Path: path, Reason: "sha256 " + got + " does not match SHA256SUMS " + want}
		}
		return nil
	})
}

// fileSHA256 returns the hex sha256 of a file's content.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// absPath makes a bind-mount source absolute; docker rejects relative ones.
func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
