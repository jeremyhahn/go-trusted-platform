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

package iso

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"gopkg.in/yaml.v2"
)

// Builder implements ISOBuilder interface
type Builder struct {
	logger *logging.Logger
	runner XorrisoRunner
	// stagedKeyFiles maps the absolute ISO-tree path of each file this
	// build copied from KeysDir to its os.Lstat taken right after the copy
	// wrote it, nil when it staged none. Only those inodes are the build's
	// own to zero; any other entry in the staged tree may share its inode
	// with a key outside it.
	stagedKeyFiles map[string]os.FileInfo
}

// NewBuilder creates a new ISO builder
func NewBuilder(logger *logging.Logger) *Builder {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Builder{
		logger: logger,
		runner: &defaultXorrisoRunner{logger: logger},
	}
}

// BuildISO creates a bootable ISO image using xorriso
func (b *Builder) BuildISO(ctx context.Context, config *ISOConfig) (retErr error) {
	if err := b.validateConfig(config); err != nil {
		return &WrappedError{Msg: "invalid configuration", Err: err}
	}

	// The image carries the staged Secure Boot private keys; the copies on
	// the ISO tree must not outlive the build, whether xorriso ran or not.
	b.stagedKeyFiles = nil
	defer func() {
		if err := b.wipeStagedSecureBootKeys(config); err != nil {
			werr := &WrappedError{Msg: "failed to wipe staged Secure Boot private keys", Err: err}
			if retErr == nil {
				retErr = werr
			} else {
				retErr = errors.Join(retErr, werr)
			}
		}
	}()

	b.logger.Info("Creating bootable ISO image",
		"output", config.OutputISO,
		"iso_dir", config.ISODir)

	// Copy secure boot keys if provided
	if config.KeysDir != "" && isDir(config.KeysDir) {
		if err := b.copySecureBootKeys(config); err != nil {
			b.logger.Warn("Failed to copy secure boot keys", "error", err)
		}
	}

	// Prepare additional ISO contents
	if err := b.prepareISOContents(config); err != nil {
		return &WrappedError{Msg: "failed to prepare ISO contents", Err: err}
	}

	// Fail closed when the baked config references staged signing material
	// that is not in the tree (a retry after a failed pack whose cleanup
	// wiped it, with no KeysDir to restage from).
	if err := checkStagedSecureBootMedia(config.ISODir); err != nil {
		return &WrappedError{Msg: "missing Secure Boot signing material", Err: err}
	}

	// Build the ISO
	if err := b.runXorriso(ctx, config); err != nil {
		return &WrappedError{Msg: "xorriso failed", Err: err}
	}

	// Verify ISO was created
	info, err := os.Stat(config.OutputISO)
	if err != nil {
		return &WrappedError{Msg: "ISO file not created", Err: err}
	}

	b.logger.Info("ISO image created successfully",
		"path", config.OutputISO,
		"size_mb", info.Size()/(1024*1024),
		"size_bytes", info.Size())

	return nil
}

// validateConfig validates the ISO configuration
func (b *Builder) validateConfig(config *ISOConfig) error {
	if config == nil {
		return &MessageError{Msg: "configuration is required"}
	}
	if config.ISODir == "" {
		return &MessageError{Msg: "ISO directory is required"}
	}
	if config.OutputISO == "" {
		return &MessageError{Msg: "output ISO path is required"}
	}
	if !isDir(config.ISODir) {
		return &MessageError{Msg: fmt.Sprintf("ISO directory not found: %s", config.ISODir)}
	}

	// Set default volume ID if not specified
	if config.VolumeID == "" {
		config.VolumeID = "ALPINE_BOOT"
	}

	// Ensure volume ID doesn't exceed 32 characters
	if len(config.VolumeID) > 32 {
		config.VolumeID = config.VolumeID[:32]
	}

	return nil
}

// copySecureBootKeys copies secure boot keys into the ISO
func (b *Builder) copySecureBootKeys(config *ISOConfig) error {
	destDir := filepath.Join(config.ISODir, filepath.Base(config.KeysDir))
	b.logger.Debug("Copying secure boot keys",
		"source", config.KeysDir,
		"destination", destDir)

	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve keys destination", Err: err}
	}
	// Record every file the copy writes, even when it fails part way, so
	// the post-build wipe zeroes the partial copy too.
	if b.stagedKeyFiles == nil {
		b.stagedKeyFiles = make(map[string]os.FileInfo)
	}
	if err := copyDirRecording(config.KeysDir, absDest, b.stagedKeyFiles); err != nil {
		return &WrappedError{Msg: "failed to copy keys", Err: err}
	}

	return nil
}

// wipeStagedSecureBootKeys zeroes and removes every Secure Boot private-key
// copy staged on the ISO tree: the builder's KeysDir copy and customize's
// <iso-root>/secure-boot-keys staging. Public enrollment material stays. A
// staged directory that is the key source itself (KeysDir) is never touched,
// at the root or nested at any depth below it. Each root is Lstat'ed first: a
// missing root is skipped, and a root that is a symlink or not a directory is
// not traversed and is reported as an error, so the wipe never follows a link
// out of the ISO tree.
func (b *Builder) wipeStagedSecureBootKeys(config *ISOConfig) error {
	dirs := []string{filepath.Join(config.ISODir, SecureBootKeysISODirName)}
	if config.KeysDir != "" {
		dirs = append(dirs, filepath.Join(config.ISODir, filepath.Base(config.KeysDir)))
	}
	var errs []error
	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[abs] || sameDir(abs, config.KeysDir) {
			continue
		}
		seen[abs] = true
		info, err := os.Lstat(abs)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, err)
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			errs = append(errs, &MessageError{Msg: fmt.Sprintf("staged Secure Boot key directory is a symlink, not wiped: %s", abs)})
			continue
		}
		if !info.IsDir() {
			errs = append(errs, &MessageError{Msg: fmt.Sprintf("staged Secure Boot key path is not a directory, not wiped: %s", abs)})
			continue
		}
		// Only the files this build copied from KeysDir, still on the
		// inode the copy wrote, are its own to zero even if another link
		// was made since. Any other entry (one left from before the copy,
		// or replaced since) may share its inode with a key outside it.
		errs = append(errs, wipeSecureBootPrivateFiles(abs, config.KeysDir, b.ownsStagedKeyFile))
	}
	return errors.Join(errs...)
}

// sameDir reports whether a and b name the same existing directory.
func sameDir(a, b string) bool {
	if b == "" {
		return false
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// wipeSecureBootPrivateFiles overwrites with zeros, syncs and removes each
// regular file under dir that is not public Secure Boot enrollment material.
// A missing dir is not an error. A child directory that is the same file as
// keep (the key source, KeysDir) is skipped at any depth, and symlinks below
// dir are never followed. A file whose inode has another hard link is zeroed
// only when owned reports it as a file this build wrote; otherwise its link
// in dir is removed without overwriting the shared inode.
func wipeSecureBootPrivateFiles(dir, keep string, owned func(path string, info os.FileInfo) bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if sameDir(path, keep) {
				continue
			}
			errs = append(errs, wipeSecureBootPrivateFiles(path, keep, owned))
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		public := IsSecureBootPublicArtifact(entry.Name(), data)
		size := len(data)
		clear(data)
		if public {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if hasOtherLinksInfo(info) && (owned == nil || !owned(path, info)) {
			// The inode is shared with a link outside this copy (a tree
			// staged with `cp -al`, or a stale link this build did not
			// write): zeroing it would destroy the source
			// signing key too. Detach the tree's link without overwriting.
			errs = append(errs, os.Remove(path))
			continue
		}
		errs = append(errs, zeroAndRemove(path, size))
	}
	return errors.Join(errs...)
}

// zeroAndRemove overwrites the first size bytes of path with zeros, syncs
// them to disk and removes the file.
func zeroAndRemove(path string, size int) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(make([]byte, size))
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	return os.Remove(path)
}

// hasOtherLinksInfo reports whether the file described by info shares its
// inode with another hard link, so overwriting it in place would change that
// link.
func hasOtherLinksInfo(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(st.Nlink) > 1
}

// ownsStagedKeyFile reports whether path is a file this build copied from
// KeysDir and info (its current Lstat) is still the inode the copy wrote.
// A path the copy did not record, or a different inode, is not owned.
func (b *Builder) ownsStagedKeyFile(path string, info os.FileInfo) bool {
	recorded, ok := b.stagedKeyFiles[path]
	return ok && info != nil && os.SameFile(recorded, info)
}

// bakedInstallerConfigs are the ISO-tree paths of the installer configuration
// the customization step bakes, whose Secure Boot references the installer
// resolves from the install media.
var bakedInstallerConfigs = []string{filepath.Join("configs", "installer.yaml")}

// checkStagedSecureBootMedia fails closed when a baked installer config with
// Secure Boot enabled references media signing files that are absent from the
// ISO tree's staging directory: an earlier build's cleanup wipes the staged
// private key, and packing without it would make the installer generate a
// different DB key instead of using the configured signing identity.
func checkStagedSecureBootMedia(isoDir string) error {
	for _, rel := range bakedInstallerConfigs {
		configPath := filepath.Join(isoDir, rel)
		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return &WrappedError{Msg: "failed to read baked installer config " + configPath, Err: err}
		}
		var config map[string]interface{}
		if err := yaml.Unmarshal(data, &config); err != nil {
			return &WrappedError{Msg: "failed to parse baked installer config " + configPath, Err: err}
		}
		sb, _ := config["secure-boot"].(map[interface{}]interface{})
		if enabled, _ := sb["enabled"].(bool); !enabled {
			continue
		}
		db, _ := sb["db"].(map[interface{}]interface{})
		keyURI, _ := db["key-uri"].(string)
		certURI, _ := db["cert-uri"].(string)
		keyFile, certFile, err := classifySecureBootDBRef(keyURI, certURI)
		if err != nil {
			return &WrappedError{Msg: "baked installer config " + configPath + " has an unusable secure-boot.db reference", Err: err}
		}
		if keyFile == "" {
			continue // remote (kms://) signer: nothing staged on the media
		}
		var missing []string
		for _, name := range []string{keyFile, certFile} {
			p := filepath.Join(isoDir, SecureBootKeysISODirName, name)
			if _, err := os.Stat(p); err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return &MessageError{Msg: fmt.Sprintf(
				"baked installer config %s references Secure Boot signing files missing from %s: %s (restage the keys before packing)",
				configPath, filepath.Join(isoDir, SecureBootKeysISODirName), strings.Join(missing, ", "))}
		}
	}
	return nil
}

// prepareISOContents prepares additional contents for the ISO
func (b *Builder) prepareISOContents(config *ISOConfig) error {
	// Copy FIPS kernel if present
	if config.WorkDir != "" {
		fipsKernelDir := filepath.Join(config.WorkDir, "fips-kernel")
		if isDir(fipsKernelDir) && fileExists(filepath.Join(fipsKernelDir, "vmlinuz-fips")) {
			b.logger.Info("Adding FIPS-enabled kernel to ISO")
			fipsDestDir := filepath.Join(config.ISODir, ".fips-data")
			if err := os.MkdirAll(fipsDestDir, 0755); err != nil {
				return &WrappedError{Msg: "failed to create FIPS directory", Err: err}
			}

			files := []string{"vmlinuz-fips", "modules-fips-*.tar.gz", "config-fips", "System.map-fips"}
			for _, pattern := range files {
				matches, _ := filepath.Glob(filepath.Join(fipsKernelDir, pattern))
				for _, src := range matches {
					dest := filepath.Join(fipsDestDir, filepath.Base(src))
					if err := copyFile(src, dest); err != nil {
						b.logger.Warn("Failed to copy FIPS file",
							"file", filepath.Base(src),
							"error", err)
					}
				}
			}
		}

		// Copy pre-signed UKI if present
		hostUKIDir := filepath.Join(config.WorkDir, "host-uki")
		if fileExists(filepath.Join(hostUKIDir, "BOOTX64.EFI")) {
			b.logger.Info("Adding pre-signed UKI to ISO")
			ukiDestDir := filepath.Join(config.ISODir, ".signed-uki")
			if err := os.MkdirAll(ukiDestDir, 0755); err != nil {
				return &WrappedError{Msg: "failed to create UKI directory", Err: err}
			}

			ukiFiles := []string{"BOOTX64.EFI", "linux-*.efi"}
			for _, pattern := range ukiFiles {
				matches, _ := filepath.Glob(filepath.Join(hostUKIDir, pattern))
				for _, src := range matches {
					dest := filepath.Join(ukiDestDir, filepath.Base(src))
					if err := copyFile(src, dest); err != nil {
						b.logger.Warn("Failed to copy UKI file",
							"file", filepath.Base(src),
							"error", err)
					}
				}
			}
		}
	}

	return nil
}

// runXorriso executes xorriso to build the ISO
func (b *Builder) runXorriso(ctx context.Context, config *ISOConfig) error {
	// Convert paths to absolute paths
	absISODir, err := filepath.Abs(config.ISODir)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve ISO directory path", Err: err}
	}

	absOutputISO, err := filepath.Abs(config.OutputISO)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve output ISO path", Err: err}
	}

	// Build xorriso arguments — UEFI-only boot (this platform requires UEFI + TPM)
	args := []string{
		"-as", "mkisofs",
		// Rockridge, Joliet extensions
		"-r", "-J",
		// UEFI boot via EFI System Partition image
		"-e", "boot/grub/efi.img",
		"-no-emul-boot",
		// GPT hybrid so the ISO is bootable as a USB disk image
		"-isohybrid-gpt-basdat",
		// Output file
		"-o", absOutputISO,
		// Volume ID
		"-V", config.VolumeID,
	}

	// Add optional IDs
	if config.ApplicationID != "" {
		args = append(args, "-A", config.ApplicationID)
	}
	if config.PublisherID != "" {
		args = append(args, "-publisher", config.PublisherID)
	}

	// Source directory (must be last)
	args = append(args, absISODir)

	if config.Debug {
		b.logger.Debug("Running xorriso", "args", strings.Join(args, " "))
	}

	// Execute xorriso
	var stdout, stderr strings.Builder
	if err := b.runner.Run(ctx, args, &stdout, &stderr); err != nil {
		// Log stderr if available
		if stderr.Len() > 0 {
			b.logger.Error(&MessageError{Msg: fmt.Sprintf("xorriso stderr: %s", stderr.String())})
		}
		return &WrappedError{Msg: "xorriso execution failed", Err: err}
	}

	// Log output in debug mode
	if config.Debug && stdout.Len() > 0 {
		// Filter out NOTE: messages like the original script
		output := stdout.String()
		for _, line := range strings.Split(output, "\n") {
			if !strings.HasPrefix(line, "NOTE:") && line != "" {
				b.logger.Debug(line)
			}
		}
	}

	return nil
}

// ValidateISO verifies the created ISO
func (b *Builder) ValidateISO(ctx context.Context, isoPath string) error {
	info, err := os.Stat(isoPath)
	if err != nil {
		return &WrappedError{Msg: "ISO file not found", Err: err}
	}

	if info.Size() == 0 {
		return &MessageError{Msg: "ISO file is empty"}
	}

	b.logger.Info("ISO validation passed",
		"path", isoPath,
		"size_mb", info.Size()/(1024*1024))

	return nil
}

// defaultXorrisoRunner implements XorrisoRunner using exec.Command
type defaultXorrisoRunner struct {
	logger *logging.Logger
}

// Run executes xorriso with the given arguments
func (r *defaultXorrisoRunner) Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "xorriso", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "xorriso command failed", Err: err}
	}

	return nil
}

// Version returns the xorriso version
func (r *defaultXorrisoRunner) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "xorriso", "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", &WrappedError{Msg: "failed to get xorriso version", Err: err}
	}
	return strings.TrimSpace(string(output)), nil
}

// Helper functions

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// copyDir stages a secure boot keys tree from src to dst. Each file goes
// through stageSecureBootFile, so anything that is not a public enrollment
// artifact (IsSecureBootPublicArtifact) is written 0600 and its read buffer
// is wiped (#62); public certificates and signature lists stay 0644.
func copyDir(src, dst string) error {
	return copyDirRecording(src, dst, nil)
}

// copyDirRecording is copyDir that, when staged is not nil, records each
// file it writes as staged[dst path] = its os.Lstat right after the write.
// The recorded paths are dst joined with the entry names, so an absolute
// dst gives absolute keys.
func copyDirRecording(src, dst string, staged map[string]os.FileInfo) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDirRecording(srcPath, dstPath, staged); err != nil {
				return err
			}
			continue
		}
		if err := stageSecureBootFile(srcPath, dstPath); err != nil {
			return err
		}
		if staged != nil {
			info, err := os.Lstat(dstPath)
			if err != nil {
				return err
			}
			staged[dstPath] = info
		}
	}

	return nil
}
