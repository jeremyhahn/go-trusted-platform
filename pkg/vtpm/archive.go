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

package vtpm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// importStagingPrefix names the private directories (and temp archives) an
// import stages in BundlesDir before publishing; bundle listings skip them.
const importStagingPrefix = ".import-"

// Archiver handles bundle export/import operations.
type Archiver struct {
	config *Config
	logger *logging.Logger

	// maxExpandedBytes bounds the decompressed bytes an import may read
	// and write; maxEntries bounds the tar entries it may process.
	maxExpandedBytes int64
	maxEntries       int
	// maxCompressedBytes bounds the archive bytes Import spools to disk.
	maxCompressedBytes int64
}

// DefaultMaxImportExpandedBytes and DefaultMaxImportEntries bound a bundle
// import. A bundle is TPM state, OVMF vars and Secure Boot keys, a few MiB
// in a handful of files, so these leave ample headroom while refusing a
// decompression bomb that the compressed-size cap of the upload cannot see.
const (
	DefaultMaxImportExpandedBytes int64 = 256 << 20
	DefaultMaxImportEntries             = 4096
	// DefaultMaxImportCompressedBytes bounds the upload Import spools to disk
	// before it is validated: gzip never compresses a bundle to more than
	// its expanded size, so the expanded budget bounds the compressed one.
	DefaultMaxImportCompressedBytes = DefaultMaxImportExpandedBytes
)

// NewArchiver creates a new bundle archiver.
func NewArchiver(config *Config, logger *logging.Logger) *Archiver {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Archiver{
		config:           config,
		logger:           logger,
		maxExpandedBytes: DefaultMaxImportExpandedBytes,
		maxEntries:       DefaultMaxImportEntries,

		maxCompressedBytes: DefaultMaxImportCompressedBytes,
	}
}

// Export exports a bundle to a tar.gz archive.
func (a *Archiver) Export(ctx context.Context, bundleID string, w io.Writer) error {
	bundlePath := a.config.BundlePath(bundleID)

	// Verify bundle exists
	manifestPath := filepath.Join(bundlePath, "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		return ErrBundleNotFound{ID: bundleID}
	}

	a.logger.Info("Exporting bundle", "id", bundleID)

	// Create gzip writer
	gzw := gzip.NewWriter(w)
	defer gzw.Close()

	// Create tar writer
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Walk the bundle directory and add files
	archivePrefix := fmt.Sprintf("vtpm-bundle-%s", bundleID)

	err := filepath.Walk(bundlePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path from bundle root
		relPath, err := filepath.Rel(bundlePath, path)
		if err != nil {
			return err
		}

		// Create archive path with prefix
		archivePath := filepath.Join(archivePrefix, relPath)

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		header.Name = archivePath

		// Handle directories
		if info.IsDir() {
			header.Name += "/"
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			return nil
		}

		// The archived manifest carries checksums of the files as exported.
		if relPath == "manifest.json" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			data := exportManifest(bundlePath, raw)
			header.Size = int64(len(data))
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			_, err = tw.Write(data)
			return err
		}

		// Write file header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return ErrArchiveOperationFailed{Operation: "export", Cause: err}
	}

	a.logger.Info("Bundle exported successfully", "id", bundleID)
	return nil
}

// Import imports a bundle from a tar.gz archive.
func (a *Archiver) Import(ctx context.Context, r io.Reader) (*Bundle, error) {
	a.logger.Info("Importing bundle from archive")

	// Spool the stream to a seekable temp file inside the bundles directory,
	// then run the full two-pass extraction. The leading dot keeps the temp
	// file out of any bundle listing.
	if err := os.MkdirAll(a.config.BundlesDir(), 0700); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to create bundles directory", Err: err}}
	}

	tmp, err := os.CreateTemp(a.config.BundlesDir(), importStagingPrefix+"*.tar.gz")
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to create temp archive", Err: err}}
	}
	defer os.Remove(tmp.Name())

	// The upload is bounded and cancellable while it spools: an oversized
	// or endless stream must not fill the bundle filesystem.
	spool := &expansionBudget{ctx: ctx, r: r, remaining: a.maxCompressedBytes, limit: a.maxCompressedBytes}
	if _, err := io.Copy(tmp, spool); err != nil {
		tmp.Close()
		var tooLarge ErrArchiveTooLarge
		if errors.As(err, &tooLarge) || ctx.Err() != nil {
			return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
		}
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to spool archive", Err: err}}
	}
	if err := tmp.Close(); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to close temp archive", Err: err}}
	}

	return a.ImportFromFile(ctx, tmp.Name())
}

// ImportFromFile imports a bundle from a tar.gz file (supports full extraction).
// expansionBudget bounds a decompressed stream: every byte the tar reader
// pulls, including the bodies of entries it skips, is charged against
// remaining, and each Read stops once ctx is done. The first byte past the
// limit is refused with ErrArchiveTooLarge.
type expansionBudget struct {
	ctx       context.Context
	r         io.Reader
	remaining int64
	limit     int64
}

func (b *expansionBudget) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.r.Read(probe[:])
		if n > 0 {
			return 0, ErrArchiveTooLarge{Limit: b.limit}
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (a *Archiver) ImportFromFile(ctx context.Context, archivePath string) (*Bundle, error) {
	a.logger.Info("Importing bundle from file", "path", archivePath)

	f, err := os.Open(archivePath)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to open archive", Err: err}}
	}
	defer f.Close()

	// Create gzip reader
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to create gzip reader", Err: err}}
	}
	defer gzr.Close()

	// Create tar reader
	tr := tar.NewReader(&expansionBudget{ctx: ctx, r: gzr, remaining: a.maxExpandedBytes, limit: a.maxExpandedBytes})

	// First pass: find manifest
	var manifest *Manifest
	var archivePrefix string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
		}

		if path.Base(cleanArchiveName(header.Name)) == "manifest.json" && !header.FileInfo().IsDir() {
			data, err := io.ReadAll(io.LimitReader(tr, a.maxExpandedBytes+1))
			if err != nil {
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}
			if int64(len(data)) > a.maxExpandedBytes {
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: ErrArchiveTooLarge{Limit: a.maxExpandedBytes}}
			}

			manifest = &Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, ErrInvalidManifest{Reason: err.Error()}
			}

			archivePrefix = path.Dir(cleanArchiveName(header.Name))
			break
		}
	}

	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest.json not found"}
	}

	// The manifest ID names the bundle directory: it must be exactly one
	// local path component, so a hostile ID cannot select a directory
	// outside the bundle store.
	id := manifest.ID
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\`) ||
		!filepath.IsLocal(id) || filepath.Base(id) != id {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("bundle ID %q is not a single path component", id)}
	}

	// Check if bundle exists
	bundlePath := a.config.BundlePath(id)
	if filepath.Dir(bundlePath) != filepath.Clean(a.config.BundlesDir()) {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("bundle ID %q resolves outside the bundle store", id)}
	}
	if _, err := os.Stat(bundlePath); err == nil {
		return nil, ErrBundleAlreadyExists{ID: manifest.ID}
	}

	// Extract into a staging directory this import owns exclusively, next
	// to bundlePath so the publishing rename stays on one filesystem. A
	// concurrent import of the same ID extracts into its own staging
	// directory, and a refused import removes only its own.
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0700); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	stagePath, err := os.MkdirTemp(filepath.Dir(bundlePath), importStagingPrefix+""+id+"-")
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(stagePath)
		}
	}()

	// Reopen and extract
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	gzr2, err := gzip.NewReader(f)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	defer gzr2.Close()
	tr2 := tar.NewReader(&expansionBudget{ctx: ctx, r: gzr2, remaining: a.maxExpandedBytes, limit: a.maxExpandedBytes})

	// refuse reports why the import stopped; the deferred clean-up removes
	// the staging directory, never a published bundle.
	refuse := func(cause error) (*Bundle, error) {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: cause}
	}
	remaining := a.maxExpandedBytes
	entries := 0

	for {
		if err := ctx.Err(); err != nil {
			return refuse(err)
		}
		header, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return refuse(err)
		}

		entries++
		if entries > a.maxEntries {
			return refuse(ErrArchiveTooManyEntries{Limit: a.maxEntries})
		}

		// Calculate destination path
		relPath, ok := archiveRelPath(archivePrefix, header.Name)
		if !ok {
			continue
		}

		destPath := filepath.Join(stagePath, relPath)

		// Security check: prevent path traversal
		if destPath != stagePath && !strings.HasPrefix(destPath, stagePath+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0700); err != nil {
				return refuse(err)
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				return refuse(err)
			}

			// Create file
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return refuse(err)
			}

			n, err := io.CopyN(outFile, tr2, remaining+1)
			if err != nil && err != io.EOF {
				outFile.Close()
				return refuse(err)
			}
			if n > remaining {
				outFile.Close()
				return refuse(ErrArchiveTooLarge{Limit: a.maxExpandedBytes})
			}
			remaining -= n
			if err := outFile.Close(); err != nil {
				return refuse(err)
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	// An archive whose entries all fell outside the manifest's prefix would
	// otherwise publish an empty bundle that GetBundle cannot find (#2021).
	if _, err := os.Stat(filepath.Join(stagePath, "manifest.json")); err != nil {
		return nil, ErrInvalidManifest{Reason: "manifest.json not extracted"}
	}
	// A refused checksum publishes nothing: the deferred clean-up removes the stage.
	if err := verifyStagedChecksums(stagePath, manifest.Checksums); err != nil {
		return nil, err
	}
	if err := publishStagedBundle(stagePath, bundlePath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrBundleAlreadyExists{ID: manifest.ID}
		}
		return refuse(err)
	}
	published = true

	a.logger.Info("Bundle imported successfully", "id", manifest.ID)

	// Build bundle struct
	bundle := &Bundle{
		ID:        manifest.ID,
		Mode:      manifest.Mode,
		Manifest:  manifest,
		CreatedAt: manifest.CreatedAt,
		TPMState: &TPMState{
			StateDir:    filepath.Join(bundlePath, "tpm"),
			PermallFile: filepath.Join(bundlePath, "tpm", "tpm2-00.permall"),
		},
		OVMFState: &OVMFState{
			NVRAMFile: filepath.Join(bundlePath, "ovmf", "OVMF_VARS.fd"),
		},
	}

	if manifest.SecureBootEnabled {
		sbDir := filepath.Join(bundlePath, "secure-boot-keys")
		bundle.SecureBootKeys = &SecureBootKeyPaths{
			Dir:     sbDir,
			PKKey:   filepath.Join(sbDir, "PK.key"),
			PKCert:  filepath.Join(sbDir, "PK.crt"),
			KEKKey:  filepath.Join(sbDir, "KEK.key"),
			KEKCert: filepath.Join(sbDir, "KEK.crt"),
			DBKey:   filepath.Join(sbDir, "DB.key"),
			DBCert:  filepath.Join(sbDir, "DB.crt"),
		}
	}

	return bundle, nil
}

// publishStagedBundle moves the fully extracted stagePath to bundlePath
// without replacing anything there. os.Mkdir claims bundlePath exclusively
// (it fails with fs.ErrExist when a bundle, or another import's claim, is
// already there); the rename then replaces only that empty claim, so the
// bundle appears complete in one step. A failed rename releases the claim.
// The rename is syscall.Rename: os.Rename refuses any existing directory,
// while rename(2) atomically replaces an empty one, which is the claim.
// cleanArchiveName normalises a tar entry name: a leading "./" is dropped
// and the slash path cleaned, so "./tpm/" and "tpm" compare equal.
func cleanArchiveName(name string) string {
	return path.Clean(strings.TrimPrefix(name, "./"))
}

// archiveRelPath returns name relative to the manifest's directory prefix,
// both cleaned with cleanArchiveName. With a root-level manifest (prefix
// ".") the whole cleaned name is returned. It reports false for the prefix
// itself and for a name outside it.
func archiveRelPath(prefix, name string) (string, bool) {
	prefix = cleanArchiveName(prefix)
	name = cleanArchiveName(name)
	if name == "." || name == prefix {
		return "", false
	}
	if prefix == "." {
		return name, true
	}
	rel, found := strings.CutPrefix(name, prefix+"/")
	if !found || rel == "" {
		return "", false
	}
	return rel, true
}

func publishStagedBundle(stagePath, bundlePath string) error {
	if err := os.Mkdir(bundlePath, 0700); err != nil {
		return err
	}
	if err := syscall.Rename(stagePath, bundlePath); err != nil {
		os.Remove(bundlePath)
		return err
	}
	return nil
}

// verifyStagedChecksums requires every file the manifest checksums to be
// staged under stagePath with that SHA-256 before the bundle is published.
// A checksum path outside the bundle is an invalid manifest.
func verifyStagedChecksums(stagePath string, checksums map[string]string) error {
	for rel, expected := range checksums {
		local := filepath.FromSlash(rel)
		if !filepath.IsLocal(local) {
			return ErrInvalidManifest{Reason: fmt.Sprintf("checksum path %q is not inside the bundle", rel)}
		}
		actual, err := fileChecksum(filepath.Join(stagePath, local))
		if err != nil {
			return ErrChecksumMismatch{File: rel, Expected: expected, Actual: "file not found"}
		}
		if actual != expected {
			return ErrChecksumMismatch{File: rel, Expected: expected, Actual: actual}
		}
	}
	return nil
}

// exportManifest returns the manifest raw with each checksum recomputed from
// the file now in bundlePath, so state a running VM changed still verifies on
// import. A checksummed file that is missing keeps its old value; raw is
// returned unchanged when it does not parse.
func exportManifest(bundlePath string, raw []byte) []byte {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	for key := range m.Checksums {
		if sum, err := fileChecksum(filepath.Join(bundlePath, filepath.FromSlash(key))); err == nil {
			m.Checksums[key] = sum
		}
	}
	data, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return raw
	}
	return data
}

// ValidateArchive checks archive integrity without extracting.
func (a *Archiver) ValidateArchive(ctx context.Context, r io.Reader) (*Manifest, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "validate", Cause: err}
	}
	defer gzr.Close()

	// Every decompressed byte, the manifest's and those of the entries tar
	// skips before it, counts against the expansion budget, so a gzip bomb
	// is refused here as it is on import.
	tr := tar.NewReader(&expansionBudget{ctx: ctx, r: gzr, remaining: a.maxExpandedBytes, limit: a.maxExpandedBytes})

	var manifest *Manifest

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrArchiveOperationFailed{Operation: "validate", Cause: err}
		}

		if path.Base(cleanArchiveName(header.Name)) == "manifest.json" && !header.FileInfo().IsDir() {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, ErrArchiveOperationFailed{Operation: "validate", Cause: err}
			}

			manifest = &Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, ErrInvalidManifest{Reason: err.Error()}
			}
			break
		}
	}

	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest.json not found"}
	}

	a.logger.Debug("Archive validation passed", "bundleID", manifest.ID)
	return manifest, nil
}
