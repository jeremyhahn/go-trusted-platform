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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Archiver handles bundle export/import operations.
type Archiver struct {
	config *Config
	logger *logging.Logger
}

// NewArchiver creates a new bundle archiver.
func NewArchiver(config *Config, logger *logging.Logger) *Archiver {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Archiver{
		config: config,
		logger: logger,
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

	tmp, err := os.CreateTemp(a.config.BundlesDir(), ".import-*.tar.gz")
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to create temp archive", Err: err}}
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to spool archive", Err: err}}
	}
	if err := tmp.Close(); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: &WrappedError{Msg: "failed to close temp archive", Err: err}}
	}

	return a.ImportFromFile(ctx, tmp.Name())
}

// ImportFromFile imports a bundle from a tar.gz file (supports full extraction).
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
	tr := tar.NewReader(gzr)

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

		if strings.HasSuffix(header.Name, "manifest.json") && !header.FileInfo().IsDir() {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}

			manifest = &Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, ErrInvalidManifest{Reason: err.Error()}
			}

			archivePrefix = filepath.Dir(header.Name)
			break
		}
	}

	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest.json not found"}
	}

	// Check if bundle exists
	bundlePath := a.config.BundlePath(manifest.ID)
	if _, err := os.Stat(bundlePath); err == nil {
		return nil, ErrBundleAlreadyExists{ID: manifest.ID}
	}

	// Reopen and extract
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	gzr2, err := gzip.NewReader(f)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
	}
	defer gzr2.Close()
	tr2 := tar.NewReader(gzr2)

	for {
		header, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			os.RemoveAll(bundlePath)
			return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
		}

		// Calculate destination path
		relPath := strings.TrimPrefix(header.Name, archivePrefix+"/")
		if relPath == "" || relPath == header.Name {
			continue
		}

		destPath := filepath.Join(bundlePath, relPath)

		// Security check: prevent path traversal
		if destPath != bundlePath && !strings.HasPrefix(destPath, bundlePath+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0700); err != nil {
				os.RemoveAll(bundlePath)
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				os.RemoveAll(bundlePath)
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}

			// Create file
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				os.RemoveAll(bundlePath)
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}

			if _, err := io.Copy(outFile, tr2); err != nil {
				outFile.Close()
				os.RemoveAll(bundlePath)
				return nil, ErrArchiveOperationFailed{Operation: "import", Cause: err}
			}
			outFile.Close()
		}
	}

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

// ValidateArchive checks archive integrity without extracting.
func (a *Archiver) ValidateArchive(ctx context.Context, r io.Reader) (*Manifest, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, ErrArchiveOperationFailed{Operation: "validate", Cause: err}
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	var manifest *Manifest

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrArchiveOperationFailed{Operation: "validate", Cause: err}
		}

		if strings.HasSuffix(header.Name, "manifest.json") && !header.FileInfo().IsDir() {
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
