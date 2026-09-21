package rpi

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// An Alpine .apk is a concatenation of gzip members (signature, control,
// data) whose tar streams deliberately omit end-of-archive markers, so one
// gzip reader in multistream mode over one tar reader walks the whole
// package, exactly as `tar -xzf` does.

// extractFromAPK copies every regular file under prefix in the package at
// apkPath into destDir, keeping the path relative to prefix, when keep(rel)
// returns true. It returns the relative paths written.
func extractFromAPK(apkPath, prefix, destDir string, keep func(rel string) bool) ([]string, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return nil, &PackageError{Package: apkPath, Err: err}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, &PackageError{Package: apkPath, Err: err}
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var written []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &PackageError{Package: apkPath, Err: err}
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(name, prefix)
		if rel == "" || strings.Contains(rel, "..") || !keep(rel) {
			continue
		}
		dest := filepath.Join(destDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return nil, &PackageError{Package: apkPath, Err: err}
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, &PackageError{Package: apkPath, Err: err}
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return nil, &PackageError{Package: apkPath, Err: err}
		}
		if err := out.Close(); err != nil {
			return nil, &PackageError{Package: apkPath, Err: err}
		}
		written = append(written, rel)
	}
	return written, nil
}

// findAPK locates <name>-<version>.apk for an exact package name under the
// prefetch architecture directory. "raspberrypi-bootloader" must not match
// "raspberrypi-bootloader-common", so the version part after the name has
// to start with a digit.
func findAPK(dir, name string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, name+"-*.apk"))
	if err != nil {
		return "", &PackageError{Package: name, Err: err}
	}
	for _, m := range matches {
		rest := strings.TrimPrefix(filepath.Base(m), name+"-")
		if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			return m, nil
		}
	}
	return "", &PackageMissingError{Package: name, Dir: dir}
}
