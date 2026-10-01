package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractError reports an archive that cannot be read or extracted.
type ExtractError struct {
	Archive string
	Err     error
}

func (e *ExtractError) Error() string { return "artifact " + e.Archive + ": " + e.Err.Error() }
func (e *ExtractError) Unwrap() error { return e.Err }

// ExtractTarGz copies every regular file under prefix in the gzip-compressed
// tar at archive into destDir, keeping its path relative to prefix, when
// keep(rel) returns true. It returns the relative paths written. A path that
// would leave destDir is skipped.
//
// The gzip reader runs in multistream mode, so an Alpine .apk — gzip
// members (signature, control, data) whose tar streams deliberately omit
// end-of-archive markers — is walked whole, exactly as `tar -xzf` does.
func ExtractTarGz(archive, prefix, destDir string, keep func(rel string) bool) ([]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, &ExtractError{Archive: archive, Err: err}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, &ExtractError{Archive: archive, Err: err}
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
			return nil, &ExtractError{Archive: archive, Err: err}
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(name, prefix)
		if rel == "" || !filepath.IsLocal(filepath.FromSlash(rel)) || !keep(rel) {
			continue
		}
		if err := extractFile(tr, filepath.Join(destDir, filepath.FromSlash(rel))); err != nil {
			return nil, &ExtractError{Archive: archive, Err: err}
		}
		written = append(written, rel)
	}
	return written, nil
}

// extractFile writes the current tar entry to dest.
func extractFile(r io.Reader, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
