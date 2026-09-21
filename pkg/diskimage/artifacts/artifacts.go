// Package artifacts is what the container-built inputs of the factory
// image (U-Boot, the virt kernel) share once they are on disk: SHA256SUMS
// verification of a build directory, file digests, and the absolute paths
// docker wants for bind mounts. Nothing unverified reaches an image.
package artifacts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MissingError reports an artifact that is not where the builder puts it,
// with the command that produces it.
type MissingError struct {
	Path string
	Hint string
}

func (e *MissingError) Error() string {
	return "artifact " + e.Path + " is missing (" + e.Hint + ")"
}

// ChecksumMismatchError reports a file whose digest does not match the
// builder's SHA256SUMS, or a SHA256SUMS that cannot be read.
type ChecksumMismatchError struct {
	Path   string
	Reason string
}

func (e *ChecksumMismatchError) Error() string {
	return "artifact " + e.Path + ": " + e.Reason
}

// VerifyChecksums checks every regular file under dir (except SHA256SUMS)
// against the SHA256SUMS the builder wrote there. A file without an entry,
// a mismatching digest or a missing SHA256SUMS is an error; hint names
// the build command in the missing case.
func VerifyChecksums(dir, hint string) error {
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	f, err := os.Open(sumsPath)
	if err != nil {
		return &MissingError{Path: sumsPath, Hint: hint}
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
		got, err := FileSHA256(path)
		if err != nil {
			return &ChecksumMismatchError{Path: path, Reason: err.Error()}
		}
		if got != want {
			return &ChecksumMismatchError{Path: path, Reason: "sha256 " + got + " does not match SHA256SUMS " + want}
		}
		return nil
	})
}

// FileSHA256 returns the hex sha256 of a file's content.
func FileSHA256(path string) (string, error) {
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

// AbsPath makes a bind-mount source absolute; docker rejects relative ones.
func AbsPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
