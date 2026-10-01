package rpi

import (
	"path/filepath"
	"strings"
)

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
