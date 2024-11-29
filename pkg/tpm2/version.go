package tpm2

import (
	"fmt"
	"strconv"
	"strings"
)

// VersionStringToInt64 converts a TPM firmware version string (major.minor) to an int64.
func VersionStringToInt64(version string) (int64, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid version format, expected 'major.minor', got %q", version)
	}

	// Parse major component
	major, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid major version: %v", err)
	}
	if major < 0 || major > 0xFFFF {
		return 0, fmt.Errorf("major version out of range (0-65535): %d", major)
	}

	// Parse minor component
	minor, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid minor version: %v", err)
	}
	if minor < 0 || minor > 0xFFFF {
		return 0, fmt.Errorf("minor version out of range (0-65535): %d", minor)
	}

	// Combine major and minor into a single int64
	versionInt := (major << 16) | minor
	return versionInt, nil
}

// Int64ToVersionComponents converts an int64 back to major and minor version components.
func Int64ToVersionComponents(versionInt int64) (int64, int64, error) {
	if versionInt < 0 || versionInt > 0xFFFFFFFF {
		return 0, 0, fmt.Errorf("version number out of range (0-4294967295): %d", versionInt)
	}

	major := (versionInt >> 16) & 0xFFFF
	minor := versionInt & 0xFFFF

	return major, minor, nil
}
