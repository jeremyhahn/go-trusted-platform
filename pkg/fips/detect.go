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

package fips

import (
	"os"
	"strings"
)

// Supported KDF types
const (
	KDFPBKDF2   = "pbkdf2"
	KDFArgon2id = "argon2id"
	KDFArgon2i  = "argon2i"
)

// Supported hash algorithms for PBKDF2
const (
	HashSHA256 = "sha256"
	HashSHA512 = "sha512"
	HashSHA384 = "sha384"
	HashSHA1   = "sha1" // Not recommended, but supported by LUKS2
)

// Default values
const (
	DefaultHash    = HashSHA256
	DefaultKDFFIPS = KDFPBKDF2
	DefaultKDF     = KDFArgon2id
)

// IsEnabled checks if the kernel is running in FIPS mode by reading
// /proc/sys/crypto/fips_enabled. Returns true if FIPS mode is enabled.
//
// This is the standard way to detect FIPS mode at runtime:
// - The kernel sets this to "1" when booted with fips=1 kernel parameter
// - If the file doesn't exist or contains "0", FIPS mode is disabled
func IsEnabled() bool {
	data, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// GetKDF returns the appropriate KDF algorithm based on FIPS mode.
// Returns "pbkdf2" if FIPS is enabled, "argon2id" otherwise.
//
// FIPS 140-3 does not approve Argon2id, so PBKDF2 must be used
// for all key derivation operations in FIPS mode.
func GetKDF() string {
	if IsEnabled() {
		return DefaultKDFFIPS
	}
	return DefaultKDF
}

// GetKDFWithDefault returns the KDF algorithm, using the provided default
// if not empty, otherwise falling back to FIPS-appropriate default.
func GetKDFWithDefault(preferred string) string {
	if preferred != "" {
		// In FIPS mode, override non-compliant KDFs
		if IsEnabled() && (preferred == KDFArgon2id || preferred == KDFArgon2i) {
			return DefaultKDFFIPS
		}
		return preferred
	}
	return GetKDF()
}

// GetHash returns the default hash algorithm.
// Returns "sha256" which is approved for both FIPS and non-FIPS modes.
func GetHash() string {
	return DefaultHash
}

// GetHashWithDefault returns the hash algorithm, using the provided default
// if not empty, otherwise falling back to sha256.
func GetHashWithDefault(preferred string) string {
	if preferred != "" {
		return preferred
	}
	return DefaultHash
}

// ValidateKDF checks if the given KDF type is valid.
// In FIPS mode, only pbkdf2 is allowed.
func ValidateKDF(kdfType string) bool {
	switch kdfType {
	case KDFPBKDF2:
		return true
	case KDFArgon2id, KDFArgon2i:
		// Not allowed in FIPS mode
		return !IsEnabled()
	default:
		return false
	}
}

// ValidateHash checks if the given hash algorithm is valid for LUKS2.
func ValidateHash(hash string) bool {
	switch hash {
	case HashSHA256, HashSHA512, HashSHA384, HashSHA1:
		return true
	default:
		return false
	}
}
