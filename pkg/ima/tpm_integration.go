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

package ima

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// PCR bank identifiers
const (
	// PCRBankSHA1 is the SHA1 PCR bank identifier
	PCRBankSHA1 = "sha1"

	// PCRBankSHA256 is the SHA256 PCR bank identifier
	PCRBankSHA256 = "sha256"

	// PCRBankSHA384 is the SHA384 PCR bank identifier
	PCRBankSHA384 = "sha384"

	// PCRBankSHA512 is the SHA512 PCR bank identifier
	PCRBankSHA512 = "sha512"

	// PCR10 is the PCR index used by IMA
	PCR10 = 10
)

// ReadPCR10FromTPM reads the actual PCR 10 value from the TPM via sysfs
// The bank parameter specifies which hash bank to read from (sha1, sha256, sha384, sha512)
func (v *Verifier) ReadPCR10FromTPM(bank string) ([]byte, error) {
	return v.ReadPCR10FromTPMWithPath(DefaultTPMSysPath, bank)
}

// ReadPCR10FromTPMWithPath reads PCR 10 from TPM using a custom sysfs path
// This allows testing with mock filesystems or non-standard TPM paths
func (v *Verifier) ReadPCR10FromTPMWithPath(tpmPath string, bank string) ([]byte, error) {
	// Validate PCR bank
	if !isValidPCRBank(bank) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPCRBank, bank)
	}

	// Construct path to PCR file: /sys/class/tpm/tpm0/pcr-<bank>/10
	pcrPath := filepath.Join(tpmPath, fmt.Sprintf("pcr-%s", bank), fmt.Sprintf("%d", PCR10))

	// Read PCR value from sysfs
	data, err := os.ReadFile(pcrPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: PCR file not found at %s", ErrTPMNotAvailable, pcrPath)
		}
		return nil, fmt.Errorf("%w: %v", ErrPCRReadFailed, err)
	}

	// Parse hex value
	// The sysfs file contains a hex string, possibly with whitespace/newlines
	hexStr := strings.TrimSpace(string(data))

	pcrValue, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex format in %s: %v", ErrPCRReadFailed, pcrPath, err)
	}

	// Validate PCR value length matches expected hash size
	expectedSize := getExpectedPCRSize(bank)
	if len(pcrValue) != expectedSize {
		return nil, fmt.Errorf("%w: PCR value has unexpected length %d, expected %d for %s",
			ErrPCRReadFailed, len(pcrValue), expectedSize, bank)
	}

	return pcrValue, nil
}

// VerifyPCR10AgainstTPM performs full system verification by:
// 1. Reading the event log
// 2. Computing expected PCR 10 from the event log
// 3. Reading actual PCR 10 from the TPM
// 4. Comparing the values
func (v *Verifier) VerifyPCR10AgainstTPM(log *EventLog, bank string) error {
	return v.VerifyPCR10AgainstTPMWithPath(log, DefaultTPMSysPath, bank)
}

// VerifyPCR10AgainstTPMWithPath performs PCR 10 verification with a custom TPM path
func (v *Verifier) VerifyPCR10AgainstTPMWithPath(log *EventLog, tpmPath string, bank string) error {
	if log == nil {
		return ErrNotAvailable
	}

	// Validate PCR bank
	if !isValidPCRBank(bank) {
		return fmt.Errorf("%w: %s", ErrInvalidPCRBank, bank)
	}

	// Compute expected PCR 10 value from event log
	expectedPCR, err := v.ComputePCR10(log, bank)
	if err != nil {
		return fmt.Errorf("failed to compute PCR 10: %w", err)
	}

	// Read actual PCR 10 from TPM
	actualPCR, err := v.ReadPCR10FromTPMWithPath(tpmPath, bank)
	if err != nil {
		return fmt.Errorf("failed to read PCR 10 from TPM: %w", err)
	}

	// Compare values
	if len(expectedPCR) != len(actualPCR) {
		return fmt.Errorf("%w: length mismatch (expected %d bytes, got %d bytes)",
			ErrPCRMismatch, len(expectedPCR), len(actualPCR))
	}

	// Constant-time comparison to prevent timing attacks
	match := true
	for i := range expectedPCR {
		if expectedPCR[i] != actualPCR[i] {
			match = false
		}
	}

	if !match {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrPCRMismatch, expectedPCR, actualPCR)
	}

	return nil
}

// IsPCR10Available checks if PCR 10 is readable from the TPM
func (v *Verifier) IsPCR10Available(bank string) bool {
	return v.IsPCR10AvailableWithPath(DefaultTPMSysPath, bank)
}

// IsPCR10AvailableWithPath checks if PCR 10 is readable using a custom TPM path
func (v *Verifier) IsPCR10AvailableWithPath(tpmPath string, bank string) bool {
	// Validate PCR bank
	if !isValidPCRBank(bank) {
		return false
	}

	// Check if PCR file exists and is readable
	pcrPath := filepath.Join(tpmPath, fmt.Sprintf("pcr-%s", bank), fmt.Sprintf("%d", PCR10))

	// Try to stat the file
	info, err := os.Stat(pcrPath)
	if err != nil {
		return false
	}

	// Ensure it's a regular file and readable
	if !info.Mode().IsRegular() {
		return false
	}

	// Try to read a few bytes to verify accessibility
	file, err := os.Open(pcrPath)
	if err != nil {
		return false
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			slog.Debug("failed to close PCR file", "error", cerr)
		}
	}()

	// If we can open it, it's available
	return true
}

// IsTPMAvailable checks if the TPM device is available in sysfs
func (v *Verifier) IsTPMAvailable() bool {
	return v.IsTPMAvailableWithPath(DefaultTPMSysPath)
}

// IsTPMAvailableWithPath checks if TPM is available at a custom path
func (v *Verifier) IsTPMAvailableWithPath(tpmPath string) bool {
	info, err := os.Stat(tpmPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// GetAvailablePCRBanks returns a list of PCR banks available on the system
func (v *Verifier) GetAvailablePCRBanks() []string {
	return v.GetAvailablePCRBanksWithPath(DefaultTPMSysPath)
}

// GetAvailablePCRBanksWithPath returns available PCR banks using a custom TPM path
func (v *Verifier) GetAvailablePCRBanksWithPath(tpmPath string) []string {
	banks := []string{PCRBankSHA1, PCRBankSHA256, PCRBankSHA384, PCRBankSHA512}
	available := make([]string, 0, len(banks))

	for _, bank := range banks {
		pcrBankPath := filepath.Join(tpmPath, fmt.Sprintf("pcr-%s", bank))
		if info, err := os.Stat(pcrBankPath); err == nil && info.IsDir() {
			available = append(available, bank)
		}
	}

	return available
}

// isValidPCRBank validates that the PCR bank is supported
func isValidPCRBank(bank string) bool {
	switch bank {
	case PCRBankSHA1, PCRBankSHA256, PCRBankSHA384, PCRBankSHA512:
		return true
	default:
		return false
	}
}

// getExpectedPCRSize returns the expected byte size for a PCR bank
func getExpectedPCRSize(bank string) int {
	switch bank {
	case PCRBankSHA1:
		return 20 // SHA1 produces 160 bits = 20 bytes
	case PCRBankSHA256:
		return 32 // SHA256 produces 256 bits = 32 bytes
	case PCRBankSHA384:
		return 48 // SHA384 produces 384 bits = 48 bytes
	case PCRBankSHA512:
		return 64 // SHA512 produces 512 bits = 64 bytes
	default:
		return 0
	}
}
