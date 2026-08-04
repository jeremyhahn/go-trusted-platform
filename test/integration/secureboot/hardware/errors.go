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

//go:build integration

package hardware

import "fmt"

// ErrHardwareTPMUnavailable indicates the hardware tier was requested
// (TP_HW_TPM=1) but the TPM character device is not usable. The tier never
// skips: a missing device under an explicit hardware request is a broken
// environment and fails loudly.
type ErrHardwareTPMUnavailable struct {
	Device string
	Cause  error
}

func (e ErrHardwareTPMUnavailable) Error() string {
	return fmt.Sprintf("secureboot hardware tier: TP_HW_TPM=1 but hardware TPM %s is unavailable: %v "+
		"(run this tier ON the target node via `make integration-test-secureboot-hw`, not in the devcontainer)",
		e.Device, e.Cause)
}

func (e ErrHardwareTPMUnavailable) Unwrap() error { return e.Cause }

// ErrHardwareTPMNotProvisioned indicates the host TPM has no IAK, so an
// attestation quote cannot be produced. The operator must provision the
// platform TPM first.
type ErrHardwareTPMNotProvisioned struct {
	Cause error
}

func (e ErrHardwareTPMNotProvisioned) Error() string {
	return fmt.Sprintf("secureboot hardware tier: host TPM is not provisioned (no IAK): %v "+
		"— provision the platform first (`platformctl tpm provision` or platformd first boot)", e.Cause)
}

func (e ErrHardwareTPMNotProvisioned) Unwrap() error { return e.Cause }

// ErrEfivarsRequired indicates the efivars tier was requested
// (TP_HW_EFIVARS=1) but efivarfs is not available — the node did not boot in
// UEFI mode or /sys/firmware/efi is not exposed.
type ErrEfivarsRequired struct {
	Cause error
}

func (e ErrEfivarsRequired) Error() string {
	return fmt.Sprintf("secureboot hardware tier: TP_HW_EFIVARS=1 but efivarfs is unavailable: %v "+
		"(boot the node in UEFI mode and run on the node itself)", e.Cause)
}

func (e ErrEfivarsRequired) Unwrap() error { return e.Cause }

// ErrQuoteInvalid indicates the hardware TPM produced a quote that failed
// verification.
type ErrQuoteInvalid struct {
	Reason string
	Cause  error
}

func (e ErrQuoteInvalid) Error() string {
	return fmt.Sprintf("secureboot hardware tier: quote verification failed: %s: %v", e.Reason, e.Cause)
}

func (e ErrQuoteInvalid) Unwrap() error { return e.Cause }

// ErrUnsupportedIAKAlgorithm indicates the host IAK uses a key or signature
// algorithm the verifier in this suite does not implement.
type ErrUnsupportedIAKAlgorithm struct {
	Algorithm string
}

func (e ErrUnsupportedIAKAlgorithm) Error() string {
	return "secureboot hardware tier: unsupported IAK algorithm " + e.Algorithm +
		" (suite verifies RSA PKCS#1v1.5, RSA-PSS, and ECDSA ASN.1 quote signatures)"
}
