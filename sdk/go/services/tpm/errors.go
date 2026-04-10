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

package tpm

import "fmt"

// ErrInfoFailed is returned when getting TPM info fails.
type ErrInfoFailed struct {
	Cause error
}

func (e *ErrInfoFailed) Error() string {
	return fmt.Sprintf("failed to get TPM info: %v", e.Cause)
}

func (e *ErrInfoFailed) Unwrap() error {
	return e.Cause
}

// ErrProvisionFailed is returned when TPM provisioning fails.
type ErrProvisionFailed struct {
	Cause error
}

func (e *ErrProvisionFailed) Error() string {
	return fmt.Sprintf("failed to provision TPM: %v", e.Cause)
}

func (e *ErrProvisionFailed) Unwrap() error {
	return e.Cause
}

// ErrClearFailed is returned when clearing TPM fails.
type ErrClearFailed struct {
	Cause error
}

func (e *ErrClearFailed) Error() string {
	return fmt.Sprintf("failed to clear TPM: %v", e.Cause)
}

func (e *ErrClearFailed) Unwrap() error {
	return e.Cause
}

// EK Errors

// ErrCreateEKFailed is returned when creating EK fails.
type ErrCreateEKFailed struct {
	Cause error
}

func (e *ErrCreateEKFailed) Error() string {
	return fmt.Sprintf("failed to create EK: %v", e.Cause)
}

func (e *ErrCreateEKFailed) Unwrap() error {
	return e.Cause
}

// ErrGetEKFailed is returned when getting EK fails.
type ErrGetEKFailed struct {
	Cause error
}

func (e *ErrGetEKFailed) Error() string {
	return fmt.Sprintf("failed to get EK: %v", e.Cause)
}

func (e *ErrGetEKFailed) Unwrap() error {
	return e.Cause
}

// ErrGetEKCertFailed is returned when getting EK certificate fails.
type ErrGetEKCertFailed struct {
	Cause error
}

func (e *ErrGetEKCertFailed) Error() string {
	return fmt.Sprintf("failed to get EK certificate: %v", e.Cause)
}

func (e *ErrGetEKCertFailed) Unwrap() error {
	return e.Cause
}

// ErrImportEKCertFailed is returned when importing EK certificate fails.
type ErrImportEKCertFailed struct {
	Cause error
}

func (e *ErrImportEKCertFailed) Error() string {
	return fmt.Sprintf("failed to import EK certificate: %v", e.Cause)
}

func (e *ErrImportEKCertFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteEKFailed is returned when deleting EK fails.
type ErrDeleteEKFailed struct {
	Cause error
}

func (e *ErrDeleteEKFailed) Error() string {
	return fmt.Sprintf("failed to delete EK: %v", e.Cause)
}

func (e *ErrDeleteEKFailed) Unwrap() error {
	return e.Cause
}

// SRK Errors

// ErrCreateSRKFailed is returned when creating SRK fails.
type ErrCreateSRKFailed struct {
	Cause error
}

func (e *ErrCreateSRKFailed) Error() string {
	return fmt.Sprintf("failed to create SRK: %v", e.Cause)
}

func (e *ErrCreateSRKFailed) Unwrap() error {
	return e.Cause
}

// ErrGetSRKFailed is returned when getting SRK fails.
type ErrGetSRKFailed struct {
	Cause error
}

func (e *ErrGetSRKFailed) Error() string {
	return fmt.Sprintf("failed to get SRK: %v", e.Cause)
}

func (e *ErrGetSRKFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteSRKFailed is returned when deleting SRK fails.
type ErrDeleteSRKFailed struct {
	Cause error
}

func (e *ErrDeleteSRKFailed) Error() string {
	return fmt.Sprintf("failed to delete SRK: %v", e.Cause)
}

func (e *ErrDeleteSRKFailed) Unwrap() error {
	return e.Cause
}

// AK Errors

// ErrCreateAKFailed is returned when creating AK fails.
type ErrCreateAKFailed struct {
	Cause error
}

func (e *ErrCreateAKFailed) Error() string {
	return fmt.Sprintf("failed to create AK: %v", e.Cause)
}

func (e *ErrCreateAKFailed) Unwrap() error {
	return e.Cause
}

// ErrGetAKFailed is returned when getting AK fails.
type ErrGetAKFailed struct {
	Cause error
}

func (e *ErrGetAKFailed) Error() string {
	return fmt.Sprintf("failed to get AK: %v", e.Cause)
}

func (e *ErrGetAKFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteAKFailed is returned when deleting AK fails.
type ErrDeleteAKFailed struct {
	Cause error
}

func (e *ErrDeleteAKFailed) Error() string {
	return fmt.Sprintf("failed to delete AK: %v", e.Cause)
}

func (e *ErrDeleteAKFailed) Unwrap() error {
	return e.Cause
}

// Seal/Unseal Errors

// ErrSealFailed is returned when sealing fails.
type ErrSealFailed struct {
	Cause error
}

func (e *ErrSealFailed) Error() string {
	return fmt.Sprintf("failed to seal data: %v", e.Cause)
}

func (e *ErrSealFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsealFailed is returned when unsealing fails.
type ErrUnsealFailed struct {
	Cause error
}

func (e *ErrUnsealFailed) Error() string {
	return fmt.Sprintf("failed to unseal data: %v", e.Cause)
}

func (e *ErrUnsealFailed) Unwrap() error {
	return e.Cause
}

// Attestation Errors

// ErrQuoteFailed is returned when quote generation fails.
type ErrQuoteFailed struct {
	Cause error
}

func (e *ErrQuoteFailed) Error() string {
	return fmt.Sprintf("failed to generate quote: %v", e.Cause)
}

func (e *ErrQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyQuoteFailed is returned when quote verification fails.
type ErrVerifyQuoteFailed struct {
	Cause error
}

func (e *ErrVerifyQuoteFailed) Error() string {
	return fmt.Sprintf("failed to verify quote: %v", e.Cause)
}

func (e *ErrVerifyQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrGetEventLogFailed is returned when getting event log fails.
type ErrGetEventLogFailed struct {
	Cause error
}

func (e *ErrGetEventLogFailed) Error() string {
	return fmt.Sprintf("failed to get event log: %v", e.Cause)
}

func (e *ErrGetEventLogFailed) Unwrap() error {
	return e.Cause
}

// ErrGetPCRsFailed is returned when getting PCRs fails.
type ErrGetPCRsFailed struct {
	Cause error
}

func (e *ErrGetPCRsFailed) Error() string {
	return fmt.Sprintf("failed to get PCRs: %v", e.Cause)
}

func (e *ErrGetPCRsFailed) Unwrap() error {
	return e.Cause
}

// NVRAM Errors

// ErrDefineNVRAMFailed is returned when defining NVRAM fails.
type ErrDefineNVRAMFailed struct {
	Index uint32
	Cause error
}

func (e *ErrDefineNVRAMFailed) Error() string {
	return fmt.Sprintf("failed to define NVRAM at index 0x%x: %v", e.Index, e.Cause)
}

func (e *ErrDefineNVRAMFailed) Unwrap() error {
	return e.Cause
}

// ErrWriteNVRAMFailed is returned when writing NVRAM fails.
type ErrWriteNVRAMFailed struct {
	Index uint32
	Cause error
}

func (e *ErrWriteNVRAMFailed) Error() string {
	return fmt.Sprintf("failed to write NVRAM at index 0x%x: %v", e.Index, e.Cause)
}

func (e *ErrWriteNVRAMFailed) Unwrap() error {
	return e.Cause
}

// ErrReadNVRAMFailed is returned when reading NVRAM fails.
type ErrReadNVRAMFailed struct {
	Index uint32
	Cause error
}

func (e *ErrReadNVRAMFailed) Error() string {
	return fmt.Sprintf("failed to read NVRAM at index 0x%x: %v", e.Index, e.Cause)
}

func (e *ErrReadNVRAMFailed) Unwrap() error {
	return e.Cause
}

// ErrUndefineNVRAMFailed is returned when undefining NVRAM fails.
type ErrUndefineNVRAMFailed struct {
	Index uint32
	Cause error
}

func (e *ErrUndefineNVRAMFailed) Error() string {
	return fmt.Sprintf("failed to undefine NVRAM at index 0x%x: %v", e.Index, e.Cause)
}

func (e *ErrUndefineNVRAMFailed) Unwrap() error {
	return e.Cause
}

// ErrGetRandomFailed is returned when getting random bytes fails.
type ErrGetRandomFailed struct {
	Cause error
}

func (e *ErrGetRandomFailed) Error() string {
	return fmt.Sprintf("failed to get random bytes: %v", e.Cause)
}

func (e *ErrGetRandomFailed) Unwrap() error {
	return e.Cause
}
