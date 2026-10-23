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
	"errors"
	"strings"
	"testing"
)

func TestErrBundleNotFound_Error(t *testing.T) {
	err := ErrBundleNotFound{ID: "test-bundle-123"}

	if !strings.Contains(err.Error(), "test-bundle-123") {
		t.Errorf("Error() should contain ID, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "bundle not found") {
		t.Errorf("Error() should contain 'bundle not found', got: %v", err.Error())
	}
}

func TestErrBundleAlreadyExists_Error(t *testing.T) {
	err := ErrBundleAlreadyExists{ID: "existing-bundle"}

	if !strings.Contains(err.Error(), "existing-bundle") {
		t.Errorf("Error() should contain ID, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "bundle already exists") {
		t.Errorf("Error() should contain 'bundle already exists', got: %v", err.Error())
	}
}

func TestErrTemplateNotFound_Error(t *testing.T) {
	err := ErrTemplateNotFound{ID: "base-template"}

	if !strings.Contains(err.Error(), "base-template") {
		t.Errorf("Error() should contain ID, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "template not found") {
		t.Errorf("Error() should contain 'template not found', got: %v", err.Error())
	}
}

func TestErrTemplateAlreadyExists_Error(t *testing.T) {
	err := ErrTemplateAlreadyExists{ID: "existing-template"}

	if !strings.Contains(err.Error(), "existing-template") {
		t.Errorf("Error() should contain ID, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "template already exists") {
		t.Errorf("Error() should contain 'template already exists', got: %v", err.Error())
	}
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "BaseDir", Reason: "cannot be empty"}

	if !strings.Contains(err.Error(), "BaseDir") {
		t.Errorf("Error() should contain field name, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("Error() should contain reason, got: %v", err.Error())
	}
}

func TestErrInvalidManifest_Error(t *testing.T) {
	err := ErrInvalidManifest{Reason: "missing ID field"}

	if !strings.Contains(err.Error(), "invalid manifest") {
		t.Errorf("Error() should contain 'invalid manifest', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "missing ID field") {
		t.Errorf("Error() should contain reason, got: %v", err.Error())
	}
}

func TestErrSWTPMOperationFailed_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrSWTPMOperationFailed{Operation: "connect", Cause: cause}

	if !strings.Contains(err.Error(), "swtpm") {
		t.Errorf("Error() should contain 'swtpm', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("Error() should contain operation, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("Error() should contain cause message, got: %v", err.Error())
	}
}

func TestErrSWTPMOperationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrSWTPMOperationFailed{Operation: "start", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrEKCertInjectionFailed_Error(t *testing.T) {
	cause := errors.New("NV write failed")
	err := ErrEKCertInjectionFailed{Cause: cause}

	if !strings.Contains(err.Error(), "EK certificate injection failed") {
		t.Errorf("Error() should contain 'EK certificate injection failed', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "NV write failed") {
		t.Errorf("Error() should contain cause message, got: %v", err.Error())
	}
}

func TestErrEKCertInjectionFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrEKCertInjectionFailed{Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrSecureBootEnrollmentFailed_Error(t *testing.T) {
	cause := errors.New("key enrollment failed")
	err := ErrSecureBootEnrollmentFailed{Cause: cause}

	if !strings.Contains(err.Error(), "Secure Boot enrollment failed") {
		t.Errorf("Error() should contain 'Secure Boot enrollment failed', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "key enrollment failed") {
		t.Errorf("Error() should contain cause message, got: %v", err.Error())
	}
}

func TestErrSecureBootEnrollmentFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrSecureBootEnrollmentFailed{Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrOVMFNotFound_Error(t *testing.T) {
	err := ErrOVMFNotFound{Path: "/usr/share/OVMF/OVMF_CODE.fd"}

	if !strings.Contains(err.Error(), "OVMF") {
		t.Errorf("Error() should contain 'OVMF', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "/usr/share/OVMF/OVMF_CODE.fd") {
		t.Errorf("Error() should contain path, got: %v", err.Error())
	}
}

func TestErrNVRAMWriteFailed_Error(t *testing.T) {
	cause := errors.New("write error")
	err := ErrNVRAMWriteFailed{NVIndex: 0x01C00002, Cause: cause}

	if !strings.Contains(err.Error(), "0x01C00002") {
		t.Errorf("Error() should contain NV index, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "write error") {
		t.Errorf("Error() should contain cause message, got: %v", err.Error())
	}
}

func TestErrNVRAMWriteFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrNVRAMWriteFailed{NVIndex: 0x01C00002, Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrArchiveOperationFailed_Error(t *testing.T) {
	cause := errors.New("compression failed")
	err := ErrArchiveOperationFailed{Operation: "export", Cause: cause}

	if !strings.Contains(err.Error(), "archive") {
		t.Errorf("Error() should contain 'archive', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "export") {
		t.Errorf("Error() should contain operation, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "compression failed") {
		t.Errorf("Error() should contain cause message, got: %v", err.Error())
	}
}

func TestErrArchiveOperationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrArchiveOperationFailed{Operation: "import", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrCAUnavailable_Error(t *testing.T) {
	err := ErrCAUnavailable{}

	if !strings.Contains(err.Error(), "CA unavailable") {
		t.Errorf("Error() should contain 'CA unavailable', got: %v", err.Error())
	}
}

func TestErrCAUnavailable_WithCause(t *testing.T) {
	cause := errors.New("connection failed")
	err := ErrCAUnavailable{Cause: cause}

	if !strings.Contains(err.Error(), "connection failed") {
		t.Errorf("Error() should contain cause, got: %v", err.Error())
	}
}

func TestErrCAUnavailable_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrCAUnavailable{Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrChecksumMismatch_Error(t *testing.T) {
	err := ErrChecksumMismatch{
		File:     "manifest.json",
		Expected: "abc123",
		Actual:   "def456",
	}

	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Error() should contain 'checksum mismatch', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "manifest.json") {
		t.Errorf("Error() should contain file name, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "abc123") {
		t.Errorf("Error() should contain expected checksum, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "def456") {
		t.Errorf("Error() should contain actual checksum, got: %v", err.Error())
	}
}

func TestErrSecureBootKeyGenFailed_Error(t *testing.T) {
	cause := errors.New("key generation failed")
	err := ErrSecureBootKeyGenFailed{Cause: cause}

	if !strings.Contains(err.Error(), "Secure Boot key generation failed") {
		t.Errorf("Error() should contain 'Secure Boot key generation failed', got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "key generation failed") {
		t.Errorf("Error() should contain cause, got: %v", err.Error())
	}
}

func TestErrSecureBootKeyGenFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrSecureBootKeyGenFailed{Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

// =============================================================================
// Runtime TPM Operation Error Tests
// =============================================================================

func TestErrVTPMNotRunning_Error(t *testing.T) {
	tests := []struct {
		name     string
		bundleID string
		wantPart string
	}{
		{
			name:     "basic bundle ID",
			bundleID: "test-bundle-123",
			wantPart: "test-bundle-123",
		},
		{
			name:     "bundle with hostname",
			bundleID: "vm-host.example.com-1234567890",
			wantPart: "vm-host.example.com-1234567890",
		},
		{
			name:     "empty bundle ID",
			bundleID: "",
			wantPart: "vTPM not running for bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrVTPMNotRunning{BundleID: tt.bundleID}
			errMsg := err.Error()

			if !strings.Contains(errMsg, tt.wantPart) {
				t.Errorf("Error() = %v, want to contain %v", errMsg, tt.wantPart)
			}

			if !strings.Contains(errMsg, "vTPM not running") {
				t.Errorf("Error() should contain 'vTPM not running', got: %v", errMsg)
			}
		})
	}
}

func TestErrVTPMAlreadyRunning_Error(t *testing.T) {
	tests := []struct {
		name     string
		bundleID string
		wantPart string
	}{
		{
			name:     "basic bundle ID",
			bundleID: "running-bundle",
			wantPart: "running-bundle",
		},
		{
			name:     "UUID bundle ID",
			bundleID: "550e8400-e29b-41d4-a716-446655440000",
			wantPart: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrVTPMAlreadyRunning{BundleID: tt.bundleID}
			errMsg := err.Error()

			if !strings.Contains(errMsg, tt.wantPart) {
				t.Errorf("Error() = %v, want to contain %v", errMsg, tt.wantPart)
			}

			if !strings.Contains(errMsg, "vTPM already running") {
				t.Errorf("Error() should contain 'vTPM already running', got: %v", errMsg)
			}
		})
	}
}

func TestErrVTPMStartFailed_Error(t *testing.T) {
	cause := errors.New("socket initialization failed")
	err := ErrVTPMStartFailed{BundleID: "start-failed-bundle", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "start-failed-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "failed to start vTPM") {
		t.Errorf("Error() should contain 'failed to start vTPM', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "socket initialization failed") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrVTPMStartFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying start error")
	err := ErrVTPMStartFailed{BundleID: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrVTPMStopFailed_Error(t *testing.T) {
	cause := errors.New("process termination failed")
	err := ErrVTPMStopFailed{BundleID: "stop-failed-bundle", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "stop-failed-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "failed to stop vTPM") {
		t.Errorf("Error() should contain 'failed to stop vTPM', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "process termination failed") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrVTPMStopFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying stop error")
	err := ErrVTPMStopFailed{BundleID: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrTPMQuoteFailed_Error(t *testing.T) {
	cause := errors.New("quote signature verification failed")
	err := ErrTPMQuoteFailed{BundleID: "quote-bundle", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "quote-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "TPM quote failed") {
		t.Errorf("Error() should contain 'TPM quote failed', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "quote signature verification failed") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrTPMQuoteFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying quote error")
	err := ErrTPMQuoteFailed{BundleID: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrTPMSealFailed_Error(t *testing.T) {
	cause := errors.New("sealing key creation failed")
	err := ErrTPMSealFailed{BundleID: "seal-bundle", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "seal-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "TPM seal failed") {
		t.Errorf("Error() should contain 'TPM seal failed', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "sealing key creation failed") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrTPMSealFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying seal error")
	err := ErrTPMSealFailed{BundleID: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrTPMUnsealFailed_Error(t *testing.T) {
	cause := errors.New("PCR policy not satisfied")
	err := ErrTPMUnsealFailed{BundleID: "unseal-bundle", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "unseal-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "TPM unseal failed") {
		t.Errorf("Error() should contain 'TPM unseal failed', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR policy not satisfied") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrTPMUnsealFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying unseal error")
	err := ErrTPMUnsealFailed{BundleID: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrPCRExtendFailed_Error(t *testing.T) {
	cause := errors.New("PCR extend authorization failed")
	err := ErrPCRExtendFailed{BundleID: "pcr-bundle", PCRIndex: 7, Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "pcr-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR extend failed") {
		t.Errorf("Error() should contain 'PCR extend failed', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR 7") {
		t.Errorf("Error() should contain PCR index, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR extend authorization failed") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrPCRExtendFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying extend error")
	err := ErrPCRExtendFailed{BundleID: "test", PCRIndex: 0, Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrPCRReadFailed_Error(t *testing.T) {
	cause := errors.New("PCR bank not available")
	err := ErrPCRReadFailed{BundleID: "pcr-read-bundle", PCRIndex: 23, Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "pcr-read-bundle") {
		t.Errorf("Error() should contain bundle ID, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR read failed") {
		t.Errorf("Error() should contain 'PCR read failed', got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR 23") {
		t.Errorf("Error() should contain PCR index, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "PCR bank not available") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrPCRReadFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying read error")
	err := ErrPCRReadFailed{BundleID: "test", PCRIndex: 0, Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrInvalidPCRIndex_Error(t *testing.T) {
	tests := []struct {
		name     string
		pcrIndex int
		wantPart string
	}{
		{
			name:     "negative index",
			pcrIndex: -1,
			wantPart: "-1",
		},
		{
			name:     "too large index",
			pcrIndex: 24,
			wantPart: "24",
		},
		{
			name:     "way too large index",
			pcrIndex: 100,
			wantPart: "100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPCRIndex{PCRIndex: tt.pcrIndex}
			errMsg := err.Error()

			if !strings.Contains(errMsg, tt.wantPart) {
				t.Errorf("Error() = %v, want to contain %v", errMsg, tt.wantPart)
			}

			if !strings.Contains(errMsg, "invalid PCR index") {
				t.Errorf("Error() should contain 'invalid PCR index', got: %v", errMsg)
			}

			if !strings.Contains(errMsg, "must be 0-23") {
				t.Errorf("Error() should contain valid range, got: %v", errMsg)
			}
		})
	}
}

func TestErrInvalidNonce_Error(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "empty nonce",
			reason: "nonce cannot be empty",
		},
		{
			name:   "nonce too long",
			reason: "nonce too long (max 64 bytes)",
		},
		{
			name:   "custom reason",
			reason: "nonce must contain only printable characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidNonce{Reason: tt.reason}
			errMsg := err.Error()

			if !strings.Contains(errMsg, tt.reason) {
				t.Errorf("Error() = %v, want to contain %v", errMsg, tt.reason)
			}

			if !strings.Contains(errMsg, "invalid nonce") {
				t.Errorf("Error() should contain 'invalid nonce', got: %v", errMsg)
			}
		})
	}
}

func TestErrTPMConnectionFailed_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrTPMConnectionFailed{SocketPath: "/var/run/swtpm.sock", Cause: cause}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "/var/run/swtpm.sock") {
		t.Errorf("Error() should contain socket path, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "failed to connect to TPM socket") {
		t.Errorf("Error() should contain connection error message, got: %v", errMsg)
	}

	if !strings.Contains(errMsg, "connection refused") {
		t.Errorf("Error() should contain cause message, got: %v", errMsg)
	}
}

func TestErrTPMConnectionFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying connection error")
	err := ErrTPMConnectionFailed{SocketPath: "/tmp/test.sock", Cause: cause}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() should return the cause error")
	}
}

func TestErrInvalidEKAlgorithm_Error(t *testing.T) {
	errMsg := ErrInvalidEKAlgorithm{Algorithm: "ECDSA"}.Error()

	for _, want := range []string{`"ECDSA"`, "RSA or ECC"} {
		if !strings.Contains(errMsg, want) {
			t.Errorf("Error() = %q, want it to contain %q", errMsg, want)
		}
	}
}

// =============================================================================
// Error Type Assertions Tests
// =============================================================================

func TestErrorTypeAssertions(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "ErrBundleNotFound", err: ErrBundleNotFound{ID: "test"}},
		{name: "ErrBundleAlreadyExists", err: ErrBundleAlreadyExists{ID: "test"}},
		{name: "ErrTemplateNotFound", err: ErrTemplateNotFound{ID: "test"}},
		{name: "ErrTemplateAlreadyExists", err: ErrTemplateAlreadyExists{ID: "test"}},
		{name: "ErrInvalidManifest", err: ErrInvalidManifest{Reason: "test"}},
		{name: "ErrEKCertInjectionFailed", err: ErrEKCertInjectionFailed{Cause: errors.New("test")}},
		{name: "ErrSecureBootEnrollmentFailed", err: ErrSecureBootEnrollmentFailed{Cause: errors.New("test")}},
		{name: "ErrSWTPMOperationFailed", err: ErrSWTPMOperationFailed{Operation: "test", Cause: errors.New("test")}},
		{name: "ErrNVRAMWriteFailed", err: ErrNVRAMWriteFailed{NVIndex: 0x01C00002, Cause: errors.New("test")}},
		{name: "ErrArchiveOperationFailed", err: ErrArchiveOperationFailed{Operation: "test", Cause: errors.New("test")}},
		{name: "ErrCAUnavailable", err: ErrCAUnavailable{}},
		{name: "ErrInvalidConfig", err: ErrInvalidConfig{Field: "test", Reason: "test"}},
		{name: "ErrChecksumMismatch", err: ErrChecksumMismatch{File: "test", Expected: "a", Actual: "b"}},
		{name: "ErrSecureBootKeyGenFailed", err: ErrSecureBootKeyGenFailed{Cause: errors.New("test")}},
		{name: "ErrOVMFNotFound", err: ErrOVMFNotFound{Path: "/test"}},
		{name: "ErrVTPMNotRunning", err: ErrVTPMNotRunning{BundleID: "test"}},
		{name: "ErrVTPMAlreadyRunning", err: ErrVTPMAlreadyRunning{BundleID: "test"}},
		{name: "ErrVTPMStartFailed", err: ErrVTPMStartFailed{BundleID: "test", Cause: errors.New("test")}},
		{name: "ErrVTPMStopFailed", err: ErrVTPMStopFailed{BundleID: "test", Cause: errors.New("test")}},
		{name: "ErrTPMQuoteFailed", err: ErrTPMQuoteFailed{BundleID: "test", Cause: errors.New("test")}},
		{name: "ErrTPMSealFailed", err: ErrTPMSealFailed{BundleID: "test", Cause: errors.New("test")}},
		{name: "ErrTPMUnsealFailed", err: ErrTPMUnsealFailed{BundleID: "test", Cause: errors.New("test")}},
		{name: "ErrPCRExtendFailed", err: ErrPCRExtendFailed{BundleID: "test", PCRIndex: 0, Cause: errors.New("test")}},
		{name: "ErrPCRReadFailed", err: ErrPCRReadFailed{BundleID: "test", PCRIndex: 0, Cause: errors.New("test")}},
		{name: "ErrInvalidPCRIndex", err: ErrInvalidPCRIndex{PCRIndex: 24}},
		{name: "ErrInvalidNonce", err: ErrInvalidNonce{Reason: "test"}},
		{name: "ErrTPMConnectionFailed", err: ErrTPMConnectionFailed{SocketPath: "/test", Cause: errors.New("test")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("Error() should not return empty string")
			}
		})
	}
}

// =============================================================================
// Error Wrapping Tests
// =============================================================================

func TestErrorWrapping(t *testing.T) {
	baseErr := errors.New("base error")

	tests := []struct {
		name string
		err  error
	}{
		{name: "ErrEKCertInjectionFailed", err: ErrEKCertInjectionFailed{Cause: baseErr}},
		{name: "ErrSecureBootEnrollmentFailed", err: ErrSecureBootEnrollmentFailed{Cause: baseErr}},
		{name: "ErrSWTPMOperationFailed", err: ErrSWTPMOperationFailed{Operation: "test", Cause: baseErr}},
		{name: "ErrNVRAMWriteFailed", err: ErrNVRAMWriteFailed{NVIndex: 0, Cause: baseErr}},
		{name: "ErrArchiveOperationFailed", err: ErrArchiveOperationFailed{Operation: "test", Cause: baseErr}},
		{name: "ErrCAUnavailable", err: ErrCAUnavailable{Cause: baseErr}},
		{name: "ErrSecureBootKeyGenFailed", err: ErrSecureBootKeyGenFailed{Cause: baseErr}},
		{name: "ErrVTPMStartFailed", err: ErrVTPMStartFailed{BundleID: "test", Cause: baseErr}},
		{name: "ErrVTPMStopFailed", err: ErrVTPMStopFailed{BundleID: "test", Cause: baseErr}},
		{name: "ErrTPMQuoteFailed", err: ErrTPMQuoteFailed{BundleID: "test", Cause: baseErr}},
		{name: "ErrTPMSealFailed", err: ErrTPMSealFailed{BundleID: "test", Cause: baseErr}},
		{name: "ErrTPMUnsealFailed", err: ErrTPMUnsealFailed{BundleID: "test", Cause: baseErr}},
		{name: "ErrPCRExtendFailed", err: ErrPCRExtendFailed{BundleID: "test", PCRIndex: 0, Cause: baseErr}},
		{name: "ErrPCRReadFailed", err: ErrPCRReadFailed{BundleID: "test", PCRIndex: 0, Cause: baseErr}},
		{name: "ErrTPMConnectionFailed", err: ErrTPMConnectionFailed{SocketPath: "/test", Cause: baseErr}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify errors.Is works
			if !errors.Is(tt.err, baseErr) {
				t.Errorf("errors.Is() should find base error")
			}
		})
	}
}

func TestErrProfileAssignmentFailed_Error(t *testing.T) {
	cause := errors.New("storage unavailable")
	err := ErrProfileAssignmentFailed{
		ProfileID: 42,
		EKSerial:  "9876543210",
		Cause:     cause,
	}

	if !strings.Contains(err.Error(), "9876543210") {
		t.Errorf("Error() should contain EK serial, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "42") {
		t.Errorf("Error() should contain profile ID, got: %v", err.Error())
	}

	if !strings.Contains(err.Error(), "failed to assign") {
		t.Errorf("Error() should contain 'failed to assign', got: %v", err.Error())
	}

	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}

	if !errors.Is(err, cause) {
		t.Error("errors.Is should find the cause")
	}
}
