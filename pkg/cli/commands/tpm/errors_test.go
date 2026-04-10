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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrInvalidAlgorithm(t *testing.T) {
	err := ErrInvalidAlgorithm{
		Algorithm: "INVALID",
		Valid:     []string{"ECDSA-P256", "RSA-2048"},
	}

	assert.Equal(t, "invalid algorithm 'INVALID': valid options are [ECDSA-P256 RSA-2048]", err.Error())
}

func TestErrIDevIDNotFound(t *testing.T) {
	err := ErrIDevIDNotFound{}
	assert.Equal(t, "IDevID key not found in TPM", err.Error())
}

func TestErrIAKNotFound(t *testing.T) {
	err := ErrIAKNotFound{}
	assert.Equal(t, "IAK key not found in TPM", err.Error())
}

func TestErrIDevIDAlreadyExists(t *testing.T) {
	err := ErrIDevIDAlreadyExists{}
	assert.Equal(t, "IDevID key already exists in TPM; use --overwrite to replace", err.Error())
}

func TestErrIAKAlreadyExists(t *testing.T) {
	err := ErrIAKAlreadyExists{}
	assert.Equal(t, "IAK key already exists in TPM; use --overwrite to replace", err.Error())
}

func TestErrGenerateIDevIDFailed(t *testing.T) {
	err := ErrGenerateIDevIDFailed{Reason: "TPM not available"}
	assert.Equal(t, "failed to generate IDevID: TPM not available", err.Error())
}

func TestErrGenerateIAKFailed(t *testing.T) {
	err := ErrGenerateIAKFailed{Reason: "permission denied"}
	assert.Equal(t, "failed to generate IAK: permission denied", err.Error())
}

func TestErrDeleteIDevIDFailed(t *testing.T) {
	err := ErrDeleteIDevIDFailed{Reason: "key not found"}
	assert.Equal(t, "failed to delete IDevID: key not found", err.Error())
}

func TestErrDeleteIAKFailed(t *testing.T) {
	err := ErrDeleteIAKFailed{Reason: "authorization failed"}
	assert.Equal(t, "failed to delete IAK: authorization failed", err.Error())
}

func TestErrGetIDevIDInfoFailed(t *testing.T) {
	err := ErrGetIDevIDInfoFailed{Reason: "connection timeout"}
	assert.Equal(t, "failed to get IDevID info: connection timeout", err.Error())
}

func TestErrGetIAKInfoFailed(t *testing.T) {
	err := ErrGetIAKInfoFailed{Reason: "server error"}
	assert.Equal(t, "failed to get IAK info: server error", err.Error())
}

func TestErrFlushFailed(t *testing.T) {
	err := ErrFlushFailed{Reason: "TPM busy"}
	assert.Equal(t, "failed to flush transient contexts: TPM busy", err.Error())
}

func TestErrGetDeviceAttributesFailed(t *testing.T) {
	err := ErrGetDeviceAttributesFailed{Reason: "connection refused"}
	assert.Equal(t, "failed to get device attributes: connection refused", err.Error())
}

func TestErrCreateIDevIDCSRFailed(t *testing.T) {
	err := ErrCreateIDevIDCSRFailed{Reason: "key not found"}
	assert.Equal(t, "failed to create IDevID CSR: key not found", err.Error())
}

func TestErrCreateIAKCSRFailed(t *testing.T) {
	err := ErrCreateIAKCSRFailed{Reason: "signing failed"}
	assert.Equal(t, "failed to create IAK CSR: signing failed", err.Error())
}

func TestErrInstallIDevIDCertificateFailed(t *testing.T) {
	err := ErrInstallIDevIDCertificateFailed{Reason: "invalid certificate"}
	assert.Equal(t, "failed to install IDevID certificate: invalid certificate", err.Error())
}

func TestErrInstallIAKCertificateFailed(t *testing.T) {
	err := ErrInstallIAKCertificateFailed{Reason: "key mismatch"}
	assert.Equal(t, "failed to install IAK certificate: key mismatch", err.Error())
}

func TestErrGetIDevIDCertificateFailed(t *testing.T) {
	err := ErrGetIDevIDCertificateFailed{Reason: "storage error"}
	assert.Equal(t, "failed to get IDevID certificate: storage error", err.Error())
}

func TestErrGetIAKCertificateFailed(t *testing.T) {
	err := ErrGetIAKCertificateFailed{Reason: "NV read failed"}
	assert.Equal(t, "failed to get IAK certificate: NV read failed", err.Error())
}

func TestErrIDevIDCertificateNotFound(t *testing.T) {
	err := ErrIDevIDCertificateNotFound{}
	assert.Equal(t, "IDevID certificate not found", err.Error())
}

func TestErrIAKCertificateNotFound(t *testing.T) {
	err := ErrIAKCertificateNotFound{}
	assert.Equal(t, "IAK certificate not found", err.Error())
}
