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

package eab

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrCredentialNotFound_Error(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		err := ErrCredentialNotFound{ID: 123}
		assert.Contains(t, err.Error(), "id=123")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("with KeyID", func(t *testing.T) {
		err := ErrCredentialNotFound{KeyID: "test-key-id"}
		assert.Contains(t, err.Error(), "keyID=test-key-id")
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestErrCredentialExpired_Error(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		err := ErrCredentialExpired{ID: 456}
		assert.Contains(t, err.Error(), "id=456")
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("with KeyID", func(t *testing.T) {
		err := ErrCredentialExpired{KeyID: "expired-key"}
		assert.Contains(t, err.Error(), "keyID=expired-key")
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestErrCredentialRevoked_Error(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		err := ErrCredentialRevoked{ID: 789}
		assert.Contains(t, err.Error(), "id=789")
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("with KeyID", func(t *testing.T) {
		err := ErrCredentialRevoked{KeyID: "revoked-key"}
		assert.Contains(t, err.Error(), "keyID=revoked-key")
		assert.Contains(t, err.Error(), "revoked")
	})
}

func TestErrCredentialAlreadyUsed_Error(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		err := ErrCredentialAlreadyUsed{ID: 101}
		assert.Contains(t, err.Error(), "id=101")
		assert.Contains(t, err.Error(), "already used")
	})

	t.Run("with KeyID", func(t *testing.T) {
		err := ErrCredentialAlreadyUsed{KeyID: "used-key"}
		assert.Contains(t, err.Error(), "keyID=used-key")
		assert.Contains(t, err.Error(), "already used")
	})
}

func TestErrInvalidCredential_Error(t *testing.T) {
	err := ErrInvalidCredential{Reason: "HMAC key too short"}
	assert.Contains(t, err.Error(), "invalid credential")
	assert.Contains(t, err.Error(), "HMAC key too short")
}

func TestErrInvalidProfileID_Error(t *testing.T) {
	err := ErrInvalidProfileID{ProfileID: 0}
	assert.Contains(t, err.Error(), "invalid profile ID")
	assert.Contains(t, err.Error(), "0")
}

func TestErrInvalidTenantID_Error(t *testing.T) {
	err := ErrInvalidTenantID{TenantID: ""}
	assert.Contains(t, err.Error(), "invalid tenant ID")
}

func TestErrKeyGenerationFailed_Error(t *testing.T) {
	cause := errors.New("random source unavailable")
	err := ErrKeyGenerationFailed{Cause: cause}
	assert.Contains(t, err.Error(), "key generation failed")
	assert.Contains(t, err.Error(), "random source unavailable")
}

func TestErrKeyGenerationFailed_Unwrap(t *testing.T) {
	cause := errors.New("random source unavailable")
	err := ErrKeyGenerationFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrQRCodeGenerationFailed_Error(t *testing.T) {
	cause := errors.New("encoding failed")
	err := ErrQRCodeGenerationFailed{Cause: cause}
	assert.Contains(t, err.Error(), "QR code generation failed")
	assert.Contains(t, err.Error(), "encoding failed")
}

func TestErrQRCodeGenerationFailed_Unwrap(t *testing.T) {
	cause := errors.New("encoding failed")
	err := ErrQRCodeGenerationFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrFileExportFailed_Error(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrFileExportFailed{Path: "/tmp/test.json", Cause: cause}
	assert.Contains(t, err.Error(), "file export failed")
	assert.Contains(t, err.Error(), "/tmp/test.json")
	assert.Contains(t, err.Error(), "permission denied")
}

func TestErrFileExportFailed_Unwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrFileExportFailed{Path: "/tmp/test.json", Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrInvalidExpiresAt_Error(t *testing.T) {
	err := ErrInvalidExpiresAt{Reason: "expiration in the past"}
	assert.Contains(t, err.Error(), "invalid expiration time")
	assert.Contains(t, err.Error(), "expiration in the past")
}
