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

package image

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrTimestampVerificationFailed_Error(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		err := ErrTimestampVerificationFailed{
			Step:   "signature",
			Reason: "bad digest",
			Err:    errors.New("underlying"),
		}
		msg := err.Error()
		assert.Contains(t, msg, "timestamp verification failed")
		assert.Contains(t, msg, "signature")
		assert.Contains(t, msg, "bad digest")
		assert.Contains(t, msg, "underlying")
	})

	t.Run("step only", func(t *testing.T) {
		err := ErrTimestampVerificationFailed{Step: "cert"}
		msg := err.Error()
		assert.Contains(t, msg, "cert")
		assert.NotContains(t, msg, ":")
	})

	t.Run("reason only", func(t *testing.T) {
		err := ErrTimestampVerificationFailed{Reason: "expired"}
		msg := err.Error()
		assert.Contains(t, msg, "expired")
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrTimestampVerificationFailed{}
		assert.Equal(t, "timestamp verification failed", err.Error())
	})
}

func TestErrTimestampVerificationFailed_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := ErrTimestampVerificationFailed{Err: cause}
	assert.Equal(t, cause, err.Unwrap())

	errNil := ErrTimestampVerificationFailed{}
	assert.Nil(t, errNil.Unwrap())
}

func TestErrInvalidTimestampToken_Error(t *testing.T) {
	t.Run("with error", func(t *testing.T) {
		err := ErrInvalidTimestampToken{
			Reason: "bad format",
			Err:    errors.New("parse failed"),
		}
		msg := err.Error()
		assert.Contains(t, msg, "invalid timestamp token")
		assert.Contains(t, msg, "bad format")
		assert.Contains(t, msg, "parse failed")
	})

	t.Run("reason only", func(t *testing.T) {
		err := ErrInvalidTimestampToken{Reason: "too short"}
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrInvalidTimestampToken{}
		assert.Equal(t, "invalid timestamp token", err.Error())
	})
}

func TestErrInvalidTimestampToken_Unwrap(t *testing.T) {
	cause := errors.New("root")
	err := ErrInvalidTimestampToken{Err: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrMessageImprintMismatch_Error(t *testing.T) {
	t.Run("with values", func(t *testing.T) {
		err := ErrMessageImprintMismatch{
			Expected: "abc123",
			Actual:   "def456",
		}
		msg := err.Error()
		assert.Contains(t, msg, "abc123")
		assert.Contains(t, msg, "def456")
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrMessageImprintMismatch{}
		assert.Contains(t, err.Error(), "message imprint does not match")
	})
}

func TestPkixName_String(t *testing.T) {
	t.Run("common name", func(t *testing.T) {
		n := pkixName{CommonName: "Test CA"}
		assert.Equal(t, "Test CA", n.String())
	})

	t.Run("organization fallback", func(t *testing.T) {
		n := pkixName{Organization: []string{"Acme Corp"}}
		assert.Equal(t, "Acme Corp", n.String())
	})

	t.Run("empty", func(t *testing.T) {
		n := pkixName{}
		assert.Equal(t, "", n.String())
	})
}

func TestExtractTSAName(t *testing.T) {
	client := &RFC3161Client{}

	t.Run("directory name context tag", func(t *testing.T) {
		// A directoryName [4] with empty content falls back to hex
		raw := asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        4,
			IsCompound: true,
			Bytes:      []byte{0x01, 0x02},
		}
		result := client.extractTSAName(raw)
		require.NotEmpty(t, result)
	})

	t.Run("non-directory name fallback", func(t *testing.T) {
		raw := asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   1,
			Bytes: []byte{0xAA, 0xBB},
		}
		result := client.extractTSAName(raw)
		assert.Equal(t, "aabb", result)
	})
}
