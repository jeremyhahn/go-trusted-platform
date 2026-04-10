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

package persistence

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrStorageClosed(t *testing.T) {
	err := ErrStorageClosed{}

	assert.Equal(t, "audit persister is closed", err.Error())
}

func TestErrStorageNotStarted(t *testing.T) {
	err := ErrStorageNotStarted{}

	assert.Equal(t, "audit persister not started", err.Error())
}

func TestErrSerializationFailed(t *testing.T) {
	cause := errors.New("json marshal error")
	err := ErrSerializationFailed{
		EventID: "evt-123",
		Cause:   cause,
	}

	assert.Contains(t, err.Error(), "evt-123")
	assert.Contains(t, err.Error(), "json marshal error")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrDeserializationFailed(t *testing.T) {
	cause := errors.New("json unmarshal error")
	err := ErrDeserializationFailed{Cause: cause}

	assert.Contains(t, err.Error(), "deserialization failed")
	assert.Contains(t, err.Error(), "json unmarshal error")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrPutFailed(t *testing.T) {
	cause := errors.New("storage write error")
	err := ErrPutFailed{
		EventID: "evt-456",
		Cause:   cause,
	}

	assert.Contains(t, err.Error(), "evt-456")
	assert.Contains(t, err.Error(), "storage write error")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrQueryFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("list error")
		err := ErrQueryFailed{
			Reason: "fetch failed",
			Cause:  cause,
		}

		assert.Contains(t, err.Error(), "fetch failed")
		assert.Contains(t, err.Error(), "list error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrQueryFailed{
			Reason: "invalid filter",
			Cause:  nil,
		}

		assert.Contains(t, err.Error(), "invalid filter")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrInvalidConfig(t *testing.T) {
	err := ErrInvalidConfig{
		Field:  "Timeout",
		Reason: "cannot be negative",
	}

	assert.Contains(t, err.Error(), "Timeout")
	assert.Contains(t, err.Error(), "cannot be negative")
}

func TestErrNilStorage(t *testing.T) {
	err := ErrNilStorage{}

	assert.Equal(t, "storage cannot be nil", err.Error())
}

func TestErrNilSDKClient(t *testing.T) {
	err := ErrNilSDKClient{}

	assert.Equal(t, "quicbaas SDK client cannot be nil", err.Error())
}

func TestErrorsAs(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrStorageClosed", ErrStorageClosed{}},
		{"ErrStorageNotStarted", ErrStorageNotStarted{}},
		{"ErrSerializationFailed", ErrSerializationFailed{EventID: "test", Cause: nil}},
		{"ErrDeserializationFailed", ErrDeserializationFailed{Cause: nil}},
		{"ErrPutFailed", ErrPutFailed{EventID: "test", Cause: nil}},
		{"ErrQueryFailed", ErrQueryFailed{Reason: "test", Cause: nil}},
		{"ErrInvalidConfig", ErrInvalidConfig{Field: "test", Reason: "test"}},
		{"ErrNilStorage", ErrNilStorage{}},
		{"ErrNilSDKClient", ErrNilSDKClient{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Implements(t, (*error)(nil), tc.err)
			assert.NotEmpty(t, tc.err.Error())
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	rootCause := errors.New("root cause")

	tests := []struct {
		name       string
		err        error
		hasCause   bool
		wantUnwrap error
	}{
		{
			name:       "ErrSerializationFailed with cause",
			err:        ErrSerializationFailed{EventID: "test", Cause: rootCause},
			hasCause:   true,
			wantUnwrap: rootCause,
		},
		{
			name:       "ErrDeserializationFailed with cause",
			err:        ErrDeserializationFailed{Cause: rootCause},
			hasCause:   true,
			wantUnwrap: rootCause,
		},
		{
			name:       "ErrPutFailed with cause",
			err:        ErrPutFailed{EventID: "test", Cause: rootCause},
			hasCause:   true,
			wantUnwrap: rootCause,
		},
		{
			name:       "ErrQueryFailed with cause",
			err:        ErrQueryFailed{Reason: "test", Cause: rootCause},
			hasCause:   true,
			wantUnwrap: rootCause,
		},
		{
			name:       "ErrSerializationFailed without cause",
			err:        ErrSerializationFailed{EventID: "test", Cause: nil},
			hasCause:   false,
			wantUnwrap: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unwrapper, ok := tc.err.(interface{ Unwrap() error })
			if tc.hasCause {
				require.True(t, ok, "error should implement Unwrap")
				assert.Equal(t, tc.wantUnwrap, unwrapper.Unwrap())
			}
		})
	}
}
