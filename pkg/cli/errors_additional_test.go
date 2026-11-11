package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrConfigReadFailed(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrConfigReadFailed{Path: "/etc/config.yaml", Err: cause}

	assert.Contains(t, err.Error(), "/etc/config.yaml")
	assert.Contains(t, err.Error(), "permission denied")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrConfigParseFailed_Unwrap(t *testing.T) {
	cause := errors.New("invalid yaml")
	err := ErrConfigParseFailed{Path: "/etc/config.yaml", Err: cause}

	assert.Contains(t, err.Error(), "/etc/config.yaml")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrConfigMarshalFailed(t *testing.T) {
	cause := errors.New("marshal error")
	err := ErrConfigMarshalFailed{Err: cause}

	assert.Contains(t, err.Error(), "marshal")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrConfigWriteFailed(t *testing.T) {
	cause := errors.New("disk full")
	err := ErrConfigWriteFailed{Path: "/var/lib/user/.platformctl/config.yaml", Err: cause}

	assert.Contains(t, err.Error(), "/var/lib/user/.platformctl/config.yaml")
	assert.Contains(t, err.Error(), "disk full")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrConfigDirCreateFailed(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrConfigDirCreateFailed{Path: "/var/lib/user/.platformctl", Err: cause}

	assert.Contains(t, err.Error(), "/var/lib/user/.platformctl")
	assert.Contains(t, err.Error(), "permission denied")
	assert.Equal(t, cause, err.Unwrap())
}

func TestAllErrors_Unwrap(t *testing.T) {
	rootCause := errors.New("root cause")

	tests := []struct {
		name string
		err  error
		want error
	}{
		{"ConfigReadFailed", ErrConfigReadFailed{Err: rootCause}, rootCause},
		{"ConfigParseFailed", ErrConfigParseFailed{Err: rootCause}, rootCause},
		{"ConfigMarshalFailed", ErrConfigMarshalFailed{Err: rootCause}, rootCause},
		{"ConfigWriteFailed", ErrConfigWriteFailed{Err: rootCause}, rootCause},
		{"ConfigDirCreateFailed", ErrConfigDirCreateFailed{Err: rootCause}, rootCause},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapper, ok := tt.err.(interface{ Unwrap() error })
			require.True(t, ok, "error should implement Unwrap")
			assert.Equal(t, tt.want, unwrapper.Unwrap())
		})
	}
}
