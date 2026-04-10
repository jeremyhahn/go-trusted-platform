package podman

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConfig_Validate_EmptyRoot(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	cfg.Root = ""
	err := cfg.Validate()
	require.Error(t, err)
}

func TestRuntimeConfig_Validate_EmptyRunRoot(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	cfg.RunRoot = ""
	err := cfg.Validate()
	require.Error(t, err)
}

func TestRuntimeConfig_Validate_InvalidGraphDriver(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	cfg.GraphDriverName = "invaliddriver"
	err := cfg.Validate()
	require.Error(t, err)
}

func TestRuntimeConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestRuntimeError_NilErr(t *testing.T) {
	err := &RuntimeError{
		Operation: "stop",
		Err:       nil,
	}
	assert.Contains(t, err.Error(), "stop")
}
