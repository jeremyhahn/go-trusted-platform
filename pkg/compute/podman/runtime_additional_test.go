package podman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuntimeError_NilErr(t *testing.T) {
	err := &RuntimeError{
		Operation: "stop",
		Err:       nil,
	}
	assert.Contains(t, err.Error(), "stop")
}
