package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExitCode_CarriesTheCodeOfAnExitError(t *testing.T) {
	cause := errors.New("refused: pool-exhausted")
	err := fmt.Errorf("vpn connect: %w", &ExitError{Code: 4, Err: cause})

	assert.Equal(t, 4, ExitCode(err))
	assert.Equal(t, "vpn connect: refused: pool-exhausted", err.Error())
	assert.ErrorIs(t, err, cause)
}

func TestExitCode_GenericFailureIsOne(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, 0},
		{"plain error", errors.New("boom"), ExitGenericFailure},
		{"typed error without a code", ErrTLSCACertInvalid{Path: "ca.pem"}, ExitGenericFailure},
		{"exit error with code zero", &ExitError{Err: errors.New("boom")}, ExitGenericFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExitCode(tt.err))
		})
	}
}

func TestExitError_WithoutCauseStillDescribesItself(t *testing.T) {
	err := &ExitError{Code: 6}

	assert.Equal(t, "command failed", err.Error())
	assert.NoError(t, err.Unwrap())
}
