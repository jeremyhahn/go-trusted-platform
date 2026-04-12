package barrier

import (
	"errors"
	"testing"

	barriersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/barrier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateInitParams_ZeroThresholdWithSecret(t *testing.T) {
	err := validateInitParams("my-secret", 0, 0)
	require.NoError(t, err)
}

func TestValidateInitParams_ShamirMinimumThreshold(t *testing.T) {
	err := validateInitParams("", 2, 2)
	require.NoError(t, err)
}

func TestValidateInitParams_ShamirThresholdOne(t *testing.T) {
	// threshold=1 is single-key mode, needs secret
	err := validateInitParams("", 1, 5)
	require.Error(t, err)
	var missingErr ErrMissingSecret
	assert.True(t, errors.As(err, &missingErr))
}

func TestFormatStrategy_AllValues(t *testing.T) {
	tests := []struct {
		strategy barriersvc.Strategy
		expected string
	}{
		{barriersvc.StrategyUnspecified, "unspecified"},
		{barriersvc.StrategySingleKey, "single-key"},
		{barriersvc.StrategyShamir, "shamir"},
		{barriersvc.Strategy("unknown-strategy"), "unknown"},
		{barriersvc.Strategy(""), "unknown"},
	}

	for _, tt := range tests {
		result := formatStrategy(tt.strategy)
		assert.Equal(t, tt.expected, result)
	}
}

func TestStrategyNamesMap(t *testing.T) {
	assert.Len(t, strategyNames, 3)
	assert.Contains(t, strategyNames, barriersvc.StrategyUnspecified)
	assert.Contains(t, strategyNames, barriersvc.StrategySingleKey)
	assert.Contains(t, strategyNames, barriersvc.StrategyShamir)
}

func TestErrInvalidThreshold_Fields(t *testing.T) {
	err := ErrInvalidThreshold{Threshold: 10, Shares: 3}
	assert.Contains(t, err.Error(), "10")
	assert.Contains(t, err.Error(), "3")
}

func TestErrInvalidShares_Fields(t *testing.T) {
	err := ErrInvalidShares{Shares: -1}
	assert.Contains(t, err.Error(), "-1")
}

func TestErrBarrierInitFailed_NilErr(t *testing.T) {
	err := ErrBarrierInitFailed{Err: nil}
	assert.Contains(t, err.Error(), "barrier initialization failed")
}

func TestErrBarrierStatusFailed_NilErr(t *testing.T) {
	err := ErrBarrierStatusFailed{Err: nil}
	assert.Contains(t, err.Error(), "failed to get barrier status")
}

func TestErrBarrierUnsealFailed_NilErr(t *testing.T) {
	err := ErrBarrierUnsealFailed{Err: nil}
	assert.Contains(t, err.Error(), "barrier unseal failed")
}

func TestErrBarrierSealFailed_NilErr(t *testing.T) {
	err := ErrBarrierSealFailed{Err: nil}
	assert.Contains(t, err.Error(), "barrier seal failed")
}

func TestErrBarrierRekeyFailed_NilErr(t *testing.T) {
	err := ErrBarrierRekeyFailed{Err: nil}
	assert.Contains(t, err.Error(), "barrier rekey failed")
}
