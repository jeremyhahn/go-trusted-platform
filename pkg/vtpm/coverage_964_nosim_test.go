//go:build !tpm_simulator

package vtpm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoverage964_TPMProviderSimulator(t *testing.T) {
	provider := NewTPMProvider(nil)
	t.Cleanup(func() { require.NoError(t, provider.CloseAll()) })

	// The simulator is compiled into go-xkms only behind its tpm_simulator
	// tag, which this build does not set: the open fails closed, typed.
	tpm, err := provider.GetSimulatorTPM()
	var openErr ErrTPMDeviceOpenFailed
	require.ErrorAs(t, err, &openErr)
	require.Equal(t, simulatorCacheKey, openErr.Device)
	require.Nil(t, tpm)
}
