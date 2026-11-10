//go:build tpm_simulator

package vtpm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoverage964_TPMProviderSimulator(t *testing.T) {
	provider := NewTPMProvider(nil)
	t.Cleanup(func() { require.NoError(t, provider.CloseAll()) })

	// With the tpm_simulator tag go-xkms opens the in-process simulator,
	// and the provider caches it: a second open returns the same TPM.
	tpm, err := provider.GetSimulatorTPM()
	require.NoError(t, err)
	require.NotNil(t, tpm)
	cached, err := provider.GetSimulatorTPM()
	require.NoError(t, err)
	require.Same(t, tpm, cached)
}
