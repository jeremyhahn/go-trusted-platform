package commands

import (
	"context"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tpmBusyError stands in for a TPM device that exists but is not ready yet.
type tpmBusyError struct{}

func (tpmBusyError) Error() string { return "TPM busy" }

// failingOpens returns an open function that fails failures times with
// tpmBusyError, then returns final, counting every call in calls.
func failingOpens(failures int, final error, calls *int) func() (xkmssdk.TrustedPlatformModule, error) {
	return func() (xkmssdk.TrustedPlatformModule, error) {
		*calls++
		if *calls <= failures {
			return nil, tpmBusyError{}
		}
		return nil, final
	}
}

func TestOpenTPMWithRetry_OpensAfterTransientFailures(t *testing.T) {
	calls := 0
	_, err := openTPMWithRetry(context.Background(), logging.DefaultLogger(), failingOpens(2, nil, &calls), 5, 0)

	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestOpenTPMWithRetry_UnprovisionedTPMCountsAsOpen(t *testing.T) {
	calls := 0
	_, err := openTPMWithRetry(context.Background(), logging.DefaultLogger(), failingOpens(0, xkmssdk.ErrTPMNotInitialized, &calls), 5, 0)

	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestOpenTPMWithRetry_GivesUpAfterLastAttempt(t *testing.T) {
	calls := 0
	_, err := openTPMWithRetry(context.Background(), logging.DefaultLogger(), failingOpens(10, nil, &calls), 3, 0)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, tpmBusyError{})
	assert.Contains(t, wrapped.Msg, "after 3 attempts")
	assert.Equal(t, 3, calls)
}

func TestOpenTPMWithRetry_CancelStopsTheRetryWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// An hour between attempts: only the cancelled context can end the wait.
	calls := 0
	_, err := openTPMWithRetry(ctx, logging.DefaultLogger(), failingOpens(10, nil, &calls), 5, time.Hour)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls)
}
