package commands

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestServeShutdowner_SignalsTheServeLoop pins that POST /platform/shutdown
// in the serve command reaches the serve loop: the adapter sends SIGTERM on
// the loop's signal channel, so the coordinated stop runs as on a signal,
// and a second request while a stop is pending does not block.
func TestServeShutdowner_SignalsTheServeLoop(t *testing.T) {
	ctx := context.Background()
	sig := make(chan os.Signal, 1)
	s := platformShutdowner(sig)

	resp, err := s.Shutdown(ctx, &platformv1.ShutdownRequest{Graceful: true})
	require.NoError(t, err)
	require.NotNil(t, resp.GetStatus())
	require.True(t, resp.GetStatus().GetSuccess())

	select {
	case got := <-sig:
		require.Equal(t, syscall.SIGTERM, got)
	default:
		t.Fatal("the shutdowner did not signal the serve loop")
	}

	// A stop already pending: the channel is full, Shutdown must not block.
	sig <- syscall.SIGTERM
	done := make(chan error, 1)
	go func() {
		_, err := s.Shutdown(ctx, &platformv1.ShutdownRequest{Graceful: true})
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown blocked on a full signal channel")
	}
}
