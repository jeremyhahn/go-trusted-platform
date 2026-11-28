package commands

import (
	"context"
	"errors"
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

// TestShutdown_SwitchesCloseBeforeStop pins the shutdown order: the switch
// service closes before the daemon stops its transports, and both errors
// come back to the caller.
func TestShutdown_SwitchesCloseBeforeStop(t *testing.T) {
	var order []string
	closeErr, stopErr := stopWithSwitchesFirst(context.Background(),
		func() error { order = append(order, "switches"); return errors.New("close") },
		func(context.Context) error { order = append(order, "stop"); return errors.New("stop") })
	require.Equal(t, []string{"switches", "stop"}, order)
	require.EqualError(t, closeErr, "close")
	require.EqualError(t, stopErr, "stop")
}

// TestShutdown_StopBlockedOnSwitchesFinishes models a graceful transport
// stop that waits on a switch RPC stalled in SSH: the RPC returns only once
// the switch service closed. With the switch close first, the stop finishes.
func TestShutdown_StopBlockedOnSwitchesFinishes(t *testing.T) {
	switchesClosed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = stopWithSwitchesFirst(context.Background(),
			func() error { close(switchesClosed); return nil },
			func(context.Context) error { <-switchesClosed; return nil })
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon stop waited forever on a switch RPC")
	}
}

// TestShutdown_NoSwitchServiceStillStops pins that without a switch service
// the daemon still stops.
func TestShutdown_NoSwitchServiceStillStops(t *testing.T) {
	stopped := false
	closeErr, stopErr := stopWithSwitchesFirst(context.Background(), nil,
		func(context.Context) error { stopped = true; return nil })
	require.True(t, stopped)
	require.NoError(t, closeErr)
	require.NoError(t, stopErr)
}
