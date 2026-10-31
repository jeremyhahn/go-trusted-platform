// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package kms

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/local"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// unixClient opens a lazy Unix socket client the way UnixAdapter.Setup does.
func unixClient(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+socketPath, helpers.GRPCUnixCredentials())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return conn
}

func TestAwaitUnixReady(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "platformd.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped, its other clean-shutdown result.
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err)
		}
	})

	conn := unixClient(t, socketPath)
	ctx, cancel := context.WithTimeout(context.Background(), unixDialTimeout)
	defer cancel()

	require.NoError(t, awaitUnixReady(ctx, conn))
	assert.Equal(t, connectivity.Ready, conn.GetState())
}

func TestAwaitUnixReady_NoSocket(t *testing.T) {
	// Nothing listens on the path: the connection fails at once rather than
	// waiting out the dial timeout.
	conn := unixClient(t, filepath.Join(t.TempDir(), "absent.sock"))
	ctx, cancel := context.WithTimeout(context.Background(), unixDialTimeout)
	defer cancel()

	err := awaitUnixReady(ctx, conn)
	var notReady ErrUnixNotReady
	require.True(t, errors.As(err, &notReady), "got %v", err)
	assert.Equal(t, connectivity.TransientFailure, notReady.State)
	assert.NoError(t, ctx.Err(), "the failure must come before the timeout")
}

func TestAwaitUnixReady_ContextEnded(t *testing.T) {
	// The listener accepts but never speaks HTTP/2, so the client stays
	// CONNECTING and only the context can end the wait.
	socketPath := filepath.Join(t.TempDir(), "silent.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	accepted := make(chan net.Conn, 1)
	go func() {
		peer, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- peer
		}
		close(accepted)
	}()
	t.Cleanup(func() {
		assert.NoError(t, listener.Close())
		for peer := range accepted {
			assert.NoError(t, peer.Close())
		}
	})

	conn := unixClient(t, socketPath)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = awaitUnixReady(ctx, conn)
	var notReady ErrUnixNotReady
	require.True(t, errors.As(err, &notReady), "got %v", err)
	assert.Equal(t, connectivity.Connecting, notReady.State)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestErrUnixNotReady(t *testing.T) {
	plain := ErrUnixNotReady{State: connectivity.TransientFailure}
	assert.Equal(t, "Unix connection not ready (state TRANSIENT_FAILURE)", plain.Error())
	assert.NoError(t, plain.Unwrap())

	timedOut := ErrUnixNotReady{State: connectivity.Connecting, Err: context.DeadlineExceeded}
	assert.Equal(t, "Unix connection not ready (state CONNECTING): context deadline exceeded", timedOut.Error())
	assert.ErrorIs(t, timedOut, context.DeadlineExceeded)
}
