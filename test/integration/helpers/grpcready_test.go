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

package helpers

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/local"
)

// shortSocketDir returns a directory whose path keeps a socket under the
// 108-byte sun_path limit, which t.TempDir's long names can exceed.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "grpcready")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("RemoveAll(%s): %v", dir, err)
		}
	})
	return dir
}

func TestWaitGRPCReady_ReadyWhenServerListens(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	conn, err := grpc.NewClient("unix://"+socketPath, GRPCUnixCredentials())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := WaitGRPCReady(ctx, conn); err != nil {
		t.Fatalf("WaitGRPCReady = %v, want nil", err)
	}
	if got := conn.GetState(); got != connectivity.Ready {
		t.Fatalf("state = %s, want READY", got)
	}
}

func TestWaitGRPCReady_FailsAtDeadlineWhenNothingListens(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "absent.sock")
	conn, err := grpc.NewClient("unix://"+socketPath, GRPCUnixCredentials())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = WaitGRPCReady(ctx, conn)

	var notReady *GRPCNotReadyError
	if !errors.As(err, &notReady) {
		t.Fatalf("WaitGRPCReady = %v, want *GRPCNotReadyError", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitGRPCReady = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if notReady.State == connectivity.Ready {
		t.Fatalf("reported state READY for an absent socket")
	}
}

func TestWaitGRPCReady_FailsOnClosedConnection(t *testing.T) {
	conn, err := grpc.NewClient("unix://"+filepath.Join(shortSocketDir(t), "c.sock"), GRPCUnixCredentials())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = WaitGRPCReady(context.Background(), conn)

	var notReady *GRPCNotReadyError
	if !errors.As(err, &notReady) || notReady.State != connectivity.Shutdown {
		t.Fatalf("WaitGRPCReady = %v, want *GRPCNotReadyError in SHUTDOWN", err)
	}
}
