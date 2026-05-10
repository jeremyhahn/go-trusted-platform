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

package luks

import (
	"context"
	"os"

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// UnixAdapter drives LUKS operations over gRPC-over-UDS.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *lukssdk.GRPCClient
}

// NewUnixAdapter returns an unconfigured Unix adapter.
func NewUnixAdapter() *UnixAdapter { return &UnixAdapter{} }

// Name returns "Unix".
func (u *UnixAdapter) Name() string { return "Unix" }

// Setup dials platformd over the Unix domain socket.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformUnixSocket)
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformUnix
	}
	u.socketPath = socketPath
	if _, err := os.Stat(socketPath); err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: socketPath, Err: err}
	}
	conn, err := grpc.NewClient("unix://"+socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: socketPath, Err: err}
	}
	u.conn = conn
	u.client = lukssdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the Unix-socket gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// Status proxies Status over Unix.
func (u *UnixAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	return u.client.Status(ctx, req)
}

// ListSlots proxies ListSlots over Unix.
func (u *UnixAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	return u.client.ListSlots(ctx, req)
}

// Info proxies Info over Unix.
func (u *UnixAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	return u.client.Info(ctx, req)
}

// EnrollPassphrase proxies EnrollPassphrase over Unix.
func (u *UnixAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	return u.client.EnrollPassphrase(ctx, req)
}

// EnrollFIDO2 proxies EnrollFIDO2 over Unix.
func (u *UnixAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	return u.client.EnrollFIDO2(ctx, req)
}

// EnrollTPM proxies EnrollTPM over Unix.
func (u *UnixAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	return u.client.EnrollTPM(ctx, req)
}

// EnrollRecovery proxies EnrollRecovery over Unix.
func (u *UnixAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	return u.client.EnrollRecovery(ctx, req)
}

// RemoveKey proxies RemoveKey over Unix.
func (u *UnixAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	return u.client.RemoveKey(ctx, req)
}

// TestUnlock proxies TestUnlock over Unix.
func (u *UnixAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	return u.client.TestUnlock(ctx, req)
}

// ChangePassphrase proxies ChangePassphrase over Unix.
func (u *UnixAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	return u.client.ChangePassphrase(ctx, req)
}

var _ LUKSCommands = (*UnixAdapter)(nil)
