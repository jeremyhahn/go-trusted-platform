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

package cold_start

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// UnixAdapter drives cold-start auth operations over gRPC-over-UDS. The
// auth surface is being stood up upstream; this adapter dials the
// cold-start socket so connectivity is validated, but every mutating
// method returns "not yet wired".
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
}

// NewUnixAdapter returns a fresh Unix adapter.
func NewUnixAdapter() *UnixAdapter { return &UnixAdapter{} }

// Name returns "Unix".
func (u *UnixAdapter) Name() string { return "Unix" }

// Setup dials the cold-start Unix socket.
func (u *UnixAdapter) Setup(ctx context.Context, h *Harness) error {
	u.socketPath = GetServiceEndpoints(h.Config()).Unix
	if _, err := os.Stat(u.socketPath); err != nil {
		return &ErrAdapterNotReady{Adapter: "Unix: " + err.Error()}
	}
	conn, err := grpc.NewClient("unix://"+u.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return err
	}
	u.conn = conn
	return nil
}

// Teardown closes the Unix-socket gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// Health surfaces a snapshot derived from the Unix connection state.
func (u *UnixAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	if u.conn == nil {
		return nil, &ErrAdapterNotReady{Adapter: "Unix"}
	}
	return &HealthSnapshot{State: "unsealed", Ready: true}, nil
}

// AddMTLSFactor calls the auth-factor service over UDS. Stubbed.
func (u *UnixAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	return notWired("Unix", "auth factor add")
}

// ListFactors lists factors. Stubbed.
func (u *UnixAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	return nil, notWired("Unix", "auth factor list")
}

// LoginMTLS performs an mTLS login. Stubbed.
func (u *UnixAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	return nil, notWired("Unix", "auth login")
}

// RotateMTLSFactor rotates a factor. Stubbed.
func (u *UnixAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	return "", notWired("Unix", "auth factor rotate")
}

// RemoveFactor removes a factor. Stubbed.
func (u *UnixAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	return notWired("Unix", "auth factor remove")
}

var _ ColdStartCommands = (*UnixAdapter)(nil)
