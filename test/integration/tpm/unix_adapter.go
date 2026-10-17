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

package tpm

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Socket Protocol Adapter
// =============================================================================

const (
	// DefaultUnixTimeoutTPM is the default timeout for Unix socket operations.
	DefaultUnixTimeoutTPM = 60 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixTPMConnectionFailed indicates a Unix socket connection failure.
type ErrUnixTPMConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixTPMConnectionFailed) Error() string {
	return fmt.Sprintf("Unix TPM connection to %s failed: %v", e.Path, e.Err)
}

func (e ErrUnixTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixTPMRPCFailed indicates an RPC call failure over Unix socket.
type ErrUnixTPMRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixTPMRPCFailed) Error() string {
	return fmt.Sprintf("Unix TPM RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixTPMRPCFailed) Unwrap() error {
	return e.Err
}

// UnixAdapter implements TPMCommands using the TPM SDK client over a gRPC
// connection on a Unix domain socket.
type UnixAdapter struct {
	conn       *grpc.ClientConn
	socketPath string
	timeout    time.Duration
	client     *tpmsvc.Client
}

// NewUnixAdapter creates a new Unix socket protocol adapter instance.
func NewUnixAdapter() *UnixAdapter {
	socketPath := os.Getenv(EnvPlatformUnixSocket)
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformUnix
	}

	return &UnixAdapter{
		socketPath: socketPath,
		timeout:    DefaultUnixTimeoutTPM,
	}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup establishes the gRPC connection over Unix domain socket.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	// Check if socket exists
	if _, err := os.Stat(u.socketPath); os.IsNotExist(err) {
		return ErrUnixTPMConnectionFailed{Path: u.socketPath, Err: err}
	}

	conn, err := grpc.NewClient(
		"unix://"+u.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrUnixTPMConnectionFailed{Path: u.socketPath, Err: err}
	}

	u.conn = conn
	u.client = tpmsvc.NewClientFromGRPC(pb.NewTPMServiceClient(conn))

	// Verify connectivity by getting TPM info
	if _, err := u.client.InfoDomain(ctx); err != nil {
		conn.Close()
		return ErrUnixTPMConnectionFailed{Path: u.socketPath, Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via the SDK client over Unix socket.
func (u *UnixAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := u.client.InfoDomain(ctx)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Info", Err: err}
	}

	return infoResultFromResponse(resp), nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via the SDK client over Unix socket.
func (u *UnixAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	resp, err := u.client.ProvisionDomain(ctx, provisionRequestFromOptions(opts))
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Provision", Err: err}
	}

	return provisionResultFromResponse(resp), nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via the SDK client over Unix socket.
func (u *UnixAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	resp, err := u.client.ClearDomain(ctx, opts.OwnerPassword, opts.Confirm)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Clear", Err: err}
	}

	return clearResultFromResponse(resp), nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via the SDK client over Unix socket.
func (u *UnixAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	resp, err := u.client.CreateEKDomain(ctx, keyAlgorithmFromString(opts.Algorithm), opts.Persistent)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "CreateEK", Err: err}
	}

	return ekCreateResultFromResponse(resp, opts.Algorithm), nil
}

// EKInfo retrieves EK information via the SDK client over Unix socket.
func (u *UnixAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	resp, err := u.client.GetEKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEK", Err: err}
	}

	return ekInfoResultFromResponse(resp), nil
}

// EKCertificate retrieves the EK certificate via the SDK client over Unix socket.
func (u *UnixAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	resp, err := u.client.GetEKCertificateDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEKCertificate", Err: err}
	}

	return ekCertificateResultFromResponse(resp), nil
}

// EKDelete deletes the EK via the SDK client over Unix socket.
func (u *UnixAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	resp, err := u.client.DeleteEKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "DeleteEK", Err: err}
	}

	success, message := statusFields(deleteKeyStatus(resp))
	return &EKDeleteResult{Success: success, Message: message}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via the SDK client over Unix socket.
func (u *UnixAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	resp, err := u.client.CreateSRKDomain(ctx, keyAlgorithmFromString(opts.Algorithm),
		opts.Persistent, opts.Handle, opts.Password)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "CreateSRK", Err: err}
	}

	return srkCreateResultFromResponse(resp, opts.Algorithm), nil
}

// SRKInfo retrieves SRK information via the SDK client over Unix socket.
func (u *UnixAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	resp, err := u.client.GetSRKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetSRK", Err: err}
	}

	return srkInfoResultFromResponse(resp), nil
}

// SRKDelete deletes the SRK via the SDK client over Unix socket.
func (u *UnixAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	resp, err := u.client.DeleteSRKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "DeleteSRK", Err: err}
	}

	success, message := statusFields(deleteKeyStatus(resp))
	return &SRKDeleteResult{Success: success, Message: message}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via the SDK client over Unix socket.
func (u *UnixAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	resp, err := u.client.SealDomain(ctx, sealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Seal", Err: err}
	}

	return sealResultFromResponse(resp), nil
}

// Unseal unseals data from the TPM via the SDK client over Unix socket.
func (u *UnixAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	resp, err := u.client.UnsealDomain(ctx, unsealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Unseal", Err: err}
	}

	return unsealResultFromResponse(resp), nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via the SDK client over Unix socket.
func (u *UnixAdapter) EventLog(ctx context.Context) (*EventLogResult, error) {
	resp, err := u.client.GetEventLogDomain(ctx, "json")
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEventLog", Err: err}
	}

	return eventLogResultFromResponse(resp), nil
}

// Ensure UnixAdapter implements TPMCommands interface.
var _ TPMCommands = (*UnixAdapter)(nil)
