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

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
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

// UnixAdapter implements TPMCommands using gRPC over Unix domain socket.
type UnixAdapter struct {
	conn       *grpc.ClientConn
	socketPath string
	timeout    time.Duration
	tpm        pb.TPMServiceClient
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
	u.tpm = pb.NewTPMServiceClient(conn)

	// Verify connectivity by getting TPM info
	_, err = u.tpm.Info(ctx, &pb.TPMInfoRequest{})
	if err != nil {
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

// Info retrieves TPM information via Unix socket.
func (u *UnixAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := u.tpm.Info(ctx, &pb.TPMInfoRequest{})
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Info", Err: err}
	}

	result := &InfoResult{
		Version:      formatTPMVersion(resp.Version),
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FipsMode,
		MaxNVRAMSize: resp.MaxNvramSize,
	}

	if resp.Manufacturer != nil {
		result.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer.Name,
			ID:              resp.Manufacturer.Id,
			Model:           resp.Manufacturer.Model,
			FirmwareVersion: resp.Manufacturer.FirmwareVersion,
		}
	}

	for _, bank := range resp.PcrBanks {
		result.PCRBanks = append(result.PCRBanks, formatPCRBank(bank))
	}

	return result, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via Unix socket.
func (u *UnixAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	req := &pb.TPMProvisionRequest{
		CreateEk:            opts.CreateEK,
		CreateSrk:           opts.CreateSRK,
		CreateAk:            opts.CreateAK,
		OwnerPassword:       opts.OwnerPassword,
		EndorsementPassword: opts.EndorsementPassword,
	}

	resp, err := u.tpm.Provision(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Provision", Err: err}
	}

	result := &ProvisionResult{
		Success: resp.Status != nil && resp.Status.Success,
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	result.EKCreated = len(resp.EkPublic) > 0
	result.SRKCreated = len(resp.SrkPublic) > 0
	result.AKCreated = len(resp.AkPublic) > 0

	return result, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via Unix socket.
func (u *UnixAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	req := &pb.TPMClearRequest{
		OwnerPassword: opts.OwnerPassword,
		Confirm:       opts.Confirm,
	}

	resp, err := u.tpm.Clear(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Clear", Err: err}
	}

	result := &ClearResult{
		Success: resp.Status != nil && resp.Status.Success,
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via Unix socket.
func (u *UnixAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	alg, err := parseKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	req := &pb.CreateEKRequest{
		Attributes: &pb.KeyAttributes{
			Algorithm: alg,
		},
		Persistent: opts.Persistent,
	}

	resp, err := u.tpm.CreateEK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "CreateEK", Err: err}
	}

	return &EKCreateResult{
		Success:   resp.Status != nil && resp.Status.Success,
		Handle:    resp.Handle,
		Algorithm: opts.Algorithm,
		PublicKey: resp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via Unix socket.
func (u *UnixAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	req := &pb.GetEKRequest{
		Handle: handle,
	}

	resp, err := u.tpm.GetEK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEK", Err: err}
	}

	return &EKInfoResult{
		Handle:    resp.Handle,
		Algorithm: formatKeyAlgorithm(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}, nil
}

// EKCertificate retrieves the EK certificate via Unix socket.
func (u *UnixAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	req := &pb.GetEKCertificateRequest{}

	resp, err := u.tpm.GetEKCertificate(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEKCertificate", Err: err}
	}

	return &EKCertificateResult{
		Format:      resp.Format,
		Certificate: resp.Certificate,
	}, nil
}

// EKDelete deletes the EK via Unix socket.
func (u *UnixAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	req := &pb.DeleteEKRequest{
		Handle:   handle,
		Password: password,
	}

	resp, err := u.tpm.DeleteEK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "DeleteEK", Err: err}
	}

	result := &EKDeleteResult{
		Success: resp.Status != nil && resp.Status.Success,
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via Unix socket.
func (u *UnixAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	alg, err := parseKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	req := &pb.CreateSRKRequest{
		Attributes: &pb.KeyAttributes{
			Algorithm: alg,
		},
		Persistent:     opts.Persistent,
		ParentHandle:   opts.Handle,
		ParentPassword: opts.Password,
	}

	resp, err := u.tpm.CreateSRK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "CreateSRK", Err: err}
	}

	return &SRKCreateResult{
		Success:   resp.Status != nil && resp.Status.Success,
		Handle:    resp.Handle,
		Algorithm: opts.Algorithm,
		PublicKey: resp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via Unix socket.
func (u *UnixAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	req := &pb.GetSRKRequest{
		Handle: handle,
	}

	resp, err := u.tpm.GetSRK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetSRK", Err: err}
	}

	return &SRKInfoResult{
		Handle:    resp.Handle,
		Algorithm: formatKeyAlgorithm(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}, nil
}

// SRKDelete deletes the SRK via Unix socket.
func (u *UnixAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	req := &pb.DeleteSRKRequest{
		Handle:   handle,
		Password: password,
	}

	resp, err := u.tpm.DeleteSRK(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "DeleteSRK", Err: err}
	}

	result := &SRKDeleteResult{
		Success: resp.Status != nil && resp.Status.Success,
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via Unix socket.
func (u *UnixAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	req := &pb.SealRequest{
		Cn:             opts.CN,
		Data:           opts.Data,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}

	resp, err := u.tpm.Seal(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Seal", Err: err}
	}

	result := &SealResult{
		Success: resp.Status != nil && resp.Status.Success,
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// Unseal unseals data from the TPM via Unix socket.
func (u *UnixAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &pb.UnsealRequest{
		Cn:             opts.CN,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}

	resp, err := u.tpm.Unseal(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "Unseal", Err: err}
	}

	return &UnsealResult{
		Success: resp.Status != nil && resp.Status.Success,
		Data:    resp.Data,
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via Unix socket.
func (u *UnixAdapter) EventLog(ctx context.Context, path string) (*EventLogResult, error) {
	req := &pb.GetEventLogRequest{
		Format: "json",
	}

	resp, err := u.tpm.GetEventLog(ctx, req)
	if err != nil {
		return nil, ErrUnixTPMRPCFailed{Method: "GetEventLog", Err: err}
	}

	result := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	if len(resp.EventLog) > 0 {
		result.Events = append(result.Events, EventLogEntry{
			EventData: resp.EventLog,
		})
	}

	return result, nil
}

// Ensure UnixAdapter implements TPMCommands interface.
var _ TPMCommands = (*UnixAdapter)(nil)
