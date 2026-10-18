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

// Package secrets provides integration test adapters for Secrets services.
// This file implements the SecretsCommands interface using gRPC protocol.

//go:build integration

package secrets

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements SecretsCommands using gRPC calls to platformd.
// This adapter makes gRPC calls to the platformd server for testing
// the gRPC transport layer consistency with other protocol adapters.
type GRPCAdapter struct {
	conn    *grpc.ClientConn
	secrets pb.SecretsManagementClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformdGRPC
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.secrets = pb.NewSecretsManagementClient(conn)

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Time Conversion Helper
// =============================================================================

// grpcUnixToTime converts Unix timestamp to time.Time.
func grpcUnixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// Store stores a new secret via gRPC.
func (g *GRPCAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	req := &pb.StoreSecretRequest{
		SecretId:    opts.Name,
		Name:        opts.Name,
		Description: opts.Description,
		Data:        opts.Data,
		TenantId:    opts.TenantID,
		KeyId:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}

	resp, err := g.secrets.StoreSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StoreSecret", Err: err}
	}

	return &StoreResult{
		SecretID:  resp.SecretId,
		Version:   resp.Version,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Get retrieves a secret via gRPC.
func (g *GRPCAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	req := &pb.GetSecretRequest{
		SecretId: name,
	}

	resp, err := g.secrets.GetSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSecret", Err: err}
	}

	return &GetResult{
		SecretID:      resp.SecretId,
		Version:       resp.Version,
		Data:          resp.Data,
		Metadata:      resp.Metadata,
		Algorithm:     resp.Algorithm,
		KeyIdentifier: resp.KeyIdentifier,
		CreatedAt:     grpcUnixToTime(resp.CreatedAt),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// List lists secrets via gRPC.
func (g *GRPCAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	req := &pb.ListSecretsRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := g.secrets.ListSecrets(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListSecrets", Err: err}
	}

	secrets := make([]SecretSummary, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		secrets = append(secrets, SecretSummary{
			SecretID:       s.SecretId,
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      grpcUnixToTime(s.CreatedAt),
			UpdatedAt:      grpcUnixToTime(s.UpdatedAt),
		})
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// Delete deletes a secret via gRPC.
func (g *GRPCAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	req := &pb.DeleteSecretRequest{
		SecretId:          name,
		PermanentlyDelete: permanent,
	}

	resp, err := g.secrets.DeleteSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteSecret", Err: err}
	}

	return &DeleteResult{
		SecretID:  resp.SecretId,
		Deleted:   resp.Deleted,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Rotate rotates a secret to a new value via gRPC.
func (g *GRPCAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	req := &pb.RotateSecretRequest{
		SecretId: name,
		NewData:  newData,
	}

	resp, err := g.secrets.RotateSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RotateSecret", Err: err}
	}

	return &RotateResult{
		SecretID:   resp.SecretId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Versions lists secret versions via gRPC.
func (g *GRPCAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{
		SecretId: name,
	}

	resp, err := g.secrets.ListSecretVersions(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListSecretVersions", Err: err}
	}

	versions := make([]VersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, VersionInfo{
			Version:   v.Version,
			CreatedAt: grpcUnixToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: grpcUnixToTime(v.ExpiresAt),
			DeletedAt: grpcUnixToTime(v.DeletedAt),
		})
	}

	return &VersionsResult{
		SecretID:   name,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// Version retrieves a specific secret version via gRPC.
func (g *GRPCAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	req := &pb.GetSecretVersionRequest{
		SecretId: name,
		Version:  uint64(version),
	}

	resp, err := g.secrets.GetSecretVersion(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSecretVersion", Err: err}
	}

	return &VersionResult{
		SecretID:  name,
		Version:   resp.Version.Version,
		Data:      resp.Data,
		Metadata:  resp.Version.Metadata,
		CreatedAt: grpcUnixToTime(resp.Version.CreatedAt),
		CreatedBy: resp.Version.CreatedBy,
		ExpiresAt: grpcUnixToTime(resp.Version.ExpiresAt),
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Rollback rolls back to a previous secret version via gRPC.
func (g *GRPCAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	req := &pb.RollbackSecretRequest{
		SecretId:      name,
		TargetVersion: uint64(targetVersion),
	}

	resp, err := g.secrets.RollbackSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RollbackSecret", Err: err}
	}

	return &RollbackResult{
		SecretID:   resp.SecretId,
		NewVersion: resp.NewVersion,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Status updates the status of a secret via gRPC.
func (g *GRPCAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	status := pb.SecretStatus_SECRET_STATUS_DISABLED
	if enabled {
		status = pb.SecretStatus_SECRET_STATUS_ENABLED
	}

	req := &pb.UpdateSecretStatusRequest{
		SecretId: name,
		Status:   status,
	}

	resp, err := g.secrets.UpdateSecretStatus(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateSecretStatus", Err: err}
	}

	// docs/kms/cli.md §secrets reports the status as ENABLED or DISABLED.
	statusStr := "DISABLED"
	if resp.Status == pb.SecretStatus_SECRET_STATUS_ENABLED {
		statusStr = "ENABLED"
	}

	return &StatusResult{
		SecretID:  resp.SecretId,
		Status:    statusStr,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Policy retrieves the rotation policy for a secret via gRPC.
func (g *GRPCAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	req := &pb.GetRotationPolicyRequest{
		SecretId: name,
	}

	resp, err := g.secrets.GetRotationPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetRotationPolicy", Err: err}
	}

	return &PolicyResult{
		SecretID:        name,
		Enabled:         resp.Policy.Enabled,
		IntervalSeconds: resp.Policy.IntervalSeconds,
		NextRotation:    grpcUnixToTime(resp.Policy.NextRotation),
		RetainVersions:  resp.Policy.RetainVersions,
		RotationLambda:  resp.Policy.RotationLambda,
		UpdatedAt:       grpcUnixToTime(resp.Timestamp),
	}, nil
}

// PolicySet sets the rotation policy for a secret via gRPC.
func (g *GRPCAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	req := &pb.SetRotationPolicyRequest{
		SecretId: name,
		Policy: &pb.SecretRotationPolicy{
			Enabled:         opts.Enabled,
			IntervalSeconds: opts.IntervalSeconds,
			RetainVersions:  opts.RetainVersions,
			RotationLambda:  opts.RotationLambda,
		},
	}

	resp, err := g.secrets.SetRotationPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SetRotationPolicy", Err: err}
	}

	return &PolicySetResult{
		SecretID:  resp.SecretId,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// Prefix searches for secrets by prefix via gRPC.
func (g *GRPCAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	req := &pb.GetSecretsByPrefixRequest{
		Prefix:      prefix,
		IncludeData: includeData,
	}

	resp, err := g.secrets.GetSecretsByPrefix(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSecretsByPrefix", Err: err}
	}

	secrets := make(map[string]PrefixSecretData, len(resp.Secrets))
	for name, s := range resp.Secrets {
		// SecretData.Data is map[string][]byte, extract the first value or combine
		var data []byte
		for _, v := range s.Data {
			data = v
			break
		}
		secrets[name] = PrefixSecretData{
			Data:     data,
			Metadata: s.Metadata,
			Version:  s.Version,
		}
	}

	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure GRPCAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*GRPCAdapter)(nil)
