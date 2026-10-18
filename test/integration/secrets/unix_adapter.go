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
// This file implements the SecretsCommands interface using gRPC over Unix socket.

//go:build integration

package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Environment Variables and Constants
// =============================================================================

const (
	// EnvUnixSecretsPath is the environment variable for the secrets Unix socket path.
	EnvUnixSecretsPath = "SECRETS_SOCKET_PATH"

	// unixDialTimeoutSeconds is the timeout for establishing Unix socket connection.
	unixDialTimeoutSeconds = 10 * time.Second
)

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements the SecretsCommands interface using gRPC over Unix socket
// to communicate with platformd. This adapter provides integration testing via
// the Unix domain socket transport layer.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	secrets    pb.SecretsManagementClient
}

// NewUnixAdapter creates a new UnixAdapter instance.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (s *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix socket.
func (s *UnixAdapter) Setup(ctx context.Context) error {
	// The runner exports the daemon's socket as PLATFORM_SOCKET_PATH;
	// SECRETS_SOCKET_PATH only overrides it for a hand run.
	s.socketPath = os.Getenv(EnvUnixSecretsPath)
	if s.socketPath == "" {
		s.socketPath = helpers.GetSocketPath()
	}

	conn, err := grpc.NewClient("unix://"+s.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrUnixConnectionFailed{Path: s.socketPath, Err: err}
	}

	// The readiness wait retries until its context ends, so bound it: on the
	// suite's 10-minute context a missing socket outlived go test's timeout.
	dialCtx, cancel := context.WithTimeout(ctx, unixDialTimeoutSeconds)
	defer cancel()
	if err := helpers.WaitGRPCReady(dialCtx, conn); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return ErrUnixConnectionFailed{Path: s.socketPath, Err: errors.Join(err, closeErr)}
		}
		return ErrUnixConnectionFailed{Path: s.socketPath, Err: err}
	}

	s.conn = conn
	s.secrets = pb.NewSecretsManagementClient(conn)

	return nil
}

// Teardown closes the gRPC connection.
func (s *UnixAdapter) Teardown() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// =============================================================================
// Time Conversion Helper
// =============================================================================

// unixUnixToTime converts Unix timestamp to time.Time.
func unixUnixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// Store stores a new secret via Unix socket.
func (s *UnixAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	req := &pb.StoreSecretRequest{
		SecretId:    opts.Name,
		Name:        opts.Name,
		Description: opts.Description,
		Data:        opts.Data,
		TenantId:    opts.TenantID,
		KeyId:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}

	resp, err := s.secrets.StoreSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StoreSecret", Err: err}
	}

	return &StoreResult{
		SecretID:  resp.SecretId,
		Version:   resp.Version,
		Timestamp: unixUnixToTime(resp.Timestamp),
	}, nil
}

// Get retrieves a secret via Unix socket.
func (s *UnixAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	req := &pb.GetSecretRequest{
		SecretId: name,
	}

	resp, err := s.secrets.GetSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSecret", Err: err}
	}

	return &GetResult{
		SecretID:      resp.GetSecretId(),
		Version:       resp.GetVersion(),
		Data:          resp.GetData(),
		Metadata:      resp.GetMetadata(),
		Algorithm:     resp.GetAlgorithm(),
		KeyIdentifier: resp.GetKeyIdentifier(),
		CreatedAt:     unixUnixToTime(resp.GetCreatedAt()),
		Timestamp:     unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// List lists secrets via Unix socket.
func (s *UnixAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	req := &pb.ListSecretsRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := s.secrets.ListSecrets(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListSecrets", Err: err}
	}

	secrets := make([]SecretSummary, 0, len(resp.GetSecrets()))
	for _, sec := range resp.GetSecrets() {
		secrets = append(secrets, SecretSummary{
			SecretID:       sec.GetSecretId(),
			Name:           sec.GetName(),
			CurrentVersion: sec.GetCurrentVersion(),
			Description:    sec.GetDescription(),
			Owner:          sec.GetOwner(),
			CreatedAt:      unixUnixToTime(sec.GetCreatedAt()),
			UpdatedAt:      unixUnixToTime(sec.GetUpdatedAt()),
		})
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: resp.GetTotalCount(),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// Delete deletes a secret via Unix socket.
func (s *UnixAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	req := &pb.DeleteSecretRequest{
		SecretId:          name,
		PermanentlyDelete: permanent,
	}

	resp, err := s.secrets.DeleteSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteSecret", Err: err}
	}

	return &DeleteResult{
		SecretID:  resp.GetSecretId(),
		Deleted:   resp.GetDeleted(),
		Timestamp: unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// Rotate rotates a secret to a new value via Unix socket.
func (s *UnixAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	req := &pb.RotateSecretRequest{
		SecretId: name,
		NewData:  newData,
	}

	resp, err := s.secrets.RotateSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RotateSecret", Err: err}
	}

	return &RotateResult{
		SecretID:   resp.GetSecretId(),
		OldVersion: resp.GetOldVersion(),
		NewVersion: resp.GetNewVersion(),
		Timestamp:  unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// Versions lists secret versions via Unix socket.
func (s *UnixAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{
		SecretId: name,
	}

	resp, err := s.secrets.ListSecretVersions(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListSecretVersions", Err: err}
	}

	versions := make([]VersionInfo, 0, len(resp.GetVersions()))
	for _, v := range resp.GetVersions() {
		info := VersionInfo{
			Version:   v.GetVersion(),
			CreatedAt: unixUnixToTime(v.GetCreatedAt()),
			CreatedBy: v.GetCreatedBy(),
		}
		if v.GetExpiresAt() > 0 {
			info.ExpiresAt = unixUnixToTime(v.GetExpiresAt())
		}
		if v.GetDeletedAt() > 0 {
			info.DeletedAt = unixUnixToTime(v.GetDeletedAt())
		}
		versions = append(versions, info)
	}

	return &VersionsResult{
		SecretID:   name,
		Versions:   versions,
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// Version retrieves a specific secret version via Unix socket.
func (s *UnixAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	req := &pb.GetSecretVersionRequest{
		SecretId: name,
		Version:  uint64(version),
	}

	resp, err := s.secrets.GetSecretVersion(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSecretVersion", Err: err}
	}

	secretVersion := resp.GetVersion()
	result := &VersionResult{
		SecretID:  secretVersion.GetSecretId(),
		Version:   secretVersion.GetVersion(),
		Data:      resp.GetData(),
		Metadata:  secretVersion.GetMetadata(),
		CreatedAt: unixUnixToTime(secretVersion.GetCreatedAt()),
		CreatedBy: secretVersion.GetCreatedBy(),
		Timestamp: unixUnixToTime(resp.GetTimestamp()),
	}

	if secretVersion.GetExpiresAt() > 0 {
		result.ExpiresAt = unixUnixToTime(secretVersion.GetExpiresAt())
	}

	return result, nil
}

// Rollback rolls back to a previous secret version via Unix socket.
func (s *UnixAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	req := &pb.RollbackSecretRequest{
		SecretId:      name,
		TargetVersion: uint64(targetVersion),
	}

	resp, err := s.secrets.RollbackSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RollbackSecret", Err: err}
	}

	return &RollbackResult{
		SecretID:   resp.GetSecretId(),
		NewVersion: resp.GetNewVersion(),
		Timestamp:  unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// Status updates the status of a secret via Unix socket.
func (s *UnixAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	status := pb.SecretStatus_SECRET_STATUS_DISABLED
	if enabled {
		status = pb.SecretStatus_SECRET_STATUS_ENABLED
	}

	req := &pb.UpdateSecretStatusRequest{
		SecretId: name,
		Status:   status,
	}

	resp, err := s.secrets.UpdateSecretStatus(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateSecretStatus", Err: err}
	}

	return &StatusResult{
		SecretID:  resp.GetSecretId(),
		Status:    s.secretStatusToString(resp.GetStatus()),
		Timestamp: unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// Policy retrieves the rotation policy for a secret via Unix socket.
func (s *UnixAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	req := &pb.GetRotationPolicyRequest{
		SecretId: name,
	}

	resp, err := s.secrets.GetRotationPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetRotationPolicy", Err: err}
	}

	policy := resp.GetPolicy()
	return &PolicyResult{
		SecretID:        name,
		Enabled:         policy.GetEnabled(),
		IntervalSeconds: policy.GetIntervalSeconds(),
		NextRotation:    unixUnixToTime(policy.GetNextRotation()),
		RetainVersions:  policy.GetRetainVersions(),
		RotationLambda:  policy.GetRotationLambda(),
		UpdatedAt:       unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// PolicySet sets the rotation policy for a secret via Unix socket.
func (s *UnixAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	req := &pb.SetRotationPolicyRequest{
		SecretId: name,
		Policy: &pb.SecretRotationPolicy{
			Enabled:         opts.Enabled,
			IntervalSeconds: opts.IntervalSeconds,
			RetainVersions:  opts.RetainVersions,
			RotationLambda:  opts.RotationLambda,
		},
	}

	resp, err := s.secrets.SetRotationPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "SetRotationPolicy", Err: err}
	}

	return &PolicySetResult{
		SecretID:  resp.GetSecretId(),
		Timestamp: unixUnixToTime(resp.GetTimestamp()),
	}, nil
}

// Prefix searches for secrets by prefix via Unix socket.
func (s *UnixAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	req := &pb.GetSecretsByPrefixRequest{
		Prefix:      prefix,
		IncludeData: includeData,
	}

	resp, err := s.secrets.GetSecretsByPrefix(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSecretsByPrefix", Err: err}
	}

	secrets := make(map[string]PrefixSecretData, len(resp.GetSecrets()))
	for name, sec := range resp.GetSecrets() {
		// SecretData.Data is map[string][]byte, extract the first value
		var data []byte
		for _, v := range sec.GetData() {
			data = v
			break
		}
		secrets[name] = PrefixSecretData{
			Data:     data,
			Metadata: sec.GetMetadata(),
			Version:  sec.GetVersion(),
		}
	}

	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: resp.GetTotalCount(),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// =============================================================================
// Type Conversion Helpers
// =============================================================================

// secretStatusToString converts proto SecretStatus to string.
func (s *UnixAdapter) secretStatusToString(status pb.SecretStatus) string {
	switch status {
	case pb.SecretStatus_SECRET_STATUS_ENABLED:
		return "ENABLED"
	case pb.SecretStatus_SECRET_STATUS_DISABLED:
		return "DISABLED"
	case pb.SecretStatus_SECRET_STATUS_DELETED:
		return "DELETED"
	default:
		return "UNSPECIFIED"
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates the Unix socket connection failed.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixBackendUnavailable indicates the backend is not responding.
type ErrUnixBackendUnavailable struct {
	Err error
}

func (e ErrUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("Unix backend unavailable: %v", e.Err)
}

func (e ErrUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure UnixAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*UnixAdapter)(nil)
