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
// This file implements the SecretsCommands interface using the QUIC protocol.

//go:build integration

package secrets

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// EnvPlatformQUICEndpoint is the environment variable for the QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpoint is the default QUIC endpoint address.
	DefaultQUICEndpoint = "localhost:9444"

	// DefaultQUICTimeout is the default timeout for QUIC operations.
	DefaultQUICTimeout = 30 * time.Second

	// DefaultQUICMaxIdleTimeout is the default max idle timeout for connections.
	DefaultQUICMaxIdleTimeout = 60 * time.Second

	// quicPrefixListLimit asks the server for its largest page when Prefix
	// filters the secret list; the QUIC list reply carries no cursor.
	quicPrefixListLimit int32 = 1000
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICRequestFailed indicates a QUIC request failure.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICEncodeFailed indicates payload encoding failure.
type ErrQUICEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICDecodeFailed indicates payload decoding failure.
type ErrQUICDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICStreamFailed indicates a stream operation failure.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream operation %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICClientClosed indicates the client is closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// ErrQUICNegativeVersion indicates a negative secret version was requested.
type ErrQUICNegativeVersion struct {
	Operation string
	Version   int
}

func (e ErrQUICNegativeVersion) Error() string {
	return fmt.Sprintf("QUIC %s: version %d is negative", e.Operation, e.Version)
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements SecretsCommands over the daemon's secrets category
// (quicwire.OpSecretsCategory): one opcode, the sub-operation in the first
// payload byte.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultQUICEndpoint
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// NewQUICAdapterWithConfig creates a QUIC adapter with explicit configuration.
func NewQUICAdapterWithConfig(endpoint string, tlsConfig *tls.Config, timeout time.Duration) *QUICAdapter {
	if tlsConfig == nil {
		tlsConfig = helpers.QUICTLSConfig()
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,
		timeout:        timeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
	}
}

// Name returns the adapter name.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true

	if q.conn != nil {
		return q.conn.CloseWithError(0, "adapter teardown")
	}

	return nil
}

// secretsCategory encodes req, sends it as the given secrets sub-operation and
// decodes the reply into resp.
func (q *QUICAdapter) secretsCategory(ctx context.Context, operation string, sub byte, req, resp interface{}) error {
	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}

	answer, err := q.sendPayload(ctx, operation, append([]byte{sub}, body...))
	if err != nil {
		return err
	}

	if err := quicwire.DecodePayload(answer.Payload, resp); err != nil {
		return ErrQUICDecodeFailed{Operation: operation, Err: err}
	}
	return nil
}

// sendPayload writes one request on a fresh stream and reads its reply. The
// stream carries the ctx deadline (or the adapter timeout): keep-alives hold
// the connection open, so a read the server never answers would otherwise
// block forever.
func (q *QUICAdapter) sendPayload(ctx context.Context, operation string, payload []byte) (*quicwire.Response, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "OpenStream", Err: err}
	}
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(q.timeout)
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "SetDeadline", Err: err}
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpSecretsCategory,
		Payload: payload,
	}
	if err := quicwire.WriteRequest(stream, req); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	if resp.Status != quicwire.StatusOK {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICRequestFailed{
			Operation: operation,
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// Store creates a new secret. The description travels as metadata, the only
// place the wire request has for it.
func (q *QUICAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	req := &daemon.SecretsStoreRequest{SecretID: opts.Name, Data: opts.Data}
	if len(opts.Metadata) > 0 || opts.Description != "" {
		req.Metadata = make(map[string]string, len(opts.Metadata)+1)
		for k, v := range opts.Metadata {
			req.Metadata[k] = v
		}
		if opts.Description != "" {
			req.Metadata["description"] = opts.Description
		}
	}

	var result daemon.SecretsStoreResponse
	if err := q.secretsCategory(ctx, "Store", quicwire.SecretsSubStore, req, &result); err != nil {
		return nil, err
	}

	return &StoreResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Get retrieves the current version of a secret.
func (q *QUICAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	var result daemon.SecretsGetResponse
	if err := q.secretsCategory(ctx, "Get", quicwire.SecretsSubGet, &daemon.SecretsGetRequest{SecretID: name}, &result); err != nil {
		return nil, err
	}

	return &GetResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Data:      result.Data,
		Metadata:  result.Metadata,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// List lists secret IDs. The QUIC reply carries IDs only, so each summary
// holds the ID as both SecretID and Name.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	req := &daemon.SecretsListRequest{Limit: opts.Limit, Cursor: opts.Cursor}

	var result daemon.SecretsListResponse
	if err := q.secretsCategory(ctx, "List", quicwire.SecretsSubList, req, &result); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, 0, len(result.SecretIDs))
	for _, id := range result.SecretIDs {
		secrets = append(secrets, SecretSummary{SecretID: id, Name: id})
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: int32(len(secrets)),
	}, nil
}

// Delete deletes a secret. The wire request has no permanent flag.
func (q *QUICAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	var result daemon.SecretsDeleteResponse
	if err := q.secretsCategory(ctx, "Delete", quicwire.SecretsSubDelete, &daemon.SecretsDeleteRequest{SecretID: name}, &result); err != nil {
		return nil, err
	}

	return &DeleteResult{
		SecretID:  result.SecretID,
		Deleted:   result.Deleted,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Rotate stores new data as the secret's next version.
func (q *QUICAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	req := &pb.RotateSecretRequest{SecretId: name, NewData: newData}

	var result pb.RotateSecretResponse
	if err := q.secretsCategory(ctx, "Rotate", quicwire.SecretsSubRotate, req, &result); err != nil {
		return nil, err
	}

	return &RotateResult{
		SecretID:   result.GetSecretId(),
		OldVersion: result.GetOldVersion(),
		NewVersion: result.GetNewVersion(),
		Timestamp:  time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// Versions lists the versions of a secret.
func (q *QUICAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{SecretId: name}

	var result pb.ListSecretVersionsResponse
	if err := q.secretsCategory(ctx, "Versions", quicwire.SecretsSubListVersions, req, &result); err != nil {
		return nil, err
	}

	versions := make([]VersionInfo, 0, len(result.GetVersions()))
	for _, v := range result.GetVersions() {
		versions = append(versions, VersionInfo{
			Version:   v.GetVersion(),
			CreatedAt: time.Unix(v.GetCreatedAt(), 0),
			CreatedBy: v.GetCreatedBy(),
			ExpiresAt: time.Unix(v.GetExpiresAt(), 0),
		})
	}

	return &VersionsResult{
		SecretID:   name,
		Versions:   versions,
		HasMore:    result.GetHasMore(),
		NextCursor: result.GetNextCursor(),
	}, nil
}

// Version retrieves one version of a secret, with its data.
func (q *QUICAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	if version < 0 {
		return nil, ErrQUICNegativeVersion{Operation: "Version", Version: version}
	}
	req := &pb.GetSecretVersionRequest{SecretId: name, Version: uint64(version)}

	var result pb.GetSecretVersionResponse
	if err := q.secretsCategory(ctx, "Version", quicwire.SecretsSubGetVersion, req, &result); err != nil {
		return nil, err
	}

	info := result.GetVersion()
	return &VersionResult{
		SecretID:  name,
		Version:   info.GetVersion(),
		Data:      result.GetData(),
		Metadata:  info.GetMetadata(),
		CreatedAt: time.Unix(info.GetCreatedAt(), 0),
		CreatedBy: info.GetCreatedBy(),
		ExpiresAt: time.Unix(info.GetExpiresAt(), 0),
		Timestamp: time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// Rollback makes an earlier version current again.
func (q *QUICAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	if targetVersion < 0 {
		return nil, ErrQUICNegativeVersion{Operation: "Rollback", Version: targetVersion}
	}
	req := &pb.RollbackSecretRequest{SecretId: name, TargetVersion: uint64(targetVersion)}

	var result pb.RollbackSecretResponse
	if err := q.secretsCategory(ctx, "Rollback", quicwire.SecretsSubRollback, req, &result); err != nil {
		return nil, err
	}

	return &RollbackResult{
		SecretID:   result.GetSecretId(),
		NewVersion: result.GetNewVersion(),
		Timestamp:  time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// Status enables or disables a secret.
func (q *QUICAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	status := pb.SecretStatus_SECRET_STATUS_DISABLED
	if enabled {
		status = pb.SecretStatus_SECRET_STATUS_ENABLED
	}
	req := &pb.UpdateSecretStatusRequest{SecretId: name, Status: status}

	var result pb.UpdateSecretStatusResponse
	if err := q.secretsCategory(ctx, "Status", quicwire.SecretsSubUpdateStatus, req, &result); err != nil {
		return nil, err
	}

	return &StatusResult{
		SecretID:  result.GetSecretId(),
		Status:    secretStatusName(result.GetStatus()),
		Timestamp: time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// Policy retrieves the rotation policy of a secret.
func (q *QUICAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	var result daemon.SecretsGetRotationPolicyResponse
	if err := q.secretsCategory(ctx, "Policy", quicwire.SecretsSubGetRotationPolicy, &daemon.SecretsGetRotationPolicyRequest{SecretID: name}, &result); err != nil {
		return nil, err
	}

	policy := &PolicyResult{
		SecretID:  result.SecretID,
		UpdatedAt: time.Unix(result.Timestamp, 0),
	}
	if result.Policy != nil {
		policy.Enabled = result.Policy.Enabled
		policy.IntervalSeconds = result.Policy.IntervalSeconds
		policy.NextRotation = time.Unix(result.Policy.NextRotation, 0)
		policy.RetainVersions = result.Policy.RetainVersions
		policy.RotationLambda = result.Policy.RotationLambda
	}
	return policy, nil
}

// PolicySet sets the rotation policy of a secret.
func (q *QUICAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	req := &daemon.SecretsSetRotationPolicyRequest{
		SecretID: name,
		Policy: &daemon.SecretsRotationPolicyPayload{
			Enabled:         opts.Enabled,
			IntervalSeconds: opts.IntervalSeconds,
			RetainVersions:  opts.RetainVersions,
			RotationLambda:  opts.RotationLambda,
		},
	}

	var result daemon.SecretsSetRotationPolicyResponse
	if err := q.secretsCategory(ctx, "PolicySet", quicwire.SecretsSubSetRotationPolicy, req, &result); err != nil {
		return nil, err
	}

	return &PolicySetResult{
		SecretID:  result.SecretID,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Prefix returns the secrets whose IDs start with prefix. The secrets
// category has no prefix query, so this lists the IDs, filters them, and
// reads each match when includeData is set.
func (q *QUICAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	listed, err := q.List(ctx, ListOptions{Limit: quicPrefixListLimit})
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]PrefixSecretData)
	for _, summary := range listed.Secrets {
		if !strings.HasPrefix(summary.SecretID, prefix) {
			continue
		}
		var entry PrefixSecretData
		if includeData {
			secret, err := q.Get(ctx, summary.SecretID)
			if err != nil {
				return nil, err
			}
			entry = PrefixSecretData{
				Data:     secret.Data,
				Metadata: secret.Metadata,
				Version:  int64(secret.Version),
			}
		}
		secrets[summary.SecretID] = entry
	}

	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: int32(len(secrets)),
	}, nil
}
