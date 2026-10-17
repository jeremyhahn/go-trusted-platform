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
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Environment Variables and Constants
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

	// quicTransport names this transport in surface.ErrNoSurface declarations.
	quicTransport = "QUIC"

	// quicNoSecretLifecycleSub explains why the version lifecycle leaves the
	// QUIC matrix: the 0xCE secrets category carries store, get, list, delete
	// and rotation policy only (docs/daemon/api.md §4).
	quicNoSecretLifecycleSub = "the secrets category assigns no rotate, version listing, rollback or status sub-opcode (MISSING)"

	// quicNoSecretPrefixSub explains why Prefix leaves the QUIC matrix.
	quicNoSecretPrefixSub = "the secrets category assigns no prefix listing sub-opcode (MISSING)"
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

// ErrQUICRequestFailed indicates a request the server answered with a
// non-OK status.
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

// ErrQUICInvalidVersion indicates a negative secret version, which the
// unsigned wire field cannot carry.
type ErrQUICInvalidVersion struct {
	Version int
}

func (e ErrQUICInvalidVersion) Error() string {
	return fmt.Sprintf("QUIC secret version %d is negative", e.Version)
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements SecretsCommands over the platform QUIC wire
// (sdk/go/wire/quicwire): every secret operation is a request on the 0xCE
// secrets category with its sub-opcode in payload[0], carrying the
// pkg/api/daemon secrets payloads.
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

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return quicTransport
}

// Setup establishes the QUIC connection to the platform endpoint.
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

// =============================================================================
// Wire Protocol Methods
// =============================================================================

// secrets sends one 0xCE request, the sub-opcode in payload[0] followed by
// the encoded body, and decodes the OK response into out.
func (q *QUICAdapter) secrets(ctx context.Context, operation string, sub byte, req, out any) error {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return ErrQUICClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}
	payload := make([]byte, 1+len(body))
	payload[0] = sub
	copy(payload[1:], body)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return ErrQUICStreamFailed{Operation: "OpenStream", Err: err}
	}
	defer stream.Close()

	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: quicwire.OpSecretsCategory, Payload: payload}); err != nil {
		return ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}
	if resp.Status != quicwire.StatusOK {
		return ErrQUICRequestFailed{Operation: operation, Status: byte(resp.Status), Message: string(resp.Payload)}
	}

	if err := quicwire.DecodePayload(resp.Payload, out); err != nil {
		return ErrQUICDecodeFailed{Operation: operation, Err: err}
	}
	return nil
}

// quicNoSurface declares an operation the 0xCE secrets category does not carry.
func quicNoSurface(operation, reason string) error {
	return surface.ErrNoSurface{Transport: quicTransport, Operation: operation, Reason: reason}
}

// quicTime converts a wire Unix timestamp, leaving zero as the zero time.
func quicTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// =============================================================================
// SecretsCommands Interface Implementation
// =============================================================================

// Store stores a secret (0xCE/0x01). The request carries the secret ID, data
// and metadata only; the description travels as metadata.
func (q *QUICAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	req := &daemonpkg.SecretsStoreRequest{SecretID: opts.Name, Data: opts.Data}
	if metadata := storeMetadata(opts); len(metadata) > 0 {
		req.Metadata = metadata
	}

	var resp daemonpkg.SecretsStoreResponse
	if err := q.secrets(ctx, "Store", quicwire.SecretsSubStore, req, &resp); err != nil {
		return nil, err
	}

	return &StoreResult{SecretID: resp.SecretID, Version: resp.Version, Timestamp: quicTime(resp.Timestamp)}, nil
}

// Get retrieves the current version of a secret (0xCE/0x02).
func (q *QUICAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	var resp daemonpkg.SecretsGetResponse
	if err := q.secrets(ctx, "Get", quicwire.SecretsSubGet, &daemonpkg.SecretsGetRequest{SecretID: name}, &resp); err != nil {
		return nil, err
	}

	return &GetResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      resp.Data,
		Metadata:  resp.Metadata,
		Timestamp: quicTime(resp.Timestamp),
	}, nil
}

// List lists secret IDs (0xCE/0x03). The response carries IDs only.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	req := &daemonpkg.SecretsListRequest{Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemonpkg.SecretsListResponse
	if err := q.secrets(ctx, "List", quicwire.SecretsSubList, req, &resp); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, 0, len(resp.SecretIDs))
	for _, id := range resp.SecretIDs {
		secrets = append(secrets, SecretSummary{SecretID: id, Name: id})
	}

	return &ListResult{Secrets: secrets, TotalCount: int32(len(secrets))}, nil
}

// Delete deletes a secret (0xCE/0x04). The request has no permanent flag.
func (q *QUICAdapter) Delete(ctx context.Context, name string, _ bool) (*DeleteResult, error) {
	var resp daemonpkg.SecretsDeleteResponse
	if err := q.secrets(ctx, "Delete", quicwire.SecretsSubDelete, &daemonpkg.SecretsDeleteRequest{SecretID: name}, &resp); err != nil {
		return nil, err
	}

	return &DeleteResult{SecretID: resp.SecretID, Deleted: resp.Deleted, Timestamp: quicTime(resp.Timestamp)}, nil
}

// Rotate has no QUIC surface.
func (q *QUICAdapter) Rotate(_ context.Context, _ string, _ []byte) (*RotateResult, error) {
	return nil, quicNoSurface("Rotate", quicNoSecretLifecycleSub)
}

// Versions has no QUIC surface.
func (q *QUICAdapter) Versions(_ context.Context, _ string) (*VersionsResult, error) {
	return nil, quicNoSurface("Versions", quicNoSecretLifecycleSub)
}

// Version retrieves one version of a secret through get (0xCE/0x02); version
// 0 asks for the current one.
func (q *QUICAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	if version < 0 {
		return nil, ErrQUICInvalidVersion{Version: version}
	}
	req := &daemonpkg.SecretsGetRequest{SecretID: name, Version: uint64(version)}

	var resp daemonpkg.SecretsGetResponse
	if err := q.secrets(ctx, "Version", quicwire.SecretsSubGet, req, &resp); err != nil {
		return nil, err
	}

	return &VersionResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      resp.Data,
		Metadata:  resp.Metadata,
		Timestamp: quicTime(resp.Timestamp),
	}, nil
}

// Rollback has no QUIC surface.
func (q *QUICAdapter) Rollback(_ context.Context, _ string, _ int) (*RollbackResult, error) {
	return nil, quicNoSurface("Rollback", quicNoSecretLifecycleSub)
}

// Status has no QUIC surface.
func (q *QUICAdapter) Status(_ context.Context, _ string, _ bool) (*StatusResult, error) {
	return nil, quicNoSurface("Status", quicNoSecretLifecycleSub)
}

// Policy retrieves a secret's rotation policy (0xCE/0x06).
func (q *QUICAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	req := &daemonpkg.SecretsGetRotationPolicyRequest{SecretID: name}

	var resp daemonpkg.SecretsGetRotationPolicyResponse
	if err := q.secrets(ctx, "Policy", quicwire.SecretsSubGetRotationPolicy, req, &resp); err != nil {
		return nil, err
	}

	result := &PolicyResult{SecretID: resp.SecretID, UpdatedAt: quicTime(resp.Timestamp)}
	if policy := resp.Policy; policy != nil {
		result.Enabled = policy.Enabled
		result.IntervalSeconds = policy.IntervalSeconds
		result.NextRotation = quicTime(policy.NextRotation)
		result.RetainVersions = policy.RetainVersions
		result.RotationLambda = policy.RotationLambda
	}
	return result, nil
}

// PolicySet sets a secret's rotation policy (0xCE/0x05).
func (q *QUICAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	req := &daemonpkg.SecretsSetRotationPolicyRequest{
		SecretID: name,
		Policy: &daemonpkg.SecretsRotationPolicyPayload{
			Enabled:         opts.Enabled,
			IntervalSeconds: opts.IntervalSeconds,
			RetainVersions:  opts.RetainVersions,
			RotationLambda:  opts.RotationLambda,
		},
	}

	var resp daemonpkg.SecretsSetRotationPolicyResponse
	if err := q.secrets(ctx, "PolicySet", quicwire.SecretsSubSetRotationPolicy, req, &resp); err != nil {
		return nil, err
	}

	return &PolicySetResult{SecretID: resp.SecretID, Timestamp: quicTime(resp.Timestamp)}, nil
}

// Prefix has no QUIC surface.
func (q *QUICAdapter) Prefix(_ context.Context, _ string, _ bool) (*PrefixResult, error) {
	return nil, quicNoSurface("Prefix", quicNoSecretPrefixSub)
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*QUICAdapter)(nil)
