//go:build integration

// Package kms provides integration tests for KMS operations across all protocols.
package kms

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// QUIC Adapter Constants
// =============================================================================

const (
	// EnvPlatformQUICEndpoint names the environment variable holding the QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpoint is the default QUIC endpoint.
	DefaultQUICEndpoint = "localhost:9444"

	// DefaultQUICTimeout is the default timeout for QUIC operations.
	DefaultQUICTimeout = 30 * time.Second

	// DefaultQUICMaxIdleTimeout is the default max idle timeout for QUIC connections.
	DefaultQUICMaxIdleTimeout = 60 * time.Second

	// quicTransport names this transport in declared surface gaps.
	quicTransport = "QUIC"

	// quicNoDEKOpcode explains why DEK operations leave the QUIC matrix:
	// quicwire assigns no DEK opcode (SPEC rows 42-46, MISSING).
	quicNoDEKOpcode = "quicwire assigns no DEK management opcode (SPEC rows 42-46, MISSING)"

	// quicNoSecretVersionSub explains why secret version operations leave the
	// QUIC matrix: the 0xCE secrets category carries store, get, list, delete
	// and rotation policy only (SPEC rows 42-46, MISSING).
	quicNoSecretVersionSub = "the secrets category assigns no version, rotate, rollback or status sub-opcode (SPEC rows 42-46, MISSING)"
)

// =============================================================================
// QUIC Adapter Errors
// =============================================================================

// ErrQUICConnectionFailed indicates the QUIC connection could not be established.
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

// ErrQUICRequestFailed indicates the server answered with a non-OK status.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICEncodeFailed indicates a request payload could not be encoded.
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

// ErrQUICDecodeFailed indicates a response payload could not be decoded.
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

// ErrQUICStreamFailed indicates a stream operation failed.
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

// ErrQUICClientClosed indicates the adapter was used after Teardown.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// ErrQUICUnsupportedValue indicates a test option has no QUIC wire encoding.
type ErrQUICUnsupportedValue struct {
	Kind  string
	Value string
}

func (e ErrQUICUnsupportedValue) Error() string {
	return fmt.Sprintf("QUIC KMS wire has no %s %q", e.Kind, e.Value)
}

// =============================================================================
// Wire value mapping
// =============================================================================

// quicAlgorithms maps the suite's algorithm names to the platform KMS wire enum.
var quicAlgorithms = map[string]platformv1.KMSKeyAlgorithm{
	"":                  platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"AES-256":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"AES-256-GCM":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"ChaCha20-Poly1305": platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	"RSA-2048":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
	"RSA-4096":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096,
	"ECDSA-P256":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
	"ECDSA-P384":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
	"Ed25519":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519,
}

// quicAlgorithmNames maps the wire enum back to the suite's algorithm names.
var quicAlgorithmNames = map[platformv1.KMSKeyAlgorithm]string{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:           "AES-256-GCM",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: "ChaCha20-Poly1305",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:          "RSA-2048",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:          "RSA-4096",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:        "ECDSA-P256",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:        "ECDSA-P384",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:           "Ed25519",
}

// quicHashes maps the suite's hash names to the platform KMS wire enum.
var quicHashes = map[string]platformv1.HashAlgorithm{
	"":        platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"SHA-256": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"SHA256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"SHA-384": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"SHA384":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"SHA-512": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	"SHA512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
}

// quicHashNames maps the wire enum back to the suite's hash names.
var quicHashNames = map[platformv1.HashAlgorithm]string{
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256: "SHA-256",
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384: "SHA-384",
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512: "SHA-512",
}

var (
	quicEncryptUsages = []int32{
		int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
		int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
	}
	quicSignUsages = []int32{
		int32(platformv1.KeyUsage_KEY_USAGE_SIGN),
		int32(platformv1.KeyUsage_KEY_USAGE_VERIFY),
	}
	quicWrapUsages = []int32{int32(platformv1.KeyUsage_KEY_USAGE_WRAP)}
)

// quicPurposes maps the suite's key purposes to wire key usages.
var quicPurposes = map[string][]int32{
	"encrypt":         quicEncryptUsages,
	"encrypt_decrypt": quicEncryptUsages,
	"sign":            quicSignUsages,
	"sign_verify":     quicSignUsages,
	"wrap":            quicWrapUsages,
}

// quicSigningAlgorithms are the algorithms whose default purpose is signing.
var quicSigningAlgorithms = map[platformv1.KMSKeyAlgorithm]bool{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256: true,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384: true,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:    true,
}

func quicAlgorithm(name string) (int32, error) {
	alg, ok := quicAlgorithms[name]
	if !ok {
		return 0, ErrQUICUnsupportedValue{Kind: "key algorithm", Value: name}
	}
	return int32(alg), nil
}

func quicAlgorithmName(alg int32) string {
	if name, ok := quicAlgorithmNames[platformv1.KMSKeyAlgorithm(alg)]; ok {
		return name
	}
	return platformv1.KMSKeyAlgorithm(alg).String()
}

func quicHash(name string) (int32, error) {
	alg, ok := quicHashes[strings.ToUpper(name)]
	if !ok {
		return 0, ErrQUICUnsupportedValue{Kind: "hash algorithm", Value: name}
	}
	return int32(alg), nil
}

func quicHashName(alg int32) string {
	if name, ok := quicHashNames[platformv1.HashAlgorithm(alg)]; ok {
		return name
	}
	return platformv1.HashAlgorithm(alg).String()
}

// quicUsages resolves a purpose to wire usages; an empty purpose follows the
// algorithm (signing algorithms sign, everything else encrypts).
func quicUsages(purpose string, alg int32) ([]int32, error) {
	if purpose == "" {
		if quicSigningAlgorithms[platformv1.KMSKeyAlgorithm(alg)] {
			return quicSignUsages, nil
		}
		return quicEncryptUsages, nil
	}
	usages, ok := quicPurposes[strings.ToLower(purpose)]
	if !ok {
		return nil, ErrQUICUnsupportedValue{Kind: "key purpose", Value: purpose}
	}
	return usages, nil
}

func quicUsageNames(usages []int32) []string {
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		names = append(names, strings.ToLower(strings.TrimPrefix(platformv1.KeyUsage(u).String(), "KEY_USAGE_")))
	}
	return names
}

// quicStatusName renders a wire key status as its enum name (KEY_STATUS_ENABLED, ...).
func quicStatusName(status int32) string {
	return platformv1.KeyStatus(status).String()
}

// quicTime converts wire Unix seconds; zero stays the zero time.
func quicTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements KMSCommands over the platform QUIC wire
// (sdk/go/wire/quicwire): key ops 0xC0-0xCB, crypto ops 0xD0-0xDA, extended
// KMS through category 0xCD and secrets through category 0xCE.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a QUIC adapter for the endpoint in PLATFORM_QUIC_ENDPOINT.
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

// Name returns the protocol name.
func (q *QUICAdapter) Name() string {
	return quicTransport
}

// Setup dials the QUIC endpoint.
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

// roundTrip writes one request frame on a fresh stream and returns the OK
// response payload.
func (q *QUICAdapter) roundTrip(ctx context.Context, operation string, opcode byte, payload []byte) ([]byte, error) {
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

	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: opcode, Payload: payload}); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	if resp.Status != quicwire.StatusOK {
		return nil, ErrQUICRequestFailed{Operation: operation, Status: byte(resp.Status), Message: string(resp.Payload)}
	}

	return resp.Payload, nil
}

// call encodes req, sends it under opcode, and decodes the response into out.
func (q *QUICAdapter) call(ctx context.Context, operation string, opcode byte, req, out any) error {
	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}
	return q.exchange(ctx, operation, opcode, body, out)
}

// callSub sends a category request: the sub-opcode in payload[0], then the
// encoded body.
func (q *QUICAdapter) callSub(ctx context.Context, operation string, category, sub byte, req, out any) error {
	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}
	payload := make([]byte, 1+len(body))
	payload[0] = sub
	copy(payload[1:], body)
	return q.exchange(ctx, operation, category, payload, out)
}

func (q *QUICAdapter) exchange(ctx context.Context, operation string, opcode byte, payload []byte, out any) error {
	respPayload, err := q.roundTrip(ctx, operation, opcode, payload)
	if err != nil {
		return err
	}
	if err := quicwire.DecodePayload(respPayload, out); err != nil {
		return ErrQUICDecodeFailed{Operation: operation, Err: err}
	}
	return nil
}

func (q *QUICAdapter) extended(ctx context.Context, operation string, sub byte, req, out any) error {
	return q.callSub(ctx, operation, quicwire.OpKMSExtendedCategory, sub, req, out)
}

func (q *QUICAdapter) secrets(ctx context.Context, operation string, sub byte, req, out any) error {
	return q.callSub(ctx, operation, quicwire.OpSecretsCategory, sub, req, out)
}

func quicNoSurface(operation, reason string) error {
	return surface.ErrNoSurface{Transport: quicTransport, Operation: operation, Reason: reason}
}

// =============================================================================
// Key Management Commands
// =============================================================================

// KeyGenerate generates a new key (0xC0).
func (q *QUICAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	alg, err := quicAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}
	usages, err := quicUsages(opts.Purpose, alg)
	if err != nil {
		return nil, err
	}

	name := opts.Name
	if name == "" {
		name = opts.KeyID
	}

	req := &daemonpkg.KMSGenerateKeyRequest{
		KeySpec: &daemonpkg.KMSKeySpecRequest{
			Algorithm:          alg,
			Usage:              usages,
			Exportable:         opts.Exportable,
			DeletionProtection: opts.DeletionProtection,
		},
		Name:        name,
		Description: opts.Description,
		Owner:       opts.Owner,
	}

	var resp daemonpkg.KMSGenerateKeyResponse
	if err := q.call(ctx, "KeyGenerate", quicwire.OpKMSGenerateKey, req, &resp); err != nil {
		return nil, err
	}
	if resp.Key == nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyGenerate", Err: ErrQUICUnsupportedValue{Kind: "response", Value: "missing key handle"}}
	}

	result := &KeyGenerateResult{
		KeyID:     resp.Key.KeyId,
		Version:   resp.Key.Version,
		Algorithm: quicAlgorithmName(resp.Key.Algorithm),
		Status:    quicStatusName(resp.Key.Status),
		CreatedAt: quicTime(resp.Key.CreatedAt),
	}
	if resp.Metadata != nil {
		result.Name = resp.Metadata.Name
		result.Description = resp.Metadata.Description
		result.Exportable = resp.Metadata.Exportable
		result.DeletionProtection = resp.Metadata.DeletionProtection
	}
	return result, nil
}

// KeyGet retrieves a key and its metadata (0xC2).
func (q *QUICAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	req := &daemonpkg.KMSGetKeyRequest{KeyId: keyID, Version: version}

	var resp daemonpkg.KMSGetKeyResponse
	if err := q.call(ctx, "KeyGet", quicwire.OpKMSGetKey, req, &resp); err != nil {
		return nil, err
	}

	result := &KeyGetResult{KeyID: keyID}
	if resp.Key != nil {
		result.KeyID = resp.Key.KeyId
		result.Version = resp.Key.Version
		result.Algorithm = quicAlgorithmName(resp.Key.Algorithm)
		result.Status = quicStatusName(resp.Key.Status)
		result.CreatedAt = quicTime(resp.Key.CreatedAt)
	}
	if md := resp.Metadata; md != nil {
		result.UpdatedAt = quicTime(md.UpdatedAt)
		result.LastUsedAt = quicTime(md.LastUsedAt)
		result.Name = md.Name
		result.Description = md.Description
		result.Owner = md.Owner
		result.Exportable = md.Exportable
		result.DeletionProtection = md.DeletionProtection
		result.Usage = quicUsageNames(md.Usage)
	}
	return result, nil
}

// KeyList lists keys (0xC3).
func (q *QUICAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	req := &daemonpkg.KMSListKeysRequest{Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemonpkg.KMSListKeysResponse
	if err := q.call(ctx, "KeyList", quicwire.OpKMSListKeys, req, &resp); err != nil {
		return nil, err
	}

	keys := make([]KeySummary, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		if k == nil {
			continue
		}
		keys = append(keys, KeySummary{
			KeyID:     k.KeyId,
			Version:   k.Version,
			Algorithm: quicAlgorithmName(k.Algorithm),
			Status:    quicStatusName(k.Status),
			CreatedAt: quicTime(k.CreatedAt),
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyDelete schedules or forces key deletion (0xC4).
func (q *QUICAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	req := &daemonpkg.KMSDeleteKeyRequest{
		KeyId:             keyID,
		PendingWindowDays: opts.PendingWindowDays,
		Force:             opts.Force,
	}

	var resp daemonpkg.KMSDeleteKeyResponse
	if err := q.call(ctx, "KeyDelete", quicwire.OpKMSDeleteKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID:        resp.KeyId,
		Status:       quicStatusName(resp.KeyStatus),
		DeletionDate: quicTime(resp.DeletionDate),
	}, nil
}

// KeyRotate rotates a key to a new version (0xC5).
func (q *QUICAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	req := &daemonpkg.KMSRotateKeyRequest{KeyId: keyID, RetainOldVersion: retainOldVersion}

	var resp daemonpkg.KMSRotateKeyResponse
	if err := q.call(ctx, "KeyRotate", quicwire.OpKMSRotateKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      resp.KeyId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		RotatedAt:  quicTime(resp.Timestamp),
	}, nil
}

// KeyVersions lists a key's versions (0xC8).
func (q *QUICAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	req := &daemonpkg.KMSGetKeyVersionsRequest{KeyId: keyID, Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemonpkg.KMSGetKeyVersionsResponse
	if err := q.call(ctx, "KeyVersions", quicwire.OpKMSGetKeyVersions, req, &resp); err != nil {
		return nil, err
	}

	versions := make([]KeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		if v == nil {
			continue
		}
		versions = append(versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  quicAlgorithmName(v.Algorithm),
			Status:     quicStatusName(v.Status),
			CreatedAt:  quicTime(v.CreatedAt),
			DisabledAt: quicTime(v.DisabledAt),
		})
	}

	return &KeyVersionsResult{
		KeyID:      resp.KeyId,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyStatus enables or disables a key version (0xC6).
func (q *QUICAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	status := platformv1.KeyStatus_KEY_STATUS_DISABLED
	if enabled {
		status = platformv1.KeyStatus_KEY_STATUS_ENABLED
	}
	req := &daemonpkg.KMSUpdateKeyStatusRequest{KeyId: keyID, Version: version, Status: int32(status)}

	var resp daemonpkg.KMSUpdateKeyStatusResponse
	if err := q.call(ctx, "KeyStatus", quicwire.OpKMSUpdateKeyStatus, req, &resp); err != nil {
		return nil, err
	}

	return &KeyStatusResult{
		KeyID:     resp.KeyId,
		Version:   resp.Version,
		Status:    quicStatusName(resp.KeyStatus),
		UpdatedAt: quicTime(resp.Timestamp),
	}, nil
}

// KeyRevoke revokes a key (0xCD/0x01).
func (q *QUICAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	req := &daemonpkg.KMSRevokeKeyRequest{KeyID: keyID, Reason: reason}

	var resp daemonpkg.KMSRevokeKeyResponse
	if err := q.extended(ctx, "KeyRevoke", quicwire.KMSSubRevokeKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     resp.KeyID,
		Status:    resp.Status,
		RevokedAt: quicTime(resp.Timestamp),
	}, nil
}

// KeyMetadata retrieves key metadata (0xCD/0x02).
func (q *QUICAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	req := &daemonpkg.KMSGetKeyMetadataRequest{KeyID: keyID}

	var resp daemonpkg.KMSGetKeyMetadataResponse
	if err := q.extended(ctx, "KeyMetadata", quicwire.KMSSubGetKeyMetadata, req, &resp); err != nil {
		return nil, err
	}

	result := &KeyMetadataResult{KeyID: keyID}
	if md := resp.Metadata; md != nil {
		result.KeyID = md.KeyId
		result.Name = md.Name
		result.Description = md.Description
		result.Algorithm = quicAlgorithmName(md.Algorithm)
		result.Status = quicStatusName(md.Status)
		result.Version = md.Version
		result.Exportable = md.Exportable
		result.DeletionProtection = md.DeletionProtection
		result.Usage = quicUsageNames(md.Usage)
		result.Owner = md.Owner
		result.CreatedAt = quicTime(md.CreatedAt)
		result.UpdatedAt = quicTime(md.UpdatedAt)
		result.LastUsedAt = quicTime(md.LastUsedAt)
		result.Tags = md.Tags
	}
	return result, nil
}

// KeyMetadataUpdate updates key metadata (0xCD/0x03).
func (q *QUICAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	req := &daemonpkg.KMSUpdateKeyMetadataRequest{
		KeyID:       keyID,
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	var resp daemonpkg.KMSUpdateKeyMetadataResponse
	if err := q.extended(ctx, "KeyMetadataUpdate", quicwire.KMSSubUpdateKeyMetadata, req, &resp); err != nil {
		return nil, err
	}

	result := &KeyMetadataUpdateResult{KeyID: keyID, UpdatedAt: quicTime(resp.Timestamp)}
	if md := resp.Metadata; md != nil {
		result.KeyID = md.KeyId
		result.Name = md.Name
		result.Tags = md.Tags
		if md.UpdatedAt != 0 {
			result.UpdatedAt = quicTime(md.UpdatedAt)
		}
	}
	return result, nil
}

// KeyPolicy retrieves a key's access policy (0xCD/0x05).
func (q *QUICAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	req := &daemonpkg.KMSGetKeyPolicyRequest{KeyID: keyID}

	var resp daemonpkg.KMSGetKeyPolicyResponse
	if err := q.extended(ctx, "KeyPolicy", quicwire.KMSSubGetKeyPolicy, req, &resp); err != nil {
		return nil, err
	}

	result := &KeyPolicyResult{KeyID: keyID}
	if p := resp.Policy; p != nil {
		result.KeyID = p.KeyID
		result.Version = int32(p.Version)
		result.AllowedOperations = p.AllowedOperations
		result.AllowedPrincipals = p.AllowedPrincipals
		result.DeniedPrincipals = p.DeniedPrincipals
		result.ExpiresAt = quicTime(p.ExpiresAt)
		result.RotationRequired = p.RotationRequired
		result.MaxUsageCount = p.MaxUsageCount
		result.RequireMFA = p.RequireMFA
		result.UpdatedAt = quicTime(p.UpdatedAt)
	}
	return result, nil
}

// KeyPolicySet replaces a key's access policy (0xCD/0x04).
func (q *QUICAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	var expiresAt int64
	if opts.ExpiresIn != "" {
		ttl, err := time.ParseDuration(opts.ExpiresIn)
		if err != nil {
			return nil, ErrQUICUnsupportedValue{Kind: "policy expiry", Value: opts.ExpiresIn}
		}
		expiresAt = time.Now().Add(ttl).Unix()
	}

	req := &daemonpkg.KMSSetKeyPolicyRequest{
		KeyID: keyID,
		Policy: &daemonpkg.KMSKeyPolicyPayload{
			KeyID:             keyID,
			AllowedOperations: opts.Operations,
			AllowedPrincipals: opts.AllowPrincipals,
			DeniedPrincipals:  opts.DenyPrincipals,
			ExpiresAt:         expiresAt,
			RotationRequired:  opts.RotationRequired,
			MaxUsageCount:     opts.MaxUsageCount,
			RequireMFA:        opts.RequireMFA,
		},
	}

	var resp daemonpkg.KMSSetKeyPolicyResponse
	if err := q.extended(ctx, "KeyPolicySet", quicwire.KMSSubSetKeyPolicy, req, &resp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         resp.KeyID,
		PolicyVersion: int32(resp.PolicyVersion),
		UpdatedAt:     quicTime(resp.Timestamp),
	}, nil
}

// KeyAlgorithms lists the backend's supported algorithms (0xCD/0x06).
func (q *QUICAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	var resp daemonpkg.KMSGetSupportedAlgorithmsResponse
	if err := q.extended(ctx, "KeyAlgorithms", quicwire.KMSSubGetSupportedAlgorithms, struct{}{}, &resp); err != nil {
		return nil, err
	}
	return &KeyAlgorithmsResult{Algorithms: resp.Algorithms}, nil
}

// =============================================================================
// Crypto Commands
// =============================================================================

// CryptoEncrypt encrypts plaintext (0xD0).
func (q *QUICAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	req := &daemonpkg.KMSEncryptRequest{
		KeyId:     opts.KeyID,
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
	}

	var resp daemonpkg.KMSEncryptResponse
	if err := q.call(ctx, "CryptoEncrypt", quicwire.OpKMSEncrypt, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoEncryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  quicTime(resp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts ciphertext (0xD1).
func (q *QUICAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	req := &daemonpkg.KMSDecryptRequest{
		KeyId:      opts.KeyID,
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	var resp daemonpkg.KMSDecryptResponse
	if err := q.call(ctx, "CryptoDecrypt", quicwire.OpKMSDecrypt, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoDecryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  quicTime(resp.Timestamp),
	}, nil
}

// CryptoSign signs a message (0xD2).
func (q *QUICAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	hash, err := quicHash(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemonpkg.KMSSignRequest{KeyId: opts.KeyID, Message: opts.Message, HashAlgorithm: hash}

	var resp daemonpkg.KMSSignResponse
	if err := q.call(ctx, "CryptoSign", quicwire.OpKMSSign, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoSignResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: quicHashName(resp.HashAlgorithm),
		Timestamp:     quicTime(resp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature (0xD3).
func (q *QUICAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	hash, err := quicHash(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemonpkg.KMSVerifyRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: hash,
		KeyVersion:    opts.KeyVersion,
	}

	var resp daemonpkg.KMSVerifyResponse
	if err := q.call(ctx, "CryptoVerify", quicwire.OpKMSVerify, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  quicTime(resp.Timestamp),
	}, nil
}

// CryptoHash hashes data (0xD5).
func (q *QUICAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	hash, err := quicHash(algorithm)
	if err != nil {
		return nil, err
	}
	req := &daemonpkg.KMSHashRequest{Data: data, Algorithm: hash}

	var resp daemonpkg.KMSHashResponse
	if err := q.call(ctx, "CryptoHash", quicwire.OpKMSHash, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoHashResult{
		Algorithm: quicHashName(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: quicTime(resp.Timestamp),
	}, nil
}

// CryptoHMAC computes an HMAC (0xD6).
func (q *QUICAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	hash, err := quicHash(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemonpkg.KMSHMACRequest{KeyId: opts.KeyID, Message: opts.Message, HashAlgorithm: hash}

	var resp daemonpkg.KMSHMACResponse
	if err := q.call(ctx, "CryptoHMAC", quicwire.OpKMSHMAC, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoHMACResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.Hmac,
		HashAlgorithm: quicHashName(resp.HashAlgorithm),
		Timestamp:     quicTime(resp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC (0xD7).
func (q *QUICAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	hash, err := quicHash(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemonpkg.KMSVerifyHMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Hmac:          opts.HMAC,
		HashAlgorithm: hash,
		KeyVersion:    opts.KeyVersion,
	}

	var resp daemonpkg.KMSVerifyHMACResponse
	if err := q.call(ctx, "CryptoVerifyHMAC", quicwire.OpKMSVerifyHMAC, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  quicTime(resp.Timestamp),
	}, nil
}

// CryptoRandom generates random bytes (0xD4).
func (q *QUICAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	req := &daemonpkg.KMSGenerateRandomRequest{NumBytes: int32(numBytes)}

	var resp daemonpkg.KMSGenerateRandomResponse
	if err := q.call(ctx, "CryptoRandom", quicwire.OpKMSGenerateRandom, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoRandomResult{RandomBytes: resp.RandomBytes, Timestamp: quicTime(resp.Timestamp)}, nil
}

// =============================================================================
// DEK Commands — no QUIC surface
// =============================================================================

// DEKCreate has no QUIC surface.
func (q *QUICAdapter) DEKCreate(_ context.Context, _ DEKCreateOptions) (*DEKCreateResult, error) {
	return nil, quicNoSurface("DEKCreate", quicNoDEKOpcode)
}

// DEKGet has no QUIC surface.
func (q *QUICAdapter) DEKGet(_ context.Context, _ string) (*DEKGetResult, error) {
	return nil, quicNoSurface("DEKGet", quicNoDEKOpcode)
}

// DEKList has no QUIC surface.
func (q *QUICAdapter) DEKList(_ context.Context, _ DEKListOptions) (*DEKListResult, error) {
	return nil, quicNoSurface("DEKList", quicNoDEKOpcode)
}

// DEKDelete has no QUIC surface.
func (q *QUICAdapter) DEKDelete(_ context.Context, _ string, _ DEKDeleteOptions) (*DEKDeleteResult, error) {
	return nil, quicNoSurface("DEKDelete", quicNoDEKOpcode)
}

// DEKRotate has no QUIC surface.
func (q *QUICAdapter) DEKRotate(_ context.Context, _ string, _ bool) (*DEKRotateResult, error) {
	return nil, quicNoSurface("DEKRotate", quicNoDEKOpcode)
}

// DEKStatus has no QUIC surface.
func (q *QUICAdapter) DEKStatus(_ context.Context, _ string) (*DEKStatusResult, error) {
	return nil, quicNoSurface("DEKStatus", quicNoDEKOpcode)
}

// =============================================================================
// Secrets Commands
// =============================================================================

// SecretsStore stores a secret (0xCE/0x01).
func (q *QUICAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	var metadata map[string]string
	if opts.Description != "" {
		metadata = map[string]string{"description": opts.Description}
	}
	req := &daemonpkg.SecretsStoreRequest{SecretID: opts.Name, Data: opts.Data, Metadata: metadata}

	var resp daemonpkg.SecretsStoreResponse
	if err := q.secrets(ctx, "SecretsStore", quicwire.SecretsSubStore, req, &resp); err != nil {
		return nil, err
	}

	return &SecretsStoreResult{SecretID: resp.SecretID, Version: resp.Version, Timestamp: quicTime(resp.Timestamp)}, nil
}

// SecretsGet retrieves the current version of a secret (0xCE/0x02).
func (q *QUICAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	req := &daemonpkg.SecretsGetRequest{SecretID: name}

	var resp daemonpkg.SecretsGetResponse
	if err := q.secrets(ctx, "SecretsGet", quicwire.SecretsSubGet, req, &resp); err != nil {
		return nil, err
	}

	return &SecretsGetResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      resp.Data,
		Metadata:  resp.Metadata,
		Timestamp: quicTime(resp.Timestamp),
	}, nil
}

// SecretsList lists secret identifiers (0xCE/0x03).
func (q *QUICAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	req := &daemonpkg.SecretsListRequest{Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemonpkg.SecretsListResponse
	if err := q.secrets(ctx, "SecretsList", quicwire.SecretsSubList, req, &resp); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, 0, len(resp.SecretIDs))
	for _, id := range resp.SecretIDs {
		secrets = append(secrets, SecretSummary{Name: id})
	}

	return &SecretsListResult{Secrets: secrets, TotalCount: int32(len(secrets))}, nil
}

// SecretsDelete deletes a secret (0xCE/0x04). The wire delete is permanent.
func (q *QUICAdapter) SecretsDelete(ctx context.Context, name string, _ bool) (*SecretsDeleteResult, error) {
	req := &daemonpkg.SecretsDeleteRequest{SecretID: name}

	var resp daemonpkg.SecretsDeleteResponse
	if err := q.secrets(ctx, "SecretsDelete", quicwire.SecretsSubDelete, req, &resp); err != nil {
		return nil, err
	}

	return &SecretsDeleteResult{SecretID: resp.SecretID, Deleted: resp.Deleted, Timestamp: quicTime(resp.Timestamp)}, nil
}

// SecretsRotate has no QUIC surface.
func (q *QUICAdapter) SecretsRotate(_ context.Context, _ SecretsRotateOptions) (*SecretsRotateResult, error) {
	return nil, quicNoSurface("SecretsRotate", quicNoSecretVersionSub)
}

// SecretsVersions has no QUIC surface.
func (q *QUICAdapter) SecretsVersions(_ context.Context, _ string, _ SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	return nil, quicNoSurface("SecretsVersions", quicNoSecretVersionSub)
}

// SecretsVersion has no QUIC surface.
func (q *QUICAdapter) SecretsVersion(_ context.Context, _ string, _ uint64) (*SecretsVersionResult, error) {
	return nil, quicNoSurface("SecretsVersion", quicNoSecretVersionSub)
}

// SecretsRollback has no QUIC surface.
func (q *QUICAdapter) SecretsRollback(_ context.Context, _ string, _ uint64) (*SecretsRollbackResult, error) {
	return nil, quicNoSurface("SecretsRollback", quicNoSecretVersionSub)
}

// SecretsStatus has no QUIC surface.
func (q *QUICAdapter) SecretsStatus(_ context.Context, _ string, _ bool) (*SecretsStatusResult, error) {
	return nil, quicNoSurface("SecretsStatus", quicNoSecretVersionSub)
}

// Compile-time check that QUICAdapter implements KMSCommands.
var _ KMSCommands = (*QUICAdapter)(nil)
