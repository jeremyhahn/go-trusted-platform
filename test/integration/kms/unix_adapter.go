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

package kms

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// unixDialTimeout is the timeout for establishing Unix socket connection.
const unixDialTimeout = 10 * time.Second

// UnixAdapter implements the KMSCommands interface using gRPC over Unix socket
// to communicate with platformd. This adapter provides integration testing via
// the Unix domain socket transport layer.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	kms        pb.KeyManagementClient
	crypto     pb.CryptoClient
	dek        pb.DEKManagementClient
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
	s.socketPath = os.Getenv(EnvPlatformdSocket)
	if s.socketPath == "" {
		s.socketPath = DefaultPlatformdSocket
	}

	// Create dial context with timeout to fail fast when socket unavailable
	dialCtx, cancel := context.WithTimeout(ctx, unixDialTimeout)
	defer cancel()

	// Create gRPC connection using Unix socket dialer
	conn, err := grpc.DialContext(dialCtx, "unix://"+s.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			// Strip the unix:// prefix if present
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrUnixConnectionFailed{Path: s.socketPath, Err: err}
	}

	s.conn = conn
	s.kms = pb.NewKeyManagementClient(conn)
	s.crypto = pb.NewCryptoClient(conn)
	s.dek = pb.NewDEKManagementClient(conn)
	s.secrets = pb.NewSecretsManagementClient(conn)

	// Verify connectivity with a backend status check
	_, err = s.kms.BackendStatus(ctx, &pb.BackendStatusRequest{})
	if err != nil {
		s.conn.Close()
		return ErrUnixBackendUnavailable{Err: err}
	}

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
// Key Management Commands
// =============================================================================

// KeyGenerate creates a new cryptographic key.
func (s *UnixAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	req := &pb.GenerateKeyRequest{
		Name:        opts.Name,
		Description: opts.Description,
		Owner:       opts.Owner,
		KeySpec: &pb.KeySpec{
			Algorithm:          s.stringToKeyAlgorithm(opts.Algorithm),
			Usage:              s.purposeToKeyUsages(opts.Purpose),
			Exportable:         opts.Exportable,
			DeletionProtection: opts.DeletionProtection,
		},
	}

	resp, err := s.kms.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateKey", Err: err}
	}

	result := &KeyGenerateResult{
		KeyID:              resp.GetKey().GetKeyId(),
		Version:            resp.GetKey().GetVersion(),
		Algorithm:          s.keyAlgorithmToString(resp.GetKey().GetAlgorithm()),
		Status:             s.keyStatusToString(resp.GetKey().GetStatus()),
		CreatedAt:          time.Unix(resp.GetKey().GetCreatedAt(), 0),
		Exportable:         resp.GetMetadata().GetExportable(),
		DeletionProtection: resp.GetMetadata().GetDeletionProtection(),
	}

	if resp.GetMetadata() != nil {
		result.Name = resp.GetMetadata().GetName()
		result.Description = resp.GetMetadata().GetDescription()
	}

	return result, nil
}

// KeyGet retrieves a key by ID and optional version.
func (s *UnixAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	req := &pb.GetKeyRequest{
		KeyId:   keyID,
		Version: version,
	}

	resp, err := s.kms.GetKey(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetKey", Err: err}
	}

	key := resp.GetKey()
	meta := resp.GetMetadata()

	result := &KeyGetResult{
		KeyID:     key.GetKeyId(),
		Version:   key.GetVersion(),
		Algorithm: s.keyAlgorithmToString(key.GetAlgorithm()),
		Status:    s.keyStatusToString(key.GetStatus()),
		CreatedAt: time.Unix(key.GetCreatedAt(), 0),
	}

	if meta != nil {
		result.Name = meta.GetName()
		result.Description = meta.GetDescription()
		result.Owner = meta.GetOwner()
		result.Exportable = meta.GetExportable()
		result.DeletionProtection = meta.GetDeletionProtection()
		result.UpdatedAt = time.Unix(meta.GetUpdatedAt(), 0)
		if meta.GetLastUsedAt() > 0 {
			result.LastUsedAt = time.Unix(meta.GetLastUsedAt(), 0)
		}
		result.Usage = s.keyUsagesToStrings(meta.GetUsage())
	}

	return result, nil
}

// KeyList lists keys with pagination.
func (s *UnixAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	req := &pb.ListKeysRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := s.kms.ListKeys(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListKeys", Err: err}
	}

	keys := make([]KeySummary, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		keys = append(keys, KeySummary{
			KeyID:     k.GetKeyId(),
			Version:   k.GetVersion(),
			Algorithm: s.keyAlgorithmToString(k.GetAlgorithm()),
			Status:    s.keyStatusToString(k.GetStatus()),
			CreatedAt: time.Unix(k.GetCreatedAt(), 0),
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.GetTotalCount(),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// KeyDelete deletes a key.
func (s *UnixAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	req := &pb.DeleteKeyRequest{
		KeyId:             keyID,
		PendingWindowDays: opts.PendingWindowDays,
		Force:             opts.Force,
	}

	resp, err := s.kms.DeleteKey(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteKey", Err: err}
	}

	return &KeyDeleteResult{
		KeyID:        resp.GetKeyId(),
		Status:       s.keyStatusToString(resp.GetStatus()),
		DeletionDate: time.Unix(resp.GetDeletionDate(), 0),
	}, nil
}

// KeyRotate rotates a key to a new version.
func (s *UnixAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	req := &pb.RotateKeyRequest{
		KeyId:            keyID,
		RetainOldVersion: retainOldVersion,
	}

	resp, err := s.kms.RotateKey(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RotateKey", Err: err}
	}

	return &KeyRotateResult{
		KeyID:      resp.GetKeyId(),
		OldVersion: resp.GetOldVersion(),
		NewVersion: resp.GetNewVersion(),
		RotatedAt:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// KeyVersions lists all versions of a key.
func (s *UnixAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	req := &pb.ListKeyVersionsRequest{
		KeyId:  keyID,
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := s.kms.ListKeyVersions(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListKeyVersions", Err: err}
	}

	versions := make([]KeyVersionInfo, 0, len(resp.GetVersions()))
	for _, v := range resp.GetVersions() {
		info := KeyVersionInfo{
			Version:   v.GetVersion(),
			Algorithm: s.keyAlgorithmToString(v.GetAlgorithm()),
			Status:    s.keyStatusToString(v.GetStatus()),
			CreatedAt: time.Unix(v.GetCreatedAt(), 0),
		}
		if v.GetDisabledAt() > 0 {
			info.DisabledAt = time.Unix(v.GetDisabledAt(), 0)
		}
		versions = append(versions, info)
	}

	return &KeyVersionsResult{
		KeyID:      resp.GetKeyId(),
		Versions:   versions,
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// KeyStatus updates the enabled/disabled status of a key version.
func (s *UnixAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	status := pb.KeyStatus_KEY_STATUS_DISABLED
	if enabled {
		status = pb.KeyStatus_KEY_STATUS_ENABLED
	}

	req := &pb.UpdateKeyStatusRequest{
		KeyId:   keyID,
		Version: version,
		Status:  status,
	}

	resp, err := s.kms.UpdateKeyStatus(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateKeyStatus", Err: err}
	}

	return &KeyStatusResult{
		KeyID:     resp.GetKeyId(),
		Version:   resp.GetVersion(),
		Status:    s.keyStatusToString(resp.GetStatus()),
		UpdatedAt: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// KeyRevoke marks a key as compromised/revoked.
func (s *UnixAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	req := &pb.RevokeKeyRequest{
		KeyId:  keyID,
		Reason: reason,
	}

	resp, err := s.kms.RevokeKey(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RevokeKey", Err: err}
	}

	return &KeyRevokeResult{
		KeyID:     resp.GetKeyId(),
		Status:    s.keyStatusToString(resp.GetStatus()),
		RevokedAt: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// KeyMetadata retrieves detailed metadata for a key.
func (s *UnixAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	req := &pb.GetKeyMetadataRequest{
		KeyId: keyID,
	}

	resp, err := s.kms.GetKeyMetadata(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetKeyMetadata", Err: err}
	}

	meta := resp.GetMetadata()
	result := &KeyMetadataResult{
		KeyID:              meta.GetKeyId(),
		Name:               meta.GetName(),
		Description:        meta.GetDescription(),
		Algorithm:          s.keyAlgorithmToString(meta.GetAlgorithm()),
		Status:             s.keyStatusToString(meta.GetStatus()),
		Version:            meta.GetVersion(),
		Exportable:         meta.GetExportable(),
		DeletionProtection: meta.GetDeletionProtection(),
		Usage:              s.keyUsagesToStrings(meta.GetUsage()),
		Owner:              meta.GetOwner(),
		CreatedAt:          time.Unix(meta.GetCreatedAt(), 0),
		UpdatedAt:          time.Unix(meta.GetUpdatedAt(), 0),
		Tags:               meta.GetTags(),
	}

	if meta.GetLastUsedAt() > 0 {
		result.LastUsedAt = time.Unix(meta.GetLastUsedAt(), 0)
	}

	if meta.GetRotationPolicy() != nil {
		rp := meta.GetRotationPolicy()
		result.RotationPolicy = &RotationPolicy{
			Enabled:         rp.GetEnabled(),
			IntervalSeconds: rp.GetIntervalSeconds(),
			NextRotation:    time.Unix(rp.GetNextRotation(), 0),
			RetainVersions:  rp.GetRetainVersions(),
		}
	}

	return result, nil
}

// KeyMetadataUpdate updates mutable metadata fields for a key.
func (s *UnixAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	req := &pb.UpdateKeyMetadataRequest{
		KeyId:       keyID,
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	resp, err := s.kms.UpdateKeyMetadata(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateKeyMetadata", Err: err}
	}

	meta := resp.GetMetadata()
	return &KeyMetadataUpdateResult{
		KeyID:     meta.GetKeyId(),
		Name:      meta.GetName(),
		UpdatedAt: time.Unix(resp.GetTimestamp(), 0),
		Tags:      meta.GetTags(),
	}, nil
}

// KeyPolicy retrieves the access control policy for a key.
func (s *UnixAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	req := &pb.GetKeyPolicyRequest{
		KeyId: keyID,
	}

	resp, err := s.kms.GetKeyPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetKeyPolicy", Err: err}
	}

	policy := resp.GetPolicy()
	return &KeyPolicyResult{
		KeyID:             keyID,
		Version:           int32(policy.GetVersion()),
		AllowedOperations: s.keyUsagesToStrings(policy.GetAllowedOperations()),
		AllowedPrincipals: policy.GetAllowedPrincipals(),
		DeniedPrincipals:  policy.GetDeniedPrincipals(),
		ExpiresAt:         time.Unix(policy.GetExpiresAt(), 0),
		RotationRequired:  policy.GetRotationRequired(),
		MaxUsageCount:     policy.GetMaxUsageCount(),
		RequireMFA:        policy.GetRequireMfa(),
		UpdatedAt:         time.Unix(policy.GetUpdatedAt(), 0),
	}, nil
}

// KeyPolicySet sets the access control policy for a key.
func (s *UnixAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	// Parse ExpiresIn duration string to set ExpiresAt timestamp
	var expiresAt int64
	if opts.ExpiresIn != "" {
		duration, err := time.ParseDuration(opts.ExpiresIn)
		if err == nil {
			expiresAt = time.Now().Add(duration).Unix()
		}
	}

	req := &pb.SetKeyPolicyRequest{
		KeyId: keyID,
		Policy: &pb.KeyPolicy{
			AllowedOperations: s.stringsToKeyUsages(opts.Operations),
			AllowedPrincipals: opts.AllowPrincipals,
			DeniedPrincipals:  opts.DenyPrincipals,
			ExpiresAt:         expiresAt,
			RotationRequired:  opts.RotationRequired,
			MaxUsageCount:     opts.MaxUsageCount,
			RequireMfa:        opts.RequireMFA,
		},
	}

	resp, err := s.kms.SetKeyPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "SetKeyPolicy", Err: err}
	}

	return &KeyPolicySetResult{
		KeyID:         resp.GetKeyId(),
		PolicyVersion: int32(resp.GetPolicyVersion()),
		UpdatedAt:     time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// KeyAlgorithms returns the list of supported key algorithms.
func (s *UnixAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	resp, err := s.kms.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSupportedAlgorithms", Err: err}
	}

	// GetAlgorithms returns []string directly
	return &KeyAlgorithmsResult{
		Algorithms: resp.GetAlgorithms(),
	}, nil
}

// =============================================================================
// Crypto Commands
// =============================================================================

// CryptoEncrypt encrypts plaintext using a named key.
func (s *UnixAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	req := &pb.CryptoEncryptRequest{
		KeyId:     opts.KeyID,
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
	}

	resp, err := s.crypto.Encrypt(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Encrypt", Err: err}
	}

	return &CryptoEncryptResult{
		KeyID:      resp.GetKeyId(),
		KeyVersion: resp.GetKeyVersion(),
		Ciphertext: resp.GetCiphertext(),
		Nonce:      resp.GetNonce(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoDecrypt decrypts ciphertext using a named key.
func (s *UnixAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	req := &pb.CryptoDecryptRequest{
		KeyId:      opts.KeyID,
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	resp, err := s.crypto.Decrypt(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Decrypt", Err: err}
	}

	return &CryptoDecryptResult{
		KeyID:      resp.GetKeyId(),
		KeyVersion: resp.GetKeyVersion(),
		Plaintext:  resp.GetPlaintext(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoSign creates a digital signature.
func (s *UnixAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	req := &pb.SignRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: s.stringToHashAlgorithm(opts.HashAlgorithm),
	}

	resp, err := s.crypto.Sign(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Sign", Err: err}
	}

	return &CryptoSignResult{
		KeyID:         resp.GetKeyId(),
		KeyVersion:    resp.GetKeyVersion(),
		Signature:     resp.GetSignature(),
		HashAlgorithm: s.hashAlgorithmToString(resp.GetHashAlgorithm()),
		Timestamp:     time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoVerify verifies a digital signature.
func (s *UnixAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	req := &pb.VerifyRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: s.stringToHashAlgorithm(opts.HashAlgorithm),
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := s.crypto.Verify(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Verify", Err: err}
	}

	return &CryptoVerifyResult{
		KeyID:      resp.GetKeyId(),
		KeyVersion: resp.GetKeyVersion(),
		Valid:      resp.GetValid(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoHash computes a cryptographic hash.
func (s *UnixAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	req := &pb.HashRequest{
		Data:      data,
		Algorithm: s.stringToHashAlgorithm(algorithm),
	}

	resp, err := s.crypto.Hash(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Hash", Err: err}
	}

	return &CryptoHashResult{
		Algorithm: s.hashAlgorithmToString(resp.GetAlgorithm()),
		Hash:      resp.GetHash(),
		Timestamp: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoHMAC generates an HMAC.
func (s *UnixAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	req := &pb.HMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: s.stringToHashAlgorithm(opts.HashAlgorithm),
	}

	resp, err := s.crypto.GenerateHMAC(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateHMAC", Err: err}
	}

	return &CryptoHMACResult{
		KeyID:         resp.GetKeyId(),
		KeyVersion:    resp.GetKeyVersion(),
		HMAC:          resp.GetHmac(),
		HashAlgorithm: s.hashAlgorithmToString(resp.GetHashAlgorithm()),
		Timestamp:     time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC.
func (s *UnixAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	req := &pb.VerifyHMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Hmac:          opts.HMAC,
		HashAlgorithm: s.stringToHashAlgorithm(opts.HashAlgorithm),
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := s.crypto.VerifyHMAC(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyHMAC", Err: err}
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.GetKeyId(),
		KeyVersion: resp.GetKeyVersion(),
		Valid:      resp.GetValid(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// CryptoRandom generates cryptographically secure random bytes.
func (s *UnixAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	req := &pb.GenerateRandomRequest{
		NumBytes: int32(numBytes),
	}

	resp, err := s.crypto.GenerateRandom(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateRandom", Err: err}
	}

	return &CryptoRandomResult{
		RandomBytes: resp.GetRandomBytes(),
		Timestamp:   time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// =============================================================================
// DEK Commands
// =============================================================================

// DEKCreate creates a new Data Encryption Key.
func (s *UnixAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	req := &pb.CreateDEKRequest{
		Path:           opts.Path,
		Algorithm:      s.stringToKeyAlgorithm(opts.Algorithm),
		Description:    opts.Description,
		MaxOperations:  opts.MaxOperations,
		MaxBytes:       opts.MaxBytes,
		WarningPercent: opts.WarningPercent,
	}

	resp, err := s.dek.CreateDEK(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateDEK", Err: err}
	}

	dek := resp.GetDek()
	return &DEKCreateResult{
		Path:        dek.GetPath(),
		Algorithm:   s.keyAlgorithmToString(dek.GetAlgorithm()),
		Version:     dek.GetVersion(),
		CreatedAt:   time.Unix(dek.GetCreatedAt(), 0),
		Description: dek.GetDescription(),
	}, nil
}

// DEKGet retrieves DEK metadata.
func (s *UnixAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	req := &pb.GetDEKRequest{
		Path: path,
	}

	resp, err := s.dek.GetDEK(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetDEK", Err: err}
	}

	dek := resp.GetDek()
	result := &DEKGetResult{
		Path:           dek.GetPath(),
		Algorithm:      s.keyAlgorithmToString(dek.GetAlgorithm()),
		Version:        dek.GetVersion(),
		Status:         dek.GetStatus(),
		IsDefault:      dek.GetIsDefault(),
		CreatedAt:      time.Unix(dek.GetCreatedAt(), 0),
		Description:    dek.GetDescription(),
		BackendType:    dek.GetBackendType(),
		UsageCount:     dek.GetUsageCount(),
		BytesUsed:      dek.GetBytesUsed(),
		MaxUsageCount:  dek.GetMaxUsageCount(),
		MaxBytesUsed:   dek.GetMaxBytesUsed(),
		WarningPercent: dek.GetWarningPercent(),
	}

	if dek.GetRotatedAt() > 0 {
		result.RotatedAt = time.Unix(dek.GetRotatedAt(), 0)
	}

	return result, nil
}

// DEKList lists DEKs with optional filtering.
func (s *UnixAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	req := &pb.ListDEKsRequest{
		Prefix:    opts.Prefix,
		Recursive: opts.Recursive,
		Limit:     opts.Limit,
		Cursor:    opts.Cursor,
	}

	resp, err := s.dek.ListDEKs(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListDEKs", Err: err}
	}

	deks := make([]DEKSummary, 0, len(resp.GetDeks()))
	for _, d := range resp.GetDeks() {
		deks = append(deks, DEKSummary{
			Path:      d.GetPath(),
			Algorithm: s.keyAlgorithmToString(d.GetAlgorithm()),
			Version:   d.GetVersion(),
			Status:    d.GetStatus(),
			IsDefault: d.GetIsDefault(),
			CreatedAt: time.Unix(d.GetCreatedAt(), 0),
		})
	}

	return &DEKListResult{
		DEKs:       deks,
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// DEKDelete deletes a DEK.
func (s *UnixAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	req := &pb.DeleteDEKRequest{
		Path:      path,
		Force:     opts.Force,
		MigrateTo: opts.MigrateTo,
	}

	resp, err := s.dek.DeleteDEK(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteDEK", Err: err}
	}

	return &DEKDeleteResult{
		Path:    resp.GetPath(),
		Deleted: resp.GetDeleted(),
	}, nil
}

// DEKRotate rotates a DEK to a new version.
func (s *UnixAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	req := &pb.RotateDEKRequest{
		Path:       path,
		Background: background,
	}

	resp, err := s.dek.RotateDEK(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RotateDEK", Err: err}
	}

	return &DEKRotateResult{
		Path:       resp.GetPath(),
		OldVersion: resp.GetOldVersion(),
		NewVersion: resp.GetNewVersion(),
	}, nil
}

// DEKStatus retrieves detailed DEK status including usage metrics.
func (s *UnixAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	req := &pb.GetDEKStatusRequest{
		Path: path,
	}

	resp, err := s.dek.GetDEKStatus(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetDEKStatus", Err: err}
	}

	dek := resp.GetDek()
	reenc := resp.GetReencryptionProgress()

	result := &DEKStatusResult{
		Path:           dek.GetPath(),
		Algorithm:      s.keyAlgorithmToString(dek.GetAlgorithm()),
		Version:        dek.GetVersion(),
		Status:         dek.GetStatus(),
		IsDefault:      dek.GetIsDefault(),
		CreatedAt:      time.Unix(dek.GetCreatedAt(), 0),
		Description:    dek.GetDescription(),
		BackendType:    dek.GetBackendType(),
		UsageCount:     dek.GetUsageCount(),
		BytesUsed:      dek.GetBytesUsed(),
		MaxUsageCount:  dek.GetMaxUsageCount(),
		MaxBytesUsed:   dek.GetMaxBytesUsed(),
		WarningPercent: dek.GetWarningPercent(),
	}

	if dek.GetRotatedAt() > 0 {
		result.RotatedAt = time.Unix(dek.GetRotatedAt(), 0)
	}

	if reenc != nil {
		result.ReencryptionInProgress = reenc.GetInProgress()
		result.ProcessedKeys = int64(reenc.GetProcessedKeys())
		result.TotalKeys = int64(reenc.GetTotalKeys())
		result.FailedKeys = int64(reenc.GetFailedKeys())
		if reenc.GetStartedAt() > 0 {
			result.ReencryptionStartedAt = time.Unix(reenc.GetStartedAt(), 0)
		}
		if reenc.GetEstimatedCompletion() > 0 {
			result.EstimatedCompletion = time.Unix(reenc.GetEstimatedCompletion(), 0)
		}
	}

	return result, nil
}

// =============================================================================
// Secrets Commands
// =============================================================================

// SecretsStore stores a secret.
func (s *UnixAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	req := &pb.StoreSecretRequest{
		Name:        opts.Name,
		Data:        opts.Data,
		Description: opts.Description,
		TenantId:    opts.TenantID,
		KeyId:       opts.KeyID,
		Algorithm:   opts.Algorithm, // Algorithm is a string in the proto
	}

	resp, err := s.secrets.StoreSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StoreSecret", Err: err}
	}

	return &SecretsStoreResult{
		SecretID:  resp.GetSecretId(),
		Version:   resp.GetVersion(),
		Timestamp: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// SecretsGet retrieves the latest version of a secret.
func (s *UnixAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	req := &pb.GetSecretRequest{
		SecretId: name, // Proto uses SecretId, not Name
	}

	resp, err := s.secrets.GetSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSecret", Err: err}
	}

	// GetSecretResponse has fields directly, not via GetSecret()
	return &SecretsGetResult{
		SecretID:      resp.GetSecretId(),
		Version:       resp.GetVersion(),
		Data:          resp.GetData(),
		Metadata:      resp.GetMetadata(),
		Algorithm:     resp.GetAlgorithm(),
		KeyIdentifier: resp.GetKeyIdentifier(),
		CreatedAt:     time.Unix(resp.GetCreatedAt(), 0),
		Timestamp:     time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// SecretsList lists secrets with pagination.
func (s *UnixAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
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
			Name:           sec.GetName(),
			CurrentVersion: sec.GetCurrentVersion(),
			Description:    sec.GetDescription(),
			Owner:          sec.GetOwner(),
			CreatedAt:      time.Unix(sec.GetCreatedAt(), 0),
			UpdatedAt:      time.Unix(sec.GetUpdatedAt(), 0),
		})
	}

	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: resp.GetTotalCount(),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// SecretsDelete deletes a secret.
func (s *UnixAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	req := &pb.DeleteSecretRequest{
		SecretId:          name, // Proto uses SecretId, not Name
		PermanentlyDelete: permanent,
	}

	resp, err := s.secrets.DeleteSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteSecret", Err: err}
	}

	return &SecretsDeleteResult{
		SecretID:  resp.GetSecretId(),
		Deleted:   resp.GetDeleted(),
		Timestamp: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// SecretsRotate rotates a secret to a new value.
func (s *UnixAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	req := &pb.RotateSecretRequest{
		SecretId:  opts.Name, // Proto uses SecretId, not Name
		NewData:   opts.NewData,
		TenantId:  opts.TenantID,
		KeyId:     opts.KeyID,
		Algorithm: opts.Algorithm, // Algorithm is a string in the proto
	}

	resp, err := s.secrets.RotateSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RotateSecret", Err: err}
	}

	return &SecretsRotateResult{
		SecretID:   resp.GetSecretId(),
		OldVersion: resp.GetOldVersion(),
		NewVersion: resp.GetNewVersion(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// SecretsVersions lists all versions of a secret.
func (s *UnixAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{
		SecretId: name, // Proto uses SecretId, not Name
		Limit:    opts.Limit,
		Cursor:   opts.Cursor,
	}

	resp, err := s.secrets.ListSecretVersions(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListSecretVersions", Err: err}
	}

	versions := make([]SecretVersionInfo, 0, len(resp.GetVersions()))
	for _, v := range resp.GetVersions() {
		info := SecretVersionInfo{
			Version:   v.GetVersion(),
			CreatedAt: time.Unix(v.GetCreatedAt(), 0),
			CreatedBy: v.GetCreatedBy(),
		}
		if v.GetExpiresAt() > 0 {
			info.ExpiresAt = time.Unix(v.GetExpiresAt(), 0)
		}
		versions = append(versions, info)
	}

	// ListSecretVersionsResponse does not have GetSecretId()
	return &SecretsVersionsResult{
		SecretID:   name, // Use the input name since response doesn't have it
		Versions:   versions,
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}, nil
}

// SecretsVersion retrieves a specific version of a secret.
func (s *UnixAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	req := &pb.GetSecretVersionRequest{
		SecretId: name, // Proto uses SecretId, not Name
		Version:  version,
	}

	resp, err := s.secrets.GetSecretVersion(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSecretVersion", Err: err}
	}

	// GetSecretVersionResponse has Version (*SecretVersion), Data, and Timestamp
	secretVersion := resp.GetVersion()
	result := &SecretsVersionResult{
		SecretID:  secretVersion.GetSecretId(),
		Version:   secretVersion.GetVersion(),
		Data:      resp.GetData(),
		Metadata:  secretVersion.GetMetadata(),
		CreatedAt: time.Unix(secretVersion.GetCreatedAt(), 0),
		CreatedBy: secretVersion.GetCreatedBy(),
		Timestamp: time.Unix(resp.GetTimestamp(), 0),
	}

	if secretVersion.GetExpiresAt() > 0 {
		result.ExpiresAt = time.Unix(secretVersion.GetExpiresAt(), 0)
	}

	return result, nil
}

// SecretsRollback rolls back to a previous version of a secret.
func (s *UnixAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	req := &pb.RollbackSecretRequest{
		SecretId:      name, // Proto uses SecretId, not Name
		TargetVersion: targetVersion,
	}

	resp, err := s.secrets.RollbackSecret(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RollbackSecret", Err: err}
	}

	return &SecretsRollbackResult{
		SecretID:   resp.GetSecretId(),
		NewVersion: resp.GetNewVersion(),
		Timestamp:  time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// SecretsStatus updates the enabled/disabled status of a secret.
func (s *UnixAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	status := pb.SecretStatus_SECRET_STATUS_DISABLED
	if enabled {
		status = pb.SecretStatus_SECRET_STATUS_ENABLED
	}

	req := &pb.UpdateSecretStatusRequest{
		SecretId: name, // Proto uses SecretId, not Name
		Status:   status,
	}

	resp, err := s.secrets.UpdateSecretStatus(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateSecretStatus", Err: err}
	}

	return &SecretsStatusResult{
		SecretID:  resp.GetSecretId(),
		Status:    s.secretStatusToString(resp.GetStatus()),
		Timestamp: time.Unix(resp.GetTimestamp(), 0),
	}, nil
}

// =============================================================================
// Type Conversion Helpers
// =============================================================================

// stringToKeyAlgorithm converts a string algorithm name to proto KeyAlgorithm.
func (s *UnixAdapter) stringToKeyAlgorithm(alg string) pb.KeyAlgorithm {
	switch alg {
	case "AES-128-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_128_GCM
	case "AES-192-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_192_GCM
	case "AES-256-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case "CHACHA20-POLY1305":
		return pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case "XCHACHA20-POLY1305":
		return pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305
	case "RSA-2048":
		return pb.KeyAlgorithm_KEY_ALG_RSA_2048
	case "RSA-3072":
		return pb.KeyAlgorithm_KEY_ALG_RSA_3072
	case "RSA-4096":
		return pb.KeyAlgorithm_KEY_ALG_RSA_4096
	case "ECDSA-P256":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P256
	case "ECDSA-P384":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P384
	case "ECDSA-P521":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P521
	case "ED25519":
		return pb.KeyAlgorithm_KEY_ALG_ED25519
	case "ED448":
		return pb.KeyAlgorithm_KEY_ALG_ED448
	case "X25519":
		return pb.KeyAlgorithm_KEY_ALG_X25519
	case "X448":
		return pb.KeyAlgorithm_KEY_ALG_X448
	case "HMAC-SHA256":
		return pb.KeyAlgorithm_KEY_ALG_HMAC_SHA256
	case "HMAC-SHA384":
		return pb.KeyAlgorithm_KEY_ALG_HMAC_SHA384
	case "HMAC-SHA512":
		return pb.KeyAlgorithm_KEY_ALG_HMAC_SHA512
	default:
		return pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED
	}
}

// keyAlgorithmToString converts proto KeyAlgorithm to string.
func (s *UnixAdapter) keyAlgorithmToString(alg pb.KeyAlgorithm) string {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALG_AES_128_GCM:
		return "AES-128-GCM"
	case pb.KeyAlgorithm_KEY_ALG_AES_192_GCM:
		return "AES-192-GCM"
	case pb.KeyAlgorithm_KEY_ALG_AES_256_GCM:
		return "AES-256-GCM"
	case pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:
		return "CHACHA20-POLY1305"
	case pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305:
		return "XCHACHA20-POLY1305"
	case pb.KeyAlgorithm_KEY_ALG_RSA_2048:
		return "RSA-2048"
	case pb.KeyAlgorithm_KEY_ALG_RSA_3072:
		return "RSA-3072"
	case pb.KeyAlgorithm_KEY_ALG_RSA_4096:
		return "RSA-4096"
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P256:
		return "ECDSA-P256"
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P384:
		return "ECDSA-P384"
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P521:
		return "ECDSA-P521"
	case pb.KeyAlgorithm_KEY_ALG_ED25519:
		return "ED25519"
	case pb.KeyAlgorithm_KEY_ALG_ED448:
		return "ED448"
	case pb.KeyAlgorithm_KEY_ALG_X25519:
		return "X25519"
	case pb.KeyAlgorithm_KEY_ALG_X448:
		return "X448"
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA256:
		return "HMAC-SHA256"
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA384:
		return "HMAC-SHA384"
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA512:
		return "HMAC-SHA512"
	default:
		return "UNSPECIFIED"
	}
}

// keyStatusToString converts proto KeyStatus to string.
func (s *UnixAdapter) keyStatusToString(status pb.KeyStatus) string {
	switch status {
	case pb.KeyStatus_KEY_STATUS_ENABLED:
		return "ENABLED"
	case pb.KeyStatus_KEY_STATUS_DISABLED:
		return "DISABLED"
	case pb.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return "PENDING_DELETION"
	case pb.KeyStatus_KEY_STATUS_DELETED:
		return "DELETED"
	case pb.KeyStatus_KEY_STATUS_ROTATING:
		return "ROTATING"
	case pb.KeyStatus_KEY_STATUS_COMPROMISED:
		return "COMPROMISED"
	default:
		return "UNSPECIFIED"
	}
}

// stringToHashAlgorithm converts a string hash algorithm name to proto HashAlgorithm.
func (s *UnixAdapter) stringToHashAlgorithm(alg string) pb.HashAlgorithm {
	switch alg {
	case "SHA256", "SHA-256":
		return pb.HashAlgorithm_HASH_ALG_SHA256
	case "SHA384", "SHA-384":
		return pb.HashAlgorithm_HASH_ALG_SHA384
	case "SHA512", "SHA-512":
		return pb.HashAlgorithm_HASH_ALG_SHA512
	case "SHA3-256":
		return pb.HashAlgorithm_HASH_ALG_SHA3_256
	case "SHA3-384":
		return pb.HashAlgorithm_HASH_ALG_SHA3_384
	case "SHA3-512":
		return pb.HashAlgorithm_HASH_ALG_SHA3_512
	case "BLAKE2B-256":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_256
	case "BLAKE2B-512":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_512
	default:
		return pb.HashAlgorithm_HASH_ALG_UNSPECIFIED
	}
}

// hashAlgorithmToString converts proto HashAlgorithm to string.
func (s *UnixAdapter) hashAlgorithmToString(alg pb.HashAlgorithm) string {
	switch alg {
	case pb.HashAlgorithm_HASH_ALG_SHA256:
		return "SHA256"
	case pb.HashAlgorithm_HASH_ALG_SHA384:
		return "SHA384"
	case pb.HashAlgorithm_HASH_ALG_SHA512:
		return "SHA512"
	case pb.HashAlgorithm_HASH_ALG_SHA3_256:
		return "SHA3-256"
	case pb.HashAlgorithm_HASH_ALG_SHA3_384:
		return "SHA3-384"
	case pb.HashAlgorithm_HASH_ALG_SHA3_512:
		return "SHA3-512"
	case pb.HashAlgorithm_HASH_ALG_BLAKE2B_256:
		return "BLAKE2B-256"
	case pb.HashAlgorithm_HASH_ALG_BLAKE2B_512:
		return "BLAKE2B-512"
	default:
		return "UNSPECIFIED"
	}
}

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

// purposeToKeyUsages converts a purpose string to proto KeyUsage slice.
func (s *UnixAdapter) purposeToKeyUsages(purpose string) []pb.KeyUsage {
	switch purpose {
	case "encrypt", "encryption":
		return []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_DECRYPT}
	case "sign", "signing":
		return []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN, pb.KeyUsage_KEY_USAGE_VERIFY}
	case "hmac":
		return []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_GENERATE_MAC, pb.KeyUsage_KEY_USAGE_VERIFY_MAC}
	case "wrap", "wrapping":
		return []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_WRAP_KEY}
	case "derive", "derivation":
		return []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_DERIVE_KEY}
	default:
		return nil
	}
}

// keyUsagesToStrings converts proto KeyUsage slice to string slice.
func (s *UnixAdapter) keyUsagesToStrings(usages []pb.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		result = append(result, s.keyUsageToString(u))
	}
	return result
}

// keyUsageToString converts proto KeyUsage to string.
func (s *UnixAdapter) keyUsageToString(usage pb.KeyUsage) string {
	switch usage {
	case pb.KeyUsage_KEY_USAGE_ENCRYPT:
		return "ENCRYPT"
	case pb.KeyUsage_KEY_USAGE_DECRYPT:
		return "DECRYPT"
	case pb.KeyUsage_KEY_USAGE_SIGN:
		return "SIGN"
	case pb.KeyUsage_KEY_USAGE_VERIFY:
		return "VERIFY"
	case pb.KeyUsage_KEY_USAGE_WRAP_KEY:
		return "WRAP_KEY"
	case pb.KeyUsage_KEY_USAGE_DERIVE_KEY:
		return "DERIVE_KEY"
	case pb.KeyUsage_KEY_USAGE_GENERATE_MAC:
		return "GENERATE_MAC"
	case pb.KeyUsage_KEY_USAGE_VERIFY_MAC:
		return "VERIFY_MAC"
	default:
		return "UNSPECIFIED"
	}
}

// stringsToKeyUsages converts string slice to proto KeyUsage slice.
func (s *UnixAdapter) stringsToKeyUsages(operations []string) []pb.KeyUsage {
	result := make([]pb.KeyUsage, 0, len(operations))
	for _, op := range operations {
		result = append(result, s.stringToKeyUsage(op))
	}
	return result
}

// stringToKeyUsage converts string to proto KeyUsage.
func (s *UnixAdapter) stringToKeyUsage(op string) pb.KeyUsage {
	switch op {
	case "ENCRYPT":
		return pb.KeyUsage_KEY_USAGE_ENCRYPT
	case "DECRYPT":
		return pb.KeyUsage_KEY_USAGE_DECRYPT
	case "SIGN":
		return pb.KeyUsage_KEY_USAGE_SIGN
	case "VERIFY":
		return pb.KeyUsage_KEY_USAGE_VERIFY
	case "WRAP_KEY":
		return pb.KeyUsage_KEY_USAGE_WRAP_KEY
	case "DERIVE_KEY":
		return pb.KeyUsage_KEY_USAGE_DERIVE_KEY
	case "GENERATE_MAC":
		return pb.KeyUsage_KEY_USAGE_GENERATE_MAC
	case "VERIFY_MAC":
		return pb.KeyUsage_KEY_USAGE_VERIFY_MAC
	default:
		return pb.KeyUsage_KEY_USAGE_UNSPECIFIED
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
