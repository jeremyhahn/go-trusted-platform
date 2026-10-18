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
	"os"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements KMSCommands using gRPC calls to platformd.
// This adapter makes gRPC calls to the platformd server for testing
// the gRPC transport layer consistency with other protocol adapters.
type GRPCAdapter struct {
	conn    *grpc.ClientConn
	kms     pb.KeyManagementClient
	crypto  pb.CryptoClient
	dek     pb.DEKManagementClient
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
	g.kms = pb.NewKeyManagementClient(conn)
	g.crypto = pb.NewCryptoClient(conn)
	g.dek = pb.NewDEKManagementClient(conn)
	g.secrets = pb.NewSecretsManagementClient(conn)

	// Verify connectivity by checking backend status
	_, err = g.kms.BackendStatus(ctx, &pb.BackendStatusRequest{})
	if err != nil {
		conn.Close()
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

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
// Algorithm and Status Conversion Helpers
// =============================================================================

// algorithmStringToProto converts a string algorithm name to proto enum.
func algorithmStringToProto(alg string) pb.KeyAlgorithm {
	switch alg {
	case "AES-128-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_128_GCM
	case "AES-192-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_192_GCM
	case "AES-256-GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case "ChaCha20-Poly1305":
		return pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case "XChaCha20-Poly1305":
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
	case "Ed25519":
		return pb.KeyAlgorithm_KEY_ALG_ED25519
	case "Ed448":
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

// algorithmProtoToString converts a proto enum to string algorithm name.
func algorithmProtoToString(alg pb.KeyAlgorithm) string {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALG_AES_128_GCM:
		return "AES-128-GCM"
	case pb.KeyAlgorithm_KEY_ALG_AES_192_GCM:
		return "AES-192-GCM"
	case pb.KeyAlgorithm_KEY_ALG_AES_256_GCM:
		return "AES-256-GCM"
	case pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:
		return "ChaCha20-Poly1305"
	case pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305:
		return "XChaCha20-Poly1305"
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
		return "Ed25519"
	case pb.KeyAlgorithm_KEY_ALG_ED448:
		return "Ed448"
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

// statusProtoToString converts a proto key status enum to string.
func statusProtoToString(status pb.KeyStatus) string {
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

// hashAlgorithmStringToProto converts a string hash algorithm to proto enum.
func hashAlgorithmStringToProto(alg string) pb.HashAlgorithm {
	switch alg {
	case "SHA-256", "SHA256":
		return pb.HashAlgorithm_HASH_ALG_SHA256
	case "SHA-384", "SHA384":
		return pb.HashAlgorithm_HASH_ALG_SHA384
	case "SHA-512", "SHA512":
		return pb.HashAlgorithm_HASH_ALG_SHA512
	case "SHA3-256":
		return pb.HashAlgorithm_HASH_ALG_SHA3_256
	case "SHA3-384":
		return pb.HashAlgorithm_HASH_ALG_SHA3_384
	case "SHA3-512":
		return pb.HashAlgorithm_HASH_ALG_SHA3_512
	case "BLAKE2b-256":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_256
	case "BLAKE2b-512":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_512
	default:
		return pb.HashAlgorithm_HASH_ALG_UNSPECIFIED
	}
}

// hashAlgorithmProtoToString converts a proto hash algorithm enum to string.
func hashAlgorithmProtoToString(alg pb.HashAlgorithm) string {
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

// keyUsageProtoToStrings converts proto key usage enums to string slice.
func keyUsageProtoToStrings(usages []pb.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
		case pb.KeyUsage_KEY_USAGE_ENCRYPT:
			result = append(result, "encrypt")
		case pb.KeyUsage_KEY_USAGE_DECRYPT:
			result = append(result, "decrypt")
		case pb.KeyUsage_KEY_USAGE_SIGN:
			result = append(result, "sign")
		case pb.KeyUsage_KEY_USAGE_VERIFY:
			result = append(result, "verify")
		case pb.KeyUsage_KEY_USAGE_WRAP_KEY:
			result = append(result, "wrap_key")
		case pb.KeyUsage_KEY_USAGE_DERIVE_KEY:
			result = append(result, "derive_key")
		case pb.KeyUsage_KEY_USAGE_GENERATE_MAC:
			result = append(result, "generate_mac")
		case pb.KeyUsage_KEY_USAGE_VERIFY_MAC:
			result = append(result, "verify_mac")
		}
	}
	return result
}

// unixToTime converts Unix timestamp to time.Time.
func grpcUnixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// =============================================================================
// Key Management Operations
// =============================================================================

// KeyGenerate creates a new cryptographic key via gRPC.
func (g *GRPCAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	req := &pb.GenerateKeyRequest{
		KeySpec: &pb.KeySpec{
			Algorithm:          algorithmStringToProto(opts.Algorithm),
			Usage:              purposeToKeyUsages(opts.Purpose),
			Exportable:         opts.Exportable,
			DeletionProtection: opts.DeletionProtection,
		},
		Name:        keyName(opts),
		Description: opts.Description,
		Owner:       opts.Owner,
	}

	resp, err := g.kms.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateKey", Err: err}
	}

	result := &KeyGenerateResult{
		KeyID:              resp.Key.KeyId,
		Version:            resp.Key.Version,
		Algorithm:          algorithmProtoToString(resp.Key.Algorithm),
		Status:             statusProtoToString(resp.Key.Status),
		CreatedAt:          grpcUnixToTime(resp.Key.CreatedAt),
		Name:               resp.Metadata.Name,
		Description:        resp.Metadata.Description,
		Exportable:         resp.Metadata.Exportable,
		DeletionProtection: resp.Metadata.DeletionProtection,
	}
	if err := applyKeyDisplay(ctx, g, opts, result); err != nil {
		return nil, err
	}
	return result, nil
}

// KeyGet retrieves a key by ID and optional version via gRPC.
func (g *GRPCAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	req := &pb.GetKeyRequest{
		KeyId:   keyID,
		Version: version,
	}

	resp, err := g.kms.GetKey(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetKey", Err: err}
	}

	return &KeyGetResult{
		KeyID:              resp.Key.KeyId,
		Version:            resp.Key.Version,
		Algorithm:          algorithmProtoToString(resp.Key.Algorithm),
		Status:             statusProtoToString(resp.Key.Status),
		CreatedAt:          grpcUnixToTime(resp.Key.CreatedAt),
		UpdatedAt:          grpcUnixToTime(resp.Metadata.UpdatedAt),
		LastUsedAt:         grpcUnixToTime(resp.Metadata.LastUsedAt),
		Name:               resp.Metadata.Name,
		Description:        resp.Metadata.Description,
		Owner:              resp.Metadata.Owner,
		Exportable:         resp.Metadata.Exportable,
		DeletionProtection: resp.Metadata.DeletionProtection,
		Usage:              keyUsageProtoToStrings(resp.Metadata.Usage),
	}, nil
}

// KeyList lists keys with pagination via gRPC.
func (g *GRPCAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	req := &pb.ListKeysRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := g.kms.ListKeys(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListKeys", Err: err}
	}

	keys := make([]KeySummary, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, KeySummary{
			KeyID:     k.KeyId,
			Version:   k.Version,
			Algorithm: algorithmProtoToString(k.Algorithm),
			Status:    statusProtoToString(k.Status),
			CreatedAt: grpcUnixToTime(k.CreatedAt),
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyDelete deletes a key via gRPC.
func (g *GRPCAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	req := &pb.DeleteKeyRequest{
		KeyId:             keyID,
		PendingWindowDays: opts.PendingWindowDays,
		Force:             opts.Force,
	}

	resp, err := g.kms.DeleteKey(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteKey", Err: err}
	}

	return &KeyDeleteResult{
		KeyID:        resp.KeyId,
		Status:       statusProtoToString(resp.Status),
		DeletionDate: grpcUnixToTime(resp.DeletionDate),
	}, nil
}

// KeyRotate rotates a key to create a new version via gRPC.
func (g *GRPCAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	req := &pb.RotateKeyRequest{
		KeyId:            keyID,
		RetainOldVersion: retainOldVersion,
	}

	resp, err := g.kms.RotateKey(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RotateKey", Err: err}
	}

	return &KeyRotateResult{
		KeyID:      resp.KeyId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		RotatedAt:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyVersions lists versions of a key via gRPC.
func (g *GRPCAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	req := &pb.ListKeyVersionsRequest{
		KeyId:  keyID,
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := g.kms.ListKeyVersions(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListKeyVersions", Err: err}
	}

	versions := make([]KeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  algorithmProtoToString(v.Algorithm),
			Status:     statusProtoToString(v.Status),
			CreatedAt:  grpcUnixToTime(v.CreatedAt),
			DisabledAt: grpcUnixToTime(v.DisabledAt),
		})
	}

	return &KeyVersionsResult{
		KeyID:      resp.KeyId,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyStatus updates the status (enabled/disabled) of a key version via gRPC.
func (g *GRPCAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	status := pb.KeyStatus_KEY_STATUS_DISABLED
	if enabled {
		status = pb.KeyStatus_KEY_STATUS_ENABLED
	}

	req := &pb.UpdateKeyStatusRequest{
		KeyId:   keyID,
		Version: version,
		Status:  status,
	}

	resp, err := g.kms.UpdateKeyStatus(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateKeyStatus", Err: err}
	}

	return &KeyStatusResult{
		KeyID:     resp.KeyId,
		Version:   resp.Version,
		Status:    statusProtoToString(resp.Status),
		UpdatedAt: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyRevoke revokes a key via gRPC.
func (g *GRPCAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	req := &pb.RevokeKeyRequest{
		KeyId:  keyID,
		Reason: reason,
	}

	resp, err := g.kms.RevokeKey(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RevokeKey", Err: err}
	}

	return &KeyRevokeResult{
		KeyID:     resp.KeyId,
		Status:    statusProtoToString(resp.Status),
		RevokedAt: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyMetadata retrieves key metadata via gRPC.
func (g *GRPCAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	req := &pb.GetKeyMetadataRequest{
		KeyId: keyID,
	}

	resp, err := g.kms.GetKeyMetadata(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetKeyMetadata", Err: err}
	}

	var rotationPolicy *RotationPolicy
	if resp.Metadata.RotationPolicy != nil {
		rotationPolicy = &RotationPolicy{
			Enabled:         resp.Metadata.RotationPolicy.Enabled,
			IntervalSeconds: resp.Metadata.RotationPolicy.IntervalSeconds,
			NextRotation:    grpcUnixToTime(resp.Metadata.RotationPolicy.NextRotation),
			RetainVersions:  resp.Metadata.RotationPolicy.RetainVersions,
		}
	}

	return &KeyMetadataResult{
		KeyID:              resp.Metadata.KeyId,
		Name:               resp.Metadata.Name,
		Description:        resp.Metadata.Description,
		Algorithm:          algorithmProtoToString(resp.Metadata.Algorithm),
		Status:             statusProtoToString(resp.Metadata.Status),
		Version:            resp.Metadata.Version,
		Exportable:         resp.Metadata.Exportable,
		DeletionProtection: resp.Metadata.DeletionProtection,
		Usage:              keyUsageProtoToStrings(resp.Metadata.Usage),
		Owner:              resp.Metadata.Owner,
		CreatedAt:          grpcUnixToTime(resp.Metadata.CreatedAt),
		UpdatedAt:          grpcUnixToTime(resp.Metadata.UpdatedAt),
		LastUsedAt:         grpcUnixToTime(resp.Metadata.LastUsedAt),
		Tags:               resp.Metadata.Tags,
		RotationPolicy:     rotationPolicy,
	}, nil
}

// KeyMetadataUpdate updates key metadata via gRPC.
func (g *GRPCAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	req := &pb.UpdateKeyMetadataRequest{
		KeyId:       keyID,
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	resp, err := g.kms.UpdateKeyMetadata(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateKeyMetadata", Err: err}
	}

	return &KeyMetadataUpdateResult{
		KeyID:     resp.Metadata.KeyId,
		Name:      resp.Metadata.Name,
		UpdatedAt: grpcUnixToTime(resp.Timestamp),
		Tags:      resp.Metadata.Tags,
	}, nil
}

// KeyPolicy retrieves the access policy for a key via gRPC.
func (g *GRPCAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	req := &pb.GetKeyPolicyRequest{
		KeyId: keyID,
	}

	resp, err := g.kms.GetKeyPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetKeyPolicy", Err: err}
	}

	return &KeyPolicyResult{
		KeyID:             resp.Policy.KeyId,
		Version:           int32(resp.Policy.Version),
		AllowedOperations: keyUsageProtoToStrings(resp.Policy.AllowedOperations),
		AllowedPrincipals: resp.Policy.AllowedPrincipals,
		DeniedPrincipals:  resp.Policy.DeniedPrincipals,
		ExpiresAt:         grpcUnixToTime(resp.Policy.ExpiresAt),
		RotationRequired:  resp.Policy.RotationRequired,
		MaxUsageCount:     resp.Policy.MaxUsageCount,
		RequireMFA:        resp.Policy.RequireMfa,
		UpdatedAt:         grpcUnixToTime(resp.Policy.UpdatedAt),
	}, nil
}

// KeyPolicySet sets the access policy for a key via gRPC.
func (g *GRPCAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	operations := make([]pb.KeyUsage, 0, len(opts.Operations))
	for _, op := range opts.Operations {
		switch op {
		case "encrypt":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_ENCRYPT)
		case "decrypt":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_DECRYPT)
		case "sign":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_SIGN)
		case "verify":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_VERIFY)
		case "wrap_key":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_WRAP_KEY)
		case "derive_key":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_DERIVE_KEY)
		case "generate_mac":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_GENERATE_MAC)
		case "verify_mac":
			operations = append(operations, pb.KeyUsage_KEY_USAGE_VERIFY_MAC)
		}
	}

	req := &pb.SetKeyPolicyRequest{
		KeyId: keyID,
		Policy: &pb.KeyPolicy{
			KeyId:             keyID,
			AllowedOperations: operations,
			AllowedPrincipals: opts.AllowPrincipals,
			DeniedPrincipals:  opts.DenyPrincipals,
			RotationRequired:  opts.RotationRequired,
			MaxUsageCount:     opts.MaxUsageCount,
			RequireMfa:        opts.RequireMFA,
		},
	}

	resp, err := g.kms.SetKeyPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SetKeyPolicy", Err: err}
	}

	return &KeyPolicySetResult{
		KeyID:         resp.KeyId,
		PolicyVersion: int32(resp.PolicyVersion),
		UpdatedAt:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyAlgorithms returns supported key algorithms via gRPC.
func (g *GRPCAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	resp, err := g.kms.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSupportedAlgorithms", Err: err}
	}

	return &KeyAlgorithmsResult{
		Algorithms: resp.Algorithms,
	}, nil
}

// =============================================================================
// Crypto Operations
// =============================================================================

// CryptoEncrypt encrypts data using a key via gRPC.
func (g *GRPCAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	req := &pb.CryptoEncryptRequest{
		KeyId:     opts.KeyID,
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
	}

	resp, err := g.crypto.Encrypt(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Encrypt", Err: err}
	}

	return &CryptoEncryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts data using a key via gRPC.
func (g *GRPCAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	req := &pb.CryptoDecryptRequest{
		KeyId:      opts.KeyID,
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	resp, err := g.crypto.Decrypt(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Decrypt", Err: err}
	}

	return &CryptoDecryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoSign signs data using a key via gRPC.
func (g *GRPCAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	req := &pb.SignRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: hashAlgorithmStringToProto(opts.HashAlgorithm),
	}

	resp, err := g.crypto.Sign(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Sign", Err: err}
	}

	return &CryptoSignResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: hashAlgorithmProtoToString(resp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature via gRPC.
func (g *GRPCAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	req := &pb.VerifyRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: hashAlgorithmStringToProto(opts.HashAlgorithm),
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := g.crypto.Verify(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Verify", Err: err}
	}

	return &CryptoVerifyResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoHash computes a hash of data via gRPC.
func (g *GRPCAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	req := &pb.HashRequest{
		Data:      data,
		Algorithm: hashAlgorithmStringToProto(algorithm),
	}

	resp, err := g.crypto.Hash(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Hash", Err: err}
	}

	return &CryptoHashResult{
		Algorithm: hashAlgorithmProtoToString(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoHMAC generates an HMAC of data via gRPC.
func (g *GRPCAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	req := &pb.HMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: hashAlgorithmStringToProto(opts.HashAlgorithm),
	}

	resp, err := g.crypto.GenerateHMAC(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateHMAC", Err: err}
	}

	return &CryptoHMACResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.Hmac,
		HashAlgorithm: hashAlgorithmProtoToString(resp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC via gRPC.
func (g *GRPCAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	req := &pb.VerifyHMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Hmac:          opts.HMAC,
		HashAlgorithm: hashAlgorithmStringToProto(opts.HashAlgorithm),
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := g.crypto.VerifyHMAC(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyHMAC", Err: err}
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoRandom generates random bytes via gRPC.
func (g *GRPCAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	req := &pb.GenerateRandomRequest{
		NumBytes: int32(numBytes),
	}

	resp, err := g.crypto.GenerateRandom(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateRandom", Err: err}
	}

	return &CryptoRandomResult{
		RandomBytes: resp.RandomBytes,
		Timestamp:   grpcUnixToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// DEK Management Operations
// =============================================================================

// DEKCreate creates a new DEK via gRPC.
func (g *GRPCAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	resp, err := g.dek.CreateDEK(ctx, newCreateDEKRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateDEK", Err: err}
	}
	return dekCreateResult(resp)
}

// DEKGet retrieves a DEK by path via gRPC.
func (g *GRPCAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	resp, err := g.dek.GetDEK(ctx, &pb.GetDEKRequest{Path: path})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetDEK", Err: err}
	}
	return dekGetResult(resp)
}

// DEKList lists DEKs with optional prefix via gRPC.
func (g *GRPCAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	resp, err := g.dek.ListDEKs(ctx, newListDEKsRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListDEKs", Err: err}
	}
	return dekListResult(resp), nil
}

// DEKDelete deletes a DEK via gRPC.
func (g *GRPCAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	req := &pb.DeleteDEKRequest{
		Path:      path,
		Force:     opts.Force,
		MigrateTo: opts.MigrateTo,
	}

	resp, err := g.dek.DeleteDEK(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteDEK", Err: err}
	}

	return &DEKDeleteResult{
		Path:    resp.Path,
		Deleted: resp.Deleted,
	}, nil
}

// DEKRotate rotates a DEK to create a new version via gRPC.
func (g *GRPCAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	req := &pb.RotateDEKRequest{
		Path:       path,
		Background: background,
	}

	resp, err := g.dek.RotateDEK(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RotateDEK", Err: err}
	}

	return &DEKRotateResult{
		Path:       resp.Path,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
	}, nil
}

// DEKStatus retrieves DEK status via gRPC.
func (g *GRPCAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	resp, err := g.dek.GetDEKStatus(ctx, &pb.GetDEKStatusRequest{Path: path})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetDEKStatus", Err: err}
	}
	return dekStatusResult(resp)
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// SecretsStore stores a secret via gRPC.
func (g *GRPCAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
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

	return &SecretsStoreResult{
		SecretID:  resp.SecretId,
		Version:   resp.Version,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// SecretsGet retrieves a secret via gRPC.
func (g *GRPCAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	req := &pb.GetSecretRequest{
		SecretId: name,
	}

	resp, err := g.secrets.GetSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSecret", Err: err}
	}

	return &SecretsGetResult{
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

// SecretsList lists secrets via gRPC.
func (g *GRPCAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
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
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      grpcUnixToTime(s.CreatedAt),
			UpdatedAt:      grpcUnixToTime(s.UpdatedAt),
		})
	}

	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// SecretsDelete deletes a secret via gRPC.
func (g *GRPCAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	req := &pb.DeleteSecretRequest{
		SecretId:          name,
		PermanentlyDelete: permanent,
	}

	resp, err := g.secrets.DeleteSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteSecret", Err: err}
	}

	return &SecretsDeleteResult{
		SecretID:  resp.SecretId,
		Deleted:   resp.Deleted,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// SecretsRotate rotates a secret to a new value via gRPC.
func (g *GRPCAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	req := &pb.RotateSecretRequest{
		SecretId:  opts.Name,
		NewData:   opts.NewData,
		TenantId:  opts.TenantID,
		KeyId:     opts.KeyID,
		Algorithm: opts.Algorithm,
	}

	resp, err := g.secrets.RotateSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RotateSecret", Err: err}
	}

	return &SecretsRotateResult{
		SecretID:   resp.SecretId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// SecretsVersions lists secret versions via gRPC.
func (g *GRPCAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{
		SecretId: name,
		Limit:    opts.Limit,
		Cursor:   opts.Cursor,
	}

	resp, err := g.secrets.ListSecretVersions(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListSecretVersions", Err: err}
	}

	versions := make([]SecretVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, SecretVersionInfo{
			Version:   v.Version,
			CreatedAt: grpcUnixToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: grpcUnixToTime(v.ExpiresAt),
		})
	}

	return &SecretsVersionsResult{
		SecretID:   name,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// SecretsVersion retrieves a specific secret version via gRPC.
func (g *GRPCAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	req := &pb.GetSecretVersionRequest{
		SecretId: name,
		Version:  version,
	}

	resp, err := g.secrets.GetSecretVersion(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSecretVersion", Err: err}
	}

	return &SecretsVersionResult{
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

// SecretsRollback rolls back to a previous secret version via gRPC.
func (g *GRPCAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	req := &pb.RollbackSecretRequest{
		SecretId:      name,
		TargetVersion: targetVersion,
	}

	resp, err := g.secrets.RollbackSecret(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RollbackSecret", Err: err}
	}

	return &SecretsRollbackResult{
		SecretID:   resp.SecretId,
		NewVersion: resp.NewVersion,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// SecretsStatus updates the status of a secret via gRPC.
func (g *GRPCAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
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

	statusStr := "DISABLED"
	if resp.Status == pb.SecretStatus_SECRET_STATUS_ENABLED {
		statusStr = "ENABLED"
	}

	return &SecretsStatusResult{
		SecretID:  resp.SecretId,
		Status:    statusStr,
		Timestamp: grpcUnixToTime(resp.Timestamp),
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
	return "gRPC connection failed to " + e.Endpoint + ": " + e.Err.Error()
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
	return "gRPC call " + e.Method + " failed: " + e.Err.Error()
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}
