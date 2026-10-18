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

package daemon

import (
	"context"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// The MCP tools in this file call the PlatformKMSBackend that gRPC
// KeyManagementService, the QUIC KMS handlers and the daemon REST facade
// call, so a request answers the same on every transport.

// kmsBackendOrErr returns the shared KMS backend or a typed unavailable error.
func (p *MCPServiceProvider) kmsBackendOrErr() (*PlatformKMSBackend, error) {
	if p.kmsBackend == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	return p.kmsBackend, nil
}

// KMSHash hashes data without key material.
func (p *MCPServiceProvider) KMSHash(ctx context.Context, req *mcp.KMSHashRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.Hash(ctx, &grpcapi.KMSHashRequest{
		Data:      req.Data,
		Algorithm: req.HashAlgorithm,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"algorithm": resp.Algorithm,
		"hash":      resp.Hash,
		"timestamp": resp.Timestamp,
	}, nil
}

// KMSHMAC computes an HMAC over a message with a KMS key.
func (p *MCPServiceProvider) KMSHMAC(ctx context.Context, req *mcp.KMSHMACRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.HMAC(ctx, &grpcapi.KMSHMACRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		HashAlgorithm: req.HashAlgorithm,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"key_id":         resp.KeyID,
		"key_version":    resp.KeyVersion,
		"hmac":           resp.HMAC,
		"hash_algorithm": resp.HashAlgorithm,
		"timestamp":      resp.Timestamp,
	}, nil
}

// KMSVerifyHMAC verifies an HMAC over a message with a KMS key.
func (p *MCPServiceProvider) KMSVerifyHMAC(ctx context.Context, req *mcp.KMSVerifyHMACRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.VerifyHMAC(ctx, &grpcapi.KMSVerifyHMACRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		HMAC:          req.HMAC,
		HashAlgorithm: req.HashAlgorithm,
		KeyVersion:    req.KeyVersion,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"key_id":      resp.KeyID,
		"key_version": resp.KeyVersion,
		"valid":       resp.Valid,
		"timestamp":   resp.Timestamp,
	}, nil
}

// KMSRewrap re-encrypts a ciphertext under the key's current version. The
// backend refuses a non-zero source version (ErrKMSRewrapSourceVersionUnsupported).
func (p *MCPServiceProvider) KMSRewrap(ctx context.Context, req *mcp.KMSRewrapRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.Rewrap(ctx, &grpcapi.KMSRewrapRequest{
		KeyID:         req.KeyID,
		Ciphertext:    req.Ciphertext,
		Context:       req.Context,
		Nonce:         req.Nonce,
		SourceVersion: req.SourceVersion,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"key_id":         resp.KeyID,
		"source_version": resp.SourceVersion,
		"target_version": resp.TargetVersion,
		"ciphertext":     resp.Ciphertext,
		"nonce":          resp.Nonce,
		"timestamp":      resp.Timestamp,
	}, nil
}

// KMSImportKey imports key material through the shared KMS backend.
func (p *MCPServiceProvider) KMSImportKey(ctx context.Context, req *mcp.KMSImportKeyRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.ImportKey(ctx, &grpcapi.KMSImportKeyRequest{
		KeyMaterial:   req.KeyMaterial,
		WrappingKeyID: req.WrappingKeyID,
		KeySpec: &grpcapi.KMSKeySpec{
			Algorithm:          req.Algorithm,
			KeySize:            req.KeySize,
			Usage:              req.Usage,
			Exportable:         req.Exportable,
			DeletionProtection: req.DeletionProtection,
		},
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
	})
	if err != nil {
		return nil, err
	}
	// The answer has the platform.v1 ImportKeyResponse layout, so the SDK
	// MCP adapter decodes it straight into the gRPC reply.
	result := map[string]interface{}{
		"timestamp": resp.Timestamp,
	}
	if resp.Key != nil {
		result["key"] = map[string]interface{}{
			"key_id":     resp.Key.KeyID,
			"version":    resp.Key.Version,
			"algorithm":  resp.Key.Algorithm,
			"status":     resp.Key.Status,
			"created_at": resp.Key.CreatedAt,
		}
	}
	if resp.Metadata != nil {
		result["metadata"] = kmsKeyMetadataMap(resp.Metadata)
	}
	return result, nil
}

// KMSUpdateKeyStatus changes a key or key-version status through the shared
// KMS backend.
func (p *MCPServiceProvider) KMSUpdateKeyStatus(ctx context.Context, req *mcp.KMSUpdateKeyStatusRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.UpdateKeyStatus(ctx, &grpcapi.KMSUpdateKeyStatusRequest{
		KeyID:   req.KeyID,
		Version: req.Version,
		Status:  req.Status,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"key_id":     resp.KeyID,
		"version":    resp.Version,
		"key_status": resp.Status,
		"timestamp":  resp.Timestamp,
	}, nil
}

// KMSListKeyVersions lists a key's versions through the shared KMS backend.
func (p *MCPServiceProvider) KMSListKeyVersions(ctx context.Context, req *mcp.KMSListKeyVersionsRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	resp, err := backend.GetKeyVersions(ctx, &grpcapi.KMSGetKeyVersionsRequest{
		KeyID:  req.KeyID,
		Limit:  req.Limit,
		Cursor: req.Cursor,
	})
	if err != nil {
		return nil, err
	}
	versions := make([]map[string]interface{}, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, map[string]interface{}{
			"version":     v.Version,
			"status":      v.Status,
			"algorithm":   v.Algorithm,
			"created_at":  v.CreatedAt,
			"disabled_at": v.DisabledAt,
		})
	}
	return map[string]interface{}{
		"key_id":      resp.KeyID,
		"versions":    versions,
		"next_cursor": resp.NextCursor,
		"has_more":    resp.HasMore,
		"timestamp":   resp.Timestamp,
	}, nil
}

// KMSBatchEncrypt encrypts a batch of plaintexts through the shared KMS
// backend.
func (p *MCPServiceProvider) KMSBatchEncrypt(ctx context.Context, req *mcp.KMSBatchEncryptRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	items := make([]*grpcapi.KMSBatchEncryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = &grpcapi.KMSBatchEncryptItem{
			ItemID:    item.ItemID,
			Plaintext: item.Plaintext,
			Context:   item.Context,
			Nonce:     item.Nonce,
		}
	}
	resp, err := backend.BatchEncrypt(ctx, &grpcapi.KMSBatchEncryptRequest{KeyID: req.KeyID, Items: items})
	if err != nil {
		return nil, err
	}
	results := make([]map[string]interface{}, 0, len(resp.Results))
	for _, r := range resp.Results {
		results = append(results, map[string]interface{}{
			"item_id":     r.ItemID,
			"status":      batchItemStatus(r.Success, r.Message),
			"ciphertext":  r.Ciphertext,
			"nonce":       r.Nonce,
			"key_version": r.KeyVersion,
		})
	}
	return batchResultMap(resp.KeyID, results, resp.SuccessCount, resp.FailureCount, resp.Timestamp), nil
}

// KMSBatchDecrypt decrypts a batch of ciphertexts through the shared KMS
// backend.
func (p *MCPServiceProvider) KMSBatchDecrypt(ctx context.Context, req *mcp.KMSBatchDecryptRequest) (interface{}, error) {
	backend, err := p.kmsBackendOrErr()
	if err != nil {
		return nil, err
	}
	items := make([]*grpcapi.KMSBatchDecryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = &grpcapi.KMSBatchDecryptItem{
			ItemID:     item.ItemID,
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Nonce:      item.Nonce,
			KeyVersion: item.KeyVersion,
		}
	}
	resp, err := backend.BatchDecrypt(ctx, &grpcapi.KMSBatchDecryptRequest{KeyID: req.KeyID, Items: items})
	if err != nil {
		return nil, err
	}
	results := make([]map[string]interface{}, 0, len(resp.Results))
	for _, r := range resp.Results {
		results = append(results, map[string]interface{}{
			"item_id":     r.ItemID,
			"status":      batchItemStatus(r.Success, r.Message),
			"plaintext":   r.Plaintext,
			"key_version": r.KeyVersion,
		})
	}
	return batchResultMap(resp.KeyID, results, resp.SuccessCount, resp.FailureCount, resp.Timestamp), nil
}

// batchItemStatus is one batch item's outcome in the platform.v1 Status
// layout the gRPC result items carry.
func batchItemStatus(success bool, message string) map[string]interface{} {
	return map[string]interface{}{
		"success": success,
		"message": message,
	}
}

// batchResultMap is the answer both batch tools share, in the platform.v1
// BatchEncryptResponse / BatchDecryptResponse layout.
func batchResultMap(keyID string, results []map[string]interface{}, successCount, failureCount int32, timestamp int64) map[string]interface{} {
	return map[string]interface{}{
		"key_id":        keyID,
		"results":       results,
		"success_count": successCount,
		"failure_count": failureCount,
		"timestamp":     timestamp,
	}
}

// kmsKeyMetadataMap renders key metadata with the platform.v1 JSON names.
func kmsKeyMetadataMap(m *grpcapi.KMSKeyMetadata) map[string]interface{} {
	return map[string]interface{}{
		"key_id":              m.KeyID,
		"name":                m.Name,
		"description":         m.Description,
		"algorithm":           m.Algorithm,
		"status":              m.Status,
		"usage":               m.Usage,
		"version":             m.Version,
		"exportable":          m.Exportable,
		"deletion_protection": m.DeletionProtection,
		"created_at":          m.CreatedAt,
		"updated_at":          m.UpdatedAt,
		"last_used_at":        m.LastUsedAt,
		"tags":                m.Tags,
		"owner":               m.Owner,
	}
}
