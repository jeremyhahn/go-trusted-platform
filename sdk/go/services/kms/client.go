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

// Package kms provides a client for Key Management Service operations.
package kms

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to KMS service operations.
type Client struct {
	grpc platformv1.KeyManagementServiceClient
}

// NewClient creates a new KMS service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewKeyManagementServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new KMS service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.KeyManagementServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Key Management Operations

// GenerateKey creates a new cryptographic key.
func (c *Client) GenerateKey(ctx context.Context, req *platformv1.GenerateKeyRequest) (*platformv1.GenerateKeyResponse, error) {
	resp, err := c.grpc.GenerateKey(ctx, req)
	if err != nil {
		return nil, &ErrGenerateKeyFailed{Cause: err}
	}
	return resp, nil
}

// ImportKey imports an existing key into the KMS.
func (c *Client) ImportKey(ctx context.Context, req *platformv1.ImportKeyRequest) (*platformv1.ImportKeyResponse, error) {
	resp, err := c.grpc.ImportKey(ctx, req)
	if err != nil {
		return nil, &ErrImportKeyFailed{Cause: err}
	}
	return resp, nil
}

// GetKey retrieves key information by ID.
func (c *Client) GetKey(ctx context.Context, keyID string, version uint64) (*platformv1.GetKeyResponse, error) {
	resp, err := c.grpc.GetKey(ctx, &platformv1.GetKeyRequest{
		KeyId:   keyID,
		Version: version,
	})
	if err != nil {
		return nil, &ErrGetKeyFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// ListKeys returns a paginated list of keys.
func (c *Client) ListKeys(ctx context.Context, limit int32, cursor string, filter map[string]string) (*platformv1.ListKeysResponse, error) {
	resp, err := c.grpc.ListKeys(ctx, &platformv1.ListKeysRequest{
		Limit:  limit,
		Cursor: cursor,
		Filter: filter,
	})
	if err != nil {
		return nil, &ErrListKeysFailed{Cause: err}
	}
	return resp, nil
}

// DeleteKey schedules a key for deletion.
func (c *Client) DeleteKey(ctx context.Context, keyID string, pendingWindowDays int32, force bool) (*platformv1.DeleteKeyResponse, error) {
	resp, err := c.grpc.DeleteKey(ctx, &platformv1.DeleteKeyRequest{
		KeyId:             keyID,
		PendingWindowDays: pendingWindowDays,
		Force:             force,
	})
	if err != nil {
		return nil, &ErrDeleteKeyFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// RotateKey creates a new version of an existing key.
func (c *Client) RotateKey(ctx context.Context, keyID string, retainOldVersion bool) (*platformv1.RotateKeyResponse, error) {
	resp, err := c.grpc.RotateKey(ctx, &platformv1.RotateKeyRequest{
		KeyId:            keyID,
		RetainOldVersion: retainOldVersion,
	})
	if err != nil {
		return nil, &ErrRotateKeyFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// UpdateKeyStatus changes the status of a key.
func (c *Client) UpdateKeyStatus(ctx context.Context, keyID string, version uint64, status platformv1.KeyStatus) (*platformv1.UpdateKeyStatusResponse, error) {
	resp, err := c.grpc.UpdateKeyStatus(ctx, &platformv1.UpdateKeyStatusRequest{
		KeyId:   keyID,
		Version: version,
		Status:  status,
	})
	if err != nil {
		return nil, &ErrUpdateKeyStatusFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// ExportKey exports a key (if allowed by key policy).
func (c *Client) ExportKey(ctx context.Context, req *platformv1.ExportKeyRequest) (*platformv1.ExportKeyResponse, error) {
	resp, err := c.grpc.ExportKey(ctx, req)
	if err != nil {
		return nil, &ErrExportKeyFailed{KeyID: req.KeyId, Cause: err}
	}
	return resp, nil
}

// GetKeyVersions lists all versions of a key.
func (c *Client) GetKeyVersions(ctx context.Context, keyID string, limit int32, cursor string) (*platformv1.GetKeyVersionsResponse, error) {
	resp, err := c.grpc.GetKeyVersions(ctx, &platformv1.GetKeyVersionsRequest{
		KeyId:  keyID,
		Limit:  limit,
		Cursor: cursor,
	})
	if err != nil {
		return nil, &ErrGetKeyVersionsFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Cryptographic Operations

// Encrypt encrypts data using a specified key.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext, context, nonce []byte) (*platformv1.EncryptResponse, error) {
	resp, err := c.grpc.Encrypt(ctx, &platformv1.EncryptRequest{
		KeyId:     keyID,
		Plaintext: plaintext,
		Context:   context,
		Nonce:     nonce,
	})
	if err != nil {
		return nil, &ErrEncryptFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Decrypt decrypts data using a specified key.
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext, context, nonce []byte, keyVersion uint64) (*platformv1.DecryptResponse, error) {
	resp, err := c.grpc.Decrypt(ctx, &platformv1.DecryptRequest{
		KeyId:      keyID,
		Ciphertext: ciphertext,
		Context:    context,
		Nonce:      nonce,
		KeyVersion: keyVersion,
	})
	if err != nil {
		return nil, &ErrDecryptFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Sign creates a digital signature.
func (c *Client) Sign(ctx context.Context, keyID string, message []byte, hashAlgorithm platformv1.HashAlgorithm) (*platformv1.SignResponse, error) {
	resp, err := c.grpc.Sign(ctx, &platformv1.SignRequest{
		KeyId:         keyID,
		Message:       message,
		HashAlgorithm: hashAlgorithm,
	})
	if err != nil {
		return nil, &ErrSignFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Verify verifies a digital signature.
func (c *Client) Verify(ctx context.Context, keyID string, message, signature []byte, hashAlgorithm platformv1.HashAlgorithm, keyVersion uint64) (*platformv1.VerifyResponse, error) {
	resp, err := c.grpc.Verify(ctx, &platformv1.VerifyRequest{
		KeyId:         keyID,
		Message:       message,
		Signature:     signature,
		HashAlgorithm: hashAlgorithm,
		KeyVersion:    keyVersion,
	})
	if err != nil {
		return nil, &ErrVerifyFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Hash computes a cryptographic hash.
func (c *Client) Hash(ctx context.Context, data []byte, algorithm platformv1.HashAlgorithm) ([]byte, error) {
	resp, err := c.grpc.Hash(ctx, &platformv1.HashRequest{
		Data:      data,
		Algorithm: algorithm,
	})
	if err != nil {
		return nil, &ErrHashFailed{Cause: err}
	}
	return resp.Hash, nil
}

// HMAC computes an HMAC.
func (c *Client) HMAC(ctx context.Context, keyID string, message []byte, hashAlgorithm platformv1.HashAlgorithm) (*platformv1.HMACResponse, error) {
	resp, err := c.grpc.HMAC(ctx, &platformv1.HMACRequest{
		KeyId:         keyID,
		Message:       message,
		HashAlgorithm: hashAlgorithm,
	})
	if err != nil {
		return nil, &ErrHMACFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// VerifyHMAC verifies an HMAC.
func (c *Client) VerifyHMAC(ctx context.Context, keyID string, message, hmac []byte, hashAlgorithm platformv1.HashAlgorithm, keyVersion uint64) (*platformv1.VerifyHMACResponse, error) {
	resp, err := c.grpc.VerifyHMAC(ctx, &platformv1.VerifyHMACRequest{
		KeyId:         keyID,
		Message:       message,
		Hmac:          hmac,
		HashAlgorithm: hashAlgorithm,
		KeyVersion:    keyVersion,
	})
	if err != nil {
		return nil, &ErrVerifyHMACFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// Utility Operations

// GenerateRandom generates cryptographically secure random bytes.
func (c *Client) GenerateRandom(ctx context.Context, numBytes int32) ([]byte, error) {
	resp, err := c.grpc.GenerateRandom(ctx, &platformv1.GenerateRandomRequest{NumBytes: numBytes})
	if err != nil {
		return nil, &ErrGenerateRandomFailed{Cause: err}
	}
	return resp.RandomBytes, nil
}

// GenerateDataKey generates a data encryption key and returns it encrypted.
func (c *Client) GenerateDataKey(ctx context.Context, keyID string, algorithm platformv1.KMSKeyAlgorithm, keySize int32, context []byte) (*platformv1.GenerateDataKeyResponse, error) {
	resp, err := c.grpc.GenerateDataKey(ctx, &platformv1.GenerateDataKeyRequest{
		KeyId:     keyID,
		Algorithm: algorithm,
		KeySize:   keySize,
		Context:   context,
	})
	if err != nil {
		return nil, &ErrGenerateDataKeyFailed{Cause: err}
	}
	return resp, nil
}

// GenerateWrappedDataKey generates a data encryption key wrapped by another key.
func (c *Client) GenerateWrappedDataKey(ctx context.Context, req *platformv1.GenerateWrappedDataKeyRequest) (*platformv1.GenerateWrappedDataKeyResponse, error) {
	resp, err := c.grpc.GenerateWrappedDataKey(ctx, req)
	if err != nil {
		return nil, &ErrGenerateWrappedDataKeyFailed{Cause: err}
	}
	return resp, nil
}

// BackendStatus returns the status of the KMS backend.
func (c *Client) BackendStatus(ctx context.Context) (*platformv1.BackendStatusResponse, error) {
	resp, err := c.grpc.BackendStatus(ctx, &platformv1.BackendStatusRequest{})
	if err != nil {
		return nil, &ErrBackendStatusFailed{Cause: err}
	}
	return resp, nil
}
