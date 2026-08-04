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

package kms

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods accept and return domain types instead of proto types,
// enabling callers to avoid importing platformv1 directly.

// GenerateKeyDomain creates a new cryptographic key using domain types.
func (c *Client) GenerateKeyDomain(ctx context.Context, params *GenerateKeyParams) (*GenerateKeyResult, error) {
	keySpec := &platformv1.KMSKeySpec{
		Algorithm:          keyAlgorithmToProto(params.Algorithm),
		Usage:              keyUsagesToProto(params.Usages),
		Exportable:         params.Exportable,
		DeletionProtection: params.DeletionProtection,
	}
	req := &platformv1.GenerateKeyRequest{
		KeySpec:     keySpec,
		Name:        params.Name,
		Description: params.Description,
		Owner:       params.Owner,
	}
	resp, err := c.GenerateKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return generateKeyResultFromProto(resp), nil
}

// GetKeyDomain retrieves key information by ID using domain types.
func (c *Client) GetKeyDomain(ctx context.Context, keyID string, version uint64) (*GetKeyResult, error) {
	resp, err := c.GetKey(ctx, keyID, version)
	if err != nil {
		return nil, err
	}
	return getKeyResultFromProto(resp), nil
}

// ListKeysDomain returns a paginated list of keys using domain types.
func (c *Client) ListKeysDomain(ctx context.Context, limit int32, cursor string) (*ListKeysResult, error) {
	resp, err := c.ListKeys(ctx, limit, cursor, nil)
	if err != nil {
		return nil, err
	}
	return listKeysResultFromProto(resp), nil
}

// DeleteKeyDomain schedules a key for deletion using domain types.
func (c *Client) DeleteKeyDomain(ctx context.Context, keyID string, pendingWindowDays int32, force bool) (*DeleteKeyResult, error) {
	resp, err := c.DeleteKey(ctx, keyID, pendingWindowDays, force)
	if err != nil {
		return nil, err
	}
	return deleteKeyResultFromProto(resp), nil
}

// RotateKeyDomain creates a new version of an existing key using domain types.
func (c *Client) RotateKeyDomain(ctx context.Context, keyID string, retainOldVersion bool) (*RotateKeyResult, error) {
	resp, err := c.RotateKey(ctx, keyID, retainOldVersion)
	if err != nil {
		return nil, err
	}
	return rotateKeyResultFromProto(resp), nil
}

// EncryptDomain encrypts data using domain types.
func (c *Client) EncryptDomain(ctx context.Context, keyID string, plaintext, aadContext, nonce []byte) (*EncryptResult, error) {
	resp, err := c.Encrypt(ctx, keyID, plaintext, aadContext, nonce)
	if err != nil {
		return nil, err
	}
	return encryptResultFromProto(resp), nil
}

// DecryptDomain decrypts data using domain types.
func (c *Client) DecryptDomain(ctx context.Context, keyID string, ciphertext, aadContext, nonce []byte, keyVersion uint64) (*DecryptResult, error) {
	resp, err := c.Decrypt(ctx, keyID, ciphertext, aadContext, nonce, keyVersion)
	if err != nil {
		return nil, err
	}
	return decryptResultFromProto(resp), nil
}

// SignDomain creates a digital signature using domain types.
func (c *Client) SignDomain(ctx context.Context, keyID string, message []byte, hashAlgorithm HashAlgorithm) (*SignResult, error) {
	resp, err := c.Sign(ctx, keyID, message, hashAlgorithmToProto(hashAlgorithm))
	if err != nil {
		return nil, err
	}
	return signResultFromProto(resp), nil
}

// VerifyDomain verifies a digital signature using domain types.
func (c *Client) VerifyDomain(ctx context.Context, keyID string, message, signature []byte, hashAlgorithm HashAlgorithm, keyVersion uint64) (*VerifyResult, error) {
	resp, err := c.Verify(ctx, keyID, message, signature, hashAlgorithmToProto(hashAlgorithm), keyVersion)
	if err != nil {
		return nil, err
	}
	return verifyResultFromProto(resp), nil
}

// HashDomain computes a cryptographic hash using domain types.
func (c *Client) HashDomain(ctx context.Context, data []byte, algorithm HashAlgorithm) (*HashResult, error) {
	protoAlg := hashAlgorithmToProto(algorithm)
	resp, err := c.grpc.Hash(ctx, &platformv1.HashRequest{
		Data:      data,
		Algorithm: protoAlg,
	})
	if err != nil {
		return nil, &ErrHashFailed{Cause: err}
	}
	return hashResultFromProto(resp), nil
}

// HMACDomain computes an HMAC using domain types.
func (c *Client) HMACDomain(ctx context.Context, keyID string, message []byte, hashAlgorithm HashAlgorithm) (*HMACResult, error) {
	resp, err := c.HMAC(ctx, keyID, message, hashAlgorithmToProto(hashAlgorithm))
	if err != nil {
		return nil, err
	}
	return hmacResultFromProto(resp), nil
}

// VerifyHMACDomain verifies an HMAC using domain types.
func (c *Client) VerifyHMACDomain(ctx context.Context, keyID string, message, hmac []byte, hashAlgorithm HashAlgorithm, keyVersion uint64) (*VerifyHMACResult, error) {
	resp, err := c.VerifyHMAC(ctx, keyID, message, hmac, hashAlgorithmToProto(hashAlgorithm), keyVersion)
	if err != nil {
		return nil, err
	}
	return verifyHMACResultFromProto(resp), nil
}

// GenerateRandomDomain generates cryptographically secure random bytes using domain types.
func (c *Client) GenerateRandomDomain(ctx context.Context, numBytes int32) (*GenerateRandomResult, error) {
	resp, err := c.grpc.GenerateRandom(ctx, &platformv1.GenerateRandomRequest{NumBytes: numBytes})
	if err != nil {
		return nil, &ErrGenerateRandomFailed{Cause: err}
	}
	return generateRandomResultFromProto(resp), nil
}

// GenerateDataKeyDomain generates a data encryption key using domain types.
func (c *Client) GenerateDataKeyDomain(ctx context.Context, keyID string, algorithm KeyAlgorithm, keySize int32, aadContext []byte) (*GenerateDataKeyResult, error) {
	resp, err := c.GenerateDataKey(ctx, keyID, keyAlgorithmToProto(algorithm), keySize, aadContext)
	if err != nil {
		return nil, err
	}
	return generateDataKeyResultFromProto(resp), nil
}

// GenerateWrappedDataKeyDomain generates a wrapped data key using domain types.
func (c *Client) GenerateWrappedDataKeyDomain(ctx context.Context, wrappingKeyID string, algorithm KeyAlgorithm, keySize int32, aadContext []byte) (*GenerateWrappedDataKeyResult, error) {
	req := &platformv1.GenerateWrappedDataKeyRequest{
		WrappingKeyId: wrappingKeyID,
		KeyAlgorithm:  keyAlgorithmToProto(algorithm),
		KeySize:       keySize,
		Context:       aadContext,
	}
	resp, err := c.GenerateWrappedDataKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return generateWrappedDataKeyResultFromProto(resp), nil
}

// RewrapDomain re-encrypts data with the latest key version using domain types.
func (c *Client) RewrapDomain(ctx context.Context, keyID string, ciphertext, aadContext, nonce []byte, sourceVersion uint64) (*RewrapResult, error) {
	req := &platformv1.RewrapRequest{
		KeyId:         keyID,
		Ciphertext:    ciphertext,
		Context:       aadContext,
		Nonce:         nonce,
		SourceVersion: sourceVersion,
	}
	resp, err := c.grpc.Rewrap(ctx, req)
	if err != nil {
		return nil, &ErrRewrapFailed{Cause: err}
	}
	return rewrapResultFromProto(resp), nil
}

// BackendStatusDomain returns the status of the KMS backend using domain types.
func (c *Client) BackendStatusDomain(ctx context.Context) (*BackendStatusResult, error) {
	resp, err := c.BackendStatus(ctx)
	if err != nil {
		return nil, err
	}
	return backendStatusResultFromProto(resp), nil
}

// BatchEncryptDomain encrypts multiple items using domain types.
func (c *Client) BatchEncryptDomain(ctx context.Context, keyID string, items []*BatchEncryptItemInput) (*BatchEncryptResult, error) {
	protoItems := make([]*platformv1.BatchEncryptItem, 0, len(items))
	for _, item := range items {
		protoItems = append(protoItems, &platformv1.BatchEncryptItem{
			ItemId:    item.ItemID,
			Plaintext: item.Plaintext,
			Context:   item.Context,
			Nonce:     item.Nonce,
		})
	}
	req := &platformv1.BatchEncryptRequest{
		KeyId: keyID,
		Items: protoItems,
	}
	resp, err := c.grpc.BatchEncrypt(ctx, req)
	if err != nil {
		return nil, &ErrBatchEncryptFailed{Cause: err}
	}
	return batchEncryptResultFromProto(resp), nil
}

// BatchDecryptDomain decrypts multiple items using domain types.
func (c *Client) BatchDecryptDomain(ctx context.Context, keyID string, items []*BatchDecryptItemInput) (*BatchDecryptResult, error) {
	protoItems := make([]*platformv1.BatchDecryptItem, 0, len(items))
	for _, item := range items {
		protoItems = append(protoItems, &platformv1.BatchDecryptItem{
			ItemId:     item.ItemID,
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Nonce:      item.Nonce,
			KeyVersion: item.KeyVersion,
		})
	}
	req := &platformv1.BatchDecryptRequest{
		KeyId: keyID,
		Items: protoItems,
	}
	resp, err := c.grpc.BatchDecrypt(ctx, req)
	if err != nil {
		return nil, &ErrBatchDecryptFailed{Cause: err}
	}
	return batchDecryptResultFromProto(resp), nil
}
