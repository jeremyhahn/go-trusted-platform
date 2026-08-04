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

package main

import (
	"encoding/base64"
	"log/slog"
	"strings"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// KMSBinding exposes Key Management Service methods to the Wails frontend.
type KMSBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewKMSBinding creates a new KMSBinding.
func NewKMSBinding(logger *slog.Logger, conn *ConnectionBinding) *KMSBinding {
	return &KMSBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *KMSBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GenerateKey creates a new cryptographic key with the specified parameters.
func (b *KMSBinding) GenerateKey(algorithm, name, description string, keySize int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	kmsAlgo, err := parseKMSKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().GenerateKey(b.conn.ctx, &platformv1.GenerateKeyRequest{
		Name:        name,
		Description: description,
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm: kmsAlgo,
			KeySize:   keySize,
		},
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetKey retrieves key information by ID.
func (b *KMSBinding) GetKey(keyID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().GetKey(b.conn.ctx, &platformv1.GetKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListKeys returns a list of all keys.
func (b *KMSBinding) ListKeys() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().ListKeys(b.conn.ctx, &platformv1.ListKeysRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteKey schedules a key for deletion by ID.
func (b *KMSBinding) DeleteKey(keyID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().DeleteKey(b.conn.ctx, &platformv1.DeleteKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// RotateKey creates a new version of an existing key.
func (b *KMSBinding) RotateKey(keyID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().RotateKey(b.conn.ctx, &platformv1.RotateKeyRequest{
		KeyId:            keyID,
		RetainOldVersion: true,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Encrypt encrypts data using the specified key. Plaintext is base64-encoded.
func (b *KMSBinding) Encrypt(keyID, plaintextB64 string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "plaintext", Reason: "invalid base64 encoding"}
	}

	resp, err := cl.KMS().Encrypt(b.conn.ctx, &platformv1.EncryptRequest{
		KeyId:     keyID,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Decrypt decrypts data using the specified key. Ciphertext is base64-encoded.
func (b *KMSBinding) Decrypt(keyID, ciphertextB64 string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "ciphertext", Reason: "invalid base64 encoding"}
	}

	resp, err := cl.KMS().Decrypt(b.conn.ctx, &platformv1.DecryptRequest{
		KeyId:      keyID,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Sign creates a digital signature for the given base64-encoded data.
func (b *KMSBinding) Sign(keyID, dataB64, hashAlgorithm string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "data", Reason: "invalid base64 encoding"}
	}

	hashAlgo, err := parseHashAlgorithm(hashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().Sign(b.conn.ctx, &platformv1.SignRequest{
		KeyId:         keyID,
		Message:       data,
		HashAlgorithm: hashAlgo,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Verify verifies a digital signature. Data and signature are base64-encoded.
func (b *KMSBinding) Verify(keyID, dataB64, signatureB64, hashAlgorithm string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "data", Reason: "invalid base64 encoding"}
	}

	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "signature", Reason: "invalid base64 encoding"}
	}

	hashAlgo, err := parseHashAlgorithm(hashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().Verify(b.conn.ctx, &platformv1.VerifyRequest{
		KeyId:         keyID,
		Message:       data,
		Signature:     sig,
		HashAlgorithm: hashAlgo,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GenerateRandom generates cryptographically secure random bytes.
func (b *KMSBinding) GenerateRandom(numBytes int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().GenerateRandom(b.conn.ctx, &platformv1.GenerateRandomRequest{
		NumBytes: numBytes,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// BackendStatus returns the status of the KMS backend.
func (b *KMSBinding) BackendStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.KMS().BackendStatus(b.conn.ctx, &platformv1.BackendStatusRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// parseKMSKeyAlgorithm converts a key algorithm string to the protobuf enum.
// It accepts both short names (e.g., "rsa_2048") and full enum names
// (e.g., "KMS_KEY_ALGORITHM_RSA_2048").
func parseKMSKeyAlgorithm(input string) (platformv1.KMSKeyAlgorithm, error) {
	upper := strings.ToUpper(input)

	if val, ok := platformv1.KMSKeyAlgorithm_value[upper]; ok {
		return platformv1.KMSKeyAlgorithm(val), nil
	}

	prefixed := "KMS_KEY_ALGORITHM_" + upper
	if val, ok := platformv1.KMSKeyAlgorithm_value[prefixed]; ok {
		return platformv1.KMSKeyAlgorithm(val), nil
	}

	return platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
		&InvalidInputError{Field: "algorithm", Reason: "unknown KMS key algorithm: " + input}
}

// parseHashAlgorithm converts a hash algorithm string to the protobuf enum.
// It accepts both short names (e.g., "sha256") and full enum names
// (e.g., "HASH_ALGORITHM_SHA256").
func parseHashAlgorithm(input string) (platformv1.HashAlgorithm, error) {
	upper := strings.ToUpper(input)

	if val, ok := platformv1.HashAlgorithm_value[upper]; ok {
		return platformv1.HashAlgorithm(val), nil
	}

	prefixed := "HASH_ALGORITHM_" + upper
	if val, ok := platformv1.HashAlgorithm_value[prefixed]; ok {
		return platformv1.HashAlgorithm(val), nil
	}

	return platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		&InvalidInputError{Field: "hashAlgorithm", Reason: "unknown hash algorithm: " + input}
}
