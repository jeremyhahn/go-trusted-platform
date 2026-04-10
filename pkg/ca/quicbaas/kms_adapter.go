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

// Package caquicbaas provides adapters for integrating go-quicbaas SDK KMS services
// with go-trusted-ca's KMSClient interface.
package caquicbaas

import (
	"context"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
)

// QuicBaaSKMSAdapter adapts go-quicbaas SDK's KMS client to go-trusted-ca's
// KMSClient interface for CA key management.
//
// This adapter enables go-trusted-ca to use QuicBaaS as its underlying
// key management backend, providing distributed, consensus-based key
// storage with the signing operations required for CA operations.
//
// Thread-safety: All operations are thread-safe as they delegate to
// the underlying go-quicbaas SDK client which handles concurrency.
type QuicBaaSKMSAdapter struct {
	kms quicbaassdk.KMSClient
}

// NewKMSAdapter creates a new QuicBaaSKMSAdapter that wraps a go-quicbaas
// SDK KMS client and exposes it as a go-trusted-ca KMSClient.
//
// Parameters:
//   - kmsClient: The underlying go-quicbaas SDK KMS client to adapt
//
// Returns:
//   - *QuicBaaSKMSAdapter: The adapter instance
func NewKMSAdapter(kmsClient quicbaassdk.KMSClient) *QuicBaaSKMSAdapter {
	return &QuicBaaSKMSAdapter{
		kms: kmsClient,
	}
}

// mapAlgorithmToSDK converts a go-trusted-ca algorithm to the SDK's KeyAlgorithm.
func mapAlgorithmToSDK(algorithm trustedca.CAKMSKeyAlgorithm) kms.KeyAlgorithm {
	switch strings.ToUpper(string(algorithm)) {
	case "RSA-2048":
		return kms.AlgorithmRSA2048
	case "RSA-4096":
		return kms.AlgorithmRSA4096
	case "ECDSA-P256", "EC-P256":
		return kms.AlgorithmECDSAP256
	case "ECDSA-P384", "EC-P384":
		return kms.AlgorithmECDSAP384
	case "ED25519":
		return kms.AlgorithmED25519
	default:
		// Default to ECDSA-P256 for unknown algorithms
		return kms.AlgorithmECDSAP256
	}
}

// mapAlgorithmFromSDK converts SDK's KeyAlgorithm to go-trusted-ca's algorithm.
func mapAlgorithmFromSDK(algorithm kms.KeyAlgorithm) trustedca.CAKMSKeyAlgorithm {
	switch algorithm {
	case kms.AlgorithmRSA2048:
		return trustedca.CAKMSAlgorithmRSA2048
	case kms.AlgorithmRSA4096:
		return trustedca.CAKMSAlgorithmRSA4096
	case kms.AlgorithmECDSAP256:
		return trustedca.CAKMSAlgorithmECDSAP256
	case kms.AlgorithmECDSAP384:
		return trustedca.CAKMSAlgorithmECDSAP384
	case kms.AlgorithmED25519:
		return trustedca.CAKMSAlgorithmED25519
	default:
		return trustedca.CAKMSKeyAlgorithm(algorithm.String())
	}
}

// mapUsageToSDK converts go-trusted-ca key usage to SDK key usage.
func mapUsageToSDK(usages []trustedca.CAKMSKeyUsage) []kms.KeyUsage {
	result := make([]kms.KeyUsage, 0, len(usages))
	for _, u := range usages {
		switch u {
		case trustedca.CAKMSKeyUsageSign:
			result = append(result, kms.KeyUsageSign)
		case trustedca.CAKMSKeyUsageVerify:
			result = append(result, kms.KeyUsageVerify)
		case trustedca.CAKMSKeyUsageEncrypt:
			result = append(result, kms.KeyUsageEncrypt)
		case trustedca.CAKMSKeyUsageDecrypt:
			result = append(result, kms.KeyUsageDecrypt)
		}
	}
	return result
}

// mapUsageFromSDK converts SDK key usage to go-trusted-ca key usage.
func mapUsageFromSDK(usages []kms.KeyUsage) []trustedca.CAKMSKeyUsage {
	result := make([]trustedca.CAKMSKeyUsage, 0, len(usages))
	for _, u := range usages {
		switch u {
		case kms.KeyUsageSign:
			result = append(result, trustedca.CAKMSKeyUsageSign)
		case kms.KeyUsageVerify:
			result = append(result, trustedca.CAKMSKeyUsageVerify)
		case kms.KeyUsageEncrypt:
			result = append(result, trustedca.CAKMSKeyUsageEncrypt)
		case kms.KeyUsageDecrypt:
			result = append(result, trustedca.CAKMSKeyUsageDecrypt)
		}
	}
	return result
}

// GenerateKey generates a new signing key with the specified parameters.
//
// Parameters:
//   - ctx: Request context for cancellation and deadlines
//   - req: Key generation request containing name, algorithm, and usage
//
// Returns:
//   - *trustedca.CAKMSGenerateKeyResponse: Response containing key ID and version
//   - error: ErrInvalidInput if parameters are invalid, ErrQuicBaaSUnavailable if SDK unavailable
func (a *QuicBaaSKMSAdapter) GenerateKey(
	ctx context.Context,
	req *trustedca.CAKMSGenerateKeyRequest,
) (*trustedca.CAKMSGenerateKeyResponse, error) {

	if req == nil {
		return nil, ErrInvalidInput{Field: "request", Reason: "request is required"}
	}
	if req.Name == "" {
		return nil, ErrInvalidInput{Field: "name", Reason: "key name is required"}
	}
	if a.kms == nil {
		return nil, ErrQuicBaaSUnavailable{}
	}

	sdkReq := &kms.GenerateKeyRequest{
		Name:      req.Name,
		Algorithm: mapAlgorithmToSDK(req.Algorithm),
		Usage:     mapUsageToSDK(req.Usage),
	}

	resp, err := a.kms.GenerateKey(ctx, sdkReq)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "GenerateKey", Cause: err}
	}

	return &trustedca.CAKMSGenerateKeyResponse{
		KeyID:   resp.KeyID,
		Version: resp.Version,
	}, nil
}

// GetKey retrieves key information for the specified key ID.
//
// Parameters:
//   - ctx: Request context for cancellation and deadlines
//   - keyID: The unique identifier of the key to retrieve
//
// Returns:
//   - *trustedca.CAKMSKeyInfo: Key information including algorithm and usage
//   - error: ErrKeyNotFound if key doesn't exist, ErrQuicBaaSUnavailable if SDK unavailable
func (a *QuicBaaSKMSAdapter) GetKey(
	ctx context.Context,
	keyID string,
) (*trustedca.CAKMSKeyInfo, error) {

	if keyID == "" {
		return nil, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}
	if a.kms == nil {
		return nil, ErrQuicBaaSUnavailable{}
	}

	resp, err := a.kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: keyID, Cause: err}
	}

	return &trustedca.CAKMSKeyInfo{
		KeyID:     resp.KeyID,
		Name:      resp.Name,
		Algorithm: mapAlgorithmFromSDK(resp.Algorithm),
		Version:   resp.Version,
		Usage:     mapUsageFromSDK(resp.Usage),
	}, nil
}

// ListKeys returns all keys in the KMS.
//
// Parameters:
//   - ctx: Request context for cancellation and deadlines
//
// Returns:
//   - *trustedca.CAKMSListKeysResponse: List of key information
//   - error: ErrQuicBaaSUnavailable if SDK unavailable, ErrOperationFailed on other failures
func (a *QuicBaaSKMSAdapter) ListKeys(
	ctx context.Context,
) (*trustedca.CAKMSListKeysResponse, error) {

	if a.kms == nil {
		return nil, ErrQuicBaaSUnavailable{}
	}

	resp, err := a.kms.ListKeys(ctx)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "ListKeys", Cause: err}
	}

	keys := make([]*trustedca.CAKMSKeyInfo, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, &trustedca.CAKMSKeyInfo{
			KeyID:     k.KeyID,
			Name:      k.Name,
			Algorithm: mapAlgorithmFromSDK(k.Algorithm),
			Version:   k.Version,
			Usage:     mapUsageFromSDK(k.Usage),
		})
	}

	return &trustedca.CAKMSListKeysResponse{
		Keys: keys,
	}, nil
}

// RotateKey rotates a key to a new version.
//
// Parameters:
//   - ctx: Request context for cancellation and deadlines
//   - keyID: The unique identifier of the key to rotate
//
// Returns:
//   - *trustedca.CAKMSRotateKeyResponse: Response with new version
//   - error: ErrKeyNotFound if key doesn't exist, ErrQuicBaaSUnavailable if SDK unavailable
func (a *QuicBaaSKMSAdapter) RotateKey(
	ctx context.Context,
	keyID string,
) (*trustedca.CAKMSRotateKeyResponse, error) {

	if keyID == "" {
		return nil, ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}
	if a.kms == nil {
		return nil, ErrQuicBaaSUnavailable{}
	}

	resp, err := a.kms.RotateKey(ctx, keyID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "RotateKey", Cause: err}
	}

	return &trustedca.CAKMSRotateKeyResponse{
		KeyID:      resp.KeyID,
		NewVersion: resp.NewVersion,
	}, nil
}

// DeleteKey permanently deletes a key.
// This is a destructive operation that cannot be undone.
//
// Parameters:
//   - ctx: Request context for cancellation and deadlines
//   - keyID: The unique identifier of the key to delete
//
// Returns:
//   - error: ErrKeyNotFound if key doesn't exist, ErrQuicBaaSUnavailable if SDK unavailable
func (a *QuicBaaSKMSAdapter) DeleteKey(
	ctx context.Context,
	keyID string,
) error {

	if keyID == "" {
		return ErrInvalidInput{Field: "keyID", Reason: "key ID is required"}
	}
	if a.kms == nil {
		return ErrQuicBaaSUnavailable{}
	}

	err := a.kms.DeleteKey(ctx, keyID)
	if err != nil {
		return ErrOperationFailed{Operation: "DeleteKey", Cause: err}
	}

	return nil
}

// Verify interface compliance at compile time.
var _ trustedca.CAKMSClient = (*QuicBaaSKMSAdapter)(nil)
