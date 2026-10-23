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
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// PlatformKMSRESTFacade adapts PlatformKMSBackend to the restapi.KMSService
// interface consumed by the /api/v1/kms/* REST handlers. The REST service
// types are structurally parallel to the platform gRPC KMS types, so the
// facade performs mechanical field mapping and delegates every operation to
// the shared backend — REST, gRPC, and embedded transports therefore hit the
// same QuicBaaS SDK clients and return identical results.
type PlatformKMSRESTFacade struct {
	backend *PlatformKMSBackend
}

// NewPlatformKMSRESTFacade creates a REST facade over the platform KMS
// backend.
func NewPlatformKMSRESTFacade(backend *PlatformKMSBackend) *PlatformKMSRESTFacade {
	return &PlatformKMSRESTFacade{backend: backend}
}

// backendOrErr returns the shared backend or a typed unavailable error.
func (f *PlatformKMSRESTFacade) backendOrErr() (*PlatformKMSBackend, error) {
	if f == nil || f.backend == nil {
		return nil, restapi.ErrKMSServiceUnavailable{Reason: "platform KMS backend not configured"}
	}
	return f.backend, nil
}

// GenerateKey creates a new cryptographic key.
func (f *PlatformKMSRESTFacade) GenerateKey(
	ctx context.Context,
	req *restapi.KMSGenerateKeyServiceRequest,
) (*restapi.KMSGenerateKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GenerateKey"}
	}

	resp, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
		KeySpec:     restKeySpecToGRPC(req.KeySpec),
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Owner:       req.Owner,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSGenerateKeyServiceResponse{
		Key:       grpcKeyHandleToREST(resp.Key),
		Metadata:  grpcKeyMetadataToREST(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// ImportKey imports externally generated key material.
func (f *PlatformKMSRESTFacade) ImportKey(
	ctx context.Context,
	req *restapi.KMSImportKeyServiceRequest,
) (*restapi.KMSImportKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ImportKey"}
	}

	resp, err := backend.ImportKey(ctx, &grpcapi.KMSImportKeyRequest{
		KeyMaterial:   req.KeyMaterial,
		WrappingKeyID: req.WrappingKeyID,
		KeySpec:       restKeySpecToGRPC(req.KeySpec),
		Name:          req.Name,
		Description:   req.Description,
		Tags:          req.Tags,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSImportKeyServiceResponse{
		Key:       grpcKeyHandleToREST(resp.Key),
		Metadata:  grpcKeyMetadataToREST(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// GetKey retrieves key information and metadata.
func (f *PlatformKMSRESTFacade) GetKey(
	ctx context.Context,
	req *restapi.KMSGetKeyServiceRequest,
) (*restapi.KMSGetKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GetKey"}
	}

	resp, err := backend.GetKey(ctx, &grpcapi.KMSGetKeyRequest{
		KeyID:   req.KeyID,
		Version: req.Version,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSGetKeyServiceResponse{
		Key:       grpcKeyHandleToREST(resp.Key),
		Metadata:  grpcKeyMetadataToREST(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// ListKeys lists keys with pagination and optional filtering.
func (f *PlatformKMSRESTFacade) ListKeys(
	ctx context.Context,
	req *restapi.KMSListKeysServiceRequest,
) (*restapi.KMSListKeysServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ListKeys"}
	}

	resp, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{
		Limit:  req.Limit,
		Cursor: req.Cursor,
		Filter: req.Filter,
	})
	if err != nil {
		return nil, err
	}

	keys := make([]*restapi.KMSKeyHandle, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = grpcKeyHandleToREST(k)
	}

	return &restapi.KMSListKeysServiceResponse{
		Keys:       keys,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		TotalCount: resp.TotalCount,
		Timestamp:  resp.Timestamp,
	}, nil
}

// DeleteKey deletes a key.
func (f *PlatformKMSRESTFacade) DeleteKey(
	ctx context.Context,
	req *restapi.KMSDeleteKeyServiceRequest,
) (*restapi.KMSDeleteKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "DeleteKey"}
	}

	resp, err := backend.DeleteKey(ctx, &grpcapi.KMSDeleteKeyRequest{
		KeyID:             req.KeyID,
		PendingWindowDays: req.PendingWindowDays,
		Force:             req.Force,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSDeleteKeyServiceResponse{
		KeyID:        resp.KeyID,
		Status:       resp.Status,
		DeletionDate: resp.DeletionDate,
		Timestamp:    resp.Timestamp,
	}, nil
}

// RotateKey rotates a key to a new version.
func (f *PlatformKMSRESTFacade) RotateKey(
	ctx context.Context,
	req *restapi.KMSRotateKeyServiceRequest,
) (*restapi.KMSRotateKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "RotateKey"}
	}

	resp, err := backend.RotateKey(ctx, &grpcapi.KMSRotateKeyRequest{
		KeyID:            req.KeyID,
		RetainOldVersion: req.RetainOldVersion,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSRotateKeyServiceResponse{
		KeyID:      resp.KeyID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	}, nil
}

// UpdateKeyStatus enables or disables a key or key version.
func (f *PlatformKMSRESTFacade) UpdateKeyStatus(
	ctx context.Context,
	req *restapi.KMSUpdateKeyStatusServiceRequest,
) (*restapi.KMSUpdateKeyStatusServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "UpdateKeyStatus"}
	}

	resp, err := backend.UpdateKeyStatus(ctx, &grpcapi.KMSUpdateKeyStatusRequest{
		KeyID:   req.KeyID,
		Version: req.Version,
		Status:  req.Status,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSUpdateKeyStatusServiceResponse{
		KeyID:     resp.KeyID,
		Version:   resp.Version,
		Status:    resp.Status,
		Timestamp: resp.Timestamp,
	}, nil
}

// ExportKey exports wrapped key material.
func (f *PlatformKMSRESTFacade) ExportKey(
	ctx context.Context,
	req *restapi.KMSExportKeyServiceRequest,
) (*restapi.KMSExportKeyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ExportKey"}
	}

	resp, err := backend.ExportKey(ctx, &grpcapi.KMSExportKeyRequest{
		KeyID:             req.KeyID,
		WrappingKeyID:     req.WrappingKeyID,
		WrappingAlgorithm: req.WrappingAlgorithm,
		Format:            req.Format,
		Version:           req.Version,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSExportKeyServiceResponse{
		KeyID:             resp.KeyID,
		Format:            resp.Format,
		WrappingKeyID:     resp.WrappingKeyID,
		WrappingAlgorithm: resp.WrappingAlgorithm,
		WrappedMaterial:   resp.WrappedMaterial,
		Version:           resp.Version,
		Timestamp:         resp.Timestamp,
	}, nil
}

// GetKeyVersions lists key versions with pagination.
func (f *PlatformKMSRESTFacade) GetKeyVersions(
	ctx context.Context,
	req *restapi.KMSGetKeyVersionsServiceRequest,
) (*restapi.KMSGetKeyVersionsServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GetKeyVersions"}
	}

	resp, err := backend.GetKeyVersions(ctx, &grpcapi.KMSGetKeyVersionsRequest{
		KeyID:  req.KeyID,
		Limit:  req.Limit,
		Cursor: req.Cursor,
	})
	if err != nil {
		return nil, err
	}

	versions := make([]*restapi.KMSKeyVersionInfo, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = &restapi.KMSKeyVersionInfo{
			Version:    v.Version,
			Status:     v.Status,
			Algorithm:  v.Algorithm,
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		}
	}

	return &restapi.KMSGetKeyVersionsServiceResponse{
		KeyID:      resp.KeyID,
		Versions:   versions,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		Timestamp:  resp.Timestamp,
	}, nil
}

// BackendStatus reports KMS backend health and capabilities.
func (f *PlatformKMSRESTFacade) BackendStatus(
	ctx context.Context,
) (*restapi.KMSBackendStatusServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}

	resp, err := backend.BackendStatus(ctx)
	if err != nil {
		return nil, err
	}

	return &restapi.KMSBackendStatusServiceResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyID,
		PcrBanks:     resp.PcrBanks,
		PcrRegisters: resp.PcrRegisters,
		Capabilities: resp.Capabilities,
		Timestamp:    resp.Timestamp,
	}, nil
}

// Encrypt encrypts plaintext.
func (f *PlatformKMSRESTFacade) Encrypt(
	ctx context.Context,
	req *restapi.KMSEncryptServiceRequest,
) (*restapi.KMSEncryptServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Encrypt"}
	}

	resp, err := backend.Encrypt(ctx, &grpcapi.KMSEncryptRequest{
		KeyID:     req.KeyID,
		Plaintext: req.Plaintext,
		Context:   req.Context,
		Nonce:     req.Nonce,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSEncryptServiceResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  resp.Timestamp,
	}, nil
}

// Decrypt decrypts ciphertext.
func (f *PlatformKMSRESTFacade) Decrypt(
	ctx context.Context,
	req *restapi.KMSDecryptServiceRequest,
) (*restapi.KMSDecryptServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Decrypt"}
	}

	resp, err := backend.Decrypt(ctx, &grpcapi.KMSDecryptRequest{
		KeyID:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
		Nonce:      req.Nonce,
		KeyVersion: req.KeyVersion,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSDecryptServiceResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  resp.Timestamp,
	}, nil
}

// BatchEncrypt encrypts multiple items in a single request.
func (f *PlatformKMSRESTFacade) BatchEncrypt(
	ctx context.Context,
	req *restapi.KMSBatchEncryptServiceRequest,
) (*restapi.KMSBatchEncryptServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "BatchEncrypt"}
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

	resp, err := backend.BatchEncrypt(ctx, &grpcapi.KMSBatchEncryptRequest{
		KeyID: req.KeyID,
		Items: items,
	})
	if err != nil {
		return nil, err
	}

	var keyVersion uint64
	results := make([]*restapi.KMSBatchEncryptResultItem, len(resp.Results))
	for i, r := range resp.Results {
		results[i] = &restapi.KMSBatchEncryptResultItem{
			ItemID:     r.ItemID,
			Ciphertext: r.Ciphertext,
			Nonce:      r.Nonce,
			Error:      r.Message,
		}
		if r.Success {
			keyVersion = r.KeyVersion
		}
	}

	return &restapi.KMSBatchEncryptServiceResponse{
		KeyID:        resp.KeyID,
		KeyVersion:   keyVersion,
		Results:      results,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}, nil
}

// BatchDecrypt decrypts multiple items in a single request.
func (f *PlatformKMSRESTFacade) BatchDecrypt(
	ctx context.Context,
	req *restapi.KMSBatchDecryptServiceRequest,
) (*restapi.KMSBatchDecryptServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "BatchDecrypt"}
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

	resp, err := backend.BatchDecrypt(ctx, &grpcapi.KMSBatchDecryptRequest{
		KeyID: req.KeyID,
		Items: items,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*restapi.KMSBatchDecryptResultItem, len(resp.Results))
	for i, r := range resp.Results {
		results[i] = &restapi.KMSBatchDecryptResultItem{
			ItemID:     r.ItemID,
			Plaintext:  r.Plaintext,
			KeyVersion: r.KeyVersion,
			Error:      r.Message,
		}
	}

	return &restapi.KMSBatchDecryptServiceResponse{
		KeyID:        resp.KeyID,
		Results:      results,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}, nil
}

// Rewrap re-encrypts ciphertext. Same-key requests use the SDK rewrap
// operation, which re-encrypts under the latest version of the source key.
// Cross-key requests decrypt under the source key and immediately re-encrypt
// under the destination key without exposing plaintext to the caller.
func (f *PlatformKMSRESTFacade) Rewrap(
	ctx context.Context,
	req *restapi.KMSRewrapServiceRequest,
) (*restapi.KMSRewrapServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Rewrap"}
	}

	if req.DestinationKeyID == "" || req.DestinationKeyID == req.SourceKeyID {
		resp, err := backend.Rewrap(ctx, &grpcapi.KMSRewrapRequest{
			KeyID:         req.SourceKeyID,
			Ciphertext:    req.Ciphertext,
			Context:       req.SourceContext,
			Nonce:         req.SourceNonce,
			SourceVersion: req.SourceKeyVersion,
		})
		if err != nil {
			return nil, err
		}
		return &restapi.KMSRewrapServiceResponse{
			SourceKeyID:      resp.KeyID,
			DestinationKeyID: resp.KeyID,
			SourceKeyVersion: resp.SourceVersion,
			DestKeyVersion:   resp.TargetVersion,
			Ciphertext:       resp.Ciphertext,
			Nonce:            resp.Nonce,
			Timestamp:        resp.Timestamp,
		}, nil
	}

	decrypted, err := backend.Decrypt(ctx, &grpcapi.KMSDecryptRequest{
		KeyID:      req.SourceKeyID,
		Ciphertext: req.Ciphertext,
		Context:    req.SourceContext,
		Nonce:      req.SourceNonce,
		KeyVersion: req.SourceKeyVersion,
	})
	if err != nil {
		return nil, err
	}

	encrypted, err := backend.Encrypt(ctx, &grpcapi.KMSEncryptRequest{
		KeyID:     req.DestinationKeyID,
		Plaintext: decrypted.Plaintext,
		Context:   req.DestContext,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSRewrapServiceResponse{
		SourceKeyID:      req.SourceKeyID,
		DestinationKeyID: req.DestinationKeyID,
		SourceKeyVersion: req.SourceKeyVersion,
		DestKeyVersion:   encrypted.KeyVersion,
		Ciphertext:       encrypted.Ciphertext,
		Nonce:            encrypted.Nonce,
		Timestamp:        encrypted.Timestamp,
	}, nil
}

// Sign creates a digital signature, threading the PreHashed flag through to
// the SDK.
func (f *PlatformKMSRESTFacade) Sign(
	ctx context.Context,
	req *restapi.KMSSignServiceRequest,
) (*restapi.KMSSignServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Sign"}
	}

	resp, err := backend.Sign(ctx, &grpcapi.KMSSignRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		HashAlgorithm: req.HashAlgorithm,
		PreHashed:     req.PreHashed,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSSignServiceResponse{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     resp.Timestamp,
	}, nil
}

// Verify verifies a digital signature.
func (f *PlatformKMSRESTFacade) Verify(
	ctx context.Context,
	req *restapi.KMSVerifyServiceRequest,
) (*restapi.KMSVerifyServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Verify"}
	}

	resp, err := backend.Verify(ctx, &grpcapi.KMSVerifyRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		Signature:     req.Signature,
		HashAlgorithm: req.HashAlgorithm,
		KeyVersion:    req.KeyVersion,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSVerifyServiceResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}, nil
}

// GenerateRandom generates cryptographically secure random bytes.
func (f *PlatformKMSRESTFacade) GenerateRandom(
	ctx context.Context,
	req *restapi.KMSGenerateRandomServiceRequest,
) (*restapi.KMSGenerateRandomServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GenerateRandom"}
	}

	resp, err := backend.GenerateRandom(ctx, &grpcapi.KMSGenerateRandomRequest{
		NumBytes: req.NumBytes,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSGenerateRandomServiceResponse{
		RandomBytes: resp.RandomBytes,
		Timestamp:   resp.Timestamp,
	}, nil
}

// Hash computes a cryptographic hash.
func (f *PlatformKMSRESTFacade) Hash(
	ctx context.Context,
	req *restapi.KMSHashServiceRequest,
) (*restapi.KMSHashServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Hash"}
	}

	resp, err := backend.Hash(ctx, &grpcapi.KMSHashRequest{
		Data:      req.Data,
		Algorithm: req.Algorithm,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSHashServiceResponse{
		Algorithm: resp.Algorithm,
		Hash:      resp.Hash,
		Timestamp: resp.Timestamp,
	}, nil
}

// HMAC computes an HMAC.
func (f *PlatformKMSRESTFacade) HMAC(
	ctx context.Context,
	req *restapi.KMSHMACServiceRequest,
) (*restapi.KMSHMACServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "HMAC"}
	}

	resp, err := backend.HMAC(ctx, &grpcapi.KMSHMACRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		HashAlgorithm: req.HashAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	return &restapi.KMSHMACServiceResponse{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.HMAC,
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     resp.Timestamp,
	}, nil
}

// VerifyHMAC verifies an HMAC.
func (f *PlatformKMSRESTFacade) VerifyHMAC(
	ctx context.Context,
	req *restapi.KMSVerifyHMACServiceRequest,
) (*restapi.KMSVerifyHMACServiceResponse, error) {
	backend, err := f.backendOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "VerifyHMAC"}
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

	return &restapi.KMSVerifyHMACServiceResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}, nil
}

// Ensure PlatformKMSRESTFacade implements the REST KMS service interface.
var _ restapi.KMSService = (*PlatformKMSRESTFacade)(nil)

// =============================================================================
// REST <-> gRPC Type Conversions
// =============================================================================

// restKeySpecToGRPC converts a REST key spec to the platform gRPC key spec.
func restKeySpecToGRPC(spec *restapi.KMSKeySpec) *grpcapi.KMSKeySpec {
	if spec == nil {
		return nil
	}
	return &grpcapi.KMSKeySpec{
		Algorithm:          spec.Algorithm,
		KeySize:            spec.KeySize,
		Usage:              spec.Usage,
		Exportable:         spec.Exportable,
		DeletionProtection: spec.DeletionProtection,
	}
}

// grpcKeyHandleToREST converts a platform gRPC key handle to the REST type.
func grpcKeyHandleToREST(handle *grpcapi.KMSKeyHandle) *restapi.KMSKeyHandle {
	if handle == nil {
		return nil
	}
	return &restapi.KMSKeyHandle{
		KeyID:     handle.KeyID,
		Version:   handle.Version,
		Algorithm: handle.Algorithm,
		Status:    handle.Status,
		CreatedAt: handle.CreatedAt,
	}
}

// grpcKeyMetadataToREST converts platform gRPC key metadata to the REST type.
func grpcKeyMetadataToREST(meta *grpcapi.KMSKeyMetadata) *restapi.KMSKeyMetadata {
	if meta == nil {
		return nil
	}
	return &restapi.KMSKeyMetadata{
		KeyID:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          meta.Algorithm,
		Status:             meta.Status,
		Usage:              meta.Usage,
		Version:            meta.Version,
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		CreatedAt:          meta.CreatedAt,
		UpdatedAt:          meta.UpdatedAt,
		LastUsedAt:         meta.LastUsedAt,
		Tags:               meta.Tags,
		Owner:              meta.Owner,
	}
}
