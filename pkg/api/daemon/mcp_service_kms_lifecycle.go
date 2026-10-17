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
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	restkms "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KMS key lifecycle and secrets operations for the MCP service provider.
// Every method delegates to the quicbaas service layer (baasservice), the
// same backend that serves the gRPC, QUIC, and Unix transports.

// ErrSecretsOperationFailed is returned when a secrets operation fails.
type ErrSecretsOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSecretsOperationFailed) Error() string {
	return fmt.Sprintf("secrets operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrSecretsOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrSecretNotFound is returned when a secret is not found.
type ErrSecretNotFound struct {
	SecretID string
}

func (e ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret not found: %s", e.SecretID)
}

// GRPCStatus classifies the error as NotFound, the code the gRPC secrets
// adapter returns for the same lookup.
func (e ErrSecretNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrKMSKeyPolicyNotFound is returned when the backend reports a key's
// policy missing.
type ErrKMSKeyPolicyNotFound struct {
	KeyID string
}

func (e ErrKMSKeyPolicyNotFound) Error() string {
	return fmt.Sprintf("KMS key policy not found: %s", e.KeyID)
}

// GRPCStatus classifies the error as NotFound, the code the gRPC KMS
// adapter returns for the same lookup.
func (e ErrKMSKeyPolicyNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrSecretRotationPolicyNotFound is returned when a secret's rotation
// policy cannot be read.
type ErrSecretRotationPolicyNotFound struct {
	SecretID string
}

func (e ErrSecretRotationPolicyNotFound) Error() string {
	return fmt.Sprintf("secret rotation policy not found: %s", e.SecretID)
}

// GRPCStatus classifies the error as NotFound, the code the gRPC secrets
// adapter returns for the same lookup.
func (e ErrSecretRotationPolicyNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// kmsLookupError answers a failed key lookup the way the gRPC KMS adapter
// does: notFound when the backend's error is of class NotFound, otherwise
// the operation failure, which keeps the backend's class through its Cause.
func kmsLookupError(operation string, notFound, err error) error {
	if errclass.Code(err) == codes.NotFound {
		return notFound
	}
	return ErrKMSOperationFailed{Operation: operation, Cause: err}
}

// KMSRevokeKey revokes a key, marking it unusable.
func (p *MCPServiceProvider) KMSRevokeKey(ctx context.Context, keyID string, reason string) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if keyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	resp, err := p.kmsService.RevokeKey(ctx, &baasservice.RevokeKeyRequest{
		KeyID:  keyID,
		Reason: reason,
	})
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "RevokeKey", Cause: err}
	}

	p.logger.Info("KMS key revoked", "key_id", keyID, "reason", reason)
	return resp, nil
}

// KMSExportPublicKey exports the public portion of an asymmetric key in PEM
// (default) or DER format. A version of 0 exports the latest key version.
func (p *MCPServiceProvider) KMSExportPublicKey(ctx context.Context, req *mcp.KMSExportPublicKeyRequest) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if req == nil || req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	format := strings.ToUpper(strings.TrimSpace(req.Format))
	if format == "" {
		format = "PEM"
	}
	if format != "PEM" && format != "DER" {
		return nil, ErrKMSInvalidParameter{Parameter: "format", Reason: "format must be PEM or DER"}
	}

	resp, err := p.kmsService.GetPublicKey(ctx, &baasservice.GetPublicKeyRequest{
		KeyID:   req.KeyID,
		Version: req.Version,
	})
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "ExportPublicKey", Cause: err}
	}

	result := map[string]interface{}{
		"key_id":    resp.KeyID,
		"algorithm": resp.Algorithm,
		"version":   resp.Version,
		"format":    format,
	}
	switch format {
	case "PEM":
		result["public_key"] = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: resp.PublicKey,
		}))
	case "DER":
		result["public_key"] = resp.PublicKey
	}

	return result, nil
}

// KMSGetKeyMetadata retrieves key metadata without exposing key material.
func (p *MCPServiceProvider) KMSGetKeyMetadata(ctx context.Context, keyID string) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if keyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	resp, err := p.kmsService.GetKeyMetadata(ctx, &baasservice.GetKeyMetadataRequest{KeyID: keyID})
	if err != nil {
		return nil, kmsLookupError("GetKeyMetadata", ErrKMSKeyNotFound{KeyID: keyID}, err)
	}

	return resp.Metadata, nil
}

// KMSUpdateKeyMetadata updates mutable key metadata fields.
func (p *MCPServiceProvider) KMSUpdateKeyMetadata(ctx context.Context, req *mcp.KMSUpdateKeyMetadataRequest) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if req == nil || req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	updateReq := &baasservice.UpdateKeyMetadataRequest{
		KeyID:      req.KeyID,
		Tags:       req.Tags,
		RemoveTags: req.RemoveTags,
	}
	if req.Name != "" {
		updateReq.Name = &req.Name
	}
	if req.Description != "" {
		updateReq.Description = &req.Description
	}

	resp, err := p.kmsService.UpdateKeyMetadata(ctx, updateReq)
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "UpdateKeyMetadata", Cause: err}
	}

	p.logger.Info("KMS key metadata updated", "key_id", req.KeyID)
	return resp.Metadata, nil
}

// KMSSetKeyPolicy sets the access control policy for a key.
func (p *MCPServiceProvider) KMSSetKeyPolicy(ctx context.Context, req *mcp.KMSSetKeyPolicyRequest) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if req == nil || req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	operations := make([]baasservice.KeyUsage, 0, len(req.AllowedOperations))
	for _, op := range req.AllowedOperations {
		usage, err := parseKMSKeyUsage(op)
		if err != nil {
			return nil, err
		}
		operations = append(operations, usage)
	}

	policy := &baasservice.KeyPolicy{
		KeyID:             req.KeyID,
		AllowedOperations: operations,
		AllowedPrincipals: req.AllowedPrincipals,
		DeniedPrincipals:  req.DeniedPrincipals,
		RotationRequired:  req.RotationRequired,
		RequireMFA:        req.RequireMFA,
	}
	if req.MaxUsageCount > 0 {
		maxUsage := req.MaxUsageCount
		policy.MaxUsageCount = &maxUsage
	}
	if req.ExpiresAt > 0 {
		expiresAt := time.Unix(req.ExpiresAt, 0)
		policy.ExpiresAt = &expiresAt
	}

	resp, err := p.kmsService.SetKeyPolicy(ctx, &baasservice.SetKeyPolicyRequest{
		KeyID:  req.KeyID,
		Policy: policy,
	})
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "SetKeyPolicy", Cause: err}
	}

	p.logger.Info("KMS key policy updated", "key_id", req.KeyID)
	return resp, nil
}

// KMSGetKeyPolicy retrieves the access control policy for a key.
func (p *MCPServiceProvider) KMSGetKeyPolicy(ctx context.Context, keyID string) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}
	if keyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	resp, err := p.kmsService.GetKeyPolicy(ctx, &baasservice.GetKeyPolicyRequest{KeyID: keyID})
	if err != nil {
		return nil, kmsLookupError("GetKeyPolicy", ErrKMSKeyPolicyNotFound{KeyID: keyID}, err)
	}

	return resp.Policy, nil
}

// KMSGetSupportedAlgorithms lists algorithms supported by the KMS backend.
func (p *MCPServiceProvider) KMSGetSupportedAlgorithms(ctx context.Context) ([]string, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	algorithms, err := p.kmsService.GetSupportedAlgorithms(ctx)
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "GetSupportedAlgorithms", Cause: err}
	}

	return algorithms, nil
}

// KMSBackendStatus returns health and capability information about the KMS backend.
func (p *MCPServiceProvider) KMSBackendStatus(ctx context.Context) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	resp, err := p.kmsService.BackendStatus(ctx)
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "BackendStatus", Cause: err}
	}

	return resp, nil
}

// SecretStore stores a secret via the quicbaas secrets service.
func (p *MCPServiceProvider) SecretStore(ctx context.Context, req *mcp.SecretStoreRequest) (interface{}, error) {
	if p.secretsService == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}
	if req == nil || req.SecretID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "secret_id", Reason: "secret ID is required"}
	}
	if len(req.Data) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "data", Reason: "secret data is required"}
	}

	resp, err := p.secretsService.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		SecretID: req.SecretID,
		Name:     req.SecretID,
		Data:     req.Data,
		Metadata: req.Metadata,
	})
	if err != nil {
		return nil, ErrSecretsOperationFailed{Operation: "StoreSecret", Cause: err}
	}

	p.logger.Info("secret stored", "secret_id", req.SecretID)
	return resp, nil
}

// SecretGet retrieves a secret, optionally at a specific version.
func (p *MCPServiceProvider) SecretGet(ctx context.Context, secretID string, version uint64) (interface{}, error) {
	if p.secretsService == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}
	if secretID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "secret_id", Reason: "secret ID is required"}
	}

	resp, err := p.secretsService.GetSecret(ctx, &baasservice.GetSecretRequest{
		SecretID: secretID,
		Version:  version,
	})
	if err != nil {
		return nil, ErrSecretNotFound{SecretID: secretID}
	}

	return resp, nil
}

// SecretList lists secrets without exposing secret data.
func (p *MCPServiceProvider) SecretList(ctx context.Context, limit int, cursor string) (interface{}, error) {
	if p.secretsService == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}

	if limit < 0 {
		return nil, mcp.ErrInvalidArgument{Msg: "limit must not be negative"}
	}

	// The service answers only an unsorted first page and ignores the
	// cursor, so the whole list is read and paged here the way the other
	// transports page it (docs/kms/api.md §4).
	resp, err := p.secretsService.ListSecrets(ctx, &baasservice.ListSecretsRequest{})
	if err != nil {
		return nil, ErrSecretsOperationFailed{Operation: "ListSecrets", Cause: err}
	}

	byID := make(map[string]*baasservice.Secret, len(resp.Secrets))
	ids := make([]string, 0, len(resp.Secrets))
	for _, secret := range resp.Secrets {
		if secret == nil {
			continue
		}
		byID[secret.SecretID] = secret
		ids = append(ids, secret.SecretID)
	}

	pageIDs, next := restkms.PageSecretPaths(ids, cursor, limit)
	page := make([]*baasservice.Secret, 0, len(pageIDs))
	for _, id := range pageIDs {
		page = append(page, byID[id])
	}

	return &baasservice.ListSecretsResponse{
		Secrets:    page,
		NextCursor: next,
		HasMore:    next != "",
		TotalCount: len(ids),
		Timestamp:  resp.Timestamp,
	}, nil
}

// SecretDelete deletes a secret.
func (p *MCPServiceProvider) SecretDelete(ctx context.Context, secretID string) error {
	if p.secretsService == nil {
		return ErrServiceNotAvailable{Service: "secrets"}
	}
	if secretID == "" {
		return ErrKMSInvalidParameter{Parameter: "secret_id", Reason: "secret ID is required"}
	}

	if _, err := p.secretsService.DeleteSecret(ctx, &baasservice.DeleteSecretRequest{SecretID: secretID}); err != nil {
		return ErrSecretsOperationFailed{Operation: "DeleteSecret", Cause: err}
	}

	p.logger.Info("secret deleted", "secret_id", secretID)
	return nil
}

// SecretSetRotationPolicy sets the automatic rotation policy for a secret,
// including the number of old versions to retain after rotation.
func (p *MCPServiceProvider) SecretSetRotationPolicy(ctx context.Context, req *mcp.SecretSetRotationPolicyRequest) (interface{}, error) {
	if p.secretsService == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}
	if req == nil || req.SecretID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "secret_id", Reason: "secret ID is required"}
	}

	resp, err := p.secretsService.SetRotationPolicy(ctx, &baasservice.SetRotationPolicyRequest{
		SecretID: req.SecretID,
		Policy: &baasservice.SecretRotationPolicy{
			Enabled:        req.Enabled,
			Interval:       time.Duration(req.IntervalSeconds) * time.Second,
			RetainVersions: req.RetainVersions,
		},
	})
	if err != nil {
		return nil, ErrSecretsOperationFailed{Operation: "SetRotationPolicy", Cause: err}
	}

	p.logger.Info("secret rotation policy updated", "secret_id", req.SecretID)
	return resp, nil
}

// SecretGetRotationPolicy retrieves the automatic rotation policy for a secret.
func (p *MCPServiceProvider) SecretGetRotationPolicy(ctx context.Context, secretID string) (interface{}, error) {
	if p.secretsService == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}
	if secretID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "secret_id", Reason: "secret ID is required"}
	}

	resp, err := p.secretsService.GetRotationPolicy(ctx, &baasservice.GetRotationPolicyRequest{SecretID: secretID})
	if err != nil {
		return nil, ErrSecretRotationPolicyNotFound{SecretID: secretID}
	}

	return resp, nil
}
