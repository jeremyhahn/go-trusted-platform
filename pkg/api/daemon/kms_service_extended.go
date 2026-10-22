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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
)

// This file extends KMSServerAdapter and SecretsServerAdapter with the
// key-lifecycle verbs that are declared in the quicbaas KeyManagement /
// SecretsManagement protos: RevokeKey, GetKeyMetadata, UpdateKeyMetadata,
// SetKeyPolicy, GetKeyPolicy, GetSupportedAlgorithms, BackendStatus, and
// the secrets rotation-policy pair. All methods delegate to the same
// quicbaas SDK clients used by the previously implemented verbs, keeping
// the adapters free of business logic.

// RevokeKey implements pb.KeyManagementServer.RevokeKey by delegating to
// the SDK KMS client. Revoked keys are reported as disabled, mirroring the
// quicbaas server-side semantics.
func (a *KMSServerAdapter) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := a.client.RevokeKey(ctx, req.GetKeyId(), req.GetReason()); err != nil {
		return nil, status.Errorf(errclass.Code(err), "key revocation failed: %v", err)
	}

	return &pb.RevokeKeyResponse{
		KeyId:     req.GetKeyId(),
		Status:    pb.KeyStatus_KEY_STATUS_DISABLED,
		Timestamp: time.Now().Unix(),
	}, nil
}

// GetKeyMetadata implements pb.KeyManagementServer.GetKeyMetadata by
// delegating to the SDK KMS client.
func (a *KMSServerAdapter) GetKeyMetadata(ctx context.Context, req *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	meta, err := a.client.GetKeyMetadata(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get key metadata failed: %v", err)
	}
	if meta == nil {
		return nil, ErrKMSNilMetadata{}
	}

	return &pb.GetKeyMetadataResponse{
		Metadata:  sdkKeyMetadataToPb(meta),
		Timestamp: time.Now().Unix(),
	}, nil
}

// UpdateKeyMetadata implements pb.KeyManagementServer.UpdateKeyMetadata by
// delegating to the SDK KMS client.
func (a *KMSServerAdapter) UpdateKeyMetadata(ctx context.Context, req *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	meta, err := a.client.UpdateKeyMetadata(ctx, &kms.UpdateKeyMetadataRequest{
		KeyID:       req.GetKeyId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Tags:        req.GetTags(),
		RemoveTags:  req.GetRemoveTags(),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key metadata update failed: %v", err)
	}
	if meta == nil {
		return nil, ErrKMSNilMetadata{}
	}

	return &pb.UpdateKeyMetadataResponse{
		Metadata:  sdkKeyMetadataToPb(meta),
		Timestamp: time.Now().Unix(),
	}, nil
}

// SetKeyPolicy implements pb.KeyManagementServer.SetKeyPolicy by delegating
// to the SDK KMS client.
func (a *KMSServerAdapter) SetKeyPolicy(ctx context.Context, req *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}

	policy, err := pbKeyPolicyToSDK(req.GetPolicy())
	if err != nil {
		return nil, err
	}
	policy.KeyID = req.GetKeyId()

	if err := a.client.SetKeyPolicy(ctx, &kms.SetKeyPolicyRequest{
		KeyID:  req.GetKeyId(),
		Policy: policy,
	}); err != nil {
		return nil, status.Errorf(errclass.Code(err), "key policy update failed: %v", err)
	}

	// The KMS stamps the stored policy with a new version, but the SDK
	// SetKeyPolicy call returns only an error, so the version is read back.
	stored, err := a.client.GetKeyPolicy(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "key policy read-back failed: %v", err)
	}
	if stored == nil {
		return nil, status.Error(codes.Internal, "key policy read-back returned no policy")
	}

	return &pb.SetKeyPolicyResponse{
		KeyId:         req.GetKeyId(),
		PolicyVersion: uint64(stored.Version),
		Timestamp:     stored.UpdatedAt.Unix(),
	}, nil
}

// GetKeyPolicy implements pb.KeyManagementServer.GetKeyPolicy by delegating
// to the SDK KMS client.
func (a *KMSServerAdapter) GetKeyPolicy(ctx context.Context, req *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	policy, err := a.client.GetKeyPolicy(ctx, req.GetKeyId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get key policy failed: %v", err)
	}

	return &pb.GetKeyPolicyResponse{
		Policy:    sdkKeyPolicyToPb(policy),
		Timestamp: time.Now().Unix(),
	}, nil
}

// GetSupportedAlgorithms implements pb.KeyManagementServer.GetSupportedAlgorithms
// by delegating to the SDK KMS client.
func (a *KMSServerAdapter) GetSupportedAlgorithms(ctx context.Context, req *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	resp, err := a.client.GetSupportedAlgorithms(ctx)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "supported algorithms query failed: %v", err)
	}

	return &pb.GetSupportedAlgorithmsResponse{
		Algorithms: resp.Algorithms,
	}, nil
}

// BackendStatus implements pb.KeyManagementServer.BackendStatus by
// delegating to the SDK KMS client.
func (a *KMSServerAdapter) BackendStatus(ctx context.Context, req *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "KMS service unavailable")
	}

	resp, err := a.client.BackendStatus(ctx)
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "backend status query failed: %v", err)
	}

	pcrRegisters := make([]int32, 0, len(resp.PCRRegisters))
	for _, r := range resp.PCRRegisters {
		pcrRegisters = append(pcrRegisters, int32(r))
	}

	return &pb.BackendStatusResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyId:        resp.KeyID,
		PcrBanks:     resp.PCRBanks,
		PcrRegisters: pcrRegisters,
		Capabilities: resp.Capabilities,
		Timestamp:    time.Now().Unix(),
	}, nil
}

// SetRotationPolicy implements pb.SecretsManagementServer.SetRotationPolicy
// by delegating to the SDK secrets client.
func (a *SecretsServerAdapter) SetRotationPolicy(ctx context.Context, req *pb.SetRotationPolicyRequest) (*pb.SetRotationPolicyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}

	if err := a.client.SetRotationPolicy(ctx, &quicbaas.SetSecretRotationPolicyRequest{
		SecretID: req.GetSecretId(),
		Policy:   pbSecretRotationPolicyToSDK(req.GetPolicy()),
	}); err != nil {
		return nil, status.Errorf(errclass.Code(err), "rotation policy update failed: %v", err)
	}

	return &pb.SetRotationPolicyResponse{
		SecretId:  req.GetSecretId(),
		Policy:    req.GetPolicy(),
		Timestamp: time.Now().Unix(),
	}, nil
}

// GetRotationPolicy implements pb.SecretsManagementServer.GetRotationPolicy
// by delegating to the SDK secrets client.
func (a *SecretsServerAdapter) GetRotationPolicy(ctx context.Context, req *pb.GetRotationPolicyRequest) (*pb.GetRotationPolicyResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	policy, err := a.client.GetRotationPolicy(ctx, req.GetSecretId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get rotation policy failed: %v", err)
	}

	return &pb.GetRotationPolicyResponse{
		SecretId:  req.GetSecretId(),
		Policy:    sdkSecretRotationPolicyToPb(policy),
		Timestamp: time.Now().Unix(),
	}, nil
}

// =============================================================================
// SDK <-> protobuf conversion helpers
// =============================================================================

// sdkKeyStatusToPb converts an SDK KeyStatus to protobuf KeyStatus.
func sdkKeyStatusToPb(s kms.KeyStatus) pb.KeyStatus {
	switch s {
	case kms.KeyStatusEnabled:
		return pb.KeyStatus_KEY_STATUS_ENABLED
	case kms.KeyStatusDisabled:
		return pb.KeyStatus_KEY_STATUS_DISABLED
	case kms.KeyStatusPendingDeletion:
		return pb.KeyStatus_KEY_STATUS_PENDING_DELETION
	case kms.KeyStatusDeleted:
		return pb.KeyStatus_KEY_STATUS_DELETED
	case kms.KeyStatusRotating:
		return pb.KeyStatus_KEY_STATUS_ROTATING
	case kms.KeyStatusCompromised:
		return pb.KeyStatus_KEY_STATUS_COMPROMISED
	default:
		return pb.KeyStatus_KEY_STATUS_UNSPECIFIED
	}
}

// pbKeyStatusToSDK converts a protobuf KeyStatus to SDK KeyStatus.
func pbKeyStatusToSDK(s pb.KeyStatus) kms.KeyStatus {
	switch s {
	case pb.KeyStatus_KEY_STATUS_ENABLED:
		return kms.KeyStatusEnabled
	case pb.KeyStatus_KEY_STATUS_DISABLED:
		return kms.KeyStatusDisabled
	case pb.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return kms.KeyStatusPendingDeletion
	case pb.KeyStatus_KEY_STATUS_DELETED:
		return kms.KeyStatusDeleted
	case pb.KeyStatus_KEY_STATUS_ROTATING:
		return kms.KeyStatusRotating
	case pb.KeyStatus_KEY_STATUS_COMPROMISED:
		return kms.KeyStatusCompromised
	default:
		return kms.KeyStatusEnabled
	}
}

// sdkUsagesToPb converts SDK KeyUsage slice to protobuf KeyUsage slice.
func sdkUsagesToPb(usages []kms.KeyUsage) []pb.KeyUsage {
	result := make([]pb.KeyUsage, 0, len(usages))
	for _, u := range usages {
		switch u {
		case kms.KeyUsageEncrypt:
			result = append(result, pb.KeyUsage_KEY_USAGE_ENCRYPT)
		case kms.KeyUsageDecrypt:
			result = append(result, pb.KeyUsage_KEY_USAGE_DECRYPT)
		case kms.KeyUsageSign:
			result = append(result, pb.KeyUsage_KEY_USAGE_SIGN)
		case kms.KeyUsageVerify:
			result = append(result, pb.KeyUsage_KEY_USAGE_VERIFY)
		case kms.KeyUsageWrap:
			result = append(result, pb.KeyUsage_KEY_USAGE_WRAP_KEY)
		}
	}
	return result
}

// sdkKeyMetadataToPb converts an SDK KeyMetadataResponse to protobuf
// KeyMetadata. A nil input yields a nil output.
func sdkKeyMetadataToPb(meta *kms.KeyMetadataResponse) *pb.KeyMetadata {
	if meta == nil {
		return nil
	}
	m := &pb.KeyMetadata{
		KeyId:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          sdkAlgorithmToPb(meta.Algorithm),
		Status:             sdkKeyStatusToPb(meta.Status),
		Usage:              sdkUsagesToPb(meta.Usage),
		Version:            uint64(meta.Version),
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		Tags:               meta.Tags,
		Owner:              meta.Owner,
	}
	if !meta.CreatedAt.IsZero() {
		m.CreatedAt = meta.CreatedAt.Unix()
	}
	if !meta.UpdatedAt.IsZero() {
		m.UpdatedAt = meta.UpdatedAt.Unix()
	}
	if !meta.LastUsedAt.IsZero() {
		m.LastUsedAt = meta.LastUsedAt.Unix()
	}
	return m
}

// pbKeyPolicyToSDK converts a protobuf KeyPolicy to the SDK KeyPolicy.
// An allowed operation the SDK has no usage for is refused with
// ErrKMSUnsupportedValue. The caller rejects a nil policy first.
func pbKeyPolicyToSDK(p *pb.KeyPolicy) (*kms.KeyPolicy, error) {
	allowed, err := pbUsagesToSDK(p.GetAllowedOperations())
	if err != nil {
		return nil, err
	}
	policy := &kms.KeyPolicy{
		KeyID:             p.GetKeyId(),
		Version:           int(p.GetVersion()),
		AllowedOperations: allowed,
		AllowedPrincipals: p.GetAllowedPrincipals(),
		DeniedPrincipals:  p.GetDeniedPrincipals(),
		RotationRequired:  p.GetRotationRequired(),
		MaxUsageCount:     p.GetMaxUsageCount(),
		RequireMFA:        p.GetRequireMfa(),
	}
	if p.GetExpiresAt() > 0 {
		policy.ExpiresAt = time.Unix(p.GetExpiresAt(), 0)
	}
	return policy, nil
}

// sdkKeyPolicyToPb converts an SDK KeyPolicy to the protobuf KeyPolicy.
// A nil input yields a nil output.
func sdkKeyPolicyToPb(p *kms.KeyPolicy) *pb.KeyPolicy {
	if p == nil {
		return nil
	}
	policy := &pb.KeyPolicy{
		KeyId:             p.KeyID,
		Version:           uint64(p.Version),
		AllowedOperations: sdkUsagesToPb(p.AllowedOperations),
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMfa:        p.RequireMFA,
	}
	if !p.ExpiresAt.IsZero() {
		policy.ExpiresAt = p.ExpiresAt.Unix()
	}
	if !p.UpdatedAt.IsZero() {
		policy.UpdatedAt = p.UpdatedAt.Unix()
	}
	return policy
}

// pbSecretRotationPolicyToSDK converts a protobuf SecretRotationPolicy to
// the SDK secrets RotationPolicy. A nil input yields a nil output.
func pbSecretRotationPolicyToSDK(p *pb.SecretRotationPolicy) *quicbaas.SecretRotationPolicy {
	if p == nil {
		return nil
	}
	policy := &quicbaas.SecretRotationPolicy{
		Enabled:        p.GetEnabled(),
		Interval:       time.Duration(p.GetIntervalSeconds()) * time.Second,
		RetainVersions: int(p.GetRetainVersions()),
		RotationLambda: p.GetRotationLambda(),
	}
	if p.GetNextRotation() > 0 {
		policy.NextRotation = time.Unix(p.GetNextRotation(), 0)
	}
	return policy
}

// sdkSecretRotationPolicyToPb converts an SDK secrets RotationPolicy to
// the protobuf SecretRotationPolicy. A nil input yields a nil output.
func sdkSecretRotationPolicyToPb(p *quicbaas.SecretRotationPolicy) *pb.SecretRotationPolicy {
	if p == nil {
		return nil
	}
	policy := &pb.SecretRotationPolicy{
		Enabled:         p.Enabled,
		IntervalSeconds: int64(p.Interval / time.Second),
		RetainVersions:  int32(p.RetainVersions),
		RotationLambda:  p.RotationLambda,
	}
	if !p.NextRotation.IsZero() {
		policy.NextRotation = p.NextRotation.Unix()
	}
	return policy
}
