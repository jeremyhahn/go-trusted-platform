package daemon

import (
	"context"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
)

// ListDEKs returns the DEKs under an optional path prefix.
func (a *DEKServerAdapter) ListDEKs(ctx context.Context, req *pb.ListDEKsRequest) (*pb.ListDEKsResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}

	resp, err := a.client.ListDEKs(ctx, &dekclient.ListDEKsRequest{
		Prefix:    req.GetPrefix(),
		Recursive: req.GetRecursive(),
		Limit:     int(req.GetLimit()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DEK listing failed: %v", err)
	}

	deks := make([]*pb.DEKMetadata, 0, len(resp.DEKs))
	for i := range resp.DEKs {
		deks = append(deks, dekInfoToPb(&resp.DEKs[i]))
	}
	return &pb.ListDEKsResponse{
		Deks:       deks,
		TotalCount: int32(resp.TotalCount),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// GetDEKStatus returns a DEK's metadata, AEAD usage and re-encryption progress.
func (a *DEKServerAdapter) GetDEKStatus(ctx context.Context, req *pb.GetDEKStatusRequest) (*pb.GetDEKStatusResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "DEK service unavailable")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	resp, err := a.client.GetDEKStatus(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "DEK status not found: %v", err)
	}

	out := &pb.GetDEKStatusResponse{
		Dek:       dekInfoToPb(resp.DEK),
		Timestamp: time.Now().Unix(),
	}
	if resp.DEK != nil {
		out.UsagePercent = dekUsagePercent(resp.DEK)
	}
	if progress := resp.ReencryptionProgress; progress != nil {
		out.ReencryptionProgress = &pb.ReencryptionProgress{
			InProgress:    progress.InProgress,
			TotalKeys:     int32(progress.TotalKeys),
			ProcessedKeys: int32(progress.ProcessedKeys),
			FailedKeys:    int32(progress.FailedKeys),
			StartedAt:     unixOrZero(progress.StartedAt),
		}
	}
	return out, nil
}

// dekInfoToPb converts SDK DEK metadata to its proto form; nil stays nil.
func dekInfoToPb(info *dekclient.DEKInfo) *pb.DEKMetadata {
	if info == nil {
		return nil
	}
	return &pb.DEKMetadata{
		Path:           info.Path,
		Algorithm:      dekAlgorithmToPb(info.Algorithm),
		Version:        uint64(info.Version),
		Status:         info.Status,
		IsDefault:      info.IsDefault,
		CreatedAt:      unixOrZero(info.CreatedAt),
		RotatedAt:      unixOrZero(info.RotatedAt),
		UsageCount:     info.UsageCount,
		BytesUsed:      info.BytesUsed,
		MaxUsageCount:  info.MaxUsageCount,
		MaxBytesUsed:   info.MaxBytesUsed,
		WarningPercent: int32(info.WarningPercent),
		Description:    info.Description,
		BackendType:    info.BackendType,
	}
}

// dekAlgorithmsByName maps the DEK service's algorithm names (matched
// case-insensitively) to their proto enum values.
var dekAlgorithmsByName = map[string]pb.KeyAlgorithm{
	"aes-256-gcm":       pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
	"chacha20-poly1305": pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305,
}

// dekAlgorithmToPb maps a DEK algorithm name to the proto enum; unknown
// names map to KEY_ALG_UNSPECIFIED.
func dekAlgorithmToPb(name string) pb.KeyAlgorithm {
	return dekAlgorithmsByName[strings.ToLower(name)]
}

// dekUsagePercent is the larger of the operation-count and byte-count usage
// against their limits; a DEK without limits reports zero.
func dekUsagePercent(info *dekclient.DEKInfo) float64 {
	var percent float64
	if info.MaxUsageCount > 0 {
		percent = float64(info.UsageCount) * 100 / float64(info.MaxUsageCount)
	}
	if info.MaxBytesUsed > 0 {
		percent = max(percent, float64(info.BytesUsed)*100/float64(info.MaxBytesUsed))
	}
	return percent
}

// GetSecretVersion retrieves one version of a secret, including its data.
func (a *SecretsServerAdapter) GetSecretVersion(ctx context.Context, req *pb.GetSecretVersionRequest) (*pb.GetSecretVersionResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	info, err := a.client.GetVersion(ctx, &secretsclient.GetSecretVersionRequest{
		SecretID: req.GetSecretId(),
		Version:  int(req.GetVersion()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "get secret version failed: %v", err)
	}

	return &pb.GetSecretVersionResponse{
		Version:   secretVersionToPb(info),
		Data:      info.Data,
		Timestamp: time.Now().Unix(),
	}, nil
}

// ListSecretVersions lists the versions of a secret without their data.
func (a *SecretsServerAdapter) ListSecretVersions(ctx context.Context, req *pb.ListSecretVersionsRequest) (*pb.ListSecretVersionsResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	resp, err := a.client.ListVersions(ctx, req.GetSecretId())
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "list secret versions failed: %v", err)
	}

	versions := make([]*pb.SecretVersion, 0, len(resp.Versions))
	for i := range resp.Versions {
		versions = append(versions, secretVersionToPb(&resp.Versions[i]))
	}
	return &pb.ListSecretVersionsResponse{
		Versions:  versions,
		Timestamp: time.Now().Unix(),
	}, nil
}

// RotateSecret stores new data as the secret's next version.
func (a *SecretsServerAdapter) RotateSecret(ctx context.Context, req *pb.RotateSecretRequest) (*pb.RotateSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if len(req.GetNewData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "new_data is required")
	}

	resp, err := a.client.Rotate(ctx, &secretsclient.RotateSecretRequest{
		SecretID: req.GetSecretId(),
		NewData:  req.GetNewData(),
		Metadata: req.GetMetadata(),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "secret rotation failed: %v", err)
	}

	return &pb.RotateSecretResponse{
		SecretId:   resp.SecretID,
		OldVersion: uint64(resp.OldVersion),
		NewVersion: uint64(resp.NewVersion),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// RollbackSecret makes an earlier version's data the secret's newest version.
func (a *SecretsServerAdapter) RollbackSecret(ctx context.Context, req *pb.RollbackSecretRequest) (*pb.RollbackSecretResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if req.GetTargetVersion() == 0 {
		return nil, status.Error(codes.InvalidArgument, "target_version is required")
	}

	resp, err := a.client.Rollback(ctx, &secretsclient.RollbackSecretRequest{
		SecretID:      req.GetSecretId(),
		TargetVersion: int(req.GetTargetVersion()),
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "secret rollback failed: %v", err)
	}

	return &pb.RollbackSecretResponse{
		SecretId:   resp.SecretID,
		NewVersion: uint64(resp.NewVersion),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// secretStatusFromPb maps the proto secret status to the SDK status.
var secretStatusFromPb = map[pb.SecretStatus]secretsclient.SecretStatus{
	pb.SecretStatus_SECRET_STATUS_ENABLED:  secretsclient.SecretStatusEnabled,
	pb.SecretStatus_SECRET_STATUS_DISABLED: secretsclient.SecretStatusDisabled,
	pb.SecretStatus_SECRET_STATUS_DELETED:  secretsclient.SecretStatusDeleted,
}

// UpdateSecretStatus enables, disables or soft-deletes a secret.
func (a *SecretsServerAdapter) UpdateSecretStatus(ctx context.Context, req *pb.UpdateSecretStatusRequest) (*pb.UpdateSecretStatusResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	sdkStatus, ok := secretStatusFromPb[req.GetStatus()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported secret status %s", req.GetStatus())
	}

	err := a.client.UpdateStatus(ctx, &secretsclient.UpdateSecretStatusRequest{
		SecretID: req.GetSecretId(),
		Status:   sdkStatus,
	})
	if err != nil {
		return nil, status.Errorf(errclass.Code(err), "secret status update failed: %v", err)
	}

	return &pb.UpdateSecretStatusResponse{
		SecretId:  req.GetSecretId(),
		Status:    req.GetStatus(),
		Timestamp: time.Now().Unix(),
	}, nil
}

// secretVersionToPb converts SDK secret version metadata to its proto form.
// The data is not part of pb.SecretVersion; callers that return it carry it
// separately.
func secretVersionToPb(info *secretsclient.SecretVersionInfo) *pb.SecretVersion {
	return &pb.SecretVersion{
		SecretId:  info.SecretID,
		Version:   uint64(info.Version),
		Metadata:  info.Metadata,
		CreatedAt: unixOrZero(info.CreatedAt),
		CreatedBy: info.CreatedBy,
	}
}
