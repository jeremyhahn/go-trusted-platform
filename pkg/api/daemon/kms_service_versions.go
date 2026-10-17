package daemon

import (
	"context"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListDEKs returns the DEKs under an optional path prefix.
func (a *DEKServerAdapter) ListDEKs(ctx context.Context, req *pb.ListDEKsRequest) (*pb.ListDEKsResponse, error) {
	if err := a.admit(ctx); err != nil {
		return nil, err
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
	if err := a.admit(ctx); err != nil {
		return nil, err
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
