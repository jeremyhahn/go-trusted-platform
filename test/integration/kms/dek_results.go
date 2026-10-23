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

// This file holds the DEK request builders and result conversions shared by
// the adapters that speak the QuicBaaS DEK messages (gRPC and QUIC).

//go:build integration

package kms

import (
	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

// ErrDEKMissingInResponse is returned when a DEK response carries no DEK.
type ErrDEKMissingInResponse struct {
	Operation string
}

func (e ErrDEKMissingInResponse) Error() string {
	return e.Operation + ": response carries no DEK"
}

// newCreateDEKRequest builds the CreateDEK message from the test options.
func newCreateDEKRequest(opts DEKCreateOptions) *pb.CreateDEKRequest {
	return &pb.CreateDEKRequest{
		Path:           opts.Path,
		Algorithm:      algorithmStringToProto(opts.Algorithm),
		Description:    opts.Description,
		MaxOperations:  opts.MaxOperations,
		MaxBytes:       opts.MaxBytes,
		WarningPercent: opts.WarningPercent,
	}
}

// newListDEKsRequest builds the ListDEKs message from the test options.
func newListDEKsRequest(opts DEKListOptions) *pb.ListDEKsRequest {
	return &pb.ListDEKsRequest{
		Prefix:    opts.Prefix,
		Recursive: opts.Recursive,
		Limit:     opts.Limit,
		Cursor:    opts.Cursor,
	}
}

// dekCreateResult converts a CreateDEK response.
func dekCreateResult(resp *pb.CreateDEKResponse) (*DEKCreateResult, error) {
	if resp.Dek == nil {
		return nil, ErrDEKMissingInResponse{Operation: "CreateDEK"}
	}
	return &DEKCreateResult{
		Path:        resp.Dek.Path,
		Algorithm:   algorithmProtoToString(resp.Dek.Algorithm),
		Version:     resp.Dek.Version,
		CreatedAt:   grpcUnixToTime(resp.Dek.CreatedAt),
		Description: resp.Dek.Description,
	}, nil
}

// dekGetResult converts a GetDEK response.
func dekGetResult(resp *pb.GetDEKResponse) (*DEKGetResult, error) {
	d := resp.Dek
	if d == nil {
		return nil, ErrDEKMissingInResponse{Operation: "GetDEK"}
	}
	return &DEKGetResult{
		Path:           d.Path,
		Algorithm:      algorithmProtoToString(d.Algorithm),
		Version:        d.Version,
		Status:         d.Status,
		IsDefault:      d.IsDefault,
		CreatedAt:      grpcUnixToTime(d.CreatedAt),
		RotatedAt:      grpcUnixToTime(d.RotatedAt),
		Description:    d.Description,
		BackendType:    d.BackendType,
		UsageCount:     d.UsageCount,
		BytesUsed:      d.BytesUsed,
		MaxUsageCount:  d.MaxUsageCount,
		MaxBytesUsed:   d.MaxBytesUsed,
		WarningPercent: d.WarningPercent,
	}, nil
}

// dekListResult converts a ListDEKs response.
func dekListResult(resp *pb.ListDEKsResponse) *DEKListResult {
	deks := make([]DEKSummary, 0, len(resp.Deks))
	for _, d := range resp.Deks {
		deks = append(deks, DEKSummary{
			Path:      d.Path,
			Algorithm: algorithmProtoToString(d.Algorithm),
			Version:   d.Version,
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: grpcUnixToTime(d.CreatedAt),
		})
	}
	return &DEKListResult{
		DEKs:       deks,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}
}

// dekStatusResult converts a GetDEKStatus response, including the
// re-encryption progress when a rotation is running.
func dekStatusResult(resp *pb.GetDEKStatusResponse) (*DEKStatusResult, error) {
	d := resp.Dek
	if d == nil {
		return nil, ErrDEKMissingInResponse{Operation: "GetDEKStatus"}
	}
	result := &DEKStatusResult{
		Path:           d.Path,
		Algorithm:      algorithmProtoToString(d.Algorithm),
		Version:        d.Version,
		Status:         d.Status,
		IsDefault:      d.IsDefault,
		CreatedAt:      grpcUnixToTime(d.CreatedAt),
		RotatedAt:      grpcUnixToTime(d.RotatedAt),
		Description:    d.Description,
		BackendType:    d.BackendType,
		UsageCount:     d.UsageCount,
		BytesUsed:      d.BytesUsed,
		MaxUsageCount:  d.MaxUsageCount,
		MaxBytesUsed:   d.MaxBytesUsed,
		WarningPercent: d.WarningPercent,
	}
	if p := resp.ReencryptionProgress; p != nil {
		result.ReencryptionInProgress = p.InProgress
		result.ProcessedKeys = int64(p.ProcessedKeys)
		result.TotalKeys = int64(p.TotalKeys)
		result.FailedKeys = int64(p.FailedKeys)
		result.ReencryptionStartedAt = grpcUnixToTime(p.StartedAt)
		result.EstimatedCompletion = grpcUnixToTime(p.EstimatedCompletion)
	}
	return result, nil
}
