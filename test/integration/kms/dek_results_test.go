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

//go:build integration

package kms

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

func testDEKMetadata() *pb.DEKMetadata {
	return &pb.DEKMetadata{
		Path:           "tenant/a",
		Algorithm:      pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		Version:        3,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      1_700_000_000,
		RotatedAt:      1_700_000_100,
		Description:    "dek",
		BackendType:    "software",
		UsageCount:     7,
		BytesUsed:      70,
		MaxUsageCount:  100,
		MaxBytesUsed:   1000,
		WarningPercent: 80,
	}
}

func TestNewCreateDEKRequest(t *testing.T) {
	req := newCreateDEKRequest(DEKCreateOptions{
		Path:           "tenant/a",
		Algorithm:      "AES-256-GCM",
		Description:    "dek",
		MaxOperations:  10,
		MaxBytes:       20,
		WarningPercent: 75,
	})
	assert.Equal(t, "tenant/a", req.Path)
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, req.Algorithm)
	assert.Equal(t, "dek", req.Description)
	assert.Equal(t, uint64(10), req.MaxOperations)
	assert.Equal(t, uint64(20), req.MaxBytes)
	assert.Equal(t, int32(75), req.WarningPercent)
}

func TestNewListDEKsRequest(t *testing.T) {
	req := newListDEKsRequest(DEKListOptions{Prefix: "tenant/", Recursive: true, Limit: 5, Cursor: "c"})
	assert.Equal(t, "tenant/", req.Prefix)
	assert.True(t, req.Recursive)
	assert.Equal(t, int32(5), req.Limit)
	assert.Equal(t, "c", req.Cursor)
}

func TestDEKCreateResult(t *testing.T) {
	got, err := dekCreateResult(&pb.CreateDEKResponse{Dek: testDEKMetadata()})
	require.NoError(t, err)
	assert.Equal(t, "tenant/a", got.Path)
	assert.Equal(t, "AES-256-GCM", got.Algorithm)
	assert.Equal(t, uint64(3), got.Version)
	assert.Equal(t, time.Unix(1_700_000_000, 0), got.CreatedAt)
}

func TestDEKGetResult(t *testing.T) {
	got, err := dekGetResult(&pb.GetDEKResponse{Dek: testDEKMetadata()})
	require.NoError(t, err)
	assert.Equal(t, "active", got.Status)
	assert.True(t, got.IsDefault)
	assert.Equal(t, "software", got.BackendType)
	assert.Equal(t, uint64(1000), got.MaxBytesUsed)
	assert.Equal(t, int32(80), got.WarningPercent)
	assert.Equal(t, time.Unix(1_700_000_100, 0), got.RotatedAt)
}

func TestDEKListResult(t *testing.T) {
	got := dekListResult(&pb.ListDEKsResponse{
		Deks:       []*pb.DEKMetadata{testDEKMetadata()},
		HasMore:    true,
		NextCursor: "next",
	})
	require.Len(t, got.DEKs, 1)
	assert.Equal(t, "tenant/a", got.DEKs[0].Path)
	assert.Equal(t, "AES-256-GCM", got.DEKs[0].Algorithm)
	assert.True(t, got.HasMore)
	assert.Equal(t, "next", got.NextCursor)

	empty := dekListResult(&pb.ListDEKsResponse{})
	assert.NotNil(t, empty.DEKs, "an empty list must not be nil")
	assert.Empty(t, empty.DEKs)
}

func TestDEKStatusResult(t *testing.T) {
	got, err := dekStatusResult(&pb.GetDEKStatusResponse{
		Dek: testDEKMetadata(),
		ReencryptionProgress: &pb.ReencryptionProgress{
			InProgress:    true,
			ProcessedKeys: 4,
			TotalKeys:     10,
			FailedKeys:    1,
			StartedAt:     1_700_000_200,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant/a", got.Path)
	assert.True(t, got.ReencryptionInProgress)
	assert.Equal(t, int64(4), got.ProcessedKeys)
	assert.Equal(t, int64(10), got.TotalKeys)
	assert.Equal(t, int64(1), got.FailedKeys)
	assert.Equal(t, time.Unix(1_700_000_200, 0), got.ReencryptionStartedAt)
	assert.True(t, got.EstimatedCompletion.IsZero(), "an unset estimate must stay zero")

	idle, err := dekStatusResult(&pb.GetDEKStatusResponse{Dek: testDEKMetadata()})
	require.NoError(t, err)
	assert.False(t, idle.ReencryptionInProgress)
}

func TestDEKResults_MissingDEK(t *testing.T) {
	results := map[string]func() error{
		"CreateDEK": func() error {
			_, err := dekCreateResult(&pb.CreateDEKResponse{})
			return err
		},
		"GetDEK": func() error {
			_, err := dekGetResult(&pb.GetDEKResponse{})
			return err
		},
		"GetDEKStatus": func() error {
			_, err := dekStatusResult(&pb.GetDEKStatusResponse{})
			return err
		},
	}
	for op, run := range results {
		var missing ErrDEKMissingInResponse
		require.True(t, errors.As(run(), &missing), op)
		assert.Equal(t, op, missing.Operation)
		assert.Equal(t, op+": response carries no DEK", missing.Error())
	}
}
