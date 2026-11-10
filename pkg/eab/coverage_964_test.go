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

package eab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errStorage964 is the storage failure injected into the mock storage.
type errStorage964 struct{}

func (errStorage964) Error() string { return "injected storage failure" }

// TestDelivery_FileExportFailures964 verifies that both file exporters
// report ErrFileExportFailed, carrying the requested path and the cause,
// when the parent directory cannot be created or the file cannot be written.
func TestDelivery_FileExportFailures964(t *testing.T) {
	delivery := NewDelivery(DefaultDeliveryConfig())

	exporters := map[string]func(*Credential, string) error{
		"ToFile":       delivery.ToFile,
		"ToQRCodeFile": delivery.ToQRCodeFile,
	}

	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{
			name: "parent is a regular file",
			path: func(t *testing.T) string {
				parent := filepath.Join(t.TempDir(), "not-a-dir")
				require.NoError(t, os.WriteFile(parent, []byte("x"), 0600))
				return filepath.Join(parent, "cred.out")
			},
		},
		{
			name: "target is a directory",
			path: func(t *testing.T) string {
				target := filepath.Join(t.TempDir(), "dir-target")
				require.NoError(t, os.Mkdir(target, 0750))
				return target
			},
		},
	}

	for exporterName, export := range exporters {
		for _, tt := range tests {
			t.Run(exporterName+"/"+tt.name, func(t *testing.T) {
				path := tt.path(t)

				err := export(testCredential(), path)

				var exportErr ErrFileExportFailed
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, path, exportErr.Path)
				assert.Error(t, exportErr.Cause)
			})
		}
	}
}

// TestDelivery_ToQRCodeFile_ContentMatchesToQRCode964 verifies the file
// holds exactly the PNG bytes ToQRCode produces.
func TestDelivery_ToQRCodeFile_ContentMatchesToQRCode964(t *testing.T) {
	delivery := NewDelivery(DefaultDeliveryConfig())
	cred := testCredential()
	path := filepath.Join(t.TempDir(), "nested", "cred.png")

	require.NoError(t, delivery.ToQRCodeFile(cred, path))

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	expected, err := delivery.ToQRCode(cred)
	require.NoError(t, err)
	assert.Equal(t, expected, written)
}

// TestQuicBaaSDAO_FindByKeyID_Failures964 covers the index and scan failure
// paths of FindByKeyID.
func TestQuicBaaSDAO_FindByKeyID_Failures964(t *testing.T) {
	ctx := context.Background()

	t.Run("malformed index result is a deserialization error", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		mockStorage.SetQueryResult(entityTypeEABCredential, "KeyID", []byte("bad-json"), []*service.Entity{
			{ID: 1, Data: []byte("{not json")},
		})

		found, err := dao.FindByKeyID(ctx, "bad-json")

		assert.Nil(t, found)
		var deserErr quicbaas.ErrDeserializationFailed
		require.ErrorAs(t, err, &deserErr)
		assert.Equal(t, entityTypeEABCredential, deserErr.EntityType)
	})

	t.Run("query failure falls back to the scan", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		require.NoError(t, dao.Save(ctx, &EABCredential{ID: 7, KeyID: "scan-key", ProfileID: 1}))
		mockStorage.QueryError = errStorage964{}

		found, err := dao.FindByKeyID(ctx, "scan-key")

		require.NoError(t, err)
		assert.Equal(t, uint64(7), found.ID)
	})

	t.Run("scan failure is returned", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		mockStorage.QueryError = errStorage964{}
		mockStorage.ListError = errStorage964{}

		found, err := dao.FindByKeyID(ctx, "any-key")

		assert.Nil(t, found)
		require.Error(t, err)
		var notFound quicbaas.ErrNotFoundByIndex
		assert.False(t, errors.As(err, &notFound), "a storage failure must not be reported as not found")
	})
}

// TestQuicBaaSDAO_DeleteExpired_Failures964 covers the error and partial
// failure paths of DeleteExpired.
func TestQuicBaaSDAO_DeleteExpired_Failures964(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("listing failure is returned with zero deleted", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		mockStorage.ListError = errStorage964{}

		deleted, err := dao.DeleteExpired(ctx, now)

		require.Error(t, err)
		assert.Zero(t, deleted)
	})

	t.Run("delete failures are skipped and not counted", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		for i := uint64(1); i <= 2; i++ {
			require.NoError(t, dao.Save(ctx, &EABCredential{
				ID:        i,
				KeyID:     "expired",
				ExpiresAt: now.Add(-time.Hour).Unix(),
				ProfileID: 1,
			}))
		}
		mockStorage.DeleteError = errStorage964{}

		deleted, err := dao.DeleteExpired(ctx, now)

		require.NoError(t, err)
		assert.Zero(t, deleted)
		count, err := dao.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})
}
