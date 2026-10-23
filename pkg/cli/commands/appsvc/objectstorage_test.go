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

package appsvc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestObjectStoragePut_ReadsTheDataFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.bin")
	require.NoError(t, os.WriteFile(path, []byte{0x00, 0xFF, 0x10}, 0o600))
	conn := &fakeConn{}
	withFakeConn(t, conn)

	require.NoError(t, execute(&cli.CommonFlags{}, "objectstorage", "put", "docs:report.bin", "--file", path, "--backend", "default"))
	want := &platformv1.PutObjectRequest{Key: "docs:report.bin", Value: []byte{0x00, 0xFF, 0x10}, TargetBackend: "default"}
	assert.True(t, proto.Equal(want, conn.request), "sent %v, want %v", conn.request, want)
}

func TestObjectStoragePut_RefusesAmbiguousOrMissingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.txt")
	require.NoError(t, os.WriteFile(path, []byte("a"), 0o600))
	for name, args := range map[string][]string{
		"data and file": {"objectstorage", "put", "docs:a.txt", "inline", "--file", path},
		"neither":       {"objectstorage", "put", "docs:a.txt"},
	} {
		t.Run(name, func(t *testing.T) {
			conn := &fakeConn{}
			withFakeConn(t, conn)
			assert.ErrorIs(t, execute(&cli.CommonFlags{}, args...), ErrObjectData{})
			assert.Empty(t, conn.method, "no call is made")
		})
	}
}

func TestObjectStoragePut_SurfacesAnUnreadableFile(t *testing.T) {
	conn := &fakeConn{}
	withFakeConn(t, conn)

	err := execute(&cli.CommonFlags{}, "objectstorage", "put", "docs:a.txt", "--file", filepath.Join(t.TempDir(), "missing"))
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "error = %v", err)
	assert.Contains(t, wrapped.Msg, "failed to read --file")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Empty(t, conn.method, "no call is made")
}

func TestObjectStoragePut_SendsNoPolicyWithoutItsFlags(t *testing.T) {
	request := (&putOptions{}).request("docs:a.txt", []byte("a"))
	assert.Nil(t, request.GetReplicationPolicy())
	assert.Nil(t, request.GetArchivePolicy())
	assert.Nil(t, request.GetRetentionPolicy())
}

func TestObjectStorageList_PrintsOneRowPerObject(t *testing.T) {
	conn := &fakeConn{replies: map[string]proto.Message{
		platformv1.ObjectStorageService_ListObjects_FullMethodName: &platformv1.ListObjectsResponse{Objects: []*platformv1.ObjectSummary{
			{Key: "docs:a.txt", Size: 5, ContentType: "text/plain", Version: 2, Status: "active", ModifiedAtUnixMs: 1791878400000},
			{Key: "docs:b.txt"},
		}},
	}}
	printed := withFakeConn(t, conn)

	require.NoError(t, execute(&cli.CommonFlags{}, "objectstorage", "list"))
	table, ok := (*printed).(*cli.TableData)
	require.True(t, ok, "printed %T", *printed)
	assert.Equal(t, []string{"KEY", "SIZE", "CONTENT TYPE", "VERSION", "STATUS", "MODIFIED AT"}, table.Headers)
	require.Len(t, table.Rows, 2)
	assert.Equal(t, []string{"docs:a.txt", "5", "text/plain", "2", "active", "2026-10-13T08:00:00Z"}, table.Rows[0])
	assert.Equal(t, "never", table.Rows[1][5])
}

func TestErrObjectData(t *testing.T) {
	assert.Contains(t, ErrObjectData{}.Error(), "--file")
}
