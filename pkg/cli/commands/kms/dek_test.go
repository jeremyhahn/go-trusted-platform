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

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

var errDEKBackend = errors.New("dek backend unavailable")

// fakeDEKClient implements quicbaassdk.DEKClient. Each verb records its
// request and returns the configured response or err.
type fakeDEKClient struct {
	err error

	info        *dek.DEKInfo
	createReq   *dek.CreateDEKRequest
	listReq     *dek.ListDEKsRequest
	listResp    *dek.ListDEKsResponse
	rotateReq   *dek.RotateDEKRequest
	rotateResp  *dek.RotateDEKResponse
	deleteReq   *dek.DeleteDEKRequest
	deleteResp  *dek.DeleteDEKResponse
	statusResp  *dek.DEKStatusResponse
	defaultResp *dek.SetDefaultDEKResponse
	safetyReq   *dek.SetDEKSafetyRequest
	path        string
}

func (f *fakeDEKClient) CreateDEK(_ context.Context, req *dek.CreateDEKRequest) (*dek.CreateDEKResponse, error) {
	f.createReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &dek.CreateDEKResponse{DEK: f.info}, nil
}

func (f *fakeDEKClient) GetDEK(_ context.Context, path string) (*dek.DEKInfo, error) {
	f.path = path
	return f.info, f.err
}

func (f *fakeDEKClient) ListDEKs(_ context.Context, req *dek.ListDEKsRequest) (*dek.ListDEKsResponse, error) {
	f.listReq = req
	return f.listResp, f.err
}

func (f *fakeDEKClient) RotateDEK(_ context.Context, req *dek.RotateDEKRequest) (*dek.RotateDEKResponse, error) {
	f.rotateReq = req
	return f.rotateResp, f.err
}

func (f *fakeDEKClient) DeleteDEK(_ context.Context, req *dek.DeleteDEKRequest) (*dek.DeleteDEKResponse, error) {
	f.deleteReq = req
	return f.deleteResp, f.err
}

func (f *fakeDEKClient) GetDEKStatus(_ context.Context, path string) (*dek.DEKStatusResponse, error) {
	f.path = path
	return f.statusResp, f.err
}

func (f *fakeDEKClient) SetDefaultDEK(_ context.Context, path string) (*dek.SetDefaultDEKResponse, error) {
	f.path = path
	return f.defaultResp, f.err
}

func (f *fakeDEKClient) SetDEKSafety(_ context.Context, req *dek.SetDEKSafetyRequest) error {
	f.safetyReq = req
	return f.err
}

func (f *fakeDEKClient) ClearDEKSafety(_ context.Context, path string) error {
	f.path = path
	return f.err
}

func (f *fakeDEKClient) StartReencryption(_ context.Context, _ *dek.StartReencryptionRequest) (*dek.StartReencryptionResponse, error) {
	return nil, errDEKBackend
}

func (f *fakeDEKClient) GetReencryptionProgress(_ context.Context, _ *dek.GetReencryptionProgressRequest) (*dek.ReencryptionProgressResponse, error) {
	return nil, errDEKBackend
}

var testDEKCreatedAt = time.Unix(1700000000, 0)

func testDEKInfo() *dek.DEKInfo {
	return &dek.DEKInfo{
		Path:           "/tenant/app/default",
		Algorithm:      "AES-256-GCM",
		Version:        2,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      testDEKCreatedAt,
		Description:    "app data",
		BackendType:    "software",
		UsageCount:     5,
		BytesUsed:      640,
		MaxUsageCount:  1000,
		MaxBytesUsed:   1 << 20,
		WarningPercent: 80,
	}
}

// printDEKJSON returns a JSON printer and the buffer it writes to.
func printDEKJSON() (*cli.Printer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, out), out
}

func decodeDEKJSON(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got), out.String())
	return got
}

func assertDEKOperationFailed(t *testing.T, err error, operation string) {
	t.Helper()
	var opErr ErrDEKOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, operation, opErr.Operation)
	assert.ErrorIs(t, err, errDEKBackend)
}

func TestSetDEKClientFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		fake := &fakeDEKClient{}
		restore := SetDEKClientFactory(func(base *cli.BaseCommand) (quicbaassdk.DEKClient, error) {
			return fake, nil
		})

		client, err := openDEKClient(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)

		restore()
		assert.NotNil(t, activeDEKClientFactory)
	})

	t.Run("FactoryError", func(t *testing.T) {
		restore := SetDEKClientFactory(func(base *cli.BaseCommand) (quicbaassdk.DEKClient, error) {
			return nil, errDEKBackend
		})
		defer restore()

		_, err := openDEKClient(nil)
		assert.ErrorIs(t, err, errDEKBackend)
	})
}

func TestExecuteDEKCreate(t *testing.T) {
	req := dek.CreateDEKRequest{Path: "/tenant/app/default", Algorithm: "AES-256-GCM", MaxOperations: 1000}

	t.Run("PrintsDEKEnvelope", func(t *testing.T) {
		fake := &fakeDEKClient{info: testDEKInfo()}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKCreate(context.Background(), fake, printer, req))

		assert.Equal(t, req, *fake.createReq)
		got := decodeDEKJSON(t, out)
		created, ok := got["dek"].(map[string]any)
		require.True(t, ok, out.String())
		assert.Equal(t, "/tenant/app/default", created["path"])
		assert.Equal(t, float64(2), created["version"])
		assert.Equal(t, float64(testDEKCreatedAt.Unix()), created["created_at"])
		assert.Equal(t, true, created["is_default"])
		assert.NotContains(t, created, "rotated_at", "a zero rotation time is omitted")
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKCreate(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, req)
		assertDEKOperationFailed(t, err, "create")
		assert.Contains(t, err.Error(), req.Path)
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKCreate(context.Background(), &fakeDEKClient{}, printer, req)
		var empty ErrDEKEmptyResponse
		require.ErrorAs(t, err, &empty)
		assert.Equal(t, "create", empty.Operation)
	})
}

func TestExecuteDEKGet(t *testing.T) {
	t.Run("PrintsDEKEnvelope", func(t *testing.T) {
		fake := &fakeDEKClient{info: testDEKInfo()}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKGet(context.Background(), fake, printer, "/tenant/app/default"))

		assert.Equal(t, "/tenant/app/default", fake.path)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, "AES-256-GCM", got["dek"].(map[string]any)["algorithm"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKGet(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, "/missing")
		assertDEKOperationFailed(t, err, "get")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		var empty ErrDEKEmptyResponse
		require.ErrorAs(t, executeDEKGet(context.Background(), &fakeDEKClient{}, printer, "/missing"), &empty)
	})
}

func TestExecuteDEKList(t *testing.T) {
	req := dek.ListDEKsRequest{Prefix: "/tenant", Recursive: true, Limit: 1}

	t.Run("ReportsHasMore", func(t *testing.T) {
		fake := &fakeDEKClient{listResp: &dek.ListDEKsResponse{DEKs: []dek.DEKInfo{*testDEKInfo()}, TotalCount: 3}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKList(context.Background(), fake, printer, req))

		assert.Equal(t, req, *fake.listReq)
		got := decodeDEKJSON(t, out)
		assert.Len(t, got["deks"], 1)
		assert.Equal(t, float64(3), got["total_count"])
		assert.Equal(t, true, got["has_more"])
	})

	t.Run("EmptyListIsAnArray", func(t *testing.T) {
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKList(context.Background(), &fakeDEKClient{}, printer, req))

		got := decodeDEKJSON(t, out)
		assert.Equal(t, []any{}, got["deks"])
		assert.Equal(t, false, got["has_more"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKList(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, req)
		assertDEKOperationFailed(t, err, "list")
	})
}

func TestExecuteDEKDelete(t *testing.T) {
	req := dek.DeleteDEKRequest{Path: "/tenant/app/old", Force: true, MigrateTo: "/tenant/app/default"}

	t.Run("PrintsResult", func(t *testing.T) {
		fake := &fakeDEKClient{deleteResp: &dek.DeleteDEKResponse{Path: req.Path, Deleted: true}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKDelete(context.Background(), fake, printer, req))

		assert.Equal(t, req, *fake.deleteReq)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, req.Path, got["path"])
		assert.Equal(t, true, got["deleted"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKDelete(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, req)
		assertDEKOperationFailed(t, err, "delete")
	})
}

func TestExecuteDEKRotate(t *testing.T) {
	req := dek.RotateDEKRequest{Path: "/tenant/app/default", Background: true}

	t.Run("PrintsVersions", func(t *testing.T) {
		fake := &fakeDEKClient{rotateResp: &dek.RotateDEKResponse{OldVersion: 2, NewVersion: 3}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKRotate(context.Background(), fake, printer, req))

		assert.Equal(t, req, *fake.rotateReq)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, req.Path, got["path"], "the request path fills an empty response path")
		assert.Equal(t, float64(2), got["old_version"])
		assert.Equal(t, float64(3), got["new_version"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKRotate(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, req)
		assertDEKOperationFailed(t, err, "rotate")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		var empty ErrDEKEmptyResponse
		require.ErrorAs(t, executeDEKRotate(context.Background(), &fakeDEKClient{}, printer, req), &empty)
	})
}

func TestExecuteDEKStatus(t *testing.T) {
	t.Run("FlattensReencryptionProgress", func(t *testing.T) {
		fake := &fakeDEKClient{statusResp: &dek.DEKStatusResponse{
			DEK: testDEKInfo(),
			ReencryptionProgress: &dek.ReencryptionProgress{
				InProgress:    true,
				TotalKeys:     10,
				ProcessedKeys: 4,
				StartedAt:     testDEKCreatedAt,
			},
		}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKStatus(context.Background(), fake, printer, "/tenant/app/default"))

		got := decodeDEKJSON(t, out)
		assert.Equal(t, "/tenant/app/default", got["path"])
		assert.Equal(t, float64(5), got["usage_count"])
		assert.Equal(t, true, got["reencryption_in_progress"])
		assert.Equal(t, float64(4), got["processed_keys"])
		assert.Equal(t, float64(10), got["total_keys"])
		assert.Equal(t, float64(testDEKCreatedAt.Unix()), got["reencryption_started_at"])
	})

	t.Run("NoProgress", func(t *testing.T) {
		fake := &fakeDEKClient{statusResp: &dek.DEKStatusResponse{DEK: testDEKInfo()}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKStatus(context.Background(), fake, printer, "/tenant/app/default"))

		assert.Equal(t, false, decodeDEKJSON(t, out)["reencryption_in_progress"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKStatus(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, "/x")
		assertDEKOperationFailed(t, err, "status")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		var empty ErrDEKEmptyResponse
		require.ErrorAs(t, executeDEKStatus(context.Background(), &fakeDEKClient{}, printer, "/x"), &empty)
	})
}

func TestExecuteDEKSetDefault(t *testing.T) {
	t.Run("PrintsPreviousDefault", func(t *testing.T) {
		fake := &fakeDEKClient{defaultResp: &dek.SetDefaultDEKResponse{Path: "/tenant/app/new", PreviousDefault: "/tenant/app/old"}}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKSetDefault(context.Background(), fake, printer, "/tenant/app/new"))

		assert.Equal(t, "/tenant/app/new", fake.path)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, "/tenant/app/old", got["previous_default"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKSetDefault(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, "/x")
		assertDEKOperationFailed(t, err, "set-default")
	})
}

func TestExecuteDEKSetSafety(t *testing.T) {
	req := dek.SetDEKSafetyRequest{Path: "/tenant/app/default", MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75}

	t.Run("PrintsLimits", func(t *testing.T) {
		fake := &fakeDEKClient{}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKSetSafety(context.Background(), fake, printer, req))

		assert.Equal(t, req, *fake.safetyReq)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, float64(1000), got["max_operations"])
		assert.Equal(t, float64(75), got["warning_percent"])
		assert.Equal(t, false, got["cleared"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKSetSafety(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, req)
		assertDEKOperationFailed(t, err, "set-safety")
	})
}

func TestExecuteDEKClearSafety(t *testing.T) {
	t.Run("PrintsCleared", func(t *testing.T) {
		fake := &fakeDEKClient{}
		printer, out := printDEKJSON()

		require.NoError(t, executeDEKClearSafety(context.Background(), fake, printer, "/tenant/app/default"))

		assert.Equal(t, "/tenant/app/default", fake.path)
		assert.Equal(t, true, decodeDEKJSON(t, out)["cleared"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeDEKClearSafety(context.Background(), &fakeDEKClient{err: errDEKBackend}, printer, "/x")
		assertDEKOperationFailed(t, err, "clear-safety")
	})
}

func TestDEKCommandFlags(t *testing.T) {
	cmd := NewDEKCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	create, _, err := cmd.Find([]string{"create"})
	require.NoError(t, err)
	algorithm := create.Flags().Lookup("algorithm")
	require.NotNil(t, algorithm)
	assert.Equal(t, defaultDEKAlgorithm, algorithm.DefValue)
	for _, name := range []string{"description", "max-operations", "max-bytes", "warning-percent"} {
		assert.NotNil(t, create.Flags().Lookup(name), "create --%s", name)
	}

	setDefault, _, err := cmd.Find([]string{"set-default"})
	require.NoError(t, err)
	assert.Error(t, setDefault.Args(setDefault, []string{"/a", "2"}), "set-default takes the path only")
	assert.NoError(t, setDefault.Args(setDefault, []string{"/a"}))

	list, _, err := cmd.Find([]string{"list"})
	require.NoError(t, err)
	assert.Nil(t, list.Flags().Lookup("cursor"), "the SDK has no list cursor")
}

func TestErrDEKOperationFailedMessage(t *testing.T) {
	withPath := ErrDEKOperationFailed{Operation: "get", Path: "/a", Err: errDEKBackend}
	assert.Equal(t, "dek get failed for /a: dek backend unavailable", withPath.Error())

	noPath := ErrDEKOperationFailed{Operation: "list", Err: errDEKBackend}
	assert.Equal(t, "dek list failed: dek backend unavailable", noPath.Error())

	empty := ErrDEKEmptyResponse{Operation: "get", Path: "/a"}
	assert.Equal(t, "dek get returned no DEK for /a", empty.Error())
}
