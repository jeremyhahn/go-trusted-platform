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

//go:build codec_msgpack

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newDEKTestHandler serves the gRPC DEKServerAdapter over client through the
// QUIC handler, with no KMS key service, as the DEK subs need none.
func newDEKTestHandler(client *fakeDEKClient) *QUICServiceHandler {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetDEKService(NewDEKServerAdapter(client, slog.Default()))
	return handler
}

func TestHandleKMSExtendedCategoryDEK(t *testing.T) {
	ctx := context.Background()
	client := &fakeDEKClient{info: testDEKInfo()}
	handler := newDEKTestHandler(client)

	t.Run("Create", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubCreateDEK,
			&pb.CreateDEKRequest{Path: "tenants/a/dek", Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, MaxOperations: 100}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.CreateDEKResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, uint64(3), out.GetDek().GetVersion())
		assert.Equal(t, uint64(100), client.lastCreate.MaxOperations)
	})

	t.Run("List", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubListDEKs,
			&pb.ListDEKsRequest{Prefix: "tenants/", Recursive: true}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.ListDEKsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.Len(t, out.GetDeks(), 1)
		assert.Equal(t, "tenants/", client.lastList.Prefix)
		assert.True(t, client.lastList.Recursive)
	})

	t.Run("Get", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetDEK,
			&pb.GetDEKRequest{Path: "tenants/a/dek"}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.GetDEKResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.True(t, out.GetDek().GetIsDefault())
		assert.Equal(t, "tenants/a/dek", client.lastPath)
	})

	t.Run("Status", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetDEKStatus,
			&pb.GetDEKStatusRequest{Path: "tenants/a/dek"}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.GetDEKStatusResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.InDelta(t, 50.0, out.GetUsagePercent(), 0.001)
		assert.True(t, out.GetReencryptionProgress().GetInProgress())
	})

	t.Run("Rotate", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubRotateDEK,
			&pb.RotateDEKRequest{Path: "tenants/a/dek", Background: true}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.RotateDEKResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, uint64(2), out.GetNewVersion())
		assert.True(t, client.lastRotate.Background)
	})

	t.Run("Delete", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubDeleteDEK,
			&pb.DeleteDEKRequest{Path: "tenants/a/dek", Force: true}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.DeleteDEKResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.True(t, out.GetDeleted())
		assert.True(t, client.lastDelete.Force)
	})

	t.Run("SetDefault", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubSetDefaultDEK,
			&pb.SetDefaultDEKRequest{Path: "tenants/a/new"}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.SetDefaultDEKResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "tenants/a/new", out.GetPath())
		assert.Equal(t, "tenants/a/old", out.GetPreviousDefault())
		assert.Equal(t, "tenants/a/new", client.lastPath)
	})

	t.Run("SetSafety", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubSetDEKSafety,
			&pb.SetDEKSafetyRequest{Path: "tenants/a/dek", MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.SetDEKSafetyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "tenants/a/dek", out.GetPath())
		require.NotNil(t, client.lastSafety)
		assert.Equal(t, uint64(1000), client.lastSafety.MaxOperations)
		assert.Equal(t, uint64(4096), client.lastSafety.MaxBytes)
		assert.Equal(t, 75, client.lastSafety.WarningPercent)
	})

	t.Run("ClearSafety", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubClearDEKSafety,
			&pb.ClearDEKSafetyRequest{Path: "tenants/a/cleared"}))
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out pb.ClearDEKSafetyResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, "tenants/a/cleared", out.GetPath())
		assert.Equal(t, "tenants/a/cleared", client.lastPath)
	})
}

// TestHandleKMSExtendedCategoryDEKErrors holds each DEK sub to the class the
// gRPC method answers for the same input.
func TestHandleKMSExtendedCategoryDEKErrors(t *testing.T) {
	ctx := context.Background()
	requests := map[string]struct {
		sub     byte
		valid   interface{}
		noPath  interface{}
		failing byte
	}{
		"Create":      {quicwire.KMSSubCreateDEK, &pb.CreateDEKRequest{Path: "p"}, &pb.CreateDEKRequest{}, quicwire.StatusInternalError},
		"Get":         {quicwire.KMSSubGetDEK, &pb.GetDEKRequest{Path: "p"}, &pb.GetDEKRequest{}, quicwire.StatusNotFound},
		"Status":      {quicwire.KMSSubGetDEKStatus, &pb.GetDEKStatusRequest{Path: "p"}, &pb.GetDEKStatusRequest{}, quicwire.StatusNotFound},
		"Rotate":      {quicwire.KMSSubRotateDEK, &pb.RotateDEKRequest{Path: "p"}, &pb.RotateDEKRequest{}, quicwire.StatusInternalError},
		"Delete":      {quicwire.KMSSubDeleteDEK, &pb.DeleteDEKRequest{Path: "p"}, &pb.DeleteDEKRequest{}, quicwire.StatusInternalError},
		"SetDefault":  {quicwire.KMSSubSetDefaultDEK, &pb.SetDefaultDEKRequest{Path: "p"}, &pb.SetDefaultDEKRequest{}, quicwire.StatusInternalError},
		"SetSafety":   {quicwire.KMSSubSetDEKSafety, &pb.SetDEKSafetyRequest{Path: "p"}, &pb.SetDEKSafetyRequest{}, quicwire.StatusInternalError},
		"ClearSafety": {quicwire.KMSSubClearDEKSafety, &pb.ClearDEKSafetyRequest{Path: "p"}, &pb.ClearDEKSafetyRequest{}, quicwire.StatusInternalError},
	}

	for name, tc := range requests {
		t.Run(name, func(t *testing.T) {
			handler := newDEKTestHandler(&fakeDEKClient{info: testDEKInfo()})
			resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, tc.sub, tc.noPath))
			assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "missing path")

			resp = handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpKMSExtendedCategory, Payload: []byte{tc.sub, 0xC1}})
			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "undecodable payload")

			failing := newDEKTestHandler(&fakeDEKClient{err: errKMSLifecycleMock{method: name}})
			resp = failing.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, tc.sub, tc.valid))
			assert.Equal(t, tc.failing, resp.Status, "SDK failure")
		})
	}

	t.Run("ListFailure", func(t *testing.T) {
		failing := newDEKTestHandler(&fakeDEKClient{err: errKMSLifecycleMock{method: "ListDEKs"}})
		resp := failing.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubListDEKs, &pb.ListDEKsRequest{}))
		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("NoDEKService", func(t *testing.T) {
		handler := newTestQUICServiceHandler(logging.DefaultLogger())
		resp := handler.HandleRequest(ctx, kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetDEK, &pb.GetDEKRequest{Path: "p"}))
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

// connectDEKQUIC serves the gRPC DEKServerAdapter over client through the
// daemon's QUIC handler, which authorizes each DEK sub with the scope its
// gRPC method requires, and returns a DEKManagement client on the SDK's QUIC
// adapter for a caller holding scopes.
func connectDEKQUIC(t *testing.T, client dekclient.Client, scopes ...string) pb.DEKManagementClient {
	t.Helper()
	validator := &quicScopeValidator{scopes: scopes}
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	require.NoError(t, err)
	handler.SetDEKService(NewDEKServerAdapter(client, slog.Default()))
	bundle := testutil.GenerateTestTLSBundle(t)
	conn := newPhase35QUICClient(t, handler, bundle, platform.WithBearerToken("operator-token")).Connection()
	return pb.NewDEKManagementClient(conn)
}

// TestSDKQUIC_DEK drives the nine DEK methods through the SDK's QUIC adapter
// and the daemon's OpKMSExtendedCategory handler into the adapter the gRPC
// transport serves.
func TestSDKQUIC_DEK(t *testing.T) {
	// The fake's recorded requests are read only by the in-process tests,
	// since the race detector cannot see ordering through the socket.
	deks := connectDEKQUIC(t, &fakeDEKClient{info: testDEKInfo()}, "kms:read", "kms:write", "kms:delete")
	ctx := context.Background()

	created, err := deks.CreateDEK(ctx, &pb.CreateDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), created.GetDek().GetVersion())

	list, err := deks.ListDEKs(ctx, &pb.ListDEKsRequest{Prefix: "tenants/"})
	require.NoError(t, err)
	require.Len(t, list.GetDeks(), 1)

	got, err := deks.GetDEK(ctx, &pb.GetDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, "tenants/a/dek", got.GetDek().GetPath())

	st, err := deks.GetDEKStatus(ctx, &pb.GetDEKStatusRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.InDelta(t, 50.0, st.GetUsagePercent(), 0.001)

	rotated, err := deks.RotateDEK(ctx, &pb.RotateDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), rotated.GetNewVersion())

	deleted, err := deks.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.True(t, deleted.GetDeleted())

	def, err := deks.SetDefaultDEK(ctx, &pb.SetDefaultDEKRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, "tenants/a/old", def.GetPreviousDefault())

	safety, err := deks.SetDEKSafety(ctx, &pb.SetDEKSafetyRequest{Path: "tenants/a/dek", MaxOperations: 10})
	require.NoError(t, err)
	assert.Equal(t, "tenants/a/dek", safety.GetPath())

	cleared, err := deks.ClearDEKSafety(ctx, &pb.ClearDEKSafetyRequest{Path: "tenants/a/dek"})
	require.NoError(t, err)
	assert.Equal(t, "tenants/a/dek", cleared.GetPath())
}

// TestSDKQUIC_DEKRefuse checks the QUIC path refuses a read-only caller's
// rotate and delete, a missing path and an SDK failure with the codes gRPC
// gives.
func TestSDKQUIC_DEKRefuse(t *testing.T) {
	ctx := context.Background()

	readOnly := connectDEKQUIC(t, &fakeDEKClient{info: testDEKInfo()}, "kms:read")
	_, err := readOnly.RotateDEK(ctx, &pb.RotateDEKRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "rotate needs kms:write: %v", err)
	_, err = readOnly.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "delete needs kms:delete: %v", err)
	_, err = readOnly.SetDefaultDEK(ctx, &pb.SetDefaultDEKRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "set-default needs kms:write: %v", err)
	_, err = readOnly.SetDEKSafety(ctx, &pb.SetDEKSafetyRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "set-safety needs kms:write: %v", err)
	_, err = readOnly.ClearDEKSafety(ctx, &pb.ClearDEKSafetyRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "clear-safety needs kms:write: %v", err)
	_, err = readOnly.GetDEK(ctx, &pb.GetDEKRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "missing path: %v", err)

	failing := connectDEKQUIC(t, &fakeDEKClient{err: errKMSLifecycleMock{method: "GetDEK"}}, "kms:read", "kms:write")
	_, err = failing.GetDEK(ctx, &pb.GetDEKRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.NotFound, status.Code(err), "SDK get failure: %v", err)
	_, err = failing.CreateDEK(ctx, &pb.CreateDEKRequest{Path: "tenants/a/dek"})
	assert.Equal(t, codes.Internal, status.Code(err), "SDK create failure: %v", err)
}
