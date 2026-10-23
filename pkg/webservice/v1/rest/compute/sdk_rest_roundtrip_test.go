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

package compute

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// recordingComputeServer captures the request each container method
// receives, so a test can assert what crossed the wire.
type recordingComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
	deleted  *platformv1.DeleteContainerRequest
	started  *platformv1.StartContainerRequest
	stopped  *platformv1.StopContainerRequest
	attested *platformv1.AttestContainerRequest
	listed   *platformv1.ListVMsRequest
	snapshot *platformv1.GetSnapshotRequest
	prepared *platformv1.PrepareMigrationRequest
	finished *platformv1.FinalizeMigrationRequest
}

// PrepareMigration hands every inbound migration receiver "recv-1".
func (s *recordingComputeServer) PrepareMigration(_ context.Context, req *platformv1.PrepareMigrationRequest) (*platformv1.PrepareMigrationResponse, error) {
	s.prepared = req
	return &platformv1.PrepareMigrationResponse{ReceiverId: "recv-1", Port: 49152, TlsHostname: "node-2"}, nil
}

// FinalizeMigration knows one receiver, "recv-1"; any other id is NotFound.
func (s *recordingComputeServer) FinalizeMigration(_ context.Context, req *platformv1.FinalizeMigrationRequest) (*platformv1.FinalizeMigrationResponse, error) {
	s.finished = req
	if req.GetReceiverId() != "recv-1" {
		return nil, status.Error(codes.NotFound, "migration receiver not found")
	}
	return &platformv1.FinalizeMigrationResponse{Status: &platformv1.Status{Success: true}}, nil
}

// GetSnapshot knows one snapshot, "nightly"; any other id is NotFound.
func (s *recordingComputeServer) GetSnapshot(_ context.Context, req *platformv1.GetSnapshotRequest) (*platformv1.GetSnapshotResponse, error) {
	s.snapshot = req
	if req.GetSnapshotId() != "nightly" {
		return nil, status.Error(codes.NotFound, "snapshot not found")
	}
	return &platformv1.GetSnapshotResponse{Snapshot: &platformv1.Snapshot{Id: "nightly", VmId: req.GetVmId()}}, nil
}

func (s *recordingComputeServer) DeleteContainer(_ context.Context, req *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	s.deleted = req
	return &platformv1.DeleteContainerResponse{}, nil
}

func (s *recordingComputeServer) StartContainer(_ context.Context, req *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	s.started = req
	return &platformv1.StartContainerResponse{}, nil
}

func (s *recordingComputeServer) StopContainer(_ context.Context, req *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	s.stopped = req
	return &platformv1.StopContainerResponse{}, nil
}

func (s *recordingComputeServer) ListVMs(_ context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	s.listed = req
	return &platformv1.ListVMsResponse{}, nil
}

func (s *recordingComputeServer) AttestContainer(_ context.Context, req *platformv1.AttestContainerRequest) (*platformv1.AttestContainerResponse, error) {
	s.attested = req
	return &platformv1.AttestContainerResponse{ContainerId: req.GetId()}, nil
}

// grantingAuthorizer grants exactly one scope and refuses every other
// with 403, standing in for the session scope check.
type grantingAuthorizer struct {
	granted string
}

func (a grantingAuthorizer) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// connectComputeSDK serves the compute router over TLS and returns an SDK
// client on the REST transport, plus a count of the API requests that
// reached the server.
func connectComputeSDK(t *testing.T, server platformv1.ComputeServiceServer) (platformv1.ComputeServiceClient, *atomic.Int32) {
	t.Helper()

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), server, newTestWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	var apiRequests atomic.Int32
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiRequests.Add(1)
		}
		root.ServeHTTP(w, r)
	})

	httpServer := httptest.NewTLSServer(counted)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewComputeServiceClient(adapter.Connection()), &apiRequests
}

func TestSDKREST_DeleteContainer(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.DeleteContainer(context.Background(),
		&platformv1.DeleteContainerRequest{Id: "c1", Force: true, DeleteVolumes: true})

	require.NoError(t, err)
	require.NotNil(t, server.deleted)
	assert.Equal(t, "c1", server.deleted.GetId())
	assert.True(t, server.deleted.GetForce())
	assert.True(t, server.deleted.GetDeleteVolumes())
}

func TestSDKREST_GetSnapshot(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.GetSnapshot(context.Background(),
		&platformv1.GetSnapshotRequest{VmId: "vm-1", SnapshotId: "nightly"})

	require.NoError(t, err)
	require.NotNil(t, server.snapshot)
	assert.Equal(t, "vm-1", server.snapshot.GetVmId())
	assert.Equal(t, "nightly", server.snapshot.GetSnapshotId())
	assert.Equal(t, "nightly", resp.GetSnapshot().GetId())
	assert.Equal(t, "vm-1", resp.GetSnapshot().GetVmId())
}

func TestSDKREST_GetSnapshotUnknownIsNotFound(t *testing.T) {
	client, _ := connectComputeSDK(t, &recordingComputeServer{})

	_, err := client.GetSnapshot(context.Background(),
		&platformv1.GetSnapshotRequest{VmId: "vm-1", SnapshotId: "gone"})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDKREST_PrepareAndFinalizeMigration(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	prepared, err := client.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
		VmName: "web", Mode: "live",
		Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2},
	})
	require.NoError(t, err)
	require.NotNil(t, server.prepared)
	assert.Equal(t, "web", server.prepared.GetVmName())
	assert.Equal(t, int32(2048), server.prepared.GetSpec().GetMemoryMb())
	assert.Equal(t, "recv-1", prepared.GetReceiverId())
	assert.Equal(t, int32(49152), prepared.GetPort())

	_, err = client.FinalizeMigration(context.Background(),
		&platformv1.FinalizeMigrationRequest{ReceiverId: prepared.GetReceiverId(), Commit: true})
	require.NoError(t, err)
	require.NotNil(t, server.finished)
	assert.Equal(t, "recv-1", server.finished.GetReceiverId())
	assert.True(t, server.finished.GetCommit())
}

func TestSDKREST_FinalizeMigrationUnknownReceiverIsNotFound(t *testing.T) {
	client, _ := connectComputeSDK(t, &recordingComputeServer{})

	_, err := client.FinalizeMigration(context.Background(),
		&platformv1.FinalizeMigrationRequest{ReceiverId: "gone", Commit: true})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDKREST_StartContainer(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.StartContainer(context.Background(), &platformv1.StartContainerRequest{Id: "c1"})

	require.NoError(t, err)
	require.NotNil(t, server.started)
	assert.Equal(t, "c1", server.started.GetId())
}

func TestSDKREST_StopContainer(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.StopContainer(context.Background(),
		&platformv1.StopContainerRequest{Id: "c1", TimeoutSeconds: 7})

	require.NoError(t, err)
	require.NotNil(t, server.stopped)
	assert.Equal(t, "c1", server.stopped.GetId())
	assert.Equal(t, uint32(7), server.stopped.GetTimeoutSeconds())
}

func TestSDKREST_ListVMsSendsTheWholeFilter(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)
	want := &platformv1.ListVMsRequest{
		States:     []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, platformv1.VMState_VM_STATE_PAUSED},
		Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
		Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 5, SortBy: "name", Ascending: true},
	}

	_, err := client.ListVMs(context.Background(), want)

	require.NoError(t, err)
	require.NotNil(t, server.listed)
	assert.True(t, proto.Equal(want, server.listed), "server read %v, want %v", server.listed, want)
}

// serveListVMs sends one ListVMs request straight to the router.
func serveListVMs(t *testing.T, server platformv1.ComputeServiceServer, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	return serveCompute(t, server, http.MethodGet, "/api/v1/compute/vms"+query, body)
}

func TestComputeHandlers_ListVMsQueryPagesOverTheBody(t *testing.T) {
	server := &recordingComputeServer{}

	rec := serveListVMs(t, server, "?page=3&page_size=4",
		`{"states":["VM_STATE_STOPPED"],"pagination":{"page":1,"page_size":10,"sort_by":"created_at"}}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, server.listed)
	assert.Equal(t, []platformv1.VMState{platformv1.VMState_VM_STATE_STOPPED}, server.listed.GetStates())
	assert.True(t, proto.Equal(&platformv1.PaginationRequest{Page: 3, PageSize: 4, SortBy: "created_at"},
		server.listed.GetPagination()), "pagination = %v", server.listed.GetPagination())
}

func TestComputeHandlers_ListVMsRefusesABadRequest(t *testing.T) {
	cases := []struct {
		name, query, body string
	}{
		{"body is not JSON", "", `{"states":`},
		{"page is not a number", "?page=two", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &recordingComputeServer{}

			rec := serveListVMs(t, server, tc.query, tc.body)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, server.listed, "the service must not be called")
		})
	}
}

func TestSDKREST_AttestContainer(t *testing.T) {
	server := &recordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.AttestContainer(context.Background(), &platformv1.AttestContainerRequest{
		Id:         "c1",
		Nonce:      []byte{0x01, 0x02, 0x03},
		PcrIndices: []uint32{0, 7},
		PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
	})

	require.NoError(t, err)
	require.NotNil(t, server.attested)
	assert.Equal(t, "c1", server.attested.GetId())
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, server.attested.GetNonce())
	assert.Equal(t, []uint32{0, 7}, server.attested.GetPcrIndices())
	assert.Equal(t, platformv1.PCRBank_PCR_BANK_SHA256, server.attested.GetPcrBank())
	assert.Equal(t, "c1", resp.GetContainerId())
}

func TestSDKREST_ContainerClaims_EmptyIDRefusedBeforeSending(t *testing.T) {
	server := &recordingComputeServer{}
	client, apiRequests := connectComputeSDK(t, server)
	ctx := context.Background()

	calls := map[string]func() error{
		"DeleteContainer": func() error {
			_, err := client.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{Force: true})
			return err
		},
		"StartContainer": func() error {
			_, err := client.StartContainer(ctx, &platformv1.StartContainerRequest{})
			return err
		},
		"StopContainer": func() error {
			_, err := client.StopContainer(ctx, &platformv1.StopContainerRequest{TimeoutSeconds: 7})
			return err
		},
		"AttestContainer": func() error {
			_, err := client.AttestContainer(ctx, &platformv1.AttestContainerRequest{Nonce: []byte{0x01}})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	assert.Zero(t, apiRequests.Load(), "an empty id must be refused before any request is sent")
}

func TestComputeRouter_AttestContainerRequiresContainerRead(t *testing.T) {
	cases := []struct {
		name       string
		authorizer middleware.ScopeAuthorizer
		wantStatus int
		wantCalled bool
	}{
		{"without container:read", grantingAuthorizer{granted: "container:write"}, http.StatusForbidden, false},
		{"with container:read", grantingAuthorizer{granted: "container:read"}, http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &recordingComputeServer{}
			r := NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), server, newTestWriter())
			r.SetScopeAuthorizer(tc.authorizer)
			parent := mux.NewRouter()
			r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())

			req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c1/attest",
				strings.NewReader(`{"nonce":"AQI="}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			parent.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantCalled, server.attested != nil)
			if tc.wantCalled {
				assert.Equal(t, "c1", server.attested.GetId())
				assert.Equal(t, []byte{0x01, 0x02}, server.attested.GetNonce())
			}
		})
	}
}
