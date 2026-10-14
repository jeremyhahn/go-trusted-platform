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
