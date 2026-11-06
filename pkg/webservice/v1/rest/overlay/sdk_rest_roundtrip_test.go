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

package overlay

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// fakeOverlayServer records the DeleteVNI request the handler built.
type fakeOverlayServer struct {
	platformv1.UnimplementedOverlayServiceServer
	deleted *platformv1.DeleteVNIRequest
	err     error
}

func (f *fakeOverlayServer) DeleteVNI(_ context.Context, r *platformv1.DeleteVNIRequest) (*platformv1.DeleteVNIResponse, error) {
	f.deleted = r
	return &platformv1.DeleteVNIResponse{Status: &platformv1.Status{Success: true}}, f.err
}

// serveOverlay serves the overlay router over TLS and returns the server and
// the SDK overlay client dialed through the REST transport.
func serveOverlay(t *testing.T, srv platformv1.OverlayServiceServer) (*httptest.Server, platformv1.OverlayServiceClient) {
	t.Helper()

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewOverlayRouter(logger, srv, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return server, platformv1.NewOverlayServiceClient(adapter.Connection())
}

// TestSDKREST_DeleteVNI_ZeroVNINeverLeavesTheClient: zero would leave the
// numeric segment empty, so the SDK refuses it before the wire.
func TestSDKREST_DeleteVNI_ZeroVNINeverLeavesTheClient(t *testing.T) {
	srv := &fakeOverlayServer{}
	_, client := serveOverlay(t, srv)

	_, err := client.DeleteVNI(context.Background(), &platformv1.DeleteVNIRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, srv.deleted)
}

// TestSDKREST_DeleteVNI_NonNumericVNIIsRefused: the route accepts only a
// numeric VNI; anything else matches no route and reaches no handler.
func TestSDKREST_DeleteVNI_NonNumericVNIIsRefused(t *testing.T) {
	srv := &fakeOverlayServer{}
	server, _ := serveOverlay(t, srv)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		server.URL+"/api/v1/overlay/vnis/abc", nil)
	require.NoError(t, err)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Nil(t, srv.deleted, "a non-numeric VNI reached the handler")
}
