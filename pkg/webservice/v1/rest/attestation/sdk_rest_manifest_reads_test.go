// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package attestation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectManifestReadsSDK mounts the attestation server router under
// /api/v1 on a TLS test server, backed by server, and returns an SDK
// attestation client connected to it over REST.
func connectManifestReadsSDK(t *testing.T, server platformv1.AttestationServiceServer) *attestationsvc.Client {
	t.Helper()

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewAttestationServerRouter(testLoggerFor(), server, testWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })

	return attestationsvc.NewClientFromGRPC(platformv1.NewAttestationServiceClient(adapter.Connection()))
}

func TestSDKREST_ManifestReads(t *testing.T) {
	ctx := context.Background()

	t.Run("GetManifest", func(t *testing.T) {
		server := &recordingAttestationServer{}
		manifest, err := connectManifestReadsSDK(t, server).GetManifest(ctx, "m1")
		require.NoError(t, err)
		assert.Equal(t, "m1", manifest.GetId())
		req, ok := server.req.(*platformv1.GetManifestRequest)
		require.True(t, ok, "server got %T", server.req)
		assert.Equal(t, "m1", req.GetId())
	})

	t.Run("ListManifests", func(t *testing.T) {
		server := &recordingAttestationServer{}
		manifests, _, err := connectManifestReadsSDK(t, server).ListManifests(ctx, &platformv1.ListManifestsRequest{})
		require.NoError(t, err)
		require.Len(t, manifests, 2)
		assert.Equal(t, "m-a", manifests[0].GetId())
		assert.Equal(t, "m-b", manifests[1].GetId())
		_, ok := server.req.(*platformv1.ListManifestsRequest)
		assert.True(t, ok, "server got %T", server.req)
	})

	t.Run("DeleteManifest", func(t *testing.T) {
		server := &recordingAttestationServer{}
		require.NoError(t, connectManifestReadsSDK(t, server).DeleteManifest(ctx, "m1"))
		req, ok := server.req.(*platformv1.DeleteManifestRequest)
		require.True(t, ok, "server got %T", server.req)
		assert.Equal(t, "m1", req.GetId())
	})

	t.Run("GetManifestRefused", func(t *testing.T) {
		server := &recordingAttestationServer{err: status.Error(codes.NotFound, "no such manifest")}
		_, err := connectManifestReadsSDK(t, server).GetManifest(ctx, "m1")
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
	})
}
