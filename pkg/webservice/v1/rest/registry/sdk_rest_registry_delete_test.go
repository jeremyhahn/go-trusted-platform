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
package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectRegistryDeleteSDK serves the registry router under /api/v1, as the
// webservice mounts it, and returns the SDK registry client over REST.
func connectRegistryDeleteSDK(t *testing.T, svc *fakeRegistryService) *regsvc.Client {
	t.Helper()

	logger := logging.DefaultLogger()
	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewRouter(logger, svc, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	client, err := regsvc.NewClient(adapter)
	require.NoError(t, err)
	return client
}

func TestSDKREST_RegistryDelete(t *testing.T) {
	t.Run("deletes the named reference", func(t *testing.T) {
		svc := &fakeRegistryService{deleteResp: &grpcapi.RegistryDeleteResponse{
			Digest:     "sha256:abc",
			BytesFreed: 4096,
			Timestamp:  time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC),
		}}
		client := connectRegistryDeleteSDK(t, svc)

		resp, err := client.Delete(context.Background(), "team/app", "v1", "", false)
		require.NoError(t, err)

		require.NotNil(t, svc.deleteReq)
		assert.Equal(t, "team/app", svc.deleteReq.Repository)
		assert.Equal(t, "v1", svc.deleteReq.Reference)
		assert.Equal(t, "sha256:abc", resp.GetDigest())
		assert.Equal(t, int64(4096), resp.GetBytesFreed())
		assert.True(t, resp.GetTimestamp().AsTime().Equal(svc.deleteResp.Timestamp))
	})

	t.Run("a missing artifact is NotFound", func(t *testing.T) {
		svc := &fakeRegistryService{deleteErr: grpcapi.ErrArtifactNotFound{Repository: "team/app", Reference: "v1"}}
		client := connectRegistryDeleteSDK(t, svc)

		_, err := client.Delete(context.Background(), "team/app", "v1", "", false)
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err), "err: %v", err)
	})
}
