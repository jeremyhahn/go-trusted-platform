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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkregistry "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectRegistryReadsSDK serves the registry router under /api/v1 on a TLS
// server and returns an SDK registry client connected to it over REST.
func connectRegistryReadsSDK(t *testing.T, svc *fakeRegistryService) *sdkregistry.Client {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)

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

	client, err := sdkregistry.NewClient(adapter)
	require.NoError(t, err)
	return client
}

func TestSDKREST_RegistryReads(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	svc := &fakeRegistryService{
		listResp: &grpcapi.RegistryListResponse{
			Artifacts: []*grpcapi.RegistryArtifact{{
				Repository: "team/app", Tag: "v1", Digest: "sha256:aa", Size: 42, CreatedAt: created,
			}},
			Total: 1,
		},
		status: &grpcapi.RegistryStatusResponse{
			Health:  grpcapi.RegistryHealthStatusHealthy,
			Version: "1.2.3",
			Storage: &grpcapi.RegistryStorageStats{UsedBytes: 40},
		},
		inspect: &grpcapi.RegistryInspectResponse{Detail: &grpcapi.RegistryArtifactDetail{
			Artifact: &grpcapi.RegistryArtifact{Repository: "team/app", Tag: "v1", Digest: "sha256:bb", CreatedAt: created},
			Tags:     []string{"v1", "latest"},
		}},
	}
	client := connectRegistryReadsSDK(t, svc)
	ctx := context.Background()

	list, err := client.List(ctx, "team/app", 5, "", "", false)
	require.NoError(t, err)
	require.NotNil(t, svc.listReq)
	require.Equal(t, "team/app", svc.listReq.Repository)
	require.Equal(t, int32(5), svc.listReq.Limit)
	require.Equal(t, int32(1), list.GetTotal())
	require.Len(t, list.GetArtifacts(), 1)
	require.Equal(t, "sha256:aa", list.GetArtifacts()[0].GetDigest())
	require.Equal(t, int64(42), list.GetArtifacts()[0].GetSize())
	require.True(t, list.GetArtifacts()[0].GetCreatedAt().AsTime().Equal(created))

	st, err := client.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, st.GetHealth())
	require.Equal(t, "1.2.3", st.GetVersion())
	require.Equal(t, int64(40), st.GetStorage().GetUsedBytes())

	in, err := client.Inspect(ctx, "team/app", "v1", "", false)
	require.NoError(t, err)
	require.NotNil(t, svc.inspectReq)
	require.Equal(t, "team/app", svc.inspectReq.Repository)
	require.Equal(t, "v1", svc.inspectReq.Reference)
	require.Equal(t, "sha256:bb", in.GetDetail().GetArtifact().GetDigest())
	require.Equal(t, []string{"v1", "latest"}, in.GetDetail().GetTags())

	svc.inspectErr = grpcapi.ErrArtifactNotFound{Repository: "team/app", Reference: "gone"}
	_, err = client.Inspect(ctx, "team/app", "gone", "", false)
	require.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
}
