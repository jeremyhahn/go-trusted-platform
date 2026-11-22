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
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectCollectSDK serves the attestation server router under /api/v1
// over TLS and returns the SDK attestation client wired to it over REST.
func connectCollectSDK(t *testing.T, server platformv1.AttestationServiceServer) *attestationsvc.Client {
	t.Helper()

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewAttestationServerRouter(logging.NewLogger(slog.LevelError, io.Discard), server, testWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return attestationsvc.NewClientFromGRPC(platformv1.NewAttestationServiceClient(adapter.Connection()))
}

func TestSDKREST_Collect(t *testing.T) {
	t.Run("vm", func(t *testing.T) {
		server := &recordingAttestationServer{}
		client := connectCollectSDK(t, server)

		att, err := client.CollectVMAttestation(context.Background(), "vm-1", nil, []byte{1, 2, 3})
		require.NoError(t, err)
		got, ok := server.req.(*platformv1.CollectVMAttestationRequest)
		require.True(t, ok, "server got %T, want CollectVMAttestationRequest", server.req)
		assert.Equal(t, "vm-1", got.GetVmId())
		assert.Equal(t, []byte{1, 2, 3}, got.GetNonce())
		assert.Equal(t, "vm-1", att.GetVmId())
	})

	t.Run("container", func(t *testing.T) {
		server := &recordingAttestationServer{}
		client := connectCollectSDK(t, server)

		att, err := client.CollectContainerAttestation(context.Background(), "ctr-1")
		require.NoError(t, err)
		got, ok := server.req.(*platformv1.CollectContainerAttestationRequest)
		require.True(t, ok, "server got %T, want CollectContainerAttestationRequest", server.req)
		assert.Equal(t, "ctr-1", got.GetContainerId())
		assert.Equal(t, "ctr-1", att.GetContainerId())
	})

	t.Run("refusal", func(t *testing.T) {
		server := &recordingAttestationServer{err: status.Error(codes.NotFound, "no such vm")}
		client := connectCollectSDK(t, server)

		_, err := client.CollectVMAttestation(context.Background(), "vm-1", nil, []byte{1})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
		assert.Contains(t, err.Error(), "no such vm", "the handler's refusal, not a router 404")
		require.NotNil(t, server.req, "the handler reached the server")
	})
}
