// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// TestKMSHash_SDKRoundTripAgainstDaemon: the SDK REST Hash reaches the
// daemon's hash route with a numeric algorithm the daemon reads, and the
// daemon's {algorithm, hash, timestamp} reply decodes into the proto reply.
func TestKMSHash_SDKRoundTripAgainstDaemon(t *testing.T) {
	svc := newMockKMSService()
	router := mux.NewRouter()
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewKMSHandlers(svc, slog.Default()).RegisterRoutes(router)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	// The SDK refuses plaintext REST; trust the test server's certificate.
	trustServer := platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })

	client := platformv1.NewKeyManagementServiceClient(adapter.Connection())
	resp, err := client.Hash(context.Background(), &platformv1.HashRequest{
		Data:      []byte("data"),
		Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	})
	require.NoError(t, err)
	require.NotNil(t, svc.lastHashReq)
	require.Equal(t, int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384), svc.lastHashReq.Algorithm)
	require.Equal(t, "data", string(svc.lastHashReq.Data))
	require.Equal(t, "hash-result", string(resp.GetHash()))
	require.Equal(t, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, resp.GetAlgorithm())
}
