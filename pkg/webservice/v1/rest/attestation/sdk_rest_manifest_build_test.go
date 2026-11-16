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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectManifestBuildSDK serves the attestation router under /api/v1 over
// TLS, backed by server, and returns the SDK attestation client connected
// to it over the REST transport.
func connectManifestBuildSDK(t *testing.T, server platformv1.AttestationServiceServer) *attestationsvc.Client {
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
	adapter, err := rest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return attestationsvc.NewClientFromGRPC(platformv1.NewAttestationServiceClient(adapter.Connection()))
}

func TestSDKREST_ManifestBuildAndVerify(t *testing.T) {
	ctx := context.Background()

	t.Run("build", func(t *testing.T) {
		fake := &recordingAttestationServer{}
		client := connectManifestBuildSDK(t, fake)

		manifest, err := client.BuildManifest(ctx, &platformv1.BuildManifestRequest{Nonce: []byte("n-1"), Sign: true})
		require.NoError(t, err)

		got, ok := fake.req.(*platformv1.BuildManifestRequest)
		require.True(t, ok, "fake received %T", fake.req)
		assert.Equal(t, []byte("n-1"), got.GetNonce())
		assert.True(t, got.GetSign())
		assert.Equal(t, "m-built", manifest.GetId())
		assert.Equal(t, []byte("n-1"), manifest.GetNonce())
	})

	t.Run("verify", func(t *testing.T) {
		fake := &recordingAttestationServer{}
		client := connectManifestBuildSDK(t, fake)

		sent := &platformv1.HostManifest{
			Id:        "m-1",
			Nonce:     []byte("nonce"),
			Timestamp: &timestamppb.Timestamp{Seconds: 1767225600, Nanos: 500},
		}
		result, err := client.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{
			Manifest:      sent,
			ExpectedNonce: []byte("nonce"),
			ExpectedPcrs:  map[uint32][]byte{7: {0xaa}},
		})
		require.NoError(t, err)

		got, ok := fake.req.(*platformv1.VerifyManifestRequest)
		require.True(t, ok, "fake received %T", fake.req)
		assert.True(t, proto.Equal(sent, got.GetManifest()), "manifest = %v, want %v", got.GetManifest(), sent)
		assert.Equal(t, map[uint32][]byte{7: {0xaa}}, got.GetExpectedPcrs())
		assert.Equal(t, platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED, result.GetStatus())
	})

	t.Run("build refused", func(t *testing.T) {
		fake := &recordingAttestationServer{err: status.Error(codes.PermissionDenied, "caller not admitted")}
		client := connectManifestBuildSDK(t, fake)

		_, err := client.BuildManifest(ctx, &platformv1.BuildManifestRequest{Nonce: []byte("n-1")})
		require.Error(t, err)
		// The handler answers PermissionDenied as 403, which the SDK reads
		// back as PermissionDenied (a missing route would be NotFound).
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}
