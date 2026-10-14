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

package vtpm

import (
	"context"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectVTPMSDK serves the vTPM router over TLS with the production response
// writer and returns the SDK vTPM client dialed through the REST transport.
// The admin gate sits on the parent router and is proven in
// pkg/webservice/v1/router_authz_test.go; this proves the wire.
func connectVTPMSDK(t *testing.T, service *mockVTPMService) platformv1.VTPMServiceClient {
	t.Helper()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	root := mux.NewRouter()
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewVTPMRouter(logger, service, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewVTPMServiceClient(adapter.Connection())
}

func TestSDKREST_StartVTPM(t *testing.T) {
	var started string
	client := connectVTPMSDK(t, &mockVTPMService{
		startFn:        func(_ context.Context, id string) error { started = id; return nil },
		isRunningFn:    func(string) bool { return true },
		getTPMSocketFn: func(id string) string { return "/run/vtpm/" + id + ".sock" },
	})

	resp, err := client.StartVTPM(context.Background(), &platformv1.StartVTPMRequest{BundleId: "b1"})

	require.NoError(t, err)
	assert.Equal(t, "b1", started)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "b1", resp.GetBundleId())
	assert.True(t, resp.GetRunning())
	assert.Equal(t, "/run/vtpm/b1.sock", resp.GetSocketPath())
}

func TestSDKREST_StartVTPM_ServiceErrorsKeepTheirStatus(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		startFn: func(_ context.Context, id string) error { return vtpm.ErrBundleNotFound{ID: id} },
	})

	_, err := client.StartVTPM(context.Background(), &platformv1.StartVTPMRequest{BundleId: "gone"})

	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDKREST_QuoteVTPM(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		quoteFn: func(_ context.Context, id string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
			assert.Equal(t, "b1", id)
			assert.Equal(t, []byte("fresh-nonce"), nonce)
			assert.Equal(t, []int{0, 7}, pcrs)
			return &vtpm.QuoteResult{
				Quote:         []byte("attest"),
				Signature:     []byte("sig"),
				PCRValues:     map[int][]byte{0: {0x00}, 7: {0x07}},
				HashAlgorithm: "SHA256",
			}, nil
		},
	})

	resp, err := client.QuoteVTPM(context.Background(), &platformv1.QuoteVTPMRequest{
		BundleId: "b1", Nonce: []byte("fresh-nonce"), Pcrs: []int32{0, 7},
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("attest"), resp.GetQuote())
	assert.Equal(t, []byte("sig"), resp.GetSignature())
	assert.Equal(t, map[int32][]byte{0: {0x00}, 7: {0x07}}, resp.GetPcrValues())
	assert.Equal(t, "SHA256", resp.GetHashAlgorithm())
}

func TestSDKREST_SealVTPM(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		sealFn: func(_ context.Context, id string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
			assert.Equal(t, "b1", id)
			assert.Equal(t, []byte("secret"), data)
			assert.Equal(t, []int{7}, opts.PCRs)
			assert.Equal(t, "pw", opts.AuthValue)
			return []byte("sealed"), nil
		},
	})

	resp, err := client.SealVTPM(context.Background(), &platformv1.SealVTPMRequest{
		BundleId: "b1", Data: []byte("secret"), Pcrs: []int32{7}, AuthValue: "pw",
	})

	require.NoError(t, err)
	assert.Equal(t, "b1", resp.GetBundleId())
	assert.Equal(t, []byte("sealed"), resp.GetSealedData())
}

func TestSDKREST_ReadVTPMPCR(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		readPCRFn: func(_ context.Context, id string, index int) ([]byte, error) {
			assert.Equal(t, "b1", id)
			assert.Equal(t, 7, index)
			return []byte{0xaa}, nil
		},
	})

	resp, err := client.ReadVTPMPCR(context.Background(), &platformv1.ReadVTPMPCRRequest{BundleId: "b1", PcrIndex: 7})

	require.NoError(t, err)
	assert.Equal(t, int32(7), resp.GetPcrIndex())
	assert.Equal(t, []byte{0xaa}, resp.GetValue())
}

func TestSDKREST_CreateBundle(t *testing.T) {
	client := connectVTPMSDK(t, &mockVTPMService{
		createBundleFn: func(_ context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			assert.Equal(t, vtpm.BundleModeTemplate, opts.Mode)
			assert.Equal(t, uint64(9), opts.DeviceProfileID)
			return createTestBundle("b1"), nil
		},
	})

	resp, err := client.CreateBundle(context.Background(), &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:            platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
			DeviceProfileId: 9,
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "b1", resp.GetBundle().GetId())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, resp.GetBundle().GetMode())
	assert.Equal(t, "test-host", resp.GetBundle().GetManifest().GetHostname())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_RSA, resp.GetBundle().GetManifest().GetEkAlgorithm())
	assert.Equal(t, "/bundles/b1/secure-boot-keys/PK.crt", resp.GetBundle().GetSecureBootKeys().GetPkCrt())
}
