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
package pxe

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// knownDevice is the one device recordingPXEServer knows.
const knownDevice = "pxe-7"

// recordingPXEServer is the gRPC service behind the router: it records the
// device action it was asked for and refuses any device but knownDevice.
type recordingPXEServer struct {
	platformv1.UnimplementedPXEServiceServer
	called string
	got    interface{ GetDeviceId() string }
}

func (s *recordingPXEServer) device(called string, req interface{ GetDeviceId() string }) (*platformv1.PXEDeviceInfo, error) {
	s.called, s.got = called, req
	if req.GetDeviceId() != knownDevice {
		return nil, status.Errorf(codes.NotFound, "pxe device %q not found", req.GetDeviceId())
	}
	return &platformv1.PXEDeviceInfo{Id: knownDevice, State: platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED}, nil
}

func (s *recordingPXEServer) UpdateState(_ context.Context, req *platformv1.UpdatePXEStateRequest) (*platformv1.UpdatePXEStateResponse, error) {
	device, err := s.device("UpdateState", req)
	if err != nil {
		return nil, err
	}
	return &platformv1.UpdatePXEStateResponse{Status: &platformv1.Status{Success: true}, Device: device}, nil
}

func (s *recordingPXEServer) Authorize(_ context.Context, req *platformv1.AuthorizePXEDeviceRequest) (*platformv1.AuthorizePXEDeviceResponse, error) {
	device, err := s.device("Authorize", req)
	if err != nil {
		return nil, err
	}
	return &platformv1.AuthorizePXEDeviceResponse{Status: &platformv1.Status{Success: true}, Device: device}, nil
}

func (s *recordingPXEServer) Quarantine(_ context.Context, req *platformv1.QuarantinePXEDeviceRequest) (*platformv1.QuarantinePXEDeviceResponse, error) {
	device, err := s.device("Quarantine", req)
	if err != nil {
		return nil, err
	}
	return &platformv1.QuarantinePXEDeviceResponse{Status: &platformv1.Status{Success: true}, Device: device}, nil
}

// pxeRoutes mounts the operator PXE routes for server under /api/v1.
func pxeRoutes(server platformv1.PXEServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	root := mux.NewRouter()
	NewPXERouter(logger, server, response.NewResponseWriter(logger, nil), false).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// connectPXESDK serves the real PXE router over TLS and returns the SDK's
// REST client for it (#452).
func connectPXESDK(t *testing.T, server platformv1.PXEServiceServer) platformv1.PXEServiceClient {
	t.Helper()
	root := pxeRoutes(server)
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)
	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return platformv1.NewPXEServiceClient(adapter.Connection())
}

func TestPXEDeviceActions_SDKReachesTheHandlerWithTheDeviceFromThePath(t *testing.T) {
	server := &recordingPXEServer{}
	client := connectPXESDK(t, server)
	ctx := context.Background()

	t.Run("Authorize", func(t *testing.T) {
		resp, err := client.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{DeviceId: knownDevice, TargetVlan: 200})
		require.NoError(t, err)
		assert.Equal(t, "Authorize", server.called)
		got := server.got.(*platformv1.AuthorizePXEDeviceRequest)
		assert.Equal(t, knownDevice, got.GetDeviceId())
		assert.Equal(t, uint32(200), got.GetTargetVlan())
		assert.Equal(t, knownDevice, resp.GetDevice().GetId())
	})
	t.Run("UpdateState", func(t *testing.T) {
		resp, err := client.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
			DeviceId: knownDevice, State: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED, Reason: "disk",
		})
		require.NoError(t, err)
		assert.Equal(t, "UpdateState", server.called)
		got := server.got.(*platformv1.UpdatePXEStateRequest)
		assert.Equal(t, knownDevice, got.GetDeviceId())
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_FAILED, got.GetState())
		assert.Equal(t, "disk", got.GetReason())
		assert.Equal(t, knownDevice, resp.GetDevice().GetId())
	})
	t.Run("Quarantine", func(t *testing.T) {
		resp, err := client.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{DeviceId: knownDevice, Reason: "attestation failed"})
		require.NoError(t, err)
		assert.Equal(t, "Quarantine", server.called)
		got := server.got.(*platformv1.QuarantinePXEDeviceRequest)
		assert.Equal(t, knownDevice, got.GetDeviceId())
		assert.Equal(t, "attestation failed", got.GetReason())
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED, resp.GetDevice().GetState())
	})
}

func TestPXEDeviceActions_SDKSurfacesAnUnknownDeviceAsNotFound(t *testing.T) {
	client := connectPXESDK(t, &recordingPXEServer{})
	ctx := context.Background()

	_, err := client.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{DeviceId: "pxe-unknown", TargetVlan: 200})
	assert.Equal(t, codes.NotFound, status.Code(err), "Authorize: %v", err)
	_, err = client.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: "pxe-unknown", State: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED,
	})
	assert.Equal(t, codes.NotFound, status.Code(err), "UpdateState: %v", err)
	_, err = client.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{DeviceId: "pxe-unknown"})
	assert.Equal(t, codes.NotFound, status.Code(err), "Quarantine: %v", err)
}

func TestPXEDeviceActions_SDKSurfacesAMissingServiceAsUnavailable(t *testing.T) {
	client := connectPXESDK(t, nil)

	_, err := client.Authorize(context.Background(), &platformv1.AuthorizePXEDeviceRequest{DeviceId: knownDevice})
	assert.Equal(t, codes.Unavailable, status.Code(err), "Authorize: %v", err)
}

func TestPXEDeviceActions_RefuseABodyThatIsNotJSON(t *testing.T) {
	server := &recordingPXEServer{}
	router := pxeRoutes(server)

	for _, path := range []string{
		"/api/v1/pxe/devices/" + knownDevice + "/authorize",
		"/api/v1/pxe/devices/" + knownDevice + "/quarantine",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{not json"))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, path)
	}
	assert.Empty(t, server.called, "a malformed body reached the service")
}
