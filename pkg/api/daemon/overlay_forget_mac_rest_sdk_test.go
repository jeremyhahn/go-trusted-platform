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

package daemon

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	overlayrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/overlay"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// forgottenMAC is one MAC/VNI pair a forget reached the controller with.
type forgottenMAC struct {
	mac string
	vni uint32
}

// forgetRecordingController is the mock overlay controller that also records
// each forget it receives, so a test can prove which MAC and VNI arrived.
type forgetRecordingController struct {
	*mockOverlayController
	forgotten []forgottenMAC
}

func (c *forgetRecordingController) ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error {
	c.forgotten = append(c.forgotten, forgottenMAC{mac: mac.String(), vni: vni})
	return c.mockOverlayController.ForgetMAC(ctx, mac, vni)
}

// newForgetMACRESTClient serves the webservice overlay router
// (pkg/webservice/v1/rest/overlay/router.go) over TLS, backed by a real
// OverlayService, and returns the SDK's REST adapter as an overlay client
// together with that service, so a test can compare REST with gRPC.
func newForgetMACRESTClient(t *testing.T, ctrl OverlayControllerInterface) (platformv1.OverlayServiceClient, *OverlayService) {
	t.Helper()
	svc := NewOverlayService(WithOverlayController(ctrl))

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent, api := newWebserviceRESTMux()
	overlayrest.NewOverlayRouter(logger, svc, response.NewResponseWriter(logger, nil)).RegisterRoutes(api)

	adapter := connectPhase35REST(t, parent)
	return platformv1.NewOverlayServiceClient(adapter.Connection()), svc
}

// The SDK sent the MAC and VNI in a DELETE body while the server reads only
// ?mac= and ?vni=, so every REST forget failed with "mac is required".
func TestOverlayForgetMAC_RESTSDKReachesServer(t *testing.T) {
	ctrl := &forgetRecordingController{mockOverlayController: newMockOverlayController()}
	client, _ := newForgetMACRESTClient(t, ctrl)

	resp, err := client.ForgetMAC(context.Background(), &platformv1.ForgetMACRequest{Mac: "02:42:ac:11:00:02", Vni: 4097})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, []forgottenMAC{{mac: "02:42:ac:11:00:02", vni: 4097}}, ctrl.forgotten)
}

// A missing MAC, a zero VNI or a malformed MAC is refused over REST with the
// same code and reason gRPC returns, and never reaches the controller.
func TestOverlayForgetMAC_RESTSDKRefusesBadInputLikeGRPC(t *testing.T) {
	cases := []struct {
		name   string
		req    *platformv1.ForgetMACRequest
		reason string
	}{
		{name: "missing mac", req: &platformv1.ForgetMACRequest{Vni: 100}, reason: "mac is required"},
		{name: "zero vni", req: &platformv1.ForgetMACRequest{Mac: "02:42:ac:11:00:02"}, reason: "vni is required"},
		{name: "malformed mac", req: &platformv1.ForgetMACRequest{Mac: "not-a-mac", Vni: 100}, reason: "invalid MAC address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := &forgetRecordingController{mockOverlayController: newMockOverlayController()}
			client, svc := newForgetMACRESTClient(t, ctrl)

			_, grpcErr := svc.ForgetMAC(context.Background(), tc.req)
			require.Error(t, grpcErr)
			_, restErr := client.ForgetMAC(context.Background(), tc.req)
			require.Error(t, restErr)

			assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
			assert.Equal(t, status.Code(grpcErr), status.Code(restErr))
			assert.Contains(t, status.Convert(grpcErr).Message(), tc.reason)
			assert.Contains(t, status.Convert(restErr).Message(), tc.reason)
			assert.Empty(t, ctrl.forgotten)
		})
	}
}
