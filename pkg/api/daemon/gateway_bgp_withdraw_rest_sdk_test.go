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
	"net/http"
	"net/netip"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	gatewayrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// withdrawRecordingSpeaker is the mock speaker that also records the prefix
// each withdraw reached it with, so a test can prove which prefix arrived.
type withdrawRecordingSpeaker struct {
	*mockBGPSpeaker
	withdrawn []netip.Prefix
}

func (s *withdrawRecordingSpeaker) WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error {
	s.withdrawn = append(s.withdrawn, prefix)
	return s.mockBGPSpeaker.WithdrawPrefix(ctx, prefix)
}

// newBGPWithdrawRESTClient serves the webservice gateway router
// (pkg/webservice/v1/rest/gateway/router.go) over TLS, backed by a real
// GatewayService, and returns the SDK's REST adapter as a gateway client
// together with that service, so a test can compare REST with gRPC.
func newBGPWithdrawRESTClient(t *testing.T, speaker BGPSpeakerInterface) (platformv1.GatewayServiceClient, *GatewayService) {
	t.Helper()
	svc := NewGatewayService()
	svc.SetBGPSpeaker(speaker)

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent, api := newWebserviceRESTMux()
	gatewayrest.NewGatewayRouter(logger, svc, response.NewResponseWriter(logger, nil)).RegisterRoutes(api)

	adapter := connectPhase35REST(t, parent)
	return platformv1.NewGatewayServiceClient(adapter.Connection()), svc
}

// newWebserviceRESTMux returns a root router that answers the /health probe
// the SDK adapter sends on connect, and its /api/v1 subrouter, where a
// webservice router registers its routes as it does in the daemon.
func newWebserviceRESTMux() (*mux.Router, *mux.Router) {
	parent := mux.NewRouter()
	parent.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return parent, parent.PathPrefix("/api/v1").Subrouter()
}

// The SDK sent the withdrawn prefix in a DELETE body while the server reads
// only ?prefix=, so every REST withdraw failed with "prefix is required".
func TestGatewayBGPWithdraw_RESTSDKReachesServer(t *testing.T) {
	for _, prefix := range []string{"198.51.100.0/24", "2001:db8:1234::/48"} {
		t.Run(prefix, func(t *testing.T) {
			speaker := &withdrawRecordingSpeaker{mockBGPSpeaker: newMockBGPSpeaker()}
			client, _ := newBGPWithdrawRESTClient(t, speaker)

			resp, err := client.WithdrawPrefix(context.Background(), &platformv1.WithdrawPrefixRequest{Prefix: prefix})
			require.NoError(t, err)
			assert.True(t, resp.GetStatus().GetSuccess())
			assert.Equal(t, []netip.Prefix{netip.MustParsePrefix(prefix)}, speaker.withdrawn)
		})
	}
}

// A missing or malformed prefix is refused over REST with the same code and
// reason gRPC returns, and never reaches the speaker.
func TestGatewayBGPWithdraw_RESTSDKRefusesBadPrefixLikeGRPC(t *testing.T) {
	cases := []struct{ prefix, reason string }{
		{prefix: "", reason: "prefix is required"},
		{prefix: "not-a-prefix", reason: "invalid prefix"},
		{prefix: "10.0.0.1", reason: "invalid prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.reason+" "+tc.prefix, func(t *testing.T) {
			speaker := &withdrawRecordingSpeaker{mockBGPSpeaker: newMockBGPSpeaker()}
			client, svc := newBGPWithdrawRESTClient(t, speaker)
			req := &platformv1.WithdrawPrefixRequest{Prefix: tc.prefix}

			_, grpcErr := svc.WithdrawPrefix(context.Background(), req)
			require.Error(t, grpcErr)
			_, restErr := client.WithdrawPrefix(context.Background(), req)
			require.Error(t, restErr)

			assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
			assert.Equal(t, status.Code(grpcErr), status.Code(restErr))
			assert.Contains(t, status.Convert(grpcErr).Message(), tc.reason)
			assert.Contains(t, status.Convert(restErr).Message(), tc.reason)
			assert.Empty(t, speaker.withdrawn)
		})
	}
}
