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
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ntpCallLog records the NTPBackend methods a servicer reaches, in order.
type ntpCallLog struct {
	backend NTPBackend
	calls   []string
}

func (l *ntpCallLog) Status(ctx context.Context) (*ntp.Status, error) {
	l.calls = append(l.calls, "Status")
	return l.backend.Status(ctx)
}

func (l *ntpCallLog) Sources(ctx context.Context) ([]ntp.Source, error) {
	l.calls = append(l.calls, "Sources")
	return l.backend.Sources(ctx)
}

func (l *ntpCallLog) Step(ctx context.Context) (*ntp.Status, error) {
	l.calls = append(l.calls, "Step")
	return l.backend.Step(ctx)
}

// syncedNTPBackend answers every NTPBackend method with a synchronized
// node and its two sources.
func syncedNTPBackend() *ntpCallLog {
	return &ntpCallLog{backend: &fakeNTPBackend{
		status:     syncedNTPStatus(),
		sources:    ntpTestSources(),
		stepStatus: syncedNTPStatus(),
	}}
}

// ntpSDKCalls holds one call for every NTPService method.
func ntpSDKCalls() []sdkCall {
	return []sdkCall{
		{platformv1.NTPService_GetStatus_FullMethodName, &platformv1.GetNTPStatusRequest{}, &platformv1.GetNTPStatusResponse{}},
		{platformv1.NTPService_ListSources_FullMethodName, &platformv1.ListNTPSourcesRequest{}, &platformv1.ListNTPSourcesResponse{}},
		{platformv1.NTPService_Step_FullMethodName, &platformv1.StepNTPClockRequest{}, &platformv1.StepNTPClockResponse{}},
	}
}

// connectNTPEmbedded wires server as an embedded host's NTP service and
// connects the SDK's embedded adapter to the registry the host builds.
func connectNTPEmbedded(t *testing.T, server *NTPGRPCService) grpc.ClientConnInterface {
	t.Helper()
	return connectEmbeddedHost(t, func(d *Daemon) { d.ntpGRPCService = server })
}

// TestSDKEmbedded_NTPMethods drives every NTPService method through the
// SDK's embedded adapter and the registry the daemon's embedded host
// builds. Each reply, and each call the backend sees, matches a direct
// gRPC call on the same servicer.
func TestSDKEmbedded_NTPMethods(t *testing.T) {
	calls := ntpSDKCalls()
	require.Len(t, calls, len(platformv1.NTPService_ServiceDesc.Methods))

	for _, call := range calls {
		t.Run(path.Base(call.method), func(t *testing.T) {
			direct := syncedNTPBackend()
			want, err := invokeGRPCMethod(&platformv1.NTPService_ServiceDesc, NewNTPGRPCService(nil, direct), call.method, call.req)
			require.NoError(t, err)

			via := syncedNTPBackend()
			conn := connectNTPEmbedded(t, NewNTPGRPCService(nil, via))
			require.NoError(t, conn.Invoke(context.Background(), call.method, call.req, call.resp))

			require.True(t, proto.Equal(want, call.resp), "embedded reply\n%v\nwant the gRPC reply\n%v", call.resp, want)
			require.NotEmpty(t, via.calls, "the NTP backend saw no call")
			require.Equal(t, direct.calls, via.calls)
		})
	}
}

// TestSDKEmbedded_NTPMethodsRefuse checks every NTPService method refuses
// through the embedded adapter with the status a direct gRPC call gives:
// a node without an ntp: section, a backend with no reachable source, and
// a daemon whose registry carries no NTP service at all.
func TestSDKEmbedded_NTPMethodsRefuse(t *testing.T) {
	unreachable := ntp.ErrNoReachableSource{Total: 2}
	refusals := []struct {
		name    string
		backend func() NTPBackend
		want    codes.Code
	}{
		{"not configured", func() NTPBackend { return nil }, codes.Unavailable},
		{"no reachable source", func() NTPBackend {
			return &fakeNTPBackend{statusErr: unreachable, sourcesErr: unreachable, stepErr: unreachable}
		}, codes.Aborted},
	}
	for _, refusal := range refusals {
		for _, call := range ntpSDKCalls() {
			t.Run(refusal.name+"/"+path.Base(call.method), func(t *testing.T) {
				_, direct := invokeGRPCMethod(&platformv1.NTPService_ServiceDesc, NewNTPGRPCService(nil, refusal.backend()), call.method, call.req)

				conn := connectNTPEmbedded(t, NewNTPGRPCService(nil, refusal.backend()))
				via := conn.Invoke(context.Background(), call.method, call.req, call.resp)

				requireSameRefusal(t, refusal.want, direct, via)
			})
		}
	}

	for _, call := range ntpSDKCalls() {
		t.Run("not registered/"+path.Base(call.method), func(t *testing.T) {
			conn := connectNTPEmbedded(t, nil)
			err := conn.Invoke(context.Background(), call.method, call.req, call.resp)
			require.Equal(t, codes.Unimplemented, status.Code(err), "%v", err)
		})
	}
}
