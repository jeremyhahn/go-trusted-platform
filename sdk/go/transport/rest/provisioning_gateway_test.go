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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewayCapture records the one API request a gateway RPC sends.
type gatewayCapture struct {
	method string
	path   string
	body   map[string]interface{}
}

// gatewayAdapter serves reply as the payload of every API request and
// records the request into the returned capture.
func gatewayAdapter(t *testing.T, reply string) (*Adapter, *gatewayCapture) {
	t.Helper()
	captured := &gatewayCapture{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(reply)))
	})
	return a, captured
}

func TestProvisioningGateway_RoutesNameTheDeviceInThePath(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	cases := []struct {
		rpc        string
		req        proto.Message
		resp       proto.Message
		wantMethod string
		wantPath   string
	}{
		{
			rpc:        platformv1.ProvisioningGateway_RegisterPXEDevice_FullMethodName,
			req:        &platformv1.RegisterProvisioningDeviceRequest{MacAddress: mac, PortId: "port-1"},
			resp:       &platformv1.RegisterProvisioningDeviceResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/provisioning/devices/aa:bb:cc:dd:ee:ff/register",
		},
		{
			rpc:        platformv1.ProvisioningGateway_GetBootConfig_FullMethodName,
			req:        &platformv1.GetBootConfigRequest{MacAddress: mac},
			resp:       &platformv1.GetBootConfigResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/provisioning/devices/aa:bb:cc:dd:ee:ff/boot-config",
		},
		{
			rpc:        platformv1.ProvisioningGateway_ReportDeviceState_FullMethodName,
			req:        &platformv1.ReportDeviceStateRequest{MacAddress: mac, State: "booting"},
			resp:       &platformv1.ReportDeviceStateResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/provisioning/devices/aa:bb:cc:dd:ee:ff/state",
		},
		{
			rpc:        platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName,
			req:        &platformv1.NotifyInstallCompleteRequest{MacAddress: mac, Status: "success"},
			resp:       &platformv1.NotifyInstallCompleteResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/provisioning/devices/aa:bb:cc:dd:ee:ff/install-complete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.rpc, func(t *testing.T) {
			a, captured := gatewayAdapter(t, `{}`)
			if err := a.Connection().Invoke(context.Background(), tc.rpc, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod || captured.path != tc.wantPath {
				t.Errorf("route = %s %s, want %s %s", captured.method, captured.path, tc.wantMethod, tc.wantPath)
			}
			if _, has := captured.body["mac_address"]; has {
				t.Errorf("body must not echo mac_address: %v", captured.body)
			}
		})
	}
}

func TestProvisioningGateway_RegisterPXEDevice_BodyAndReply(t *testing.T) {
	a, captured := gatewayAdapter(t, `{"device_id":"dev-1","status":"registered"}`)
	resp := &platformv1.RegisterProvisioningDeviceResponse{}
	req := &platformv1.RegisterProvisioningDeviceRequest{MacAddress: "aa:bb:cc:dd:ee:ff", PortId: "port-1", GatewayId: "gw-1"}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.ProvisioningGateway_RegisterPXEDevice_FullMethodName, req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.body["port_id"] != "port-1" || captured.body["gateway_id"] != "gw-1" {
		t.Errorf("request body = %v", captured.body)
	}
	if resp.GetDeviceId() != "dev-1" || resp.GetStatus() != "registered" {
		t.Errorf("reply = %+v", resp)
	}
}

func TestProvisioningGateway_NotifyInstallComplete_SendsRFC3339Timestamp(t *testing.T) {
	a, captured := gatewayAdapter(t, `{}`)
	at := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	req := &platformv1.NotifyInstallCompleteRequest{
		MacAddress: "aa:bb:cc:dd:ee:ff",
		Status:     "failure",
		Timestamp:  timestamppb.New(at),
	}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName, req,
		&platformv1.NotifyInstallCompleteResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.body["status"] != "failure" {
		t.Errorf("body status = %v, want failure", captured.body["status"])
	}
	if captured.body["timestamp"] != "2026-10-14T09:30:00Z" {
		t.Errorf("body timestamp = %v, want 2026-10-14T09:30:00Z", captured.body["timestamp"])
	}
}

func TestProvisioningGateway_NotifyInstallComplete_OmitsUnsetTimestamp(t *testing.T) {
	a, captured := gatewayAdapter(t, `{}`)
	req := &platformv1.NotifyInstallCompleteRequest{MacAddress: "aa:bb:cc:dd:ee:ff", Status: "success"}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName, req,
		&platformv1.NotifyInstallCompleteResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if _, has := captured.body["timestamp"]; has {
		t.Errorf("body must omit an unset timestamp: %v", captured.body)
	}
}

func TestProvisioningGateway_EmptyMACRejected(t *testing.T) {
	var apiHits int
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/live" {
			apiHits++
		}
		w.WriteHeader(http.StatusOK)
	})
	err := a.Connection().Invoke(context.Background(),
		platformv1.ProvisioningGateway_ReportDeviceState_FullMethodName,
		&platformv1.ReportDeviceStateRequest{State: "booting"}, &platformv1.ReportDeviceStateResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
	if apiHits != 0 {
		t.Errorf("request must not reach the server, got %d API hits", apiHits)
	}
}
