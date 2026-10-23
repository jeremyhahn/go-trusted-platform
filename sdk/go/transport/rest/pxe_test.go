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
package rest

import (
	"context"
	"net/http"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pxeDeviceAnswer is the server's answer to a PXE device action: the gRPC
// reply in proto JSON (pkg/webservice/v1/rest/pxe/router.go).
const pxeDeviceAnswer = `{"status":{"success":true},"device":{"id":"pxe-7","state":"PROVISIONING_STATE_QUARANTINED"}}`

// pxeOverREST is recordOverREST with a PXEService client.
func pxeOverREST(t *testing.T) (platformv1.PXEServiceClient, *sentRequest) {
	t.Helper()
	a, sent := recordOverREST(t, pxeDeviceAnswer)
	return platformv1.NewPXEServiceClient(a.Connection()), sent
}

func TestPXEDeviceActions_SDKOverREST(t *testing.T) {
	cases := []struct {
		name       string
		call       func(platformv1.PXEServiceClient) (*platformv1.PXEDeviceInfo, error)
		wantMethod string
		wantPath   string
		wantField  string
		wantValue  interface{}
	}{
		{
			name: "UpdateState",
			call: func(c platformv1.PXEServiceClient) (*platformv1.PXEDeviceInfo, error) {
				resp, err := c.UpdateState(context.Background(), &platformv1.UpdatePXEStateRequest{
					DeviceId: "pxe-7", State: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED, Reason: "disk",
				})
				return resp.GetDevice(), err
			},
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/pxe/devices/pxe-7/state",
			wantField:  "reason",
			wantValue:  "disk",
		},
		{
			name: "Authorize",
			call: func(c platformv1.PXEServiceClient) (*platformv1.PXEDeviceInfo, error) {
				resp, err := c.Authorize(context.Background(), &platformv1.AuthorizePXEDeviceRequest{
					DeviceId: "pxe-7", TargetVlan: 200,
				})
				return resp.GetDevice(), err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/devices/pxe-7/authorize",
			wantField:  "target_vlan",
			wantValue:  float64(200),
		},
		{
			name: "Quarantine",
			call: func(c platformv1.PXEServiceClient) (*platformv1.PXEDeviceInfo, error) {
				resp, err := c.Quarantine(context.Background(), &platformv1.QuarantinePXEDeviceRequest{
					DeviceId: "pxe-7", Reason: "attestation failed",
				})
				return resp.GetDevice(), err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/devices/pxe-7/quarantine",
			wantField:  "reason",
			wantValue:  "attestation failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := pxeOverREST(t)

			device, err := tc.call(client)
			if err != nil {
				t.Fatalf("%s over REST: %v", tc.name, err)
			}
			if sent.method != tc.wantMethod || sent.path != tc.wantPath {
				t.Errorf("sent %s %s, want %s %s", sent.method, sent.path, tc.wantMethod, tc.wantPath)
			}
			if sent.body[tc.wantField] != tc.wantValue {
				t.Errorf("body = %v, want %s %v", sent.body, tc.wantField, tc.wantValue)
			}
			if _, ok := sent.body["device_id"]; ok {
				t.Errorf("body = %v: the device travels in the path, not the body", sent.body)
			}
			if device.GetId() != "pxe-7" ||
				device.GetState() != platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED {
				t.Errorf("device = %v, want pxe-7 quarantined", device)
			}
		})
	}
}

func TestPXEDeviceActions_RefuseAMissingDevice(t *testing.T) {
	cases := []struct {
		name string
		call func(platformv1.PXEServiceClient) error
	}{
		{"UpdateState", func(c platformv1.PXEServiceClient) error {
			_, err := c.UpdateState(context.Background(), &platformv1.UpdatePXEStateRequest{
				State: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED,
			})
			return err
		}},
		{"Authorize", func(c platformv1.PXEServiceClient) error {
			_, err := c.Authorize(context.Background(), &platformv1.AuthorizePXEDeviceRequest{TargetVlan: 200})
			return err
		}},
		{"Quarantine", func(c platformv1.PXEServiceClient) error {
			_, err := c.Quarantine(context.Background(), &platformv1.QuarantinePXEDeviceRequest{Reason: "x"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := pxeOverREST(t)
			err := tc.call(client)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if sent.path != "" {
				t.Errorf("a request without a device reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}

// TestPXEControlPlane_SDKOverREST pins the RPCs #975 mapped to the route the
// web service serves each on: the device id or MAC only in the path, the
// ListDevices filter only in the query.
func TestPXEControlPlane_SDKOverREST(t *testing.T) {
	cases := []struct {
		name       string
		call       func(platformv1.PXEServiceClient) error
		wantMethod string
		wantPath   string
		wantQuery  string
		wantBody   map[string]interface{}
	}{
		{
			name: "GetDeviceByMAC",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.GetDeviceByMAC(context.Background(), &platformv1.GetPXEDeviceByMACRequest{MacAddress: "52:54:00:aa:bb:cc"})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/pxe/devices/mac/52:54:00:aa:bb:cc",
		},
		{
			name: "RemoveDevice",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.RemoveDevice(context.Background(), &platformv1.RemovePXEDeviceRequest{DeviceId: "pxe-7"})
				return err
			},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/pxe/devices/pxe-7",
		},
		{
			name: "SetDeviceEnrolled",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.SetDeviceEnrolled(context.Background(), &platformv1.SetPXEDeviceEnrolledRequest{
					DeviceId: "pxe-7", CertificateSerial: "0a1b",
				})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/devices/pxe-7/enrolled",
			wantBody:   map[string]interface{}{"certificate_serial": "0a1b"},
		},
		{
			name: "Retry",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.Retry(context.Background(), &platformv1.RetryPXEDeviceRequest{DeviceId: "pxe-7"})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/devices/pxe-7/retry",
		},
		{
			name: "GetEvents",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.GetEvents(context.Background(), &platformv1.GetPXEEventsRequest{DeviceId: "pxe-7"})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/pxe/devices/pxe-7/events",
		},
		{
			name: "StartService",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.StartService(context.Background(), &platformv1.StartPXEServiceRequest{})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/start",
		},
		{
			name: "StopService",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.StopService(context.Background(), &platformv1.StopPXEServiceRequest{})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/stop",
		},
		{
			name: "WebhookComplete",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.WebhookComplete(context.Background(), &platformv1.PXEWebhookCompleteRequest{
					MacAddress: "52:54:00:aa:bb:cc", Success: true,
				})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/pxe/webhook/complete",
			wantBody:   map[string]interface{}{"mac_address": "52:54:00:aa:bb:cc", "success": true},
		},
		{
			name: "ListDevices without a filter",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.ListDevices(context.Background(), &platformv1.ListPXEDevicesRequest{})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/pxe/devices",
		},
		{
			name: "ListDevices with every filter",
			call: func(c platformv1.PXEServiceClient) error {
				_, err := c.ListDevices(context.Background(), &platformv1.ListPXEDevicesRequest{
					Filter: &platformv1.PXEDeviceFilter{
						State:      platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED,
						MacAddress: "52:54:00",
						Vlan:       405,
						Limit:      10,
						Offset:     20,
					},
				})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/pxe/devices",
			wantQuery:  "limit=10&mac_address=52%3A54%3A00&offset=20&state=PROVISIONING_STATE_QUARANTINED&vlan=405",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := pxeOverREST(t)

			if err := tc.call(client); err != nil {
				t.Fatalf("%s over REST: %v", tc.name, err)
			}
			if sent.method != tc.wantMethod || sent.path != tc.wantPath {
				t.Errorf("sent %s %s, want %s %s", sent.method, sent.path, tc.wantMethod, tc.wantPath)
			}
			if sent.query != tc.wantQuery {
				t.Errorf("query = %q, want %q", sent.query, tc.wantQuery)
			}
			for field, want := range tc.wantBody {
				if sent.body[field] != want {
					t.Errorf("body = %v, want %s %v", sent.body, field, want)
				}
			}
			if _, ok := sent.body["device_id"]; ok {
				t.Errorf("body = %v: the device travels in the path, not the body", sent.body)
			}
			if filter, ok := sent.body["filter"].(map[string]interface{}); ok && len(filter) > 0 {
				t.Errorf("body = %v: the filter travels in the query, not the body", sent.body)
			}
			if tc.name != "WebhookComplete" {
				if _, ok := sent.body["mac_address"]; ok {
					t.Errorf("body = %v: the MAC travels in the path, not the body", sent.body)
				}
			}
		})
	}
}

func TestPXEControlPlane_RefuseAMissingDevice(t *testing.T) {
	cases := []struct {
		name string
		call func(platformv1.PXEServiceClient) error
	}{
		{"GetDeviceByMAC", func(c platformv1.PXEServiceClient) error {
			_, err := c.GetDeviceByMAC(context.Background(), &platformv1.GetPXEDeviceByMACRequest{})
			return err
		}},
		{"RemoveDevice", func(c platformv1.PXEServiceClient) error {
			_, err := c.RemoveDevice(context.Background(), &platformv1.RemovePXEDeviceRequest{})
			return err
		}},
		{"SetDeviceEnrolled", func(c platformv1.PXEServiceClient) error {
			_, err := c.SetDeviceEnrolled(context.Background(), &platformv1.SetPXEDeviceEnrolledRequest{CertificateSerial: "0a1b"})
			return err
		}},
		{"Retry", func(c platformv1.PXEServiceClient) error {
			_, err := c.Retry(context.Background(), &platformv1.RetryPXEDeviceRequest{})
			return err
		}},
		{"GetEvents", func(c platformv1.PXEServiceClient) error {
			_, err := c.GetEvents(context.Background(), &platformv1.GetPXEEventsRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := pxeOverREST(t)
			err := tc.call(client)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if sent.path != "" {
				t.Errorf("a request without a device reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}
