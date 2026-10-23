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
