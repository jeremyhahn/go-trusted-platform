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
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceLifecycle_RoutesToTheTransitionEndpoints proves DisableDevice and
// EnableDevice reach the dedicated POST endpoints, never the generic PUT,
// with the device id in the path only, and that the server's reply decodes
// into the pb response.
func TestDeviceLifecycle_RoutesToTheTransitionEndpoints(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		wantPath   string
	}{
		{"disable", "/platform.v1.DeviceService/DisableDevice",
			&platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"}, "/api/v1/devices/42/disable"},
		{"enable", "/platform.v1.DeviceService/EnableDevice",
			&platformv1.EnableDeviceRequest{DeviceId: "42"}, "/api/v1/devices/42/enable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				method string
				path   string
				body   map[string]interface{}
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					w.WriteHeader(http.StatusOK) // Connect's health probe
					return
				}
				captured.method = r.Method
				captured.path = r.URL.Path
				if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil {
					t.Errorf("decode request body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte(`{"success":true,"payload":{"device_id":"42","state":"suspended","previous_state":"activated"}}`)); err != nil {
					t.Errorf("write reply: %v", err)
				}
			})

			resp := &platformv1.DeviceLifecycleResponse{}
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != http.MethodPost {
				t.Errorf("method = %q, want POST", captured.method)
			}
			if captured.path != tc.wantPath {
				t.Errorf("path = %q, want %q", captured.path, tc.wantPath)
			}
			if _, has := captured.body["device_id"]; has {
				t.Errorf("device_id travels in the body as well as the path: %v", captured.body)
			}
			if resp.GetDeviceId() != 42 || resp.GetState() != "suspended" {
				t.Errorf("reply = %+v, want device 42 suspended", resp)
			}
		})
	}
}

func TestDeviceLifecycle_DisableCarriesTheReason(t *testing.T) {
	var body map[string]interface{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK) // Connect's health probe
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"success":true,"payload":{}}`)); err != nil {
			t.Errorf("write reply: %v", err)
		}
	})

	err := a.Connection().Invoke(context.Background(), "/platform.v1.DeviceService/DisableDevice",
		&platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"}, &platformv1.DeviceLifecycleResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if body["reason"] != "rma pending" {
		t.Errorf("body = %v, want the reason", body)
	}
}

func TestDeviceLifecycle_MissingIDNeverLeavesTheClient(t *testing.T) {
	var apiHits int
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			apiHits++
		}
		w.WriteHeader(http.StatusOK)
	})

	err := a.Connection().Invoke(context.Background(), "/platform.v1.DeviceService/EnableDevice",
		&platformv1.EnableDeviceRequest{}, &platformv1.DeviceLifecycleResponse{})
	if st, _ := status.FromError(err); st == nil || st.Code() != codes.InvalidArgument {
		t.Errorf("status = %v, want InvalidArgument", err)
	}
	if apiHits != 0 {
		t.Errorf("server saw %d API hits; want 0", apiHits)
	}
}
