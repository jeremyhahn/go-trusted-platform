// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// adapterAgainst spins up a test HTTP server, connects an Adapter to
// it, and returns both. Caller closes server on cleanup; adapter is
// closed automatically.
func adapterAgainst(t *testing.T, handler http.HandlerFunc) (*Adapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	ctx := context.Background()
	a, err := Connect(ctx, platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer(server)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	return a.(*Adapter), server
}

func TestBMCPower_PathTemplated(t *testing.T) {
	var captured struct {
		method  string
		path    string
		body    map[string]interface{}
		hasBody bool
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		// Decode body — server-side we should never see profile_id here.
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&captured.body)
		}
		captured.hasBody = captured.body != nil
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	conn := a.Connection()
	req := &platformv1.BMCPowerRequest{ProfileId: 42}
	resp := &platformv1.BMCPowerResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.BMCService/PowerOn", req, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost {
		t.Errorf("method = %q, want POST", captured.method)
	}
	if captured.path != "/api/v1/bmc/42/power" {
		t.Errorf("path = %q, want /api/v1/bmc/42/power", captured.path)
	}
	// profile_id is in the URL; the body must not echo it back.
	if _, has := captured.body["profile_id"]; has {
		t.Errorf("body still contains profile_id: %v", captured.body)
	}
}

func TestBMCPower_ZeroProfileIDRejected(t *testing.T) {
	var apiHits int
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		// Connect()'s probe hits /health; only count real API calls.
		if r.URL.Path != "/health" {
			apiHits++
		}
		w.WriteHeader(http.StatusOK)
	})

	conn := a.Connection()
	req := &platformv1.BMCPowerRequest{ProfileId: 0}
	resp := &platformv1.BMCPowerResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.BMCService/PowerOn", req, resp)
	if err == nil {
		t.Fatal("expected error for zero profile_id, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", st.Code())
	}
	if apiHits != 0 {
		t.Errorf("server saw %d API hits; want 0 (path-param validation should fail before HTTP)", apiHits)
	}
}

func TestBMCPower_GetReadsPathOnly(t *testing.T) {
	var capturedPath string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{"state":1}}`))
	})

	conn := a.Connection()
	req := &platformv1.BMCPowerStatusRequest{ProfileId: 7}
	resp := &platformv1.BMCPowerStatusResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.BMCService/PowerStatus", req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if capturedPath != "/api/v1/bmc/7/power" {
		t.Errorf("path = %q, want /api/v1/bmc/7/power", capturedPath)
	}
}

func TestBMCMountISO_BodyKeepsNonTemplatedFields(t *testing.T) {
	var captured map[string]interface{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	conn := a.Connection()
	req := &platformv1.BMCMountISORequest{
		ProfileId: 99,
		IsoUrl:    "https://example.com/installer.iso",
	}
	resp := &platformv1.BMCMountISOResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.BMCService/MountISO", req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if _, has := captured["profile_id"]; has {
		t.Errorf("body still contains profile_id: %v", captured)
	}
	gotURL, _ := captured["iso_url"].(string)
	if gotURL != "https://example.com/installer.iso" {
		t.Errorf("iso_url in body = %q, want the original URL", gotURL)
	}
}

func TestTenantBarrier_Init_PathTemplated(t *testing.T) {
	var captured struct {
		method string
		path   string
		body   map[string]interface{}
	}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	conn := a.Connection()
	req := &platformv1.InitTenantBarrierRequest{
		TenantId:  "acme-prod",
		Threshold: 3,
		Shares:    5,
	}
	resp := &platformv1.InitTenantBarrierResponse{}
	if err := conn.Invoke(context.Background(),
		"/platform.v1.TenantService/InitTenantBarrier", req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost {
		t.Errorf("method = %q, want POST", captured.method)
	}
	if captured.path != "/api/v1/tenants/acme-prod/barrier/init" {
		t.Errorf("path = %q, want /api/v1/tenants/acme-prod/barrier/init", captured.path)
	}
	if _, has := captured.body["tenant_id"]; has {
		t.Errorf("body still contains tenant_id: %v", captured.body)
	}
	// Other fields survive the strip — server reads them from the body.
	if got, _ := captured.body["threshold"].(float64); got != 3 {
		t.Errorf("threshold in body = %v, want 3", captured.body["threshold"])
	}
}

func TestTenantBarrier_EmptyTenantIDRejected(t *testing.T) {
	var apiHits int
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			apiHits++
		}
		w.WriteHeader(http.StatusOK)
	})

	conn := a.Connection()
	req := &platformv1.SealTenantBarrierRequest{TenantId: ""}
	resp := &platformv1.SealTenantBarrierResponse{}
	err := conn.Invoke(context.Background(),
		"/platform.v1.TenantService/SealTenantBarrier", req, resp)
	if err == nil {
		t.Fatal("expected error for empty tenant_id, got nil")
	}
	st, _ := status.FromError(err)
	if st == nil || st.Code() != codes.InvalidArgument {
		t.Errorf("status = %v, want InvalidArgument", st)
	}
	if apiHits != 0 {
		t.Errorf("server saw %d API hits; want 0", apiHits)
	}
}

func TestTenantBarrier_TenantIDIsURLEscaped(t *testing.T) {
	var capturedRawPath string
	var capturedPath string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		// Raw form preserves the percent-encoded segment as we sent it.
		capturedRawPath = r.URL.EscapedPath()
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	conn := a.Connection()
	req := &platformv1.GetTenantBarrierStatusRequest{TenantId: "acme/west"}
	resp := &platformv1.GetTenantBarrierStatusResponse{}
	if err := conn.Invoke(context.Background(),
		"/platform.v1.TenantService/GetTenantBarrierStatus", req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if capturedRawPath != "/api/v1/tenants/acme%2Fwest/barrier" {
		t.Errorf("escaped path = %q, want /api/v1/tenants/acme%%2Fwest/barrier", capturedRawPath)
	}
	if capturedPath != "/api/v1/tenants/acme/west/barrier" {
		t.Errorf("decoded path = %q, want /api/v1/tenants/acme/west/barrier", capturedPath)
	}
}

func TestFlatRouteUnchanged(t *testing.T) {
	// Flat routes (no templating) should work exactly as before. Pick a
	// well-known one and verify the URL is the literal path with no
	// substitution attempted.
	var capturedPath string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	// Use a real proto request shape that's not in the templated table.
	conn := a.Connection()
	req := &platformv1.GetCAInfoRequest{}
	resp := &platformv1.GetCAInfoResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.CAService/GetCAInfo", req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if capturedPath != "/api/v1/ca/info" {
		t.Errorf("path = %q, want /api/v1/ca/info", capturedPath)
	}
}

func TestBuildTemplatedRequest_NonProtoArgsRejected(t *testing.T) {
	_, _, err := buildTemplatedRequest(templatedRoute{
		path:       "/api/v1/bmc/{profileID}/power",
		method:     http.MethodPost,
		pathParams: []pathParam{{placeholder: "{profileID}", field: "profile_id"}},
	}, map[string]interface{}{"profile_id": 1})
	if err == nil {
		t.Fatal("expected error for non-proto args, got nil")
	}
	st, _ := status.FromError(err)
	if st == nil || st.Code() != codes.InvalidArgument {
		t.Errorf("status = %v, want InvalidArgument", st)
	}
}

// TestSingularAccessors_IdentifierTravelsInThePath walks every singular
// accessor converted from a collection claim in #379 and asserts the URL the
// client actually puts on the wire.
//
// It sends real requests through the adapter rather than reading the route
// table, because the table is what was wrong before: reading it back proves
// only that the edit was applied, not that the identifier reaches the URL.
// The body assertion is the other half -- the identifier must not travel
// twice, or the server sees the same value in two places and the two can
// disagree.
func TestSingularAccessors_IdentifierTravelsInThePath(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantPath   string
		strippedIn string // proto JSON field name that must be gone from the body
	}{
		{
			name:       "CAService/GetCertificate",
			grpcMethod: "/platform.v1.CAService/GetCertificate",
			req:        &platformv1.GetCertificateRequest{Serial: "0A1B2C", IncludePem: true},
			resp:       &platformv1.GetCertificateResponse{},
			wantPath:   "/api/v1/ca/certificates/0A1B2C",
			strippedIn: "serial",
		},
		{
			name:       "ComputeService/GetContainer",
			grpcMethod: "/platform.v1.ComputeService/GetContainer",
			req:        &platformv1.GetContainerRequest{Id: "ctr-7"},
			resp:       &platformv1.GetContainerResponse{},
			wantPath:   "/api/v1/compute/containers/ctr-7",
			strippedIn: "id",
		},
		{
			name:       "DeviceService/GetDevice",
			grpcMethod: "/platform.v1.DeviceService/GetDevice",
			req:        &platformv1.GetDeviceRequest{Id: 42},
			resp:       &platformv1.GetDeviceResponse{},
			wantPath:   "/api/v1/devices/42",
			strippedIn: "id",
		},
		{
			name:       "DeviceService/GetProfile",
			grpcMethod: "/platform.v1.DeviceService/GetProfile",
			req:        &platformv1.GetProfileRequest{Id: 9},
			resp:       &platformv1.GetProfileResponse{},
			wantPath:   "/api/v1/device/profiles/9",
			strippedIn: "id",
		},
		{
			name:       "InvitationService/GetInvitation",
			grpcMethod: "/platform.v1.InvitationService/GetInvitation",
			req:        &platformv1.GetInvitationRequest{InvitationId: 17},
			resp:       &platformv1.GetInvitationResponse{},
			wantPath:   "/api/v1/invitations/17",
			strippedIn: "invitation_id",
		},
		{
			name:       "KeyManagementService/GetKey",
			grpcMethod: "/platform.v1.KeyManagementService/GetKey",
			req:        &platformv1.GetKeyRequest{KeyId: "tenant-dek", Version: 3},
			resp:       &platformv1.GetKeyResponse{},
			wantPath:   "/api/v1/kms/keys/tenant-dek",
			strippedIn: "key_id",
		},
		{
			name:       "OverlayService/GetVTEP",
			grpcMethod: "/platform.v1.OverlayService/GetVTEP",
			req:        &platformv1.GetVTEPRequest{NodeId: "node-03"},
			resp:       &platformv1.GetVTEPResponse{},
			wantPath:   "/api/v1/overlay/vteps/node-03",
			strippedIn: "node_id",
		},
		{
			name:       "PXEService/GetDevice",
			grpcMethod: "/platform.v1.PXEService/GetDevice",
			req:        &platformv1.GetPXEDeviceRequest{DeviceId: "pxe-1"},
			resp:       &platformv1.GetPXEDeviceResponse{},
			wantPath:   "/api/v1/pxe/devices/pxe-1",
			strippedIn: "device_id",
		},
		{
			name:       "SDNService/GetPolicy",
			grpcMethod: "/platform.v1.SDNService/GetPolicy",
			req:        &platformv1.GetPolicyRequest{PolicyId: "pol-2"},
			resp:       &platformv1.GetPolicyResponse{},
			wantPath:   "/api/v1/sdn/policies/pol-2",
			strippedIn: "policy_id",
		},
		{
			name:       "TenantService/GetTenant",
			grpcMethod: "/platform.v1.TenantService/GetTenant",
			req:        &platformv1.GetTenantRequest{TenantId: "acme-prod"},
			resp:       &platformv1.GetTenantResponse{},
			wantPath:   "/api/v1/tenants/acme-prod",
			strippedIn: "tenant_id",
		},
		{
			name:       "PlatformIAMService/GetUser",
			grpcMethod: "/platform.v1.PlatformIAMService/GetUser",
			req:        &platformv1.GetIAMUserRequest{TenantId: "acme-prod", UserId: "u-5"},
			resp:       &platformv1.IAMUserResponse{},
			wantPath:   "/api/v1/iam/tenants/acme-prod/users/u-5",
			strippedIn: "user_id",
		},
		{
			name:       "PlatformIAMService/GetRole",
			grpcMethod: "/platform.v1.PlatformIAMService/GetRole",
			req:        &platformv1.GetIAMRoleRequest{TenantId: "acme-prod", RoleId: "r-2"},
			resp:       &platformv1.IAMRoleResponse{},
			wantPath:   "/api/v1/iam/tenants/acme-prod/roles/r-2",
			strippedIn: "role_id",
		},
		{
			name:       "PlatformIAMService/GetTenant",
			grpcMethod: "/platform.v1.PlatformIAMService/GetTenant",
			req:        &platformv1.GetIAMTenantRequest{TenantId: "acme-prod"},
			resp:       &platformv1.IAMTenantResponse{},
			wantPath:   "/api/v1/iam/tenants/acme-prod",
			strippedIn: "tenant_id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				method string
				path   string
				body   map[string]interface{}
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				captured.method = r.Method
				captured.path = r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&captured.body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			if err := a.Connection().Invoke(
				context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != http.MethodGet {
				t.Errorf("method = %q, want GET", captured.method)
			}
			if captured.path != tc.wantPath {
				t.Errorf("path = %q, want %q", captured.path, tc.wantPath)
			}
			if _, has := captured.body[tc.strippedIn]; has {
				t.Errorf("identifier %q travels in the body as well as the path: %v",
					tc.strippedIn, captured.body)
			}
		})
	}
}

// TestSingularAccessors_ZeroIdentifierRejectedBeforeTheWire is the control on
// the test above: with the identifier unset, the adapter must fail rather than
// send anything.
//
// Before #379 the same call returned 200 and the whole collection, so a caller
// asking for "" or 0 got a plausible answer. The point of the conversion is
// that it now cannot: an empty identifier stops at the client.
func TestSingularAccessors_ZeroIdentifierRejectedBeforeTheWire(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"CAService/GetCertificate", "/platform.v1.CAService/GetCertificate",
			&platformv1.GetCertificateRequest{}, &platformv1.GetCertificateResponse{}},
		{"DeviceService/GetDevice", "/platform.v1.DeviceService/GetDevice",
			&platformv1.GetDeviceRequest{}, &platformv1.GetDeviceResponse{}},
		{"InvitationService/GetInvitation", "/platform.v1.InvitationService/GetInvitation",
			&platformv1.GetInvitationRequest{}, &platformv1.GetInvitationResponse{}},
		{"KeyManagementService/GetKey", "/platform.v1.KeyManagementService/GetKey",
			&platformv1.GetKeyRequest{}, &platformv1.GetKeyResponse{}},
		{"TenantService/GetTenant", "/platform.v1.TenantService/GetTenant",
			&platformv1.GetTenantRequest{}, &platformv1.GetTenantResponse{}},
		{"PlatformIAMService/GetUser", "/platform.v1.PlatformIAMService/GetUser",
			&platformv1.GetIAMUserRequest{TenantId: "acme-prod"}, &platformv1.IAMUserResponse{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var apiHits int
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					apiHits++
				}
				w.WriteHeader(http.StatusOK)
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if err == nil {
				t.Fatal("expected an error for the zero identifier, got nil")
			}
			if st, _ := status.FromError(err); st == nil || st.Code() != codes.InvalidArgument {
				t.Errorf("status = %v, want InvalidArgument", st)
			}
			if apiHits != 0 {
				t.Errorf("server saw %d API hits; want 0 -- the request must not leave the client", apiHits)
			}
		})
	}
}
