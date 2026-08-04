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

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// adapterAgainst spins up a test HTTP server, connects an Adapter to
// it, and returns both. Caller closes server on cleanup; adapter is
// closed automatically.
func adapterAgainst(t *testing.T, handler http.HandlerFunc) (*Adapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	ctx := context.Background()
	a, err := Connect(ctx, platform.NewOptions(platform.WithRESTAddr(server.URL)))
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
