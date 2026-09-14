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

package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// mockZoneSDNService implements the zone RPCs of
// platformv1.SDNServiceServer for the REST zone handler tests.
type mockZoneSDNService struct {
	platformv1.UnimplementedSDNServiceServer

	createZoneFunc func(ctx context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error)
	updateZoneFunc func(ctx context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.UpdateNetworkZoneResponse, error)
	deleteZoneFunc func(ctx context.Context, req *platformv1.DeleteNetworkZoneRequest) (*platformv1.DeleteNetworkZoneResponse, error)
	listZonesFunc  func(ctx context.Context, req *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error)
	assignZoneFunc func(ctx context.Context, req *platformv1.AssignNetworkZoneRequest) (*platformv1.AssignNetworkZoneResponse, error)
}

func (m *mockZoneSDNService) AssignNetworkZone(ctx context.Context, req *platformv1.AssignNetworkZoneRequest) (*platformv1.AssignNetworkZoneResponse, error) {
	if m.assignZoneFunc != nil {
		return m.assignZoneFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockZoneSDNService) CreateNetworkZone(ctx context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error) {
	if m.createZoneFunc != nil {
		return m.createZoneFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockZoneSDNService) UpdateNetworkZone(ctx context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.UpdateNetworkZoneResponse, error) {
	if m.updateZoneFunc != nil {
		return m.updateZoneFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockZoneSDNService) DeleteNetworkZone(ctx context.Context, req *platformv1.DeleteNetworkZoneRequest) (*platformv1.DeleteNetworkZoneResponse, error) {
	if m.deleteZoneFunc != nil {
		return m.deleteZoneFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockZoneSDNService) ListNetworkZones(ctx context.Context, req *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error) {
	if m.listZonesFunc != nil {
		return m.listZonesFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func newZoneTestRouter(t *testing.T, svc platformv1.SDNServiceServer) *mux.Router {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	writer := response.NewResponseWriter(logger, nil)
	mr := mux.NewRouter()
	NewSDNRouter(logger, svc, writer).RegisterRoutes(mr)
	return mr
}

// envelope decodes the platform response envelope.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return env
}

func testZoneProto(name string) *platformv1.NetworkZone {
	return &platformv1.NetworkZone{
		Config: &platformv1.NetworkZoneConfig{
			Name:            name,
			InternetIngress: true,
			IsolateFrom:     []string{"quarantine"},
			AllowTo: []*platformv1.NetworkZonePath{
				{Zone: "trusted", Services: []string{"dns"}},
			},
			LifecycleRole: "provisioning",
		},
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}
}

func TestZoneRoutes_ListZones(t *testing.T) {
	var gotRole string
	mr := newZoneTestRouter(t, &mockZoneSDNService{
		listZonesFunc: func(_ context.Context, req *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error) {
			gotRole = req.GetLifecycleRole()
			return &platformv1.ListNetworkZonesResponse{
				Zones: []*platformv1.NetworkZone{testZoneProto("dmz")},
			}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/zones?lifecycle_role=provisioning", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotRole != "provisioning" {
		t.Fatalf("lifecycle_role = %q, want provisioning", gotRole)
	}

	env := decodeEnvelope(t, rec)
	var payload NetworkZoneListResponse
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 1 || len(payload.Zones) != 1 {
		t.Fatalf("zones = %+v, want one zone", payload)
	}
	z := payload.Zones[0]
	if z.Name != "dmz" || !z.InternetIngress || z.LifecycleRole != "provisioning" {
		t.Fatalf("zone fields wrong: %+v", z)
	}
	if len(z.AllowTo) != 1 || z.AllowTo[0].Zone != "trusted" {
		t.Fatalf("allow_to wrong: %+v", z.AllowTo)
	}
}

func TestZoneRoutes_CreateZone(t *testing.T) {
	var gotCfg *platformv1.NetworkZoneConfig
	mr := newZoneTestRouter(t, &mockZoneSDNService{
		createZoneFunc: func(_ context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error) {
			gotCfg = req.GetConfig()
			return &platformv1.CreateNetworkZoneResponse{Zone: testZoneProto(req.GetConfig().GetName())}, nil
		},
	})

	body := bytes.NewBufferString(`{"name":"dmz","internet_ingress":true,"allow_to":[{"zone":"trusted","services":["dns"]}],"isolate":true}`)
	req := httptest.NewRequest(http.MethodPost, "/sdn/zones", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotCfg.GetName() != "dmz" || !gotCfg.GetInternetIngress() || !gotCfg.GetIsolate() {
		t.Fatalf("config not converted: %+v", gotCfg)
	}
	if len(gotCfg.GetAllowTo()) != 1 || gotCfg.GetAllowTo()[0].GetZone() != "trusted" {
		t.Fatalf("allow_to not converted: %+v", gotCfg.GetAllowTo())
	}
}

func TestZoneRoutes_CreateZone_MissingName(t *testing.T) {
	mr := newZoneTestRouter(t, &mockZoneSDNService{})

	req := httptest.NewRequest(http.MethodPost, "/sdn/zones", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestZoneRoutes_UpdateZone_NameMismatch(t *testing.T) {
	mr := newZoneTestRouter(t, &mockZoneSDNService{})

	body := bytes.NewBufferString(`{"name":"other"}`)
	req := httptest.NewRequest(http.MethodPut, "/sdn/zones/dmz", body)
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestZoneRoutes_UpdateZone(t *testing.T) {
	var gotName string
	mr := newZoneTestRouter(t, &mockZoneSDNService{
		updateZoneFunc: func(_ context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.UpdateNetworkZoneResponse, error) {
			gotName = req.GetName()
			return &platformv1.UpdateNetworkZoneResponse{Zone: testZoneProto(req.GetName())}, nil
		},
	})

	body := bytes.NewBufferString(`{"internet_ingress":true}`)
	req := httptest.NewRequest(http.MethodPut, "/sdn/zones/dmz", body)
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotName != "dmz" {
		t.Fatalf("name = %q, want dmz", gotName)
	}
}

func TestZoneRoutes_DeleteZone(t *testing.T) {
	mr := newZoneTestRouter(t, &mockZoneSDNService{
		deleteZoneFunc: func(_ context.Context, req *platformv1.DeleteNetworkZoneRequest) (*platformv1.DeleteNetworkZoneResponse, error) {
			return &platformv1.DeleteNetworkZoneResponse{RestartRequired: true}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/sdn/zones/dmz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	env := decodeEnvelope(t, rec)
	var payload NetworkZoneDeleteResponse
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !payload.Deleted || !payload.RestartRequired {
		t.Fatalf("delete payload wrong (want documented {deleted, restart_required} shape): %+v", payload)
	}
}

func TestZoneRoutes_AssignZone(t *testing.T) {
	var gotNetwork, gotZone string
	mr := newZoneTestRouter(t, &mockZoneSDNService{
		assignZoneFunc: func(_ context.Context, req *platformv1.AssignNetworkZoneRequest) (*platformv1.AssignNetworkZoneResponse, error) {
			gotNetwork = req.GetNetwork()
			gotZone = req.GetZone()
			return &platformv1.AssignNetworkZoneResponse{RestartRequired: true}, nil
		},
	})

	body := bytes.NewBufferString(`{"zone":"trusted"}`)
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/networks/office/zone", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotNetwork != "office" || gotZone != "trusted" {
		t.Fatalf("assign args = (%q, %q), want (office, trusted)", gotNetwork, gotZone)
	}
}

func TestZoneRoutes_AssignZone_MissingZone(t *testing.T) {
	mr := newZoneTestRouter(t, &mockZoneSDNService{})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/networks/office/zone", bytes.NewBufferString(`{}`)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestZoneRoutes_GRPCErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
		want int
	}{
		{"unavailable maps 503", codes.Unavailable, http.StatusServiceUnavailable},
		{"already exists maps 409", codes.AlreadyExists, http.StatusConflict},
		{"not found maps 404", codes.NotFound, http.StatusNotFound},
		{"invalid argument maps 400", codes.InvalidArgument, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr := newZoneTestRouter(t, &mockZoneSDNService{
				listZonesFunc: func(_ context.Context, _ *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error) {
					return nil, status.Error(tc.code, "zone backend says no")
				},
			})
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/zones", nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
			env := decodeEnvelope(t, rec)
			if env.Error == "" {
				t.Fatal("error envelope should carry the cause for the operator")
			}
		})
	}
}
