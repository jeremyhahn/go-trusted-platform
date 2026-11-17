package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type zoneCall struct {
	method string
	path   string
	query  string
	body   map[string]interface{}
}

// zoneAdapter serves reply on every request and records what reached it.
func zoneAdapter(t *testing.T, status int, reply string) (*Adapter, *zoneCall) {
	t.Helper()
	call := &zoneCall{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		call.method = r.Method
		call.path = r.URL.Path
		call.query = r.URL.RawQuery
		raw, _ := io.ReadAll(r.Body)
		call.body = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	})
	return a, call
}

const flatZoneReply = `{"success":true,"code":200,"payload":{"name":"lab","offset":12,"port_classes":["hypervisor"],"isolate":true,"allow_to":[{"zone":"edge","services":["dns"]}],"numbering":{"vlan":112,"subnet4":"10.0.12.0/24","gateway":"10.0.12.1"},"restart_required":true,"created_at":"2026-11-16T10:00:00Z","updated_at":"2026-11-16T11:00:00Z"}}`

func TestSDNZoneRoutes_ResolveToTheServedRoutes(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		req, reply interface{}
		wantMethod string
		wantPath   string
		wantQuery  string
		served     string
	}{
		{"create", platformv1.SDNService_CreateNetworkZone_FullMethodName,
			&platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{Name: "lab"}},
			&platformv1.CreateNetworkZoneResponse{}, http.MethodPost, "/api/v1/sdn/zones", "", flatZoneReply},
		{"list", platformv1.SDNService_ListNetworkZones_FullMethodName,
			&platformv1.ListNetworkZonesRequest{LifecycleRole: "quarantine"},
			&platformv1.ListNetworkZonesResponse{}, http.MethodGet, "/api/v1/sdn/zones", "lifecycle_role=quarantine",
			`{"success":true,"code":200,"payload":{"zones":[],"count":0}}`},
		{"update", platformv1.SDNService_UpdateNetworkZone_FullMethodName,
			&platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: &platformv1.NetworkZoneConfig{Name: "lab"}},
			&platformv1.UpdateNetworkZoneResponse{}, http.MethodPut, "/api/v1/sdn/zones/lab", "", flatZoneReply},
		{"delete", platformv1.SDNService_DeleteNetworkZone_FullMethodName,
			&platformv1.DeleteNetworkZoneRequest{Name: "lab"},
			&platformv1.DeleteNetworkZoneResponse{}, http.MethodDelete, "/api/v1/sdn/zones/lab", "",
			`{"success":true,"code":200,"payload":{"deleted":true,"restart_required":true}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, call := zoneAdapter(t, http.StatusOK, tc.served)
			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if call.method != tc.wantMethod || call.path != tc.wantPath || call.query != tc.wantQuery {
				t.Errorf("got %s %s?%s, want %s %s?%s", call.method, call.path, call.query,
					tc.wantMethod, tc.wantPath, tc.wantQuery)
			}
		})
	}
}

func TestSDNZoneCreate_SendsTheFlatZoneDocument(t *testing.T) {
	a, call := zoneAdapter(t, http.StatusCreated, flatZoneReply)
	req := &platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{
		Name:        "lab",
		Offset:      12,
		PortClasses: []string{"hypervisor"},
		Isolate:     true,
		AllowTo:     []*platformv1.NetworkZonePath{{Zone: "edge", Services: []string{"dns"}}},
		PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{
			Reason: "audit", ApprovedBy: "owner",
		},
	}}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.SDNService_CreateNetworkZone_FullMethodName, req, &platformv1.CreateNetworkZoneResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if _, nested := call.body["config"]; nested {
		t.Fatalf("body nests config: %v", call.body)
	}
	if call.body["name"] != "lab" || call.body["offset"] != float64(12) || call.body["isolate"] != true {
		t.Errorf("flat body = %v", call.body)
	}
	allow, _ := call.body["allow_to"].([]interface{})
	if len(allow) != 1 {
		t.Fatalf("allow_to = %v", call.body["allow_to"])
	}
	pa, _ := call.body["privileged_access"].(map[string]interface{})
	if pa["approved_by"] != "owner" {
		t.Errorf("privileged_access = %v", call.body["privileged_access"])
	}
}

// The flat zone document has no omit field on either the webservice or the
// daemon side, so an Omit=true Create or Update is refused before the wire,
// as the gRPC path refuses it, instead of creating or replacing the zone.
func TestSDNZoneOmit_RefusedBeforeTheWire(t *testing.T) {
	cfg := &platformv1.NetworkZoneConfig{Name: "lab", Offset: 12, Omit: true}
	cases := []struct {
		name   string
		method string
		req    interface{}
		reply  interface{}
	}{
		{"create", platformv1.SDNService_CreateNetworkZone_FullMethodName,
			&platformv1.CreateNetworkZoneRequest{Config: cfg}, &platformv1.CreateNetworkZoneResponse{}},
		{"update", platformv1.SDNService_UpdateNetworkZone_FullMethodName,
			&platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: cfg}, &platformv1.UpdateNetworkZoneResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, call := zoneAdapter(t, http.StatusOK, flatZoneReply)
			err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if call.method != "" || call.path != "" {
				t.Fatalf("request reached the server: %s %s", call.method, call.path)
			}
		})
	}
}

func TestSDNZoneDecode_FoldsTheFlatZoneIntoConfig(t *testing.T) {
	a, _ := zoneAdapter(t, http.StatusOK, flatZoneReply)
	reply := &platformv1.UpdateNetworkZoneResponse{}
	req := &platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: &platformv1.NetworkZoneConfig{Name: "lab"}}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.SDNService_UpdateNetworkZone_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	zone := reply.GetZone()
	if zone.GetConfig().GetName() != "lab" || zone.GetConfig().GetOffset() != 12 || !zone.GetConfig().GetIsolate() {
		t.Errorf("config = %v", zone.GetConfig())
	}
	if got := zone.GetConfig().GetAllowTo(); len(got) != 1 || got[0].GetZone() != "edge" {
		t.Errorf("allow_to = %v", got)
	}
	if zone.GetNumbering().GetVlan() != 112 || zone.GetNumbering().GetGateway() != "10.0.12.1" {
		t.Errorf("numbering = %v", zone.GetNumbering())
	}
	if !zone.GetRestartRequired() || zone.GetCreatedAt() == nil || zone.GetUpdatedAt() == nil {
		t.Errorf("zone = %v", zone)
	}
	if !reply.GetStatus().GetSuccess() {
		t.Errorf("status = %v", reply.GetStatus())
	}
}
