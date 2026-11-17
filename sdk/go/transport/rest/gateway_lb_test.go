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
	"io"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const sampleVIPJSON = `{"address":"10.100.0.10","port":443,"protocol":"tcp","algorithm":"hash",` +
	`"ct_zone":7,"group_id":12,` +
	`"backends":[{"backend":{"address":"10.0.1.5","port":8443,"weight":2},"healthy":true}]}`

// lbCall is what the fake daemon saw for one SDK call.
type lbCall struct {
	method string
	path   string
	body   []byte
}

// lbServer answers every lb route with a reply shaped like the daemon's and
// records the request it saw.
func lbServer(t *testing.T) (*Adapter, *lbCall) {
	t.Helper()
	seen := &lbCall{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		seen.method, seen.path, seen.body = r.Method, r.URL.Path, raw
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/sdn/gateway/lb/status":
			_, _ = w.Write([]byte(`{"active":true,"vip_count":2,"healthy_backends":3,"total_backends":4,` +
				`"last_reconcile":"2026-10-01T12:00:00Z","timestamp":"2026-10-01T12:00:01Z"}`))
		case r.URL.Path == "/api/v1/sdn/gateway/lb/vips" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"vips":[` + sampleVIPJSON + `],"count":1,"timestamp":"2026-10-01T12:00:01Z"}`))
		case r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{"resource_id":"tcp/10.100.0.10:443","resource_type":"vip","action":"remove","success":true}`))
		default:
			_, _ = w.Write([]byte(sampleVIPJSON))
		}
	})
	return a, seen
}

func TestLBVIPRoutes_ResolveToTheServedDaemonRoutes(t *testing.T) {
	const item = "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443"
	cases := []struct {
		name       string
		method     string
		req, reply proto.Message
		wantMethod string
		wantPath   string
	}{
		{"AddVIP", platformv1.GatewayService_AddVIP_FullMethodName,
			&platformv1.AddVIPRequest{Vip: &platformv1.VIPConfig{Address: "10.100.0.10", Port: 443, Protocol: "tcp"}},
			&platformv1.AddVIPResponse{}, http.MethodPost, "/api/v1/sdn/gateway/lb/vips"},
		{"ListVIPs", platformv1.GatewayService_ListVIPs_FullMethodName,
			&platformv1.ListVIPsRequest{}, &platformv1.ListVIPsResponse{}, http.MethodGet, "/api/v1/sdn/gateway/lb/vips"},
		{"GetVIP", platformv1.GatewayService_GetVIP_FullMethodName,
			&platformv1.GetVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443},
			&platformv1.GetVIPResponse{}, http.MethodGet, item},
		{"RemoveVIP", platformv1.GatewayService_RemoveVIP_FullMethodName,
			&platformv1.RemoveVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443},
			&platformv1.RemoveVIPResponse{}, http.MethodDelete, item},
		{"SetVIPBackends", platformv1.GatewayService_SetVIPBackends_FullMethodName,
			&platformv1.SetVIPBackendsRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443,
				Backends: []*platformv1.VIPBackend{{Address: "10.0.1.9", Port: 9000}}},
			&platformv1.SetVIPBackendsResponse{}, http.MethodPut, item + "/backends"},
		{"GetLBStatus", platformv1.GatewayService_GetLBStatus_FullMethodName,
			&platformv1.GetLBStatusRequest{}, &platformv1.GetLBStatusResponse{}, http.MethodGet, "/api/v1/sdn/gateway/lb/status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, seen := lbServer(t)
			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if seen.method != tc.wantMethod || seen.path != tc.wantPath {
				t.Errorf("%s sent %s %s, want %s %s", tc.name, seen.method, seen.path, tc.wantMethod, tc.wantPath)
			}
		})
	}
}

func TestAddVIP_SendsTheFlatVIPDocument(t *testing.T) {
	a, seen := lbServer(t)
	req := &platformv1.AddVIPRequest{Vip: &platformv1.VIPConfig{
		Address: "10.100.0.10", Port: 443, Protocol: "tcp", Algorithm: "hash",
		Backends: []*platformv1.VIPBackend{{Address: "10.0.1.5", Port: 8443, Weight: 2}},
	}}
	reply := &platformv1.AddVIPResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.GatewayService_AddVIP_FullMethodName, req, reply); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}

	var sent struct {
		Address   string `json:"address"`
		Port      uint16 `json:"port"`
		Protocol  string `json:"protocol"`
		Algorithm string `json:"algorithm"`
		Backends  []struct {
			Address string `json:"address"`
			Port    uint16 `json:"port"`
			Weight  uint16 `json:"weight"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(seen.body, &sent); err != nil {
		t.Fatalf("body %q is not the flat VIP document: %v", seen.body, err)
	}
	if sent.Address != "10.100.0.10" || sent.Port != 443 || sent.Protocol != "tcp" || sent.Algorithm != "hash" {
		t.Errorf("sent %+v, want the VIP fields at the top level", sent)
	}
	if len(sent.Backends) != 1 || sent.Backends[0].Address != "10.0.1.5" || sent.Backends[0].Port != 8443 || sent.Backends[0].Weight != 2 {
		t.Errorf("sent backends %+v, want the one backend", sent.Backends)
	}

	vip := reply.GetVip()
	if vip.GetVip().GetAddress() != "10.100.0.10" || vip.GetCtZone() != 7 || vip.GetGroupId() != 12 {
		t.Errorf("reply %v, want the served VIP folded into VIPStatus", vip)
	}
	if len(vip.GetBackends()) != 1 || !vip.GetBackends()[0].GetHealthy() {
		t.Errorf("reply backends %v, want one healthy backend", vip.GetBackends())
	}
}

func TestSetVIPBackends_SendsTheBackendsAndFoldsTheVIP(t *testing.T) {
	a, seen := lbServer(t)
	req := &platformv1.SetVIPBackendsRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443,
		Backends: []*platformv1.VIPBackend{{Address: "10.0.1.9", Port: 9000, Weight: 3}}}
	reply := &platformv1.SetVIPBackendsResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.GatewayService_SetVIPBackends_FullMethodName, req, reply); err != nil {
		t.Fatalf("SetVIPBackends: %v", err)
	}

	var sent struct {
		Backends []struct {
			Address string `json:"address"`
			Port    uint32 `json:"port"`
			Weight  uint32 `json:"weight"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(seen.body, &sent); err != nil {
		t.Fatalf("body %q is not the backends document: %v", seen.body, err)
	}
	if len(sent.Backends) != 1 || sent.Backends[0].Address != "10.0.1.9" || sent.Backends[0].Port != 9000 || sent.Backends[0].Weight != 3 {
		t.Errorf("sent backends %+v, want the one backend 10.0.1.9:9000 weight 3", sent.Backends)
	}

	if !reply.GetStatus().GetSuccess() {
		t.Errorf("reply status %v, want success", reply.GetStatus())
	}
	vip := reply.GetVip()
	cfg := vip.GetVip()
	if cfg.GetAddress() != "10.100.0.10" || cfg.GetPort() != 443 || cfg.GetProtocol() != "tcp" || cfg.GetAlgorithm() != "hash" {
		t.Errorf("reply VIP %v, want the served VIP config", cfg)
	}
	if vip.GetCtZone() != 7 || vip.GetGroupId() != 12 {
		t.Errorf("reply %v, want ct_zone 7 and group_id 12", vip)
	}
	if len(vip.GetBackends()) != 1 || !vip.GetBackends()[0].GetHealthy() ||
		vip.GetBackends()[0].GetBackend().GetAddress() != "10.0.1.5" || vip.GetBackends()[0].GetBackend().GetWeight() != 2 {
		t.Errorf("reply backends %v, want the one served healthy backend", vip.GetBackends())
	}
}

func TestLBVIP_RepliesFoldIntoTheProtoReplies(t *testing.T) {
	a, _ := lbServer(t)
	ctx := context.Background()

	list := &platformv1.ListVIPsResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.GatewayService_ListVIPs_FullMethodName, &platformv1.ListVIPsRequest{}, list); err != nil {
		t.Fatalf("ListVIPs: %v", err)
	}
	if len(list.GetVips()) != 1 || list.GetVips()[0].GetVip().GetPort() != 443 {
		t.Errorf("ListVIPs = %v, want the one served VIP", list)
	}

	st := &platformv1.GetLBStatusResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.GatewayService_GetLBStatus_FullMethodName, &platformv1.GetLBStatusRequest{}, st); err != nil {
		t.Fatalf("GetLBStatus: %v", err)
	}
	s := st.GetStatus()
	if !s.GetActive() || s.GetVipCount() != 2 || s.GetHealthyBackends() != 3 || s.GetTotalBackends() != 4 || s.GetLastReconcile() == nil {
		t.Errorf("GetLBStatus = %v, want the served status", s)
	}

	rm := &platformv1.RemoveVIPResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.GatewayService_RemoveVIP_FullMethodName,
		&platformv1.RemoveVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}, rm); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
	if rm.GetStatus() == nil {
		t.Errorf("RemoveVIP = %v, want the action status", rm)
	}
}
