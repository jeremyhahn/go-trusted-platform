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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmRequest is what the VM lifecycle server saw for one API call.
type vmRequest struct {
	method string
	path   string
	query  string
	body   map[string]interface{}
}

// vmLifecycleServer answers every API call with reply and records it; the
// health probe Connect sends is not recorded.
func vmLifecycleServer(t *testing.T, code int, reply string) (*Adapter, *vmRequest) {
	t.Helper()
	seen := &vmRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		seen.method, seen.path, seen.query = r.Method, r.URL.Path, r.URL.RawQuery
		seen.body = nil
		_ = json.NewDecoder(r.Body).Decode(&seen.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(reply))
	})
	return a, seen
}

func TestVMLifecycleRoutes_IDTravelsInThePath(t *testing.T) {
	tests := []struct {
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		httpMethod string
		path       string
		query      string
		body       map[string]interface{}
	}{
		{platformv1.ComputeService_StartVM_FullMethodName, &platformv1.StartVMRequest{Id: "vm-1"}, &platformv1.StartVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/start", "", map[string]interface{}{}},
		{platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1", Force: true, TimeoutSeconds: 30}, &platformv1.StopVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/stop", "", map[string]interface{}{"force": true, "timeout_seconds": float64(30)}},
		{platformv1.ComputeService_RebootVM_FullMethodName, &platformv1.RebootVMRequest{Id: "vm-1", Force: true}, &platformv1.RebootVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/reboot", "", map[string]interface{}{"force": true}},
		{platformv1.ComputeService_SuspendVM_FullMethodName, &platformv1.SuspendVMRequest{Id: "vm-1"}, &platformv1.SuspendVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/suspend", "", map[string]interface{}{}},
		{platformv1.ComputeService_ResumeVM_FullMethodName, &platformv1.ResumeVMRequest{Id: "vm-1"}, &platformv1.ResumeVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/resume", "", map[string]interface{}{}},
		{platformv1.ComputeService_DeleteVM_FullMethodName, &platformv1.DeleteVMRequest{Id: "vm-1", DeleteDisks: true}, &platformv1.DeleteVMResponse{},
			http.MethodDelete, "/api/v1/compute/vms/vm-1", "delete_disks=true", nil},
	}
	for _, tt := range tests {
		t.Run(tt.grpcMethod, func(t *testing.T) {
			a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{"status":{"success":true}}}`)
			if err := a.Connection().Invoke(context.Background(), tt.grpcMethod, tt.req, tt.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if seen.method != tt.httpMethod || seen.path != tt.path {
				t.Errorf("request = %s %s, want %s %s", seen.method, seen.path, tt.httpMethod, tt.path)
			}
			if seen.query != tt.query {
				t.Errorf("query = %q, want %q", seen.query, tt.query)
			}
			if tt.body != nil && !mapsEqual(seen.body, tt.body) {
				t.Errorf("body = %v, want %v", seen.body, tt.body)
			}
			if _, has := seen.body["id"]; has {
				t.Errorf("body still carries id: %v", seen.body)
			}
		})
	}
}

func TestListVMsRoute_TheFilterTravelsInTheBody(t *testing.T) {
	a, seen := vmLifecycleServer(t, http.StatusOK, `{"vms":[{"id":"vm-1"}],"pagination":{"page":2,"pageSize":1}}`)
	req := &platformv1.ListVMsRequest{
		States:     []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING},
		Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
		Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 1, SortBy: "name"},
	}

	resp, err := platformv1.NewComputeServiceClient(a.Connection()).ListVMs(context.Background(), req)

	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if seen.method != http.MethodGet || seen.path != "/api/v1/compute/vms" || seen.query != "" {
		t.Errorf("request = %s %s?%s, want GET /api/v1/compute/vms", seen.method, seen.path, seen.query)
	}
	sent := &platformv1.ListVMsRequest{}
	body, err := json.Marshal(seen.body)
	if err != nil {
		t.Fatalf("re-marshal body: %v", err)
	}
	if err := protojson.Unmarshal(body, sent); err != nil {
		t.Fatalf("body %s is not a ListVMsRequest: %v", body, err)
	}
	if !proto.Equal(sent, req) {
		t.Errorf("body = %v, want %v", sent, req)
	}
	if len(resp.GetVms()) != 1 || resp.GetVms()[0].GetId() != "vm-1" || resp.GetPagination().GetPage() != 2 {
		t.Errorf("reply = %v", resp)
	}
}

func TestCreateVMRoute_TheWholeRequestTravelsInTheBody(t *testing.T) {
	a, seen := vmLifecycleServer(t, http.StatusOK, `{"vm":{"id":"vm-1","config":{"name":"vm-web"}}}`)
	req := &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{
			Name:       "vm-web",
			Firmware:   platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
			Cpu:        &platformv1.CPUConfig{Cores: 4},
			Memory:     &platformv1.MemoryConfig{SizeMb: 4096},
			Disks:      []*platformv1.DiskConfig{{SizeGb: 40, Bus: platformv1.DiskBus_DISK_BUS_SATA}},
			Networks:   []*platformv1.NetworkConfig{{MacAddress: "52:54:00:12:34:56"}},
			Tpm:        &platformv1.TPMConfig{Enabled: true},
			SecureBoot: true,
			Labels:     map[string]string{"tier": "web"},
		},
		Start: true,
	}

	resp, err := platformv1.NewComputeServiceClient(a.Connection()).CreateVM(context.Background(), req)

	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if seen.method != http.MethodPost || seen.path != "/api/v1/compute/vms" {
		t.Errorf("request = %s %s, want POST /api/v1/compute/vms", seen.method, seen.path)
	}
	sent := &platformv1.CreateVMRequest{}
	body, err := json.Marshal(seen.body)
	if err != nil {
		t.Fatalf("re-marshal body: %v", err)
	}
	if err := protojson.Unmarshal(body, sent); err != nil {
		t.Fatalf("body %s is not a CreateVMRequest: %v", body, err)
	}
	if !proto.Equal(sent, req) {
		t.Errorf("body = %v, want %v", sent, req)
	}
	if resp.GetVm().GetId() != "vm-1" {
		t.Errorf("reply = %v", resp)
	}
}

func TestCreateVMRoute_RefusalKeepsItsClass(t *testing.T) {
	a, _ := vmLifecycleServer(t, http.StatusBadRequest, `{"error":"create VM: config.firmware is not supported: VMs boot UEFI firmware"}`)

	_, err := platformv1.NewComputeServiceClient(a.Connection()).CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: "vm-bios", Firmware: platformv1.FirmwareType_FIRMWARE_TYPE_BIOS},
	})

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

func TestVMLifecycleRoutes_EmptyIDRejectedBeforeTheWire(t *testing.T) {
	a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{}}`)
	err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_SuspendVM_FullMethodName,
		&platformv1.SuspendVMRequest{}, &platformv1.SuspendVMResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	if seen.path != "" {
		t.Errorf("server saw %s; the request must not leave the client", seen.path)
	}
}

// Both REST servers answer an unknown VM 404 and a VM in the wrong state 409
// (FailedPrecondition renders as 409 there, #665), so the adapter returns
// NotFound and AlreadyExists.
func TestVMLifecycleRoutes_ServerErrorsKeepTheirClass(t *testing.T) {
	tests := []struct {
		name     string
		httpCode int
		body     string
		want     codes.Code
	}{
		{"unknown VM", http.StatusNotFound, `{"code":404,"success":false,"error":"vm not found"}`, codes.NotFound},
		{"wrong state", http.StatusConflict, `{"code":409,"success":false,"error":"instance not running"}`, codes.AlreadyExists},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := vmLifecycleServer(t, tt.httpCode, tt.body)
			client := platformv1.NewComputeServiceClient(a.Connection())
			_, err := client.ResumeVM(context.Background(), &platformv1.ResumeVMRequest{Id: "vm-1"})
			if status.Code(err) != tt.want {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func mapsEqual(got, want map[string]interface{}) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
