// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockSDNControlService records the requests the VLAN routes send to the
// shared SDN service and answers with canned responses or err.
type mockSDNControlService struct {
	createVLANReq *platformv1.CreateVLANRequest
	listVLANsReq  *platformv1.ListVLANsRequest
	deleteVLANReq *platformv1.DeleteVLANRequest

	createVLANResp *platformv1.CreateVLANResponse
	listVLANsResp  *platformv1.ListVLANsResponse

	applyPolicyReq   *platformv1.ApplyPolicyRequest
	getPolicyReq     *platformv1.GetPolicyRequest
	listPoliciesReq  *platformv1.ListPoliciesRequest
	deletePolicyReq  *platformv1.DeletePolicyRequest
	policy           *platformv1.Policy
	listPoliciesResp *platformv1.ListPoliciesResponse

	err error
}

func (m *mockSDNControlService) CreateVLAN(_ context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	m.createVLANReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.createVLANResp, nil
}

func (m *mockSDNControlService) ListVLANs(_ context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	m.listVLANsReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.listVLANsResp, nil
}

func (m *mockSDNControlService) DeleteVLAN(_ context.Context, req *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	m.deleteVLANReq = req
	if m.err != nil {
		return nil, m.err
	}
	return &platformv1.DeleteVLANResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (m *mockSDNControlService) ApplyPolicy(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	m.applyPolicyReq = req
	if m.err != nil {
		return nil, m.err
	}
	return &platformv1.ApplyPolicyResponse{Status: &platformv1.Status{Success: true}, Policy: m.policy}, nil
}

func (m *mockSDNControlService) GetPolicy(_ context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error) {
	m.getPolicyReq = req
	if m.err != nil {
		return nil, m.err
	}
	return &platformv1.GetPolicyResponse{Policy: m.policy}, nil
}

func (m *mockSDNControlService) ListPolicies(_ context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error) {
	m.listPoliciesReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.listPoliciesResp, nil
}

func (m *mockSDNControlService) DeletePolicy(_ context.Context, req *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error) {
	m.deletePolicyReq = req
	if m.err != nil {
		return nil, m.err
	}
	return &platformv1.DeletePolicyResponse{Status: &platformv1.Status{Success: true, Message: "policy deleted successfully"}}, nil
}

// controlRouter mounts the SDN routes with control wired in (nil leaves the
// control service unset).
func controlRouter(control SDNControlServiceInterface) *mux.Router {
	handlers := NewSDNHandlers(newMockSDNService(), slog.Default())
	if control != nil {
		handlers.SetControlService(control)
	}
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router
}

func serveSDN(router *mux.Router, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

var testVLANCreatedAt = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func testVLAN() *platformv1.VLAN {
	return &platformv1.VLAN{
		Id: "vlan-br0-100",
		Config: &platformv1.VLANConfig{
			VlanId:   100,
			Name:     "tenant-a",
			BridgeId: "br0",
			Ports:    []string{"p1", "p2"},
			Labels:   map[string]string{"zone": "lan"},
		},
		Stats:     &platformv1.VLANStats{PortCount: 2},
		CreatedAt: timestamppb.New(testVLANCreatedAt),
	}
}

// serviceErrorCases are the shared service's typed errors and the HTTP
// statuses every VLAN route maps them to.
var serviceErrorCases = []struct {
	name string
	err  error
	want int
}{
	{"invalid argument", status.Error(codes.InvalidArgument, "vlan_id must be between 1 and 4095"), http.StatusBadRequest},
	{"not found", status.Error(codes.NotFound, "bridge not found"), http.StatusNotFound},
	{"already exists", status.Error(codes.AlreadyExists, "VLAN already exists on this bridge"), http.StatusConflict},
	{"internal", status.Error(codes.Internal, "failed to set VLAN on port p1"), http.StatusInternalServerError},
}

func TestCreateVLAN(t *testing.T) {
	t.Run("passes the request to the shared service", func(t *testing.T) {
		control := &mockSDNControlService{
			createVLANResp: &platformv1.CreateVLANResponse{Vlan: testVLAN()},
		}
		body := []byte(`{"vlan_id":100,"name":"tenant-a","bridge_id":"br0","ports":["p1","p2"],"labels":{"zone":"lan"}}`)

		w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/vlans", body)

		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		require.NotNil(t, control.createVLANReq)
		config := control.createVLANReq.GetConfig()
		assert.Equal(t, uint32(100), config.GetVlanId())
		assert.Equal(t, "tenant-a", config.GetName())
		assert.Equal(t, "br0", config.GetBridgeId())
		assert.Equal(t, []string{"p1", "p2"}, config.GetPorts())
		assert.Equal(t, map[string]string{"zone": "lan"}, config.GetLabels())

		var resp VLANResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, VLANResponse{
			ID:        "vlan-br0-100",
			VLANID:    100,
			Name:      "tenant-a",
			BridgeID:  "br0",
			Ports:     []string{"p1", "p2"},
			Labels:    map[string]string{"zone": "lan"},
			PortCount: 2,
			CreatedAt: testVLANCreatedAt,
		}, resp)
	})

	t.Run("rejects a malformed body without calling the service", func(t *testing.T) {
		control := &mockSDNControlService{}

		w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/vlans", []byte("bad"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Nil(t, control.createVLANReq)
	})

	t.Run("rejects a negative VLAN ID without calling the service", func(t *testing.T) {
		control := &mockSDNControlService{}

		w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/vlans", []byte(`{"vlan_id":-1,"bridge_id":"br0"}`))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Nil(t, control.createVLANReq)
	})

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/vlans", []byte(`{"vlan_id":100,"bridge_id":"br0"}`))

			assert.Equal(t, tc.want, w.Code)
			var resp SDNErrorResponse
			decodeSDNResponse(t, w.Body, &resp)
			assert.Contains(t, resp.Error, "create_vlan")
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodPost, "/api/v1/sdn/vlans", []byte(`{"vlan_id":100,"bridge_id":"br0"}`))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListVLANs(t *testing.T) {
	t.Run("lists the bridge's VLANs from the shared service", func(t *testing.T) {
		control := &mockSDNControlService{
			listVLANsResp: &platformv1.ListVLANsResponse{Vlans: []*platformv1.VLAN{testVLAN()}},
		}

		w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, control.listVLANsReq)
		assert.Equal(t, "br0", control.listVLANsReq.GetBridgeId())

		var resp VLANListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 1, resp.Count)
		require.Len(t, resp.VLANs, 1)
		assert.Equal(t, "vlan-br0-100", resp.VLANs[0].ID)
		assert.Equal(t, uint32(100), resp.VLANs[0].VLANID)
	})

	t.Run("answers an empty list as an empty array", func(t *testing.T) {
		control := &mockSDNControlService{listVLANsResp: &platformv1.ListVLANsResponse{}}

		w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"vlans":[]`)
	})

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/vlans", nil)

			assert.Equal(t, tc.want, w.Code)
			require.NotNil(t, control.listVLANsReq)
			assert.Empty(t, control.listVLANsReq.GetBridgeId())
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteVLAN(t *testing.T) {
	t.Run("deletes the VLAN through the shared service", func(t *testing.T) {
		control := &mockSDNControlService{}

		w := serveSDN(controlRouter(control), http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, control.deleteVLANReq)
		assert.Equal(t, "br0", control.deleteVLANReq.GetBridgeId())
		assert.Equal(t, uint32(100), control.deleteVLANReq.GetVlanId())

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, SDNActionResponse{
			ResourceID:   "100",
			ResourceType: "vlan",
			Action:       "deleted",
			Success:      true,
			Message:      "VLAN deleted successfully",
		}, resp)
	})

	for _, id := range []string{"abc", "-1", "4294967296"} {
		t.Run("rejects path ID "+id+" without calling the service", func(t *testing.T) {
			control := &mockSDNControlService{}

			w := serveSDN(controlRouter(control), http.MethodDelete, "/api/v1/sdn/vlans/"+id+"?bridge_id=br0", nil)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Nil(t, control.deleteVLANReq)
		})
	}

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)

			assert.Equal(t, tc.want, w.Code)
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestErrInvalidVLANID(t *testing.T) {
	assert.Equal(t, `invalid VLAN ID: "abc"`, ErrInvalidVLANID{Value: "abc"}.Error())
	assert.Equal(t, `invalid VLAN ID: ""`, ErrInvalidVLANID{}.Error())
}

func TestVLANToResponse(t *testing.T) {
	t.Run("converts every field", func(t *testing.T) {
		resp := vlanToResponse(testVLAN())

		assert.Equal(t, "vlan-br0-100", resp.ID)
		assert.Equal(t, uint32(2), resp.PortCount)
		assert.Equal(t, testVLANCreatedAt, resp.CreatedAt)
	})

	t.Run("tolerates a nil VLAN", func(t *testing.T) {
		assert.Equal(t, VLANResponse{}, vlanToResponse(nil))
	})
}

func TestVLANListResponseJSON(t *testing.T) {
	raw, err := json.Marshal(VLANListResponse{VLANs: []VLANResponse{}})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"count":0`)
}
