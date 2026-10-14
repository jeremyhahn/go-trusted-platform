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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// samplePoolJSON is a pool as pkg/webservice/v1/rest/gateway/ipam.go
// writes it (IPAMPoolResponse).
const samplePoolJSON = `{"id":"p1","name":"cp","cidr":"10.0.0.0/24","gateway":"10.0.0.1",` +
	`"zone":"control-plane","total":253,"allocated":1,"available":252,` +
	`"default_lease_duration_nanos":3600000000000,"reserved":["10.0.0.0/28"],` +
	`"range_start":"10.0.0.100","range_end":"10.0.0.200",` +
	`"created_at":"2026-10-13T12:00:00Z","updated_at":"2026-10-13T12:30:00.5Z"}`

// sampleAllocationJSON is an allocation as ipam.go writes it
// (IPAllocationResponse).
const sampleAllocationJSON = `{"ip":"10.0.0.100","pool_id":"p1","device_id":"dev-1",` +
	`"hostname":"node1","allocated_at":"2026-10-13T12:00:00Z","expires_at":"2026-10-13T13:00:00Z"}`

// sampleActionJSON is ipam.go's IPAMActionResponse.
const sampleActionJSON = `{"resource_id":"p1","resource_type":"ipam_pool","action":"delete",` +
	`"success":true,"message":"pool deleted"}`

type ipamCapture struct {
	method string
	path   string
	query  string
	body   map[string]interface{}
}

// ipamServer answers every request with the enveloped payload and records
// what the adapter sent.
func ipamServer(t *testing.T, statusCode int, payload string, c *ipamCapture) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		c.method, c.path, c.query = r.Method, r.URL.Path, r.URL.RawQuery
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		c.body = nil
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &c.body); err != nil {
				t.Errorf("request body is not a JSON object: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if _, err := w.Write([]byte(envelope(payload))); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	return a
}

func invokeIPAM(t *testing.T, a *Adapter, method string, req, reply interface{}) error {
	t.Helper()
	return a.Connection().Invoke(context.Background(), method, req, reply)
}

func TestGatewayIPAMREST_ListPools(t *testing.T) {
	tests := []struct {
		name      string
		zone      string
		wantQuery string
	}{
		{name: "zone filter", zone: "control-plane", wantQuery: "zone=control-plane"},
		{name: "no filter", zone: "", wantQuery: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c ipamCapture
			a := ipamServer(t, http.StatusOK,
				`{"pools":[`+samplePoolJSON+`],"count":1,"timestamp":"2026-10-13T12:00:00Z"}`, &c)

			reply := &platformv1.ListIPAMPoolsResponse{}
			require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_ListIPAMPools_FullMethodName,
				&platformv1.ListIPAMPoolsRequest{Zone: tc.zone}, reply))

			assert.Equal(t, http.MethodGet, c.method)
			assert.Equal(t, "/api/v1/sdn/gateway/ipam/pools", c.path)
			assert.Equal(t, tc.wantQuery, c.query)
			require.Len(t, reply.GetPools(), 1)
			pool := reply.GetPools()[0]
			assert.Equal(t, "p1", pool.GetId())
			assert.Equal(t, uint64(253), pool.GetTotal())
			assert.Equal(t, int64(3600000000000), pool.GetDefaultLeaseDurationNanos())
			assert.Equal(t, []string{"10.0.0.0/28"}, pool.GetReserved())
			assert.Equal(t, int64(500000000), int64(pool.GetUpdatedAt().GetNanos()))
		})
	}
}

func TestGatewayIPAMREST_GetPool(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, samplePoolJSON, &c)

	reply := &platformv1.GetIPAMPoolResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_GetIPAMPool_FullMethodName,
		&platformv1.GetIPAMPoolRequest{Id: "p1"}, reply))

	assert.Equal(t, http.MethodGet, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/pools/p1", c.path)
	assert.Equal(t, "control-plane", reply.GetPool().GetZone())
	assert.Equal(t, "10.0.0.100", reply.GetPool().GetRangeStart())
	assert.Equal(t, 2026, reply.GetPool().GetCreatedAt().AsTime().Year())
}

func TestGatewayIPAMREST_GetPool_RefusesEmptyID(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, samplePoolJSON, &c)

	err := invokeIPAM(t, a, platformv1.GatewayService_GetIPAMPool_FullMethodName,
		&platformv1.GetIPAMPoolRequest{}, &platformv1.GetIPAMPoolResponse{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, c.method, "an empty pool ID must not reach the server")
}

func TestGatewayIPAMREST_GetPool_ServerErrorMapsToStatus(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusNotFound, `null`, &c)

	err := invokeIPAM(t, a, platformv1.GatewayService_GetIPAMPool_FullMethodName,
		&platformv1.GetIPAMPoolRequest{Id: "missing"}, &platformv1.GetIPAMPoolResponse{})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGatewayIPAMREST_CreatePool(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusCreated, samplePoolJSON, &c)

	reply := &platformv1.CreateIPAMPoolResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_CreateIPAMPool_FullMethodName,
		&platformv1.CreateIPAMPoolRequest{
			Id:                        "p1",
			Name:                      "cp",
			Cidr:                      "10.0.0.0/24",
			DefaultLeaseDurationNanos: 3600000000000,
			InactivityTimeoutNanos:    600000000000,
			Reserved:                  []string{"10.0.0.0/28"},
			RangeStart:                "10.0.0.100",
			RangeEnd:                  "10.0.0.200",
		}, reply))

	assert.Equal(t, http.MethodPost, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/pools", c.path)
	assert.Equal(t, "p1", c.body["id"])
	assert.Equal(t, "10.0.0.0/24", c.body["cidr"])
	assert.InDelta(t, 3600000000000, c.body["default_lease_duration_nanos"], 0)
	assert.InDelta(t, 600000000000, c.body["inactivity_timeout_nanos"], 0)
	assert.Equal(t, []interface{}{"10.0.0.0/28"}, c.body["reserved"])
	assert.Equal(t, "10.0.0.100", c.body["range_start"])
	assert.True(t, reply.GetStatus().GetSuccess())
	assert.Equal(t, "p1", reply.GetPool().GetId())
}

func TestGatewayIPAMREST_UpdatePool_SendsOnlyWhatItChanges(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, samplePoolJSON, &c)

	reply := &platformv1.UpdateIPAMPoolResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
		&platformv1.UpdateIPAMPoolRequest{
			Id:                        "p1",
			Name:                      "renamed",
			Zone:                      "control-plane",
			DefaultLeaseDurationNanos: keepDuration,
			InactivityTimeoutNanos:    keepDuration,
		}, reply))

	assert.Equal(t, http.MethodPut, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/pools/p1", c.path)
	assert.Equal(t, map[string]interface{}{"name": "renamed", "zone": "control-plane"}, c.body,
		"kept durations and an untouched window must be omitted")
	assert.True(t, reply.GetStatus().GetSuccess())
	assert.Equal(t, "p1", reply.GetPool().GetId())
}

func TestGatewayIPAMREST_UpdatePool_ReplacesWindowAndDurations(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, samplePoolJSON, &c)

	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
		&platformv1.UpdateIPAMPoolRequest{
			Id:                        "p1",
			DefaultLeaseDurationNanos: 7200000000000,
			InactivityTimeoutNanos:    300000000000,
			UpdateWindow:              true,
		}, &platformv1.UpdateIPAMPoolResponse{}))

	assert.InDelta(t, 7200000000000, c.body["default_lease_duration_nanos"], 0)
	assert.InDelta(t, 300000000000, c.body["inactivity_timeout_nanos"], 0)
	assert.Equal(t, []interface{}{}, c.body["reserved"], "an empty window clears the reserved list")
	assert.Equal(t, "", c.body["range_start"])
	assert.Equal(t, "", c.body["range_end"])
}

func TestGatewayIPAMREST_UpdatePool_RefusesZeroDurations(t *testing.T) {
	tests := []struct {
		name       string
		lease      int64
		inactivity int64
		field      string
	}{
		{name: "zero lease", lease: 0, inactivity: keepDuration, field: "default_lease_duration_nanos"},
		{name: "negative lease", lease: -5, inactivity: keepDuration, field: "default_lease_duration_nanos"},
		{name: "zero inactivity", lease: keepDuration, inactivity: 0, field: "inactivity_timeout_nanos"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c ipamCapture
			a := ipamServer(t, http.StatusOK, samplePoolJSON, &c)

			err := invokeIPAM(t, a, platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
				&platformv1.UpdateIPAMPoolRequest{
					Id:                        "p1",
					DefaultLeaseDurationNanos: tc.lease,
					InactivityTimeoutNanos:    tc.inactivity,
				}, &platformv1.UpdateIPAMPoolResponse{})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, err.Error(), tc.field)
			assert.Empty(t, c.method, "a refused update must not reach the server")
		})
	}
}

func TestGatewayIPAMREST_DeletePool(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, sampleActionJSON, &c)

	reply := &platformv1.DeleteIPAMPoolResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_DeleteIPAMPool_FullMethodName,
		&platformv1.DeleteIPAMPoolRequest{Id: "p1"}, reply))

	assert.Equal(t, http.MethodDelete, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/pools/p1", c.path)
	assert.True(t, reply.GetStatus().GetSuccess())
	assert.Equal(t, "pool deleted", reply.GetStatus().GetMessage())
}

func TestGatewayIPAMREST_AllocateIP(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusCreated, sampleAllocationJSON, &c)

	reply := &platformv1.AllocateIPResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_AllocateIP_FullMethodName,
		&platformv1.AllocateIPRequest{PoolId: "p1", DeviceId: "dev-1", Hostname: "node1"}, reply))

	assert.Equal(t, http.MethodPost, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/allocations", c.path)
	assert.Equal(t, map[string]interface{}{"pool_id": "p1", "device_id": "dev-1", "hostname": "node1"}, c.body)
	assert.True(t, reply.GetStatus().GetSuccess())
	assert.Equal(t, "10.0.0.100", reply.GetAllocation().GetIp())
	assert.Equal(t, 13, reply.GetAllocation().GetExpiresAt().AsTime().Hour())
}

func TestGatewayIPAMREST_ListAllocations(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK,
		`{"allocations":[`+sampleAllocationJSON+`],"count":1,"timestamp":"2026-10-13T12:00:00Z"}`, &c)

	reply := &platformv1.ListAllocationsResponse{}
	require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_ListAllocations_FullMethodName,
		&platformv1.ListAllocationsRequest{PoolId: "p1"}, reply))

	assert.Equal(t, http.MethodGet, c.method)
	assert.Equal(t, "/api/v1/sdn/gateway/ipam/allocations", c.path)
	assert.Equal(t, "pool_id=p1", c.query)
	require.Len(t, reply.GetAllocations(), 1)
	assert.Equal(t, "dev-1", reply.GetAllocations()[0].GetDeviceId())
}

func TestGatewayIPAMREST_ReleaseIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		wantPath string
	}{
		{name: "IPv4", ip: "10.0.0.100", wantPath: "/api/v1/sdn/gateway/ipam/allocations/10.0.0.100"},
		{name: "IPv6", ip: "fd00::64", wantPath: "/api/v1/sdn/gateway/ipam/allocations/fd00::64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c ipamCapture
			a := ipamServer(t, http.StatusOK, sampleActionJSON, &c)

			reply := &platformv1.ReleaseIPResponse{}
			require.NoError(t, invokeIPAM(t, a, platformv1.GatewayService_ReleaseIP_FullMethodName,
				&platformv1.ReleaseIPRequest{Ip: tc.ip}, reply))

			assert.Equal(t, http.MethodDelete, c.method)
			assert.Equal(t, tc.wantPath, c.path)
			assert.True(t, reply.GetStatus().GetSuccess())
		})
	}
}

func TestGatewayIPAMREST_ReleaseIP_RefusesEmptyIP(t *testing.T) {
	var c ipamCapture
	a := ipamServer(t, http.StatusOK, sampleActionJSON, &c)

	err := invokeIPAM(t, a, platformv1.GatewayService_ReleaseIP_FullMethodName,
		&platformv1.ReleaseIPRequest{}, &platformv1.ReleaseIPResponse{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, c.method)
}

func TestEncodeUpdateIPAMPool_RefusesTheWrongRequestType(t *testing.T) {
	_, err := encodeUpdateIPAMPool(&platformv1.GetIPAMPoolRequest{})
	var want ErrUnexpectedRequestType
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Equal(t, platformv1.GatewayService_UpdateIPAMPool_FullMethodName, want.Method)
}

func TestUpdateDuration(t *testing.T) {
	tests := []struct {
		name    string
		nanos   int64
		want    int64
		wantErr bool
	}{
		{name: "keep", nanos: keepDuration, want: 0},
		{name: "positive", nanos: 42, want: 42},
		{name: "zero", nanos: 0, wantErr: true},
		{name: "negative", nanos: -2, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := updateDuration("lease", tc.nanos)
			if tc.wantErr {
				var want ErrDurationClearNotSupported
				require.True(t, errors.As(err, &want), "got %v", err)
				assert.Equal(t, "lease", want.Field)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGatewayIPAMDecoders_RefuseTheWrongReplyType(t *testing.T) {
	decoders := map[string]restResponseDecoder{
		platformv1.GatewayService_GetIPAMPool_FullMethodName:    decodeGetIPAMPool,
		platformv1.GatewayService_CreateIPAMPool_FullMethodName: decodeCreateIPAMPool,
		platformv1.GatewayService_UpdateIPAMPool_FullMethodName: decodeUpdateIPAMPool,
		platformv1.GatewayService_DeleteIPAMPool_FullMethodName: decodeDeleteIPAMPool,
		platformv1.GatewayService_AllocateIP_FullMethodName:     decodeAllocateIP,
		platformv1.GatewayService_ReleaseIP_FullMethodName:      decodeReleaseIP,
	}
	for method, decode := range decoders {
		t.Run(method, func(t *testing.T) {
			err := decode([]byte(`{}`), &platformv1.ListIPAMPoolsResponse{})
			var want ErrUnexpectedReplyType
			require.True(t, errors.As(err, &want), "got %v", err)
			assert.Equal(t, method, want.Method)
		})
	}
}

func TestGatewayIPAMDecoders_RefuseMalformedPayloads(t *testing.T) {
	tests := []struct {
		name   string
		decode restResponseDecoder
		reply  interface{}
	}{
		{name: "get", decode: decodeGetIPAMPool, reply: &platformv1.GetIPAMPoolResponse{}},
		{name: "create", decode: decodeCreateIPAMPool, reply: &platformv1.CreateIPAMPoolResponse{}},
		{name: "update", decode: decodeUpdateIPAMPool, reply: &platformv1.UpdateIPAMPoolResponse{}},
		{name: "delete", decode: decodeDeleteIPAMPool, reply: &platformv1.DeleteIPAMPoolResponse{}},
		{name: "allocate", decode: decodeAllocateIP, reply: &platformv1.AllocateIPResponse{}},
		{name: "release", decode: decodeReleaseIP, reply: &platformv1.ReleaseIPResponse{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.decode([]byte(`{"total":"many"`), tc.reply)
			var want ErrUnmarshalFailed
			assert.True(t, errors.As(err, &want), "got %v", err)
		})
	}
}

func TestErrDurationClearNotSupported_Message(t *testing.T) {
	err := ErrDurationClearNotSupported{Field: "inactivity_timeout_nanos"}
	assert.Equal(t,
		"REST cannot set inactivity_timeout_nanos to zero: the REST pool update keeps a zero duration (send -1 to keep it)",
		err.Error())
}
