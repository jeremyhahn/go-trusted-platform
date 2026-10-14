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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
)

// recordingLeaseSink records the lease writes it is handed and answers each
// with err.
type recordingLeaseSink struct {
	err      error
	recorded []string
	released []string
}

func (s *recordingLeaseSink) RecordGatewayLease(_ context.Context, gatewayID string, lease *gwstate.DesiredVPNLease) error {
	s.recorded = append(s.recorded, gatewayID+"/"+lease.TenantID+"/"+lease.ID)
	return s.err
}

func (s *recordingLeaseSink) ReleaseGatewayLease(_ context.Context, gatewayID, tenantID, leaseID string) error {
	s.released = append(s.released, gatewayID+"/"+tenantID+"/"+leaseID)
	return s.err
}

// leaseRouter is the control-plane surface with sink as its lease record.
func leaseRouter(sink VPNLeaseSink) http.Handler {
	cp := newControlPlane(nil, nil)
	cp.SetVPNLeaseSink(sink)
	return controlPlaneRouter(cp)
}

func putLeaseRequest(t *testing.T, gatewayID string) *http.Request {
	t.Helper()
	body, err := json.Marshal(&gwstate.DesiredVPNLease{
		ID: "lease-1", TenantID: "tenant-a", DeviceID: "laptop-1", Address: "100.64.0.2/32",
	})
	require.NoError(t, err)
	return httptest.NewRequest(http.MethodPut, "/api/v1/gateway/vpn-leases/"+gatewayID, strings.NewReader(string(body)))
}

func deleteLeaseRequest(gatewayID string) *http.Request {
	return httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/vpn-leases/"+gatewayID+"/tenant-a/lease-1", nil)
}

func TestPutVPNLease_RecordsTheCallingGatewaysLease(t *testing.T) {
	sink := &recordingLeaseSink{}
	rec := httptest.NewRecorder()

	leaseRouter(sink).ServeHTTP(rec, withClientCert(putLeaseRequest(t, "node-01"), "node-01"))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"node-01/tenant-a/lease-1"}, sink.recorded)
}

func TestPutVPNLease_RejectsAMalformedBody(t *testing.T) {
	sink := &recordingLeaseSink{}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/gateway/vpn-leases/node-01", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	leaseRouter(sink).ServeHTTP(rec, withClientCert(req, "node-01"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, sink.recorded)
}

func TestDeleteVPNLease_ReleasesTheCallingGatewaysLease(t *testing.T) {
	sink := &recordingLeaseSink{}
	rec := httptest.NewRecorder()

	leaseRouter(sink).ServeHTTP(rec, withClientCert(deleteLeaseRequest("node-01"), "node-01"))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"node-01/tenant-a/lease-1"}, sink.released)
}

// TestVPNLease_RefusesAnotherGatewaysRecord keeps one gateway's certificate
// from writing or erasing the leases recorded for another gateway.
func TestVPNLease_RefusesAnotherGatewaysRecord(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"put":    putLeaseRequest(t, "node-02"),
		"delete": deleteLeaseRequest("node-02"),
	} {
		t.Run(name, func(t *testing.T) {
			sink := &recordingLeaseSink{}
			rec := httptest.NewRecorder()

			leaseRouter(sink).ServeHTTP(rec, withClientCert(req, "node-01"))

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Empty(t, sink.recorded)
			assert.Empty(t, sink.released)
		})
	}
}

func TestVPNLease_RejectsWithoutClientCert(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"put":    putLeaseRequest(t, "node-01"),
		"delete": deleteLeaseRequest("node-01"),
	} {
		t.Run(name, func(t *testing.T) {
			sink := &recordingLeaseSink{}
			rec := httptest.NewRecorder()

			leaseRouter(sink).ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Empty(t, sink.recorded)
			assert.Empty(t, sink.released)
		})
	}
}

// TestVPNLease_NotConfigured answers a daemon without a VPN control plane
// with a server error rather than a silent success the gateway would treat
// as recorded.
func TestVPNLease_NotConfigured(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"put":    putLeaseRequest(t, "node-01"),
		"delete": deleteLeaseRequest("node-01"),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			controlPlaneRouter(newControlPlane(nil, nil)).ServeHTTP(rec, withClientCert(req, "node-01"))

			assert.Equal(t, http.StatusInternalServerError, rec.Code)
		})
	}
}

func TestVPNLease_SinkRefusals(t *testing.T) {
	refusals := map[string]struct {
		err  error
		want int
	}{
		"invalid argument":         {&vpn.ErrInvalidArgument{Field: "address", Reason: "not a prefix"}, http.StatusBadRequest},
		"owned by another gateway": {&vpn.ErrLeaseOwnedByOtherGateway{TenantID: "tenant-a", LeaseID: "lease-1", GatewayID: "node-02"}, http.StatusForbidden},
		"store failure":            {errors.New("raft: no leader"), http.StatusInternalServerError},
	}
	for name, refusal := range refusals {
		for method, req := range map[string]func() *http.Request{
			"put":    func() *http.Request { return putLeaseRequest(t, "node-01") },
			"delete": func() *http.Request { return deleteLeaseRequest("node-01") },
		} {
			t.Run(name+"/"+method, func(t *testing.T) {
				rec := httptest.NewRecorder()

				leaseRouter(&recordingLeaseSink{err: refusal.err}).ServeHTTP(rec, withClientCert(req(), "node-01"))

				assert.Equal(t, refusal.want, rec.Code, rec.Body.String())
			})
		}
	}
}
