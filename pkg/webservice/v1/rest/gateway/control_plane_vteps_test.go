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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// newVTEPStore seeds gw-overlay, which reports two admitted VTEPs, and
// gw-plain, which reports no overlay at all.
func newVTEPStore(t *testing.T) *gwstate.FileStore {
	t.Helper()
	store, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	seed := []*gwstate.Snapshot{
		{
			GatewayID: "gw-overlay",
			Hostname:  "gw-overlay.example.com",
			Overlay: &gwstate.OverlayState{
				Running: true,
				AdmittedVTEPs: []gwstate.AdmittedVTEPState{
					{VTEP: "192.0.2.10", DeviceID: 7, Serial: "SN-0001"},
					{VTEP: "192.0.2.11", HostID: "h-2"},
				},
			},
		},
		{GatewayID: "gw-plain", Hostname: "gw-plain.example.com"},
	}
	for _, snap := range seed {
		if err := store.Put(snap); err != nil {
			t.Fatalf("seed %s: %v", snap.GatewayID, err)
		}
	}
	return store
}

func TestListAdmittedVTEPs_ReturnsTheOverlayList(t *testing.T) {
	rec, env := serveState(t, newVTEPStore(t), http.MethodGet, "/api/v1/gateway/state/gw-overlay/admitted-vteps")
	if rec.Code != http.StatusOK || !env.Success {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var payload struct {
		AdmittedVTEPs []gwstate.AdmittedVTEPState `json:"admitted_vteps"`
		Total         int                         `json:"total"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Total != 2 || len(payload.AdmittedVTEPs) != 2 {
		t.Fatalf("payload = %+v, want two admitted VTEPs", payload)
	}
	if payload.AdmittedVTEPs[0].VTEP != "192.0.2.10" || payload.AdmittedVTEPs[1].VTEP != "192.0.2.11" {
		t.Fatalf("admitted VTEPs = %+v, want 192.0.2.10 then 192.0.2.11", payload.AdmittedVTEPs)
	}
}

func TestGetAdmittedVTEP_ReturnsOneEntry(t *testing.T) {
	rec, env := serveState(t, newVTEPStore(t), http.MethodGet, "/api/v1/gateway/state/gw-overlay/admitted-vteps/192.0.2.10")
	if rec.Code != http.StatusOK || !env.Success {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var vtep gwstate.AdmittedVTEPState
	if err := json.Unmarshal(env.Payload, &vtep); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if vtep.VTEP != "192.0.2.10" || vtep.DeviceID != 7 || vtep.Serial != "SN-0001" {
		t.Fatalf("vtep = %+v, want 192.0.2.10 device 7 serial SN-0001", vtep)
	}
}

func TestAdmittedVTEPRoutes_Failures(t *testing.T) {
	const (
		list = "/api/v1/gateway/state/%s/admitted-vteps"
		one  = "/api/v1/gateway/state/%s/admitted-vteps/192.0.2.10"
	)
	path := func(format, id string) string { return strings.Replace(format, "%s", id, 1) }
	notReported := "overlay telemetry is not available for this gateway"
	cases := []struct {
		name    string
		store   gwstate.Store
		path    string
		want    int
		wantErr string
	}{
		{"list without a store", nil, path(list, "gw-overlay"), http.StatusInternalServerError, ErrGatewayControlNotConfigured{}.Error()},
		{"get without a store", nil, path(one, "gw-overlay"), http.StatusInternalServerError, ErrGatewayControlNotConfigured{}.Error()},
		{"list on a failing store", brokenStateStore{}, path(list, "gw-overlay"), http.StatusInternalServerError, errStateBackend{}.Error()},
		{"get on a failing store", brokenStateStore{}, path(one, "gw-overlay"), http.StatusInternalServerError, errStateBackend{}.Error()},
		{"list an unknown gateway", newVTEPStore(t), path(list, "gw-x"), http.StatusNotFound, gwstate.ErrSnapshotNotFound{GatewayID: "gw-x"}.Error()},
		{"get an unknown gateway", newVTEPStore(t), path(one, "gw-x"), http.StatusNotFound, gwstate.ErrSnapshotNotFound{GatewayID: "gw-x"}.Error()},
		{"list without an overlay", newVTEPStore(t), path(list, "gw-plain"), http.StatusServiceUnavailable, notReported},
		{"get without an overlay", newVTEPStore(t), path(one, "gw-plain"), http.StatusServiceUnavailable, notReported},
		{"get an unknown VTEP", newVTEPStore(t), "/api/v1/gateway/state/gw-overlay/admitted-vteps/192.0.2.99", http.StatusNotFound, "gateway admitted VTEP 192.0.2.99 was not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, env := serveState(t, tc.store, http.MethodGet, tc.path)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
			if env.Success || !strings.Contains(env.Error, tc.wantErr) {
				t.Fatalf("envelope = %+v, want a failure naming %q", env, tc.wantErr)
			}
		})
	}
}
