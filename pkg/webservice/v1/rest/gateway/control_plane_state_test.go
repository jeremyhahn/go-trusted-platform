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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// errStateBackend is the failure brokenStateStore reports from every call.
type errStateBackend struct{}

func (errStateBackend) Error() string { return "gateway/state: backend unavailable" }

// brokenStateStore fails every operation, as a store on a dead disk would.
type brokenStateStore struct{}

func (brokenStateStore) Put(*gwstate.Snapshot) error           { return errStateBackend{} }
func (brokenStateStore) Get(string) (*gwstate.Snapshot, error) { return nil, errStateBackend{} }
func (brokenStateStore) List() ([]*gwstate.Snapshot, error)    { return nil, errStateBackend{} }
func (brokenStateStore) Delete(string) error                   { return errStateBackend{} }

// newStateFileStore is the production FileStore under a test directory,
// seeded with one snapshot per gateway ID.
func newStateFileStore(t *testing.T, gatewayIDs ...string) *gwstate.FileStore {
	t.Helper()
	store, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	for _, id := range gatewayIDs {
		if err := store.Put(&gwstate.Snapshot{GatewayID: id, Hostname: id + ".example.com"}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	return store
}

func serveState(t *testing.T, store gwstate.Store, method, path string) (*httptest.ResponseRecorder, ipamEnvelope) {
	t.Helper()
	rec := httptest.NewRecorder()
	controlPlaneRouter(newControlPlane(store, nil)).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec, decodeIPAMEnvelope(t, rec)
}

func TestListState_ReturnsEverySnapshot(t *testing.T) {
	rec, env := serveState(t, newStateFileStore(t, "gw-a", "gw-b"), http.MethodGet, "/api/v1/gateway/state")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var payload struct {
		Gateways []gwstate.Snapshot `json:"gateways"`
		Total    int                `json:"total"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Total != 2 || len(payload.Gateways) != 2 {
		t.Fatalf("payload = %+v, want two gateways", payload)
	}
	seen := map[string]string{}
	for _, snap := range payload.Gateways {
		seen[snap.GatewayID] = snap.Hostname
	}
	if seen["gw-a"] != "gw-a.example.com" || seen["gw-b"] != "gw-b.example.com" {
		t.Fatalf("snapshots = %v, want gw-a and gw-b with their hostnames", seen)
	}
}

func TestGetState_ReturnsTheSnapshot(t *testing.T) {
	rec, env := serveState(t, newStateFileStore(t, "gw-a"), http.MethodGet, "/api/v1/gateway/state/gw-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var snap gwstate.Snapshot
	if err := json.Unmarshal(env.Payload, &snap); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if snap.GatewayID != "gw-a" || snap.Hostname != "gw-a.example.com" {
		t.Fatalf("snapshot = %+v, want gw-a", snap)
	}
}

func TestDeleteState_RemovesTheSnapshot(t *testing.T) {
	store := newStateFileStore(t, "gw-a", "gw-b")
	rec, env := serveState(t, store, http.MethodDelete, "/api/v1/gateway/state/gw-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var payload struct {
		Deleted bool   `json:"deleted"`
		ID      string `json:"id"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !payload.Deleted || payload.ID != "gw-a" {
		t.Fatalf("payload = %+v, want deleted gw-a", payload)
	}
	var nf gwstate.ErrSnapshotNotFound
	if _, err := store.Get("gw-a"); !errors.As(err, &nf) {
		t.Fatalf("gw-a still readable after delete: err = %v", err)
	}
	if _, err := store.Get("gw-b"); err != nil {
		t.Fatalf("delete of gw-a removed gw-b: %v", err)
	}
}

func TestStateRoutes_Failures(t *testing.T) {
	cases := []struct {
		name    string
		store   gwstate.Store
		method  string
		path    string
		want    int
		wantErr string
	}{
		{"list without a store", nil, http.MethodGet, "/api/v1/gateway/state", http.StatusInternalServerError, ErrGatewayControlNotConfigured{}.Error()},
		{"get without a store", nil, http.MethodGet, "/api/v1/gateway/state/gw-a", http.StatusInternalServerError, ErrGatewayControlNotConfigured{}.Error()},
		{"delete without a store", nil, http.MethodDelete, "/api/v1/gateway/state/gw-a", http.StatusInternalServerError, ErrGatewayControlNotConfigured{}.Error()},
		{"list on a failing store", brokenStateStore{}, http.MethodGet, "/api/v1/gateway/state", http.StatusInternalServerError, errStateBackend{}.Error()},
		{"get on a failing store", brokenStateStore{}, http.MethodGet, "/api/v1/gateway/state/gw-a", http.StatusInternalServerError, errStateBackend{}.Error()},
		{"delete on a failing store", brokenStateStore{}, http.MethodDelete, "/api/v1/gateway/state/gw-a", http.StatusInternalServerError, errStateBackend{}.Error()},
		{"get an unknown gateway", newStateFileStore(t), http.MethodGet, "/api/v1/gateway/state/gw-x", http.StatusNotFound, gwstate.ErrSnapshotNotFound{GatewayID: "gw-x"}.Error()},
		{"delete an unknown gateway", newStateFileStore(t), http.MethodDelete, "/api/v1/gateway/state/gw-x", http.StatusNotFound, gwstate.ErrSnapshotNotFound{GatewayID: "gw-x"}.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, env := serveState(t, tc.store, tc.method, tc.path)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
			if env.Success || !strings.Contains(env.Error, tc.wantErr) {
				t.Fatalf("envelope = %+v, want a failure naming %q", env, tc.wantErr)
			}
		})
	}
}

// TestHandlers_RefuseAnEmptyGatewayID calls each {id} handler directly
// with no route variables: the mux never routes an empty segment, so this
// is the only way to prove the handlers' own guard holds.
func TestHandlers_RefuseAnEmptyGatewayID(t *testing.T) {
	cp := newControlPlane(newStateFileStore(t, "gw-a"), &recordingConfigSource{payload: sampleDesiredConfig()})
	cp.SetVPNLeaseSink(&recordingLeaseSink{})
	handlers := map[string]http.HandlerFunc{
		"get state":      cp.getState,
		"delete state":   cp.deleteState,
		"desired config": cp.getDesiredConfig,
		"put vpn lease":  cp.putVPNLease,
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, withClientCert(httptest.NewRequest(http.MethodGet, "/", strings.NewReader("{}")), "gw-a"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if env := decodeIPAMEnvelope(t, rec); !strings.Contains(env.Error, ErrGatewayIDRequired{}.Error()) {
				t.Fatalf("error = %q, want %q", env.Error, ErrGatewayIDRequired{}.Error())
			}
		})
	}
}

func TestPostTelemetry_UnreadableBody(t *testing.T) {
	store := newMemStore()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", iotest.ErrReader(errStateBackend{}))
	rec := httptest.NewRecorder()
	controlPlaneRouter(newControlPlane(store, nil)).ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}
