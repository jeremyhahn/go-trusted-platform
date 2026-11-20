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

package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type fakeDaemonOps struct {
	shutdownReq *platformv1.ShutdownRequest
	updateReq   *platformv1.UpdateConfigRequest
	updateErr   error
	types       *platformv1.ListEntityTypesResponse
}

func (f *fakeDaemonOps) Shutdown(_ context.Context, req *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error) {
	f.shutdownReq = req
	return &platformv1.ShutdownResponse{Status: &platformv1.Status{Success: true, Message: "shutdown completed successfully"}}, nil
}

func (f *fakeDaemonOps) UpdateConfig(_ context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error) {
	f.updateReq = req
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return &platformv1.UpdateConfigResponse{Status: &platformv1.Status{Success: true, Message: "configuration section applied"}}, nil
}

func (f *fakeDaemonOps) ListEntityTypes(context.Context, *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error) {
	return f.types, nil
}

func daemonOpsRouter(t *testing.T, ops DaemonOps) *mux.Router {
	t.Helper()
	h := newTestHandlers(t)
	if ops != nil {
		h.SetDaemonOps(ops)
	}
	r := &PlatformRouter{handlers: h}
	m := mux.NewRouter()
	r.registerDaemonRoutes(m)
	return m
}

func serveDaemonOp(m *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestDaemonOps_LivenessAndReadiness(t *testing.T) {
	m := daemonOpsRouter(t, nil)
	live := serveDaemonOp(m, http.MethodGet, "/health/live", "")
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), `"alive":true`) {
		t.Fatalf("liveness: %d %s", live.Code, live.Body.String())
	}
	ready := serveDaemonOp(m, http.MethodGet, "/health/ready", "")
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"ready":true`) {
		t.Fatalf("readiness: %d %s", ready.Code, ready.Body.String())
	}
}

func TestDaemonOps_UnwiredAnswers503(t *testing.T) {
	m := daemonOpsRouter(t, nil)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPatch, "/config", `{"section":"logging"}`},
		{http.MethodPost, "/shutdown", ""},
		{http.MethodGet, "/entity-types", ""},
	} {
		if rec := serveDaemonOp(m, c.method, c.path, c.body); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: got %d, want 503", c.method, c.path, rec.Code)
		}
	}
}

func TestDaemonOps_UpdateConfigPassesTheSection(t *testing.T) {
	ops := &fakeDaemonOps{}
	m := daemonOpsRouter(t, ops)
	rec := serveDaemonOp(m, http.MethodPatch, "/config", `{"section":"logging","values":{"level":"debug"},"persist":true}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "configuration section applied") {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if ops.updateReq.GetSection().GetSection() != "logging" ||
		ops.updateReq.GetSection().GetValues()["level"] != "debug" || !ops.updateReq.GetPersist() {
		t.Fatalf("request not passed through: %+v", ops.updateReq)
	}
}

func TestDaemonOps_UpdateConfigRefusals(t *testing.T) {
	ops := &fakeDaemonOps{updateErr: errors.New("unknown section")}
	m := daemonOpsRouter(t, ops)
	if rec := serveDaemonOp(m, http.MethodPatch, "/config", `{"values":{}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("missing section: got %d", rec.Code)
	}
	if rec := serveDaemonOp(m, http.MethodPatch, "/config", `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad body: got %d", rec.Code)
	}
	rec := serveDaemonOp(m, http.MethodPatch, "/config", `{"section":"nope"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown section") {
		t.Errorf("daemon refusal: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDaemonOps_ShutdownDefaultsToGraceful(t *testing.T) {
	ops := &fakeDaemonOps{}
	m := daemonOpsRouter(t, ops)
	if rec := serveDaemonOp(m, http.MethodPost, "/shutdown", ""); rec.Code != http.StatusOK {
		t.Fatalf("shutdown: %d %s", rec.Code, rec.Body.String())
	}
	if !ops.shutdownReq.GetGraceful() {
		t.Fatal("an empty body must shut down gracefully")
	}
	if rec := serveDaemonOp(m, http.MethodPost, "/shutdown", `{"graceful":false,"timeout_seconds":7}`); rec.Code != http.StatusOK {
		t.Fatalf("shutdown with body: %d", rec.Code)
	}
	if ops.shutdownReq.GetGraceful() || ops.shutdownReq.GetTimeoutSeconds() != 7 {
		t.Fatalf("body not passed: %+v", ops.shutdownReq)
	}
}

func TestDaemonOps_ListEntityTypes(t *testing.T) {
	ops := &fakeDaemonOps{types: &platformv1.ListEntityTypesResponse{
		EntityTypes:   []*platformv1.EntityTypeInfo{{Name: "tenant", EntityCount: 2, Status: "active"}},
		TotalEntities: 2,
		ActiveTypes:   1,
	}}
	m := daemonOpsRouter(t, ops)
	rec := serveDaemonOp(m, http.MethodGet, "/entity-types", "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"name":"tenant"`) || !strings.Contains(body, `"count":2`) {
		t.Fatalf("entity types: %d %s", rec.Code, body)
	}
}
