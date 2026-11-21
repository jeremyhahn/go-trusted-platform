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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// fakeConfigUpdater stands in for daemon.Service: it records the
// request and answers with a canned response or error. It never
// touches a config file.
type fakeConfigUpdater struct {
	got    *platformv1.UpdateConfigRequest
	resp   *platformv1.UpdateConfigResponse
	err    error
	called int
}

func (f *fakeConfigUpdater) UpdateConfig(_ context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error) {
	f.called++
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func okUpdater(message string) *fakeConfigUpdater {
	return &fakeConfigUpdater{resp: &platformv1.UpdateConfigResponse{
		Status: &platformv1.Status{Success: true, Message: message},
	}}
}

// putSection sends PUT /config/sections/{section} through a mux route so
// the path variable resolves.
func putSection(t *testing.T, h *PlatformHandlers, section, body string) *httptest.ResponseRecorder {
	t.Helper()
	m := mux.NewRouter()
	m.HandleFunc("/config/sections/{section}", h.UpdateConfigSection).Methods("PUT")
	req := httptest.NewRequest(http.MethodPut, "/config/sections/"+section, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	return rec
}

func decodePayload(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success to be true, body %s", raw)
	}
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be a map, body %s", raw)
	}
	return payload
}

func TestUpdateConfigSection_Unconfigured(t *testing.T) {
	h := newTestHandlers(t)
	rec := putSection(t, h, "logging", `{"values":{"level":"debug"}}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestUpdateConfigSection_AppliesValues(t *testing.T) {
	h := newTestHandlers(t)
	fake := okUpdater("configuration section applied")
	h.SetConfigUpdater(fake)

	rec := putSection(t, h, "logging", `{"values":{"level":"debug"},"persist":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if fake.called != 1 || fake.got == nil || fake.got.GetSection() == nil {
		t.Fatalf("updater not called with a section: called=%d got=%v", fake.called, fake.got)
	}
	if got := fake.got.GetSection().GetSection(); got != "logging" {
		t.Errorf("section = %q, want logging", got)
	}
	if got := fake.got.GetSection().GetValues(); !reflect.DeepEqual(got, map[string]string{"level": "debug"}) {
		t.Errorf("values = %v, want map[level:debug]", got)
	}
	if fake.got.GetPersist() {
		t.Error("persist = true, want false")
	}
	raw := rec.Body.Bytes()
	if strings.Contains(string(raw), "debug") {
		t.Errorf("reply echoes a config value: %s", raw)
	}
	payload := decodePayload(t, raw)
	if payload["section"] != "logging" {
		t.Errorf("payload.section = %v, want logging", payload["section"])
	}
	if payload["persisted"] != false {
		t.Errorf("payload.persisted = %v, want false", payload["persisted"])
	}
	if payload["message"] != "configuration section applied" {
		t.Errorf("payload.message = %v", payload["message"])
	}
}

func TestUpdateConfigSection_Persists(t *testing.T) {
	h := newTestHandlers(t)
	fake := okUpdater("configuration section applied and persisted to disk")
	h.SetConfigUpdater(fake)

	rec := putSection(t, h, "logging", `{"values":{"level":"info"},"persist":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !fake.got.GetPersist() {
		t.Error("persist = false, want true")
	}
	payload := decodePayload(t, rec.Body.Bytes())
	if payload["persisted"] != true {
		t.Errorf("payload.persisted = %v, want true", payload["persisted"])
	}
	if payload["message"] != "configuration section applied and persisted to disk" {
		t.Errorf("payload.message = %v", payload["message"])
	}
}

func TestUpdateConfigSection_MalformedBodyIs400(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":     `{"values":`,
		"unknown field": `{"values":{"a":"b"},"extra":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHandlers(t)
			fake := okUpdater("configuration section applied")
			h.SetConfigUpdater(fake)
			rec := putSection(t, h, "logging", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if fake.called != 0 {
				t.Errorf("updater called %d times, want 0", fake.called)
			}
		})
	}
}

func TestUpdateConfigSection_EmptyValuesIs400(t *testing.T) {
	h := newTestHandlers(t)
	fake := okUpdater("configuration section applied")
	h.SetConfigUpdater(fake)
	rec := putSection(t, h, "logging", `{"values":{}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fake.called != 0 {
		t.Errorf("updater called %d times, want 0", fake.called)
	}
}

func TestUpdateConfigSection_EmptyKeyIs400(t *testing.T) {
	h := newTestHandlers(t)
	fake := okUpdater("configuration section applied")
	h.SetConfigUpdater(fake)
	rec := putSection(t, h, "logging", `{"values":{"":"x"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fake.called != 0 {
		t.Errorf("updater called %d times, want 0", fake.called)
	}
}

func TestUpdateConfigSection_InvalidArgumentIs400AndOtherErrorsAre500(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "section is required"), http.StatusBadRequest},
		{"internal", status.Error(codes.Internal, "config: apply section failed: boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandlers(t)
			fake := &fakeConfigUpdater{err: tc.err}
			h.SetConfigUpdater(fake)
			rec := putSection(t, h, "logging", `{"values":{"level":"debug"}}`)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if fake.called != 1 {
				t.Errorf("updater called %d times, want 1", fake.called)
			}
		})
	}
}

func TestUpdateConfigSection_RouteIsRegisteredPUTOnly(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	router := NewPlatformRouter(logger, respWriter)
	fake := okUpdater("configuration section applied")
	router.SetConfigUpdater(fake)
	root, apiRouter := newTestRouter()
	router.RegisterRoutes(apiRouter)

	const path = "/api/v1/platform/config/sections/logging"
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"values":{"level":"debug"}}`))
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT %s = %d, want 200; body %s", path, rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, path, nil)
	rec = httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	// The route is PUT only. Behind the nested /api/v1 and /platform
	// subrouters gorilla/mux answers a method mismatch with 404 rather
	// than 405; either way GET must not reach the handler.
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("GET %s = %d, want 405 or 404", path, rec.Code)
	}
	if fake.called != 1 {
		t.Fatalf("updater called %d times, want 1 (the PUT only)", fake.called)
	}
}
