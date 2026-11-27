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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

type fakeEntityTypeLister struct {
	resp   *platformv1.ListEntityTypesResponse
	err    error
	called int
}

func (f *fakeEntityTypeLister) ListEntityTypes(_ context.Context, _ *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error) {
	f.called++
	return f.resp, f.err
}

func serveEntityTypes(t *testing.T, h *PlatformHandlers) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/entity-types", nil)
	rec := httptest.NewRecorder()
	h.ListEntityTypes(rec, req)
	return rec
}

func decodeEntityTypes(t *testing.T, body string) restwire.WebServiceResponse {
	t.Helper()
	var resp restwire.WebServiceResponse
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return resp
}

func TestListEntityTypes_Unconfigured(t *testing.T) {
	rec := serveEntityTypes(t, newTestHandlers(t))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	if resp := decodeEntityTypes(t, rec.Body.String()); resp.Success {
		t.Error("expected success to be false")
	}
}

func TestListEntityTypes_ReturnsTypesWithoutDatabasePath(t *testing.T) {
	h := newTestHandlers(t)
	fake := &fakeEntityTypeLister{resp: &platformv1.ListEntityTypesResponse{
		EntityTypes: []*platformv1.EntityTypeInfo{
			{Name: "device", EntityCount: 7, Status: "active"},
			{Name: "zone", EntityCount: 0, Status: "empty"},
		},
		TotalEntities: 7,
		ActiveTypes:   1,
		DatabasePath:  "/var/lib/test-db",
	}}
	h.SetEntityTypeLister(fake)

	rec := serveEntityTypes(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"databasePath", "database_path", "/var/lib/test-db"} {
		if strings.Contains(body, leak) {
			t.Errorf("response body leaks %q: %s", leak, body)
		}
	}
	if fake.called != 1 {
		t.Errorf("expected lister called once, got %d", fake.called)
	}

	resp := decodeEntityTypes(t, body)
	if !resp.Success {
		t.Fatal("expected success to be true")
	}
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}
	types, ok := payload["entityTypes"].([]interface{})
	if !ok || len(types) != 2 {
		t.Fatalf("expected 2 entityTypes, got %v", payload["entityTypes"])
	}
	first, ok := types[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected entity type entry to be a map")
	}
	if first["name"] != "device" {
		t.Errorf("expected name device, got %v", first["name"])
	}
	if first["entityCount"] != float64(7) {
		t.Errorf("expected entityCount 7, got %v", first["entityCount"])
	}
	if first["status"] != "active" {
		t.Errorf("expected status active, got %v", first["status"])
	}
	if payload["totalEntities"] != float64(7) {
		t.Errorf("expected totalEntities 7, got %v", payload["totalEntities"])
	}
	if payload["activeTypes"] != float64(1) {
		t.Errorf("expected activeTypes 1, got %v", payload["activeTypes"])
	}
}

func TestListEntityTypes_EmptyListIsAnEmptyArray(t *testing.T) {
	h := newTestHandlers(t)
	h.SetEntityTypeLister(&fakeEntityTypeLister{resp: &platformv1.ListEntityTypesResponse{}})

	rec := serveEntityTypes(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"entityTypes":[]`) {
		t.Errorf("expected an empty entityTypes array, got %s", body)
	}
}

func TestListEntityTypes_ListerErrorIs500(t *testing.T) {
	h := newTestHandlers(t)
	h.SetEntityTypeLister(&fakeEntityTypeLister{
		err: status.Error(codes.Internal, "failed to list entity types: boom"),
	})

	rec := serveEntityTypes(t, h)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
	if resp := decodeEntityTypes(t, rec.Body.String()); resp.Success {
		t.Error("expected success to be false")
	}
}

func TestListEntityTypes_RouteIsRegisteredGETOnly(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	router := NewPlatformRouter(logger, respWriter)
	router.SetEntityTypeLister(&fakeEntityTypeLister{resp: &platformv1.ListEntityTypesResponse{}})

	root, apiRouter := newTestRouter()
	router.RegisterRoutes(apiRouter)

	get := httptest.NewRecorder()
	root.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/v1/platform/entity-types", nil))
	if get.Code != http.StatusOK {
		t.Errorf("GET: expected status %d, got %d", http.StatusOK, get.Code)
	}

	post := httptest.NewRecorder()
	root.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/v1/platform/entity-types", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: expected status %d, got %d", http.StatusMethodNotAllowed, post.Code)
	}
}
