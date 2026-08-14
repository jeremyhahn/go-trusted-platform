package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsSnapshot(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}
	m := e.Metrics()
	route := m.Routes["svc"]
	if route.Requests != 3 {
		t.Errorf("Requests = %d, want 3", route.Requests)
	}
	if route.BytesOut != 6 { // three "ok" bodies
		t.Errorf("BytesOut = %d, want 6", route.BytesOut)
	}
	if route.Denied != 0 || route.Errors != 0 {
		t.Errorf("Denied/Errors = %d/%d, want 0/0", route.Denied, route.Errors)
	}
	if m.NotFound != 0 {
		t.Errorf("NotFound = %d, want 0", m.NotFound)
	}
}

func TestMetricsSnapshotIsCopy(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	first := e.Metrics()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if first.Routes["svc"].Requests != 0 {
		t.Error("earlier snapshot mutated by later traffic")
	}
	if e.Metrics().Routes["svc"].Requests != 1 {
		t.Error("live counters not incremented")
	}
}

func TestMetricsUnknownRouteAbsent(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	if _, ok := e.Metrics().Routes["nope"]; ok {
		t.Error("snapshot contains a route that was never configured")
	}
}
