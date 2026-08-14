package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkProxyHot measures the full handler path (route match, header
// strip, metrics, forward) through a shared reverse proxy to a local
// httptest backend.
func BenchmarkProxyHot(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			b.Errorf("backend write: %v", err)
		}
	}))
	defer backend.Close()
	e, err := New(publicConfig(backend.URL), Deps{Logger: testLogger()})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/hot", nil)
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d, want 200", rec.Code)
		}
	}
}

// BenchmarkRouterMatch measures the lock-free route table lookup in
// isolation. The match path is allocation-free for lowercase hosts.
func BenchmarkRouterMatch(b *testing.B) {
	routes := []*CompiledRoute{
		makeRoute("root", []string{"*"}, "/"),
		makeRoute("api", []string{"api.example.com"}, "/api"),
		makeRoute("api-v2", []string{"api.example.com"}, "/api/v2"),
		makeRoute("api-v2-users", []string{"api.example.com"}, "/api/v2/users"),
		makeRoute("web", []string{"www.example.com"}, "/"),
		makeRoute("assets", []string{"www.example.com"}, "/assets"),
		makeRoute("metrics", []string{"*"}, "/metrics"),
		makeRoute("admin", []string{"admin.example.com"}, "/admin"),
		makeRoute("bmc", []string{"bmc.example.com"}, "/redfish"),
		makeRoute("attest", []string{"attest.example.com"}, "/attest"),
	}
	table := buildRouteTable(routes)
	b.ReportAllocs()
	for b.Loop() {
		if cr := table.match("api.example.com:8443", "/api/v2/users/42"); cr == nil || cr.cfg.ID != "api-v2-users" {
			b.Fatal("unexpected match result")
		}
	}
}
