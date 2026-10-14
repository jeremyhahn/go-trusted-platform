package healthprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fixedChecker reports a fixed status under a name no probe body may carry.
type fixedChecker struct {
	name   string
	status health.HealthStatus
}

func (c *fixedChecker) Name() string { return c.name }

func (c *fixedChecker) Check(ctx context.Context) health.ComponentHealth {
	return health.ComponentHealth{
		Name:    c.name,
		Status:  c.status,
		Message: "secret-message-" + c.name,
		Details: map[string]interface{}{"address": "10.9.8.7"},
	}
}

// newTestRegistry returns a registry with one checker per status, named
// component-a, component-b, ...
func newTestRegistry(t *testing.T, statuses ...health.HealthStatus) health.Registry {
	t.Helper()
	registry := health.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	for i, status := range statuses {
		name := "component-" + string(rune('a'+i))
		if err := registry.Register(&fixedChecker{name: name, status: status}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	return registry
}

func serve(t *testing.T, registry health.Registry, path string) *httptest.ResponseRecorder {
	t.Helper()
	router := mux.NewRouter()
	NewHandlers(func() health.Registry { return registry }).RegisterRoutes(router)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func TestHandlers_StatusCodeFollowsTheProbe(t *testing.T) {
	cases := []struct {
		name     string
		statuses []health.HealthStatus
		want     map[string]int
	}{
		{"healthy", []health.HealthStatus{health.StatusHealthy}, map[string]int{
			HealthPath: http.StatusOK, LivenessPath: http.StatusOK, ReadinessPath: http.StatusOK}},
		{"degraded", []health.HealthStatus{health.StatusHealthy, health.StatusDegraded}, map[string]int{
			HealthPath: http.StatusServiceUnavailable, LivenessPath: http.StatusOK, ReadinessPath: http.StatusOK}},
		{"unhealthy", []health.HealthStatus{health.StatusHealthy, health.StatusUnhealthy}, map[string]int{
			HealthPath: http.StatusServiceUnavailable, LivenessPath: http.StatusOK, ReadinessPath: http.StatusServiceUnavailable}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, tc.statuses...)
			for path, want := range tc.want {
				recorder := serve(t, registry, path)
				if recorder.Code != want {
					t.Errorf("GET %s = %d, want %d", path, recorder.Code, want)
				}
				if got := recorder.Header().Get("Content-Type"); got != "application/json" {
					t.Errorf("GET %s Content-Type = %q, want application/json", path, got)
				}
			}
		})
	}
}

// The probes are unauthenticated, so the body must carry no component name,
// message or detail.
func TestHandlers_BodyCarriesNoComponent(t *testing.T) {
	registry := newTestRegistry(t, health.StatusHealthy, health.StatusUnhealthy)
	for _, path := range []string{HealthPath, LivenessPath, ReadinessPath} {
		body := serve(t, registry, path).Body.String()
		for _, leak := range []string{"component-", "secret-message", "10.9.8.7"} {
			if strings.Contains(body, leak) {
				t.Errorf("GET %s body %s leaks %q", path, body, leak)
			}
		}
	}
}

// The body decodes into the message the gRPC rpc returns, which is what the
// SDK's REST transport relies on.
func TestHandlers_BodyDecodesAsTheRPCMessage(t *testing.T) {
	registry := newTestRegistry(t, health.StatusHealthy, health.StatusUnhealthy)

	var ready platformv1.ReadinessResponse
	if err := protojson.Unmarshal(serve(t, registry, ReadinessPath).Body.Bytes(), &ready); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if ready.GetReady() || ready.GetStatus() != platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY {
		t.Errorf("readiness = %v, want not ready and unhealthy", &ready)
	}

	var summary platformv1.GetHealthResponse
	if err := protojson.Unmarshal(serve(t, registry, HealthPath).Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if summary.GetStatus() != platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY || len(summary.GetComponents()) != 0 {
		t.Errorf("health = %v, want unhealthy with no components", &summary)
	}

	var live platformv1.LivenessResponse
	if err := protojson.Unmarshal(serve(t, registry, LivenessPath).Body.Bytes(), &live); err != nil {
		t.Fatalf("decode liveness: %v", err)
	}
	if !live.GetAlive() || live.GetTimestamp() == nil {
		t.Errorf("liveness = %v, want alive with a timestamp", &live)
	}
}

func TestHandlers_NilSourceFailsOpen(t *testing.T) {
	router := mux.NewRouter()
	NewHandlers(nil).RegisterRoutes(router)
	for _, path := range []string{HealthPath, LivenessPath, ReadinessPath} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s with no registry = %d, want 200 (documented fail-open)", path, recorder.Code)
		}
	}
}

func TestHandlers_RefuseNonGet(t *testing.T) {
	registry := newTestRegistry(t, health.StatusHealthy)
	router := mux.NewRouter()
	NewHandlers(func() health.Registry { return registry }).RegisterRoutes(router)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, ReadinessPath, nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST %s = %d, want 405", ReadinessPath, recorder.Code)
	}
}

func TestStatusToProto(t *testing.T) {
	cases := map[health.HealthStatus]platformv1.HealthStatus{
		health.StatusHealthy:                platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		health.StatusDegraded:               platformv1.HealthStatus_HEALTH_STATUS_DEGRADED,
		health.StatusUnhealthy:              platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
		health.StatusUnknown:                platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED,
		health.HealthStatus("not-a-status"): platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := StatusToProto(in); got != want {
			t.Errorf("StatusToProto(%q) = %s, want %s", in, got, want)
		}
	}
}
