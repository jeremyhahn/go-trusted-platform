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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/timestamppb"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errStoreBroken is the typed failure the in-memory snapshot store
// returns when a test asks it to fail with something other than
// "not found".
type errStoreBroken struct{}

func (errStoreBroken) Error() string { return "snapshot store broken" }

// memSnapshotStore is an in-memory tpconfig.SnapshotStore.
type memSnapshotStore struct {
	snaps     map[string]*tpconfig.Snapshot
	err       error
	lastLimit int
}

func newMemSnapshotStore() *memSnapshotStore {
	return &memSnapshotStore{snaps: map[string]*tpconfig.Snapshot{}}
}

func (m *memSnapshotStore) Put(s *tpconfig.Snapshot) error {
	if m.err != nil {
		return m.err
	}
	m.snaps[s.ID] = s
	return nil
}

func (m *memSnapshotStore) Get(id string) (*tpconfig.Snapshot, error) {
	if m.err != nil {
		return nil, m.err
	}
	s, ok := m.snaps[id]
	if !ok {
		return nil, tpconfig.ErrSnapshotNotFound{ID: id}
	}
	return s, nil
}

func (m *memSnapshotStore) List(limit int) ([]tpconfig.SnapshotSummary, error) {
	m.lastLimit = limit
	if m.err != nil {
		return nil, m.err
	}
	out := make([]tpconfig.SnapshotSummary, 0, len(m.snaps))
	for _, s := range m.snaps {
		out = append(out, tpconfig.SnapshotSummary{ID: s.ID, Reason: s.Reason, Actor: s.Actor})
	}
	return out, nil
}

func (m *memSnapshotStore) Delete(id string) error {
	if m.err != nil {
		return m.err
	}
	if _, ok := m.snaps[id]; !ok {
		return tpconfig.ErrSnapshotNotFound{ID: id}
	}
	delete(m.snaps, id)
	return nil
}

// storeReloader is a ConfigReloader backed by a memSnapshotStore that
// records the arguments of RollbackConfig.
type storeReloader struct {
	store       *memSnapshotStore
	rollbackErr error
	rolledTo    string
	actor       string
}

func (s *storeReloader) ReloadConfigFromDisk() ([]string, error) { return nil, nil }

func (s *storeReloader) ReloadConfigWithSnapshot(string) ([]string, string, error) {
	return nil, "", nil
}

func (s *storeReloader) RollbackConfig(id, actor string) (string, error) {
	s.rolledTo = id
	s.actor = actor
	if s.rollbackErr != nil {
		return "", s.rollbackErr
	}
	return "pre-" + id, nil
}

func (s *storeReloader) SnapshotStore() tpconfig.SnapshotStore {
	if s.store == nil {
		return nil
	}
	return s.store
}

// newTestRouter builds a PlatformRouter mounted under /api/v1.
func newMountedRouter(t *testing.T) (*PlatformRouter, *mux.Router) {
	t.Helper()
	l := logging.NewLogger(slog.LevelDebug, nil)
	pr := NewPlatformRouter(l, response.NewResponseWriter(l, nil))
	root := mux.NewRouter()
	pr.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return pr, root
}

func serve(root http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

// payloadOf decodes the response writer's {"payload": ...} envelope.
func payloadOf(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	var env struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v (body %s)", err, rec.Body.String())
	}
	if err := json.Unmarshal(env.Payload, into); err != nil {
		t.Fatalf("unmarshal payload: %v (body %s)", err, rec.Body.String())
	}
}

func TestSnapshotRoutes_NoStoreIsServerError(t *testing.T) {
	cases := []struct {
		name, method, path string
		reloader           ConfigReloader
	}{
		{"list without reloader", http.MethodGet, "/api/v1/platform/config/snapshots", nil},
		{"create without reloader", http.MethodPost, "/api/v1/platform/config/snapshots", nil},
		{"get without reloader", http.MethodGet, "/api/v1/platform/config/snapshots/a", nil},
		{"delete without reloader", http.MethodDelete, "/api/v1/platform/config/snapshots/a", nil},
		{"rollback without reloader", http.MethodPost, "/api/v1/platform/config/snapshots/a/rollback", nil},
		{"list with nil store", http.MethodGet, "/api/v1/platform/config/snapshots", &storeReloader{}},
		{"get with nil store", http.MethodGet, "/api/v1/platform/config/snapshots/a", &storeReloader{}},
		{"delete with nil store", http.MethodDelete, "/api/v1/platform/config/snapshots/a", &storeReloader{}},
		{"create with nil store", http.MethodPost, "/api/v1/platform/config/snapshots", &storeReloader{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr, root := newMountedRouter(t)
			if tc.reloader != nil {
				pr.SetConfigReloader(tc.reloader)
			}
			rec := serve(root, tc.method, tc.path, "", nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSnapshotHandlers_MissingIDIsBadRequest(t *testing.T) {
	cases := []struct {
		name    string
		handler func(*PlatformHandlers) http.HandlerFunc
	}{
		{"get", func(h *PlatformHandlers) http.HandlerFunc { return h.GetSnapshot }},
		{"delete", func(h *PlatformHandlers) http.HandlerFunc { return h.DeleteSnapshot }},
		{"rollback", func(h *PlatformHandlers) http.HandlerFunc { return h.Rollback }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandlers(t)
			h.SetConfigReloader(&storeReloader{store: newMemSnapshotStore()})
			rec := httptest.NewRecorder()
			tc.handler(h)(rec, httptest.NewRequest(http.MethodGet, "/snapshots/", nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), ErrSnapshotIDRequired{}.Error()) {
				t.Errorf("body %s does not carry ErrSnapshotIDRequired", rec.Body.String())
			}
		})
	}
}

func TestListSnapshots_ReturnsStoreContentsAndPassesLimit(t *testing.T) {
	store := newMemSnapshotStore()
	store.snaps["s1"] = &tpconfig.Snapshot{ID: "s1", Reason: "manual"}
	pr, root := newMountedRouter(t)
	pr.SetConfigReloader(&storeReloader{store: store})

	rec := serve(root, http.MethodGet, "/api/v1/platform/config/snapshots?limit=7", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var got struct {
		Snapshots []tpconfig.SnapshotSummary `json:"snapshots"`
		Total     int                        `json:"total"`
	}
	payloadOf(t, rec, &got)
	if got.Total != 1 || len(got.Snapshots) != 1 || got.Snapshots[0].ID != "s1" {
		t.Errorf("payload = %+v, want one snapshot s1", got)
	}
	if store.lastLimit != 7 {
		t.Errorf("store limit = %d, want 7", store.lastLimit)
	}

	// A non-numeric limit falls back to 0 (all).
	serve(root, http.MethodGet, "/api/v1/platform/config/snapshots?limit=abc", "", nil)
	if store.lastLimit != 0 {
		t.Errorf("store limit for bad input = %d, want 0", store.lastLimit)
	}
}

func TestListSnapshots_StoreErrorIsServerError(t *testing.T) {
	store := newMemSnapshotStore()
	store.err = errStoreBroken{}
	pr, root := newMountedRouter(t)
	pr.SetConfigReloader(&storeReloader{store: store})
	rec := serve(root, http.MethodGet, "/api/v1/platform/config/snapshots", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestGetAndDeleteSnapshot_StatusByStoreOutcome(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		id       string
		storeErr error
		want     int
	}{
		{"get found", http.MethodGet, "s1", nil, http.StatusOK},
		{"get missing", http.MethodGet, "nope", nil, http.StatusNotFound},
		{"get broken store", http.MethodGet, "s1", errStoreBroken{}, http.StatusInternalServerError},
		{"delete found", http.MethodDelete, "s1", nil, http.StatusOK},
		{"delete missing", http.MethodDelete, "nope", nil, http.StatusNotFound},
		{"delete broken store", http.MethodDelete, "s1", errStoreBroken{}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemSnapshotStore()
			store.snaps["s1"] = &tpconfig.Snapshot{ID: "s1", Reason: "seed"}
			store.err = tc.storeErr
			pr, root := newMountedRouter(t)
			pr.SetConfigReloader(&storeReloader{store: store})

			rec := serve(root, tc.method, "/api/v1/platform/config/snapshots/"+tc.id, "", nil)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != http.StatusOK {
				return
			}
			var got map[string]any
			payloadOf(t, rec, &got)
			if got["id"] != "s1" {
				t.Errorf("payload id = %v, want s1", got["id"])
			}
			_, stillThere := store.snaps["s1"]
			if tc.method == http.MethodDelete && stillThere {
				t.Error("delete returned 200 but the snapshot is still stored")
			}
			if tc.method == http.MethodGet && !stillThere {
				t.Error("get removed the snapshot")
			}
		})
	}
}

func TestCreateSnapshot_CapturesReasonAndActor(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("ca.cn", "cp.example.com")

	cases := []struct {
		name       string
		body       string
		hdr        map[string]string
		wantReason string
		wantActor  string
	}{
		{"explicit reason, platform actor", `{"reason":"before-upgrade"}`,
			map[string]string{"X-Platform-Actor": "alice", "X-User-Id": "u-1"}, "before-upgrade", "alice"},
		{"empty body defaults to manual, user id actor", "",
			map[string]string{"X-User-Id": "u-1"}, "manual", "u-1"},
		{"no headers is anonymous", `{}`, nil, "manual", "anonymous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemSnapshotStore()
			pr, root := newMountedRouter(t)
			pr.SetConfigReloader(&storeReloader{store: store})

			rec := serve(root, http.MethodPost, "/api/v1/platform/config/snapshots", tc.body, tc.hdr)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
			}
			var got struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}
			payloadOf(t, rec, &got)
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			stored, ok := store.snaps[got.ID]
			if !ok {
				t.Fatalf("snapshot %q was not persisted", got.ID)
			}
			if stored.Actor != tc.wantActor {
				t.Errorf("actor = %q, want %q", stored.Actor, tc.wantActor)
			}
		})
	}
}

func TestCreateSnapshot_StorePutErrorIsServerError(t *testing.T) {
	store := newMemSnapshotStore()
	store.err = errStoreBroken{}
	pr, root := newMountedRouter(t)
	pr.SetConfigReloader(&storeReloader{store: store})
	rec := serve(root, http.MethodPost, "/api/v1/platform/config/snapshots", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRollback_StatusByReloaderOutcome(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, http.StatusOK},
		{"unknown snapshot", tpconfig.ErrSnapshotNotFound{ID: "s9"}, http.StatusNotFound},
		{"rollback failure", errStoreBroken{}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rl := &storeReloader{store: newMemSnapshotStore(), rollbackErr: tc.err}
			pr, root := newMountedRouter(t)
			pr.SetConfigReloader(rl)

			rec := serve(root, http.MethodPost, "/api/v1/platform/config/snapshots/s9/rollback", "",
				map[string]string{"X-Platform-Actor": "bob"})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if rl.rolledTo != "s9" || rl.actor != "bob" {
				t.Errorf("RollbackConfig(%q, %q), want (s9, bob)", rl.rolledTo, rl.actor)
			}
			if tc.want != http.StatusOK {
				return
			}
			var got map[string]string
			payloadOf(t, rec, &got)
			if got["rolled_back_to"] != "s9" || got["pre_rollback_snapshot"] != "pre-s9" {
				t.Errorf("payload = %v", got)
			}
		})
	}
}

// errReader fails every Read so ValidateConfig hits its body-read error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errStoreBroken{} }

func TestValidateConfig_UnreadableBodyIsBadRequest(t *testing.T) {
	h := newTestHandlers(t)
	rec := httptest.NewRecorder()
	h.ValidateConfig(rec, httptest.NewRequest(http.MethodPost, "/config/validate", errReader{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGetConfig_RedactFalseWithoutCapabilityStaysRedacted(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("ca.password", "hunter2")

	h := newTestHandlers(t)
	rec := httptest.NewRecorder()
	h.GetConfig(rec, httptest.NewRequest(http.MethodGet, "/config?redact=false", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("redact=false without the secrets capability leaked a secret")
	}
}

func TestWrappedError_UnwrapReachesCause(t *testing.T) {
	cause := errStoreBroken{}
	err := error(&WrappedError{Msg: "invalid since", Err: cause})
	var target errStoreBroken
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not reach the wrapped cause")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is did not match the wrapped cause")
	}
}

func TestGetSystem_ReportsRuntime(t *testing.T) {
	_, root := newMountedRouter(t)
	rec := serve(root, http.MethodGet, "/api/v1/platform/system", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got struct {
		System SystemInfoResponse `json:"system"`
	}
	payloadOf(t, rec, &got)
	if got.System.OS != runtime.GOOS || got.System.Arch != runtime.GOARCH || got.System.NumCPUs != runtime.NumCPU() {
		t.Errorf("system = %+v, want %s/%s with %d CPUs", got.System, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	}
}

func TestRouterSetVersionInfo_ReachesStatus(t *testing.T) {
	pr, root := newMountedRouter(t)
	pr.SetVersionInfo(&VersionInfo{Version: "9.9.9", GitHash: "abc123"})
	rec := serve(root, http.MethodGet, "/api/v1/platform/status", "", nil)
	var got StatusResponse
	payloadOf(t, rec, &got)
	if got.Version != "9.9.9" || got.GitCommit != "abc123" {
		t.Errorf("status = %+v, want version 9.9.9 commit abc123", got)
	}
}

// fixedServices is a ServicesManager returning one canned service.
type fixedServices struct {
	svc       *platformv1.ServiceInfo
	listErr   error
	statusErr error
	asked     platformv1.ServiceType
}

func (f *fixedServices) ListServices(context.Context, *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &platformv1.ListServicesResponse{Services: []*platformv1.ServiceInfo{f.svc}}, nil
}

func (f *fixedServices) GetServiceStatus(_ context.Context, req *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error) {
	f.asked = req.Service
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &platformv1.GetServiceStatusResponse{Service: f.svc}, nil
}

func (f *fixedServices) StartService(context.Context, *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error) {
	return &platformv1.StartServiceResponse{}, nil
}

func (f *fixedServices) StopService(context.Context, *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error) {
	return &platformv1.StopServiceResponse{}, nil
}

func (f *fixedServices) RestartService(context.Context, *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error) {
	return &platformv1.RestartServiceResponse{}, nil
}

func runningCA() *platformv1.ServiceInfo {
	return &platformv1.ServiceInfo{
		Name:      "ca",
		Status:    platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		StartedAt: timestamppb.New(time.Now().Add(-time.Minute)),
		Metadata:  map[string]string{"start_count": "3", "stop_count": "2", "last_error": "boom"},
	}
}

func assertServiceInfo(t *testing.T, got ServiceInfoResponse) {
	t.Helper()
	if got.Name != "ca" || got.Status != "running" || got.StartCount != 3 || got.StopCount != 2 || got.LastError != "boom" {
		t.Errorf("service = %+v", got)
	}
	if got.Uptime == "" || got.StartedAt.IsZero() {
		t.Errorf("started service has no uptime: %+v", got)
	}
}

func TestListServices_MapsManagerResponse(t *testing.T) {
	pr, root := newMountedRouter(t)
	pr.SetServicesManager(&fixedServices{svc: runningCA()})
	rec := serve(root, http.MethodGet, "/api/v1/platform/services", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var got ServicesListResponse
	payloadOf(t, rec, &got)
	if got.Count != 1 || len(got.Services) != 1 {
		t.Fatalf("list = %+v, want one service", got)
	}
	assertServiceInfo(t, got.Services[0])
}

func TestListServices_ManagerErrorIsServerError(t *testing.T) {
	pr, root := newMountedRouter(t)
	pr.SetServicesManager(&fixedServices{listErr: errStoreBroken{}})
	rec := serve(root, http.MethodGet, "/api/v1/platform/services", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestGetService_MapsManagerResponse(t *testing.T) {
	mgr := &fixedServices{svc: runningCA()}
	pr, root := newMountedRouter(t)
	pr.SetServicesManager(mgr)
	rec := serve(root, http.MethodGet, "/api/v1/platform/services/dns", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if mgr.asked != platformv1.ServiceType_SERVICE_TYPE_DNS {
		t.Errorf("asked for %v, want SERVICE_TYPE_DNS", mgr.asked)
	}
	var got ServiceInfoResponse
	payloadOf(t, rec, &got)
	assertServiceInfo(t, got)
}

func TestGetService_ManagerErrorIsNotFound(t *testing.T) {
	pr, root := newMountedRouter(t)
	pr.SetServicesManager(&fixedServices{statusErr: errStoreBroken{}})
	rec := serve(root, http.MethodGet, "/api/v1/platform/services/ghost", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ghost") {
		t.Errorf("body %s does not name the service", rec.Body.String())
	}
}

func TestListLogServices_ReturnsServicesAndErrors(t *testing.T) {
	pr, root := newMountedRouter(t)
	pr.SetLogQuerier(&fakeQuerier{services: []string{"ca", "dns"}})
	rec := serve(root, http.MethodGet, "/api/v1/platform/logs/services", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got struct {
		Services []string `json:"services"`
	}
	payloadOf(t, rec, &got)
	if strings.Join(got.Services, ",") != "ca,dns" {
		t.Errorf("services = %v, want [ca dns]", got.Services)
	}

	pr.SetLogQuerier(&fakeQuerier{err: errStoreBroken{}})
	rec = serve(root, http.MethodGet, "/api/v1/platform/logs/services", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status on querier error = %d, want 500", rec.Code)
	}
}

func TestParseLogFilter(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		wantErr bool
		check   func(t *testing.T, f jsonfile.Filter)
	}{
		{"bad until", "until=yesterday", true, nil},
		{"bad limit", "limit=many", true, nil},
		{"limit capped at 5000", "limit=99999", false, func(t *testing.T, f jsonfile.Filter) {
			if f.Limit != 5000 {
				t.Errorf("limit = %d, want 5000", f.Limit)
			}
		}},
		{"limit floored at 1", "limit=-4", false, func(t *testing.T, f jsonfile.Filter) {
			if f.Limit != 1 {
				t.Errorf("limit = %d, want 1", f.Limit)
			}
		}},
		{"fields parsed", "service=ca&service=dns&level=+warn+&grep=disk&until=2026-01-02T03:04:05Z", false,
			func(t *testing.T, f jsonfile.Filter) {
				if f.MinLevel != "WARN" || f.Grep != "disk" || len(f.Services) != 2 {
					t.Errorf("filter = %+v", f)
				}
				if !f.Until.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
					t.Errorf("until = %v", f.Until)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parseLogFilter(httptest.NewRequest(http.MethodGet, "/logs?"+tc.query, nil))
			if tc.wantErr {
				var we *WrappedError
				if !errors.As(err, &we) {
					t.Fatalf("err = %v, want *WrappedError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.check(t, f)
		})
	}
}

func TestFilterMatchesLine(t *testing.T) {
	caInfo := []byte(`{"time":"2026-01-02T03:04:05Z","level":"INFO","msg":"issued cert","service":"ca"}`)
	cases := []struct {
		name   string
		filter jsonfile.Filter
		line   []byte
		want   bool
	}{
		{"empty filter accepts anything", jsonfile.Filter{}, []byte("not json"), true},
		{"malformed line passes through", jsonfile.Filter{Services: []string{"ca"}}, []byte("{bad"), true},
		{"service match", jsonfile.Filter{Services: []string{"ca"}}, caInfo, true},
		{"service mismatch", jsonfile.Filter{Services: []string{"dns"}}, caInfo, false},
		{"level below minimum", jsonfile.Filter{MinLevel: "ERROR"}, caInfo, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterMatchesLine(tc.filter, tc.line); got != tc.want {
				t.Errorf("filterMatchesLine = %v, want %v", got, tc.want)
			}
		})
	}
}

// streamQuerier hands StreamLogs a channel the test controls and
// records whether the subscription was released.
type streamQuerier struct {
	fakeQuerier
	ch           chan []byte
	unsubscribed bool
}

func (s *streamQuerier) Subscribe() (<-chan []byte, func()) {
	return s.ch, func() { s.unsubscribed = true }
}

func TestStreamLogs_WritesMatchingLinesAsSSE(t *testing.T) {
	q := &streamQuerier{ch: make(chan []byte, 3)}
	q.ch <- []byte(`{"level":"INFO","msg":"from ca","service":"ca"}` + "\n")
	q.ch <- []byte(`{"level":"INFO","msg":"from dns","service":"dns"}` + "\n")
	q.ch <- []byte(`{"level":"INFO","msg":"ca again","service":"ca"}`)
	close(q.ch)

	pr, root := newMountedRouter(t)
	pr.SetLogQuerier(q)
	rec := serve(root, http.MethodGet, "/api/v1/platform/logs/stream?service=ca", "", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q", ct)
	}
	want := `data: {"level":"INFO","msg":"from ca","service":"ca"}` + "\n\n" +
		`data: {"level":"INFO","msg":"ca again","service":"ca"}` + "\n\n"
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
	if !q.unsubscribed {
		t.Error("stream ended without releasing its subscription")
	}
}

func TestStreamLogs_ReturnsOnClientDisconnect(t *testing.T) {
	q := &streamQuerier{ch: make(chan []byte)}
	h := newTestHandlers(t)
	h.SetLogQuerier(q)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	h.StreamLogs(rec, httptest.NewRequest(http.MethodGet, "/logs/stream", nil).WithContext(ctx))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("status = %d body = %q, want 200 with no events", rec.Code, rec.Body.String())
	}
	if !q.unsubscribed {
		t.Error("disconnect did not release the subscription")
	}
}

// plainWriter is an http.ResponseWriter that cannot flush.
type plainWriter struct {
	header http.Header
	code   int
}

func (p *plainWriter) Header() http.Header         { return p.header }
func (p *plainWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p *plainWriter) WriteHeader(code int)        { p.code = code }

func TestStreamLogs_RefusesBeforeSubscribing(t *testing.T) {
	cases := []struct {
		name    string
		querier LogQuerier
		query   string
		flusher bool
		want    int
	}{
		{"no querier", nil, "", true, http.StatusServiceUnavailable},
		{"bad filter", &fakeQuerier{}, "?since=soon", true, http.StatusBadRequest},
		{"writer cannot flush", &fakeQuerier{}, "", false, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandlers(t)
			if tc.querier != nil {
				h.SetLogQuerier(tc.querier)
			}
			req := httptest.NewRequest(http.MethodGet, "/logs/stream"+tc.query, nil)
			if tc.flusher {
				rec := httptest.NewRecorder()
				h.StreamLogs(rec, req)
				if rec.Code != tc.want {
					t.Errorf("status = %d, want %d", rec.Code, tc.want)
				}
				return
			}
			pw := &plainWriter{header: http.Header{}}
			h.StreamLogs(pw, req)
			if pw.code != tc.want {
				t.Errorf("status = %d, want %d", pw.code, tc.want)
			}
		})
	}
}
