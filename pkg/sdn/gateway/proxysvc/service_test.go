// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newTestEngine builds a public-route engine fronting the given backend.
func newTestEngine(t *testing.T, backendURL string) *proxy.Engine {
	t.Helper()
	cfg := proxy.Config{
		Listeners: []proxy.ListenerConfig{{ID: "test", Address: "127.0.0.1:0"}},
		Routes: []proxy.RouteConfig{{
			ID:         "app",
			PathPrefix: "/",
			PoolID:     "backend",
			Auth:       proxy.AuthRequirements{Mode: proxy.AuthModePublic},
		}},
		Pools: []proxy.BackendPoolConfig{{
			ID:       "backend",
			Backends: []proxy.BackendConfig{{URL: backendURL}},
		}},
	}
	engine, err := proxy.New(cfg, proxy.Deps{})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return engine
}

func TestNewHandlerNilEngine(t *testing.T) {
	_, err := NewHandler(HandlerConfig{})
	var nilEngine *ErrNilEngine
	if !errors.As(err, &nilEngine) {
		t.Fatalf("err = %v, want *ErrNilEngine", err)
	}
}

func TestHandlerName(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	h, err := NewHandler(HandlerConfig{Engine: newTestEngine(t, backend.URL)})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if h.Name() != ServiceName || h.Name() != "proxy" {
		t.Fatalf("Name = %q, want proxy", h.Name())
	}
}

func TestHandlerLifecycle(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "backend-ok")
	}))
	t.Cleanup(backend.Close)

	h, err := NewHandler(HandlerConfig{Engine: newTestEngine(t, backend.URL)})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if h.IsActive() {
		t.Fatal("handler active before Start")
	}
	if err := h.Health(); err == nil {
		t.Fatal("Health must fail before Start")
	}

	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { h.Stop(context.Background()) })

	if !h.IsActive() {
		t.Fatal("handler not active after Start")
	}
	if err := h.Health(); err != nil {
		t.Fatalf("Health after Start: %v", err)
	}

	// Traffic flows through the bound listener.
	snap := h.HealthSnapshot()
	if !snap.Active || snap.Engine == nil || len(snap.Engine.Listeners) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.Sync != nil {
		t.Fatal("Sync must be nil when the sync loop is disabled")
	}
	resp, err := http.Get("http://" + snap.Engine.Listeners[0].BoundAddress + "/")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "backend-ok" {
		t.Fatalf("body = %q, want backend-ok", body)
	}

	// Double start is rejected.
	if err := h.Start(ctx); !errors.Is(err, proxy.ErrEngineStarted) {
		t.Fatalf("second Start = %v, want ErrEngineStarted", err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if h.IsActive() {
		t.Fatal("handler active after Stop")
	}
	// Stop is idempotent.
	if err := h.Stop(stopCtx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestHandlerStartStopWithSyncer(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)

	fake := &fakeControlPlane{notify: make(chan struct{}, 1)}
	fake.setVersion(1)
	engine := newTestEngine(t, backend.URL)
	syncer, err := NewConfigSyncer(SyncerConfig{
		Client:   fake,
		Reloader: engine,
		Static: proxy.Config{
			Listeners: []proxy.ListenerConfig{{ID: "test", Address: "127.0.0.1:0"}},
			Routes: []proxy.RouteConfig{{
				ID:         "app",
				PathPrefix: "/",
				PoolID:     "backend",
				Auth:       proxy.AuthRequirements{Mode: proxy.AuthModePublic},
			}},
			Pools: []proxy.BackendPoolConfig{{
				ID:       "backend",
				Backends: []proxy.BackendConfig{{URL: backend.URL}},
			}},
		},
		Interval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}

	h, err := NewHandler(HandlerConfig{Engine: engine, Syncer: syncer})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The sync loop reaches the control plane without waiting a full tick.
	select {
	case <-fake.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("sync loop never called platformd")
	}

	snap := h.HealthSnapshot()
	if snap.Sync == nil {
		t.Fatal("Sync snapshot missing with sync enabled")
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestHandlerStartFailsOnListenerConflict(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)

	// Bind a port, then configure the engine to collide with it.
	blocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(blocker.Close)
	addr := blocker.Listener.Addr().String()

	cfg := proxy.Config{
		Listeners: []proxy.ListenerConfig{{ID: "conflict", Address: addr}},
		Routes: []proxy.RouteConfig{{
			ID:         "app",
			PathPrefix: "/",
			PoolID:     "backend",
			Auth:       proxy.AuthRequirements{Mode: proxy.AuthModePublic},
		}},
		Pools: []proxy.BackendPoolConfig{{
			ID:       "backend",
			Backends: []proxy.BackendConfig{{URL: backend.URL}},
		}},
	}
	engine, err := proxy.New(cfg, proxy.Deps{})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	h, err := NewHandler(HandlerConfig{Engine: engine})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("Start must fail on listener conflict")
		h.Stop(context.Background())
	}
	if h.IsActive() {
		t.Fatal("handler active after failed Start")
	}
}

// Compile-time proof the platformv1 fakes stay aligned with the seam.
var _ ControlPlaneClient = (*fakeControlPlane)(nil)
var _ = platformv1.GetProxyConfigResponse{}
