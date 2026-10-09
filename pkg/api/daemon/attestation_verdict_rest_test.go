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

package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

const (
	verdictRESTPath = "/api/v1/attestation/verdicts/stream"
	// tenantHeader stands in for the authentication chain: the tenant of the
	// session it would publish. Absent means no session.
	tenantHeader = "X-Test-Session-Tenant"
)

// verdictRESTServer serves the real REST router over the real hub. wg counts
// the handlers still running, so a test can prove each one returned.
func verdictRESTServer(t *testing.T, hub *deviceVerdictHub) (*httptest.Server, *sync.WaitGroup) {
	t.Helper()
	var wg sync.WaitGroup
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	api.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wg.Add(1)
			defer wg.Done()
			if tenant, ok := r.Header[tenantHeader]; ok {
				session := iammw.NewIAMSession(&iamsdk.User{ID: "1", TenantID: tenant[0]})
				r = r.WithContext(iammw.SetSessionInContext(r.Context(), session))
			}
			next.ServeHTTP(w, r)
		})
	})
	restattestation.NewVerdictsRouter(hub, response.NewResponseWriter(discardLogger(), nil)).RegisterRoutes(api)
	server := httptest.NewServer(root)
	t.Cleanup(server.Close)
	return server, &wg
}

// followREST opens the stream and returns once the server says the
// subscription is live.
func followREST(t *testing.T, server *httptest.Server, tenant *string) (*bufio.Reader, context.CancelFunc, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+verdictRESTPath, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if tenant != nil {
		req.Header.Set(tenantHeader, *tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { cancel(); resp.Body.Close() })
	reader := bufio.NewReader(resp.Body)
	if resp.StatusCode == http.StatusOK {
		if line, _ := reader.ReadString('\n'); !strings.HasPrefix(line, ": subscribed") {
			t.Fatalf("first line = %q, want the subscribed comment", line)
		}
		reader.ReadString('\n')
	}
	return reader, cancel, resp
}

// nextEventID reads one verdict event and returns its id.
func nextEventID(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read event: %v", err)
	}
	id := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
	for i := 0; i < 3; i++ { // event, data, blank line
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("read event: %v", err)
		}
	}
	return id
}

func strPtr(s string) *string { return &s }

// TestVerdictStreamOverREST_AudienceRules follows over REST as each kind of
// caller and publishes a verdict of another tenant, then one of the caller's
// own: the caller must receive exactly the ones its audience admits.
func TestVerdictStreamOverREST_AudienceRules(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		first  string // the first event the caller must receive
	}{
		{"tenant sees only its own", "t1", "mine"},
		{"system tenant sees every tenant", platformTenantID, "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := newDeviceVerdictHub()
			defer hub.Close()
			server, _ := verdictRESTServer(t, hub)
			reader, _, _ := followREST(t, server, &tt.tenant)

			hub.OnDeviceVerdict(context.Background(), recordedFor("t2", "other"))
			hub.OnDeviceVerdict(context.Background(), recordedFor("t1", "mine"))
			if got := nextEventID(t, reader); got != tt.first {
				t.Fatalf("first event = %q, want %q", got, tt.first)
			}
		})
	}
}

func TestVerdictStreamOverREST_RefusesWhatTheRulesRefuse(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	server, _ := verdictRESTServer(t, hub)

	t.Run("session that names no tenant", func(t *testing.T) {
		_, _, resp := followREST(t, server, strPtr(""))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("no credential", func(t *testing.T) {
		_, _, resp := followREST(t, server, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("certificate that names no tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, verdictRESTPath, nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
		w := httptest.NewRecorder()
		restRouterFor(hub).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if !strings.Contains(w.Body.String(), "the certificate names no tenant") {
			t.Fatalf("body = %s", w.Body.String())
		}
	})
	t.Run("a stream that is closed", func(t *testing.T) {
		closed := newDeviceVerdictHub()
		closed.Close()
		closedServer, _ := verdictRESTServer(t, closed)
		_, _, resp := followREST(t, closedServer, strPtr("t1"))
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.StatusCode)
		}
	})
	if len(hub.subs) != 0 {
		t.Fatalf("%d subscriptions left behind by refused callers", len(hub.subs))
	}
}

func restRouterFor(opener verdict.StreamOpener) http.Handler {
	root := mux.NewRouter()
	restattestation.NewVerdictsRouter(opener, response.NewResponseWriter(discardLogger(), nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// TestVerdictStreamOverREST_DisconnectReleasesTheSubscription disconnects and
// requires the handler to return and the hub to forget the subscriber, so an
// abandoned stream leaks neither a goroutine nor a buffered channel.
func TestVerdictStreamOverREST_DisconnectReleasesTheSubscription(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	server, handlers := verdictRESTServer(t, hub)
	reader, cancel, _ := followREST(t, server, strPtr("t1"))

	hub.OnDeviceVerdict(context.Background(), recordedFor("t1", "mine"))
	nextEventID(t, reader)

	cancel()
	returned := make(chan struct{})
	go func() { handlers.Wait(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler did not return after the client disconnected")
	}
	hub.mu.Lock()
	left := len(hub.subs)
	hub.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d subscriptions left after the client disconnected", left)
	}
}

// TestVerdictStreamOverREST_ShutdownEndsTheStream closes the hub under an open
// stream: the client is told, and the handler returns.
func TestVerdictStreamOverREST_ShutdownEndsTheStream(t *testing.T) {
	hub := newDeviceVerdictHub()
	server, handlers := verdictRESTServer(t, hub)
	reader, _, _ := followREST(t, server, strPtr("t1"))

	hub.Close()
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "event: error") {
		t.Fatalf("line = %q, err = %v, want an error event", line, err)
	}
	handlers.Wait()
}
