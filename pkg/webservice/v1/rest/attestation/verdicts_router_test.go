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

package attestation

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
)

// fakeVerdictOpener hands out one scripted subscription and records who asked.
type fakeVerdictOpener struct {
	err          error
	principal    verdict.StreamPrincipal
	subscription *fakeVerdictSubscription
}

func (o *fakeVerdictOpener) OpenVerdictStream(p verdict.StreamPrincipal) (verdict.StreamSubscription, error) {
	o.principal = p
	if o.err != nil {
		return nil, o.err
	}
	return o.subscription, nil
}

// fakeVerdictSubscription sends its verdicts, beats once when asked to, then
// returns end (or waits for the client to go away when end is nil).
type fakeVerdictSubscription struct {
	verdicts []verdict.RecordedDeviceVerdict
	beat     bool
	end      error
	closed   chan struct{}
}

func newFakeSubscription(end error, verdicts ...verdict.RecordedDeviceVerdict) *fakeVerdictSubscription {
	return &fakeVerdictSubscription{verdicts: verdicts, end: end, closed: make(chan struct{})}
}

func (s *fakeVerdictSubscription) Serve(ctx context.Context, send func(verdict.RecordedDeviceVerdict) error, hb verdict.StreamHeartbeat) error {
	if s.beat {
		if err := hb.Beat(); err != nil {
			return err
		}
	}
	for _, v := range s.verdicts {
		if err := send(v); err != nil {
			return err
		}
	}
	if s.end != nil {
		return s.end
	}
	<-ctx.Done()
	return ctx.Err()
}

func (s *fakeVerdictSubscription) Close() { close(s.closed) }

func verdictFor(tenant, event string) verdict.RecordedDeviceVerdict {
	return verdict.RecordedDeviceVerdict{EventID: event, Verdict: verdict.DeviceVerdict{DeviceID: 7, TenantID: tenant, Reason: "bad quote"}}
}

// mountVerdicts mounts the router behind a stand-in for the authentication
// chain that publishes a session of tenantID, or none when it is empty.
func mountVerdicts(opener verdict.StreamOpener, tenantID string) http.Handler {
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	api.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tenantID != "" {
				session := iammw.NewIAMSession(&iamsdk.User{ID: "1", TenantID: tenantID})
				r = r.WithContext(iammw.SetSessionInContext(r.Context(), session))
			}
			next.ServeHTTP(w, r)
		})
	})
	router := NewVerdictsRouter(opener, testWriter())
	router.heartbeat = time.Millisecond
	router.RegisterRoutes(api)
	return root
}

func TestVerdictsRouter_NilOpenerAnswers503(t *testing.T) {
	w := httptest.NewRecorder()
	mountVerdicts(nil, "t1").ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts/stream", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestVerdictsRouter_OpenFailuresMapToStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"forbidden", verdict.ErrStreamForbidden{Reason: "no tenant"}, http.StatusForbidden},
		{"unavailable", verdict.ErrStreamUnavailable{}, http.StatusServiceUnavailable},
		{"closed", verdict.ErrStreamClosed{}, http.StatusServiceUnavailable},
		{"unknown", assert.AnError, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mountVerdicts(&fakeVerdictOpener{err: tt.err}, "t1").ServeHTTP(w,
				httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts/stream", nil))
			assert.Equal(t, tt.want, w.Code, w.Body.String())
			assert.NotContains(t, w.Header().Get("Content-Type"), "text/event-stream",
				"a refusal must not start the event stream")
		})
	}
}

func TestVerdictsRouter_TellsTheStreamServiceWhoIsCalling(t *testing.T) {
	cert := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	tests := []struct {
		name     string
		tenantID string
		tls      *tls.ConnectionState
		want     verdict.StreamPrincipal
	}{
		{"session tenant", "t1", nil, verdict.StreamPrincipal{TenantID: "t1"}},
		{"certificate and no session", "", cert, verdict.StreamPrincipal{HasCertificate: true}},
		{"no credential", "", nil, verdict.StreamPrincipal{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opener := &fakeVerdictOpener{err: verdict.ErrStreamForbidden{Reason: "inspect only"}}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts/stream", nil)
			req.TLS = tt.tls
			mountVerdicts(opener, tt.tenantID).ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, tt.want, opener.principal)
			assert.False(t, opener.principal.UnixPeer, "REST has no Unix peer-credential caller")
		})
	}
}

func readSSELine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	return strings.TrimRight(line, "\n")
}

// TestVerdictsRouter_StreamsVerdictsAndReleasesOnDisconnect follows over a real
// connection, reads a verdict, and disconnects: the subscription is closed.
func TestVerdictsRouter_StreamsVerdictsAndReleasesOnDisconnect(t *testing.T) {
	sub := newFakeSubscription(nil, verdictFor("t1", "ev-1"))
	server := httptest.NewServer(mountVerdicts(&fakeVerdictOpener{subscription: sub}, "t1"))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/attestation/verdicts/stream", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	reader := bufio.NewReader(resp.Body)
	assert.Equal(t, ": subscribed", readSSELine(t, reader))
	readSSELine(t, reader)
	assert.Equal(t, "id: ev-1", readSSELine(t, reader))
	assert.Equal(t, "event: verdict", readSSELine(t, reader))
	data := readSSELine(t, reader)
	assert.True(t, strings.HasPrefix(data, "data: {"), data)
	assert.Contains(t, data, `"tenantId":"t1"`)
	assert.Contains(t, data, `"reason":"bad quote"`)

	cancel()
	select {
	case <-sub.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription was not closed after the client disconnected")
	}
}

func TestVerdictsRouter_SendsHeartbeatWhileIdle(t *testing.T) {
	sub := newFakeSubscription(verdict.ErrStreamClosed{})
	sub.beat = true
	w := httptest.NewRecorder()
	mountVerdicts(&fakeVerdictOpener{subscription: sub}, "t1").ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts/stream", nil))
	assert.Contains(t, w.Body.String(), ": heartbeat\n\n")
}

// TestVerdictsRouter_AnnouncesAnEndTheClientMustFollowAgain covers the two
// ways the service ends a healthy stream: shutdown and a subscriber that fell
// behind.
func TestVerdictsRouter_AnnouncesAnEndTheClientMustFollowAgain(t *testing.T) {
	for _, end := range []error{verdict.ErrStreamClosed{}, verdict.ErrSubscriberBehind{}} {
		sub := newFakeSubscription(end)
		w := httptest.NewRecorder()
		mountVerdicts(&fakeVerdictOpener{subscription: sub}, "t1").ServeHTTP(w,
			httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts/stream", nil))
		assert.Contains(t, w.Body.String(), "event: error\n", end.Error())
		select {
		case <-sub.closed:
		default:
			t.Errorf("%v: the subscription was left open", end)
		}
	}
}
