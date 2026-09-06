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

package attestation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

// The node clock route (#509): the collector asks the machine it is about to
// quote whether that machine can place itself in time, and the answer is
// recorded beside the verdict.

// stubClock answers a fixed state.
type stubClock struct {
	state ClockState
	err   error
	calls int
}

func (c *stubClock) ClockState(context.Context) (ClockState, error) {
	c.calls++
	return c.state, c.err
}

func syncedState(synced bool) ClockState {
	return ClockState{
		Synced:           &synced,
		Stratum:          3,
		LeapStatus:       "Normal",
		SourcesReachable: 1,
		SourcesTotal:     2,
	}
}

// mountClock builds the route the way the v1 router does: on the bare
// router, through the caller gate, with an operator chain behind it.
func mountClock(clock ClockReader, policy CallerPolicy) (*mux.Router, *int) {
	operatorHits := 0
	operator := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			operatorHits++
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	root := mux.NewRouter()
	gate := NewCallerGate(testLoggerFor(), policy, testWriter())
	NewClockRouter(clock, testWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter(), gate, operator)
	return root, &operatorHits
}

func clockRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/api/v1/attestation/clock", nil)
}

// TestClockRouter_AdmittedCollectorReadsTheState asserts the happy path: an
// admitted machine caller gets the node's clock state without an operator
// credential, which is the whole reason the route is on this gate.
func TestClockRouter_AdmittedCollectorReadsTheState(t *testing.T) {
	clock := &stubClock{state: syncedState(true)}
	policy := &stubPolicy{decision: calleradmission.Decision{
		Admitted: true, Identity: "cp.example.internal", Reason: calleradmission.ReasonAdmitted,
	}}
	router, operatorHits := mountClock(clock, policy)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, withClientCert(clockRequest()))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, true, payload["synced"])
	assert.Equal(t, float64(3), payload["stratum"])
	assert.Equal(t, "Normal", payload["leap_status"])
	assert.Equal(t, 1, clock.calls)
	assert.Equal(t, 0, *operatorHits, "an admitted machine caller never reaches the operator chain")
}

// TestClockRouter_ReportsAnUnsyncedNode asserts a node whose clock is not
// disciplined says so, rather than answering an error that the collector
// would record as unknown.
func TestClockRouter_ReportsAnUnsyncedNode(t *testing.T) {
	state := syncedState(false)
	state.LeapStatus = "Not synchronised"
	state.Stratum = 0
	state.SourcesReachable = 0
	clock := &stubClock{state: state}
	policy := &stubPolicy{decision: calleradmission.Decision{Admitted: true, Reason: calleradmission.ReasonAdmitted}}
	router, _ := mountClock(clock, policy)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, withClientCert(clockRequest()))

	require.Equal(t, http.StatusOK, w.Code)
	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, false, payload["synced"])
	assert.Equal(t, "Not synchronised", payload["leap_status"])
	assert.Equal(t, float64(0), payload["sources_reachable"])
}

// TestClockRouter_UnreadableClockIs503 is the distinction the whole design
// rests on: a clock that cannot be read must not answer `"synced": false`.
// The collector records a 503 as unknown and a false as a wrong clock, and a
// socket failure must never produce the second.
func TestClockRouter_UnreadableClockIs503(t *testing.T) {
	for name, clock := range map[string]ClockReader{
		"no time service on this node": nil,
		"control socket unreadable":    &stubClock{err: errors.New("dial /run/chrony/chronyd.sock: no such file")},
	} {
		t.Run(name, func(t *testing.T) {
			policy := &stubPolicy{decision: calleradmission.Decision{Admitted: true, Reason: calleradmission.ReasonAdmitted}}
			router, _ := mountClock(clock, policy)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, withClientCert(clockRequest()))

			require.Equal(t, http.StatusServiceUnavailable, w.Code)
			assert.NotContains(t, w.Body.String(), `"synced"`,
				"an unreadable clock must not be rendered as an unsynchronized one")
		})
	}
}

// TestClockRouter_RefusedMachineCallerGetsNoState asserts the gate applies:
// a peer the node's admission policy refuses reads nothing, and is not
// offered the operator path as a second chance.
func TestClockRouter_RefusedMachineCallerGetsNoState(t *testing.T) {
	clock := &stubClock{state: syncedState(true)}
	policy := &stubPolicy{decision: calleradmission.Decision{
		Admitted: false, Identity: "stranger", Reason: calleradmission.ReasonNotListed,
	}}
	router, operatorHits := mountClock(clock, policy)

	req := withClientCert(clockRequest())
	req.Header.Set("Authorization", "Bearer operator")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, 0, clock.calls, "a refused caller must not reach the clock")
	assert.Equal(t, 0, *operatorHits)
}

// TestClockRouter_NoCertificateTakesTheOperatorChain asserts an operator
// reaches the route the same way they reach the quote routes.
func TestClockRouter_NoCertificateTakesTheOperatorChain(t *testing.T) {
	clock := &stubClock{state: syncedState(true)}
	policy := &stubPolicy{}
	router, operatorHits := mountClock(clock, policy)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, clockRequest())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 0, clock.calls, "an unauthenticated caller reads no state")

	req := clockRequest()
	req.Header.Set("Authorization", "Bearer operator")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, clock.calls)
	assert.Equal(t, 2, *operatorHits)
}

// TestClockRouter_OnlyGET asserts the route is read-only. The privileged
// clock verbs live on the operator-gated NTP surface, and a machine caller
// must not reach one through this door.
func TestClockRouter_OnlyGET(t *testing.T) {
	clock := &stubClock{state: syncedState(true)}
	policy := &stubPolicy{decision: calleradmission.Decision{Admitted: true, Reason: calleradmission.ReasonAdmitted}}
	router, _ := mountClock(clock, policy)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, withClientCert(httptest.NewRequest(method, "/api/v1/attestation/clock", nil)))
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
	}
	assert.Equal(t, 0, clock.calls)
}

// TestErrClockUnavailable_Message asserts the error names the cause.
func TestErrClockUnavailable_Message(t *testing.T) {
	err := ErrClockUnavailable{Reason: "socket closed"}
	assert.Contains(t, err.Error(), "socket closed")
	assert.Contains(t, err.Error(), "clock state is unavailable")
}
