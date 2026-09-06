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
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ClockState is the node's own clock trust state as the attestation surface
// reports it.
//
// It is deliberately a projection of the node's time-synchronization status
// rather than the whole thing: this route exists so a verifier can say
// whether the machine it just quoted can place itself in time, not so it can
// operate the machine's clock. The full surface, with sources and the step
// action, is the `ntp` feature's own (docs/ntp/api.md).
type ClockState struct {
	// Synced reports whether the node's time daemon currently disciplines
	// the clock. It is a pointer so that a node whose clock subsystem is
	// disabled or unreachable renders as absent, never as false — an
	// unknown clock is not a wrong clock.
	Synced *bool `json:"synced"`

	// Stratum is the node's distance from a reference clock; 0 means
	// unsynchronized.
	Stratum uint32 `json:"stratum"`

	// LeapStatus is the time daemon's leap indicator, which names the
	// unsynchronized state in the daemon's own words.
	LeapStatus string `json:"leap_status,omitempty"`

	// OffsetSeconds is the current system time offset.
	OffsetSeconds float64 `json:"offset_seconds"`

	// SourcesReachable and SourcesTotal say whether the node has anything
	// to synchronize against at all — the distinction between a broken
	// clock and an upstream that does not exist.
	SourcesReachable uint32 `json:"sources_reachable"`
	SourcesTotal     uint32 `json:"sources_total"`

	// Anomaly is set when a large correction was observed after
	// convergence, which on a trusted platform means a failing oscillator
	// or a hostile time source.
	Anomaly       bool   `json:"anomaly"`
	AnomalyReason string `json:"anomaly_reason,omitempty"`
}

// ClockReader reads this node's clock trust state.
//
// It is defined here, as the narrow thing the route needs, rather than
// imported from the NTP service: the attestation REST layer holds no clock
// and operates none. *ntp.Service satisfies it through the adapter in
// pkg/daemon/commands.
type ClockReader interface {
	// ClockState returns the node's clock trust state. An error means the
	// state could not be read.
	ClockState(ctx context.Context) (ClockState, error)
}

// ClockRouter serves the node's clock trust state to the attestation
// collector:
//
//	GET /api/v1/attestation/clock
//
// Mount it on the BARE router through the caller gate, exactly like the
// quote routes: its principal is the reporting server, which authenticates
// with an mTLS client certificate and holds no operator credential. An
// operator with the admin role reaches it through the same gate's operator
// path.
//
// Why it lives on the attestation surface rather than on the NTP one: the
// question it answers is "can the machine I just quoted place itself in
// time", and the answer is recorded beside the verdict (#509). The NTP
// feature's own routes carry the full status and the privileged Step
// mutation, and they take the operator gate — a collector cannot reach
// them, and widening them to machine callers would hand the fleet's clocks
// to a read-only principal.
type ClockRouter struct {
	clock      ClockReader
	respWriter response.HttpWriter
}

// NewClockRouter builds the router. A nil reader registers a route that
// answers 503, so an operator can tell "no clock subsystem on this node"
// from a typo in the path.
func NewClockRouter(clock ClockReader, respWriter response.HttpWriter) *ClockRouter {
	return &ClockRouter{clock: clock, respWriter: respWriter}
}

// RegisterRoutes mounts the route through the caller gate. operator is the
// operator authentication chain applied when no client certificate is
// presented.
func (r *ClockRouter) RegisterRoutes(parent *mux.Router, gate *CallerGate, operator func(http.Handler) http.Handler) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.Handle("/clock", gate.Wrap(http.HandlerFunc(r.getClock), operator)).Methods(http.MethodGet)
}

func (r *ClockRouter) getClock(w http.ResponseWriter, req *http.Request) {
	if r.clock == nil {
		r.writeUnavailable(w, req, ErrClockUnavailable{Reason: "no time-synchronization service is configured on this node"})
		return
	}
	state, err := r.clock.ClockState(req.Context())
	if err != nil {
		// A clock that cannot be read is reported as unreadable, never as
		// an unsynchronized clock: the collector distinguishes the two and
		// a synthesised `"synced": false` would make a network or socket
		// failure look like a wrong clock on the node.
		r.writeUnavailable(w, req, ErrClockUnavailable{Reason: err.Error()})
		return
	}
	r.respWriter.Success200(w, req, state)
}

func (r *ClockRouter) writeUnavailable(w http.ResponseWriter, req *http.Request, err error) {
	r.respWriter.Write(w, req, http.StatusServiceUnavailable, response.WebServiceResponse{
		Code: http.StatusServiceUnavailable, Error: err.Error(),
	})
}

// ErrClockUnavailable reports a node whose clock state could not be read.
type ErrClockUnavailable struct {
	Reason string
}

func (e ErrClockUnavailable) Error() string {
	return "attestation: node clock state is unavailable: " + e.Reason
}
