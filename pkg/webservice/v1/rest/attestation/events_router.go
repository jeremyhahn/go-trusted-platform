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
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	attestationstore "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
)

// EventReader is the narrow surface the events router needs from the
// platform attestation store. Mirrors the store.Store ListEvents
// shape without taking the full Store interface (which would couple
// REST to a richer surface than it needs).
type EventReader interface {
	ListEvents(filter attestationstore.EventFilter) ([]*attestationstore.Event, error)
}

// EventsRouter wires /api/v1/attestation/events onto a store-backed
// EventReader. The WebUI's /attestation/eventlogs surface reads
// from here.
type EventsRouter struct {
	logger     *logging.Logger
	reader     EventReader
	respWriter response.HttpWriter
}

// NewEventsRouter constructs an events router. reader may be nil;
// the handler returns 503 in that case so callers can tell "no
// attestation service wired" apart from "no events recorded."
func NewEventsRouter(logger *logging.Logger, reader EventReader, respWriter response.HttpWriter) *EventsRouter {
	return &EventsRouter{logger: logger, reader: reader, respWriter: respWriter}
}

// RegisterRoutes mounts the events surface on the supplied parent
// router under /attestation/events.
//
//	GET /api/v1/attestation/events           - list events newest-first
//	GET /api/v1/attestation/events?host=X    - filter by host
//	GET /api/v1/attestation/events?kind=K    - filter by event kind
//	GET /api/v1/attestation/events?since=...&until=... - time range
//	GET /api/v1/attestation/events?limit=N   - cap response size
//
// A since or until that is not RFC 3339, or a limit that is not an integer,
// answers 400.
func (r *EventsRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/events", r.listEvents).Methods("GET")
}

func (r *EventsRouter) listEvents(w http.ResponseWriter, req *http.Request) {
	if r.reader == nil {
		r.respWriter.Error500(w, req, ErrAttestationEventsUnavailable{})
		return
	}
	filter, err := parseEventFilter(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	events, err := r.reader.ListEvents(filter)
	if err != nil {
		r.respWriter.Error500(w, req, err)
		return
	}
	r.respWriter.Success200(w, req, map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

// parseEventFilter reads the events query. A since, until or limit that does
// not parse is refused rather than dropped: dropping it would answer a
// bounded question with the unbounded event history.
func parseEventFilter(req *http.Request) (attestationstore.EventFilter, error) {
	q := req.URL.Query()
	filter := attestationstore.EventFilter{
		HostID:     q.Get("host"),
		ManifestID: q.Get("manifest"),
		Kind:       attestationstore.EventKind(q.Get("kind")),
	}
	var err error
	if filter.Since, err = queryTime(q, "since"); err != nil {
		return filter, err
	}
	if filter.Until, err = queryTime(q, "until"); err != nil {
		return filter, err
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return filter, &protorest.ErrInvalidQuery{Name: "limit", Value: v, Cause: err}
		}
		filter.Limit = n
	}
	return filter, nil
}

// queryTime parses an optional RFC 3339 query parameter; absent is the zero
// time.
func queryTime(q url.Values, name string) (time.Time, error) {
	v := q.Get(name)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, &protorest.ErrInvalidQuery{Name: name, Value: v, Cause: err}
	}
	return t, nil
}

// ErrAttestationEventsUnavailable signals that the events endpoint
// is reachable but no underlying reader is wired.
type ErrAttestationEventsUnavailable struct{}

func (ErrAttestationEventsUnavailable) Error() string {
	return "attestation: events surface not configured"
}
