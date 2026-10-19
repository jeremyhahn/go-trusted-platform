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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attestationstore "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
)

// recordingEventReader records the filter it was asked for and answers with
// the configured events or error.
type recordingEventReader struct {
	events []*attestationstore.Event
	err    error
	calls  int
	filter attestationstore.EventFilter
}

func (r *recordingEventReader) ListEvents(filter attestationstore.EventFilter) ([]*attestationstore.Event, error) {
	r.calls++
	r.filter = filter
	return r.events, r.err
}

// errEventStoreDown is the store failure the router must surface as a 500.
type errEventStoreDown struct{}

func (errEventStoreDown) Error() string { return "event store down" }

func mountEvents(reader EventReader) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	NewEventsRouter(logger, reader, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

func getEvents(t *testing.T, router http.Handler, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/events"+query, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestEventsRouter_ListPassesTheFilterAndRendersEvents(t *testing.T) {
	reader := &recordingEventReader{events: []*attestationstore.Event{
		{ID: "e-2", Kind: attestationstore.EventKindCallerRefused, HostID: "node-1"},
		{ID: "e-1", Kind: attestationstore.EventKindCallerRefused, HostID: "node-1"},
	}}
	rec := getEvents(t, mountEvents(reader),
		"?host=node-1&manifest=m-9&kind=caller_refused&since=2026-10-01T00:00:00Z&until=2026-10-02T12:30:00Z&limit=25")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, 1, reader.calls)
	assert.Equal(t, attestationstore.EventFilter{
		HostID:     "node-1",
		ManifestID: "m-9",
		Kind:       attestationstore.EventKindCallerRefused,
		Since:      time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Until:      time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC),
		Limit:      25,
	}, reader.filter)

	payload := decodeEnvelope(t, rec)["payload"].(map[string]any)
	assert.Equal(t, float64(2), payload["total"])
	events := payload["events"].([]any)
	require.Len(t, events, 2)
	assert.Equal(t, "e-2", events[0].(map[string]any)["id"])
	assert.Equal(t, "caller_refused", events[0].(map[string]any)["kind"])
}

func TestEventsRouter_NoQueryIsTheUnfilteredList(t *testing.T) {
	reader := &recordingEventReader{}
	rec := getEvents(t, mountEvents(reader), "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, attestationstore.EventFilter{}, reader.filter)
	assert.Equal(t, float64(0), decodeEnvelope(t, rec)["payload"].(map[string]any)["total"])
}

// A bound the router cannot parse is refused, never dropped: dropping it
// answered a bounded question with the whole event history.
func TestEventsRouter_MalformedBoundIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, query, param string
	}{
		{"since not RFC 3339", "?since=yesterday", "since"},
		{"until not RFC 3339", "?until=2026-10-02", "until"},
		{"limit not an integer", "?limit=ten", "limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &recordingEventReader{}
			rec := getEvents(t, mountEvents(reader), tc.query)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Zero(t, reader.calls, "the store is not read for a refused query")

			req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/events"+tc.query, nil)
			_, err := parseEventFilter(req)
			var invalid *protorest.ErrInvalidQuery
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, tc.param, invalid.Name)
		})
	}
}

func TestEventsRouter_StoreFailureIs500(t *testing.T) {
	reader := &recordingEventReader{err: errEventStoreDown{}}
	rec := getEvents(t, mountEvents(reader), "?host=node-1")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, 1, reader.calls)
}

func TestEventsRouter_NoReaderIs500NotConfigured(t *testing.T) {
	rec := getEvents(t, mountEvents(nil), "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), ErrAttestationEventsUnavailable{}.Error())
}
