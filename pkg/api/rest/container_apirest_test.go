package rest

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sentHeaderWriter is a ResponseWriter without http.Flusher that, like
// net/http, keeps only the first status and the headers as they were then.
type sentHeaderWriter struct {
	header      http.Header
	status      int
	contentType string
	body        bytes.Buffer
}

func (w *sentHeaderWriter) Header() http.Header { return w.header }

func (w *sentHeaderWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *sentHeaderWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.contentType = w.header.Get("Content-Type")
}

// closeTrackingReader records whether the handler closed the log stream.
type closeTrackingReader struct {
	*strings.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

func TestContainerAPIRest_EmptyID(t *testing.T) {
	h := NewContainerHandlers(newMockOrchestrator(), slog.Default())

	handlers := map[string]http.HandlerFunc{
		"get":    h.handleGetContainer,
		"start":  h.handleStartContainer,
		"stop":   h.handleStopContainer,
		"remove": h.handleRemoveContainer,
		"logs":   h.handleGetContainerLogs,
		"attest": h.handleAttestContainer,
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": ""})
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrInvalidContainerID{}.Error(), decodeErrorResponse(t, rec).Error)
		})
	}
}

// A writer that cannot flush must be refused with a 500 the client sees; the
// SSE 200 used to be sent first, so the refusal arrived as a successful
// event stream carrying a JSON error.
func TestContainerAPIRest_FollowLogsWithoutFlusher(t *testing.T) {
	orch := newStreamingMockOrchestrator()
	orch.addTestInstance("c1", "web", compute.StateRunning)
	logs := &closeTrackingReader{Reader: strings.NewReader("line 1\n")}
	orch.logsReader = logs
	h := NewContainerHandlers(orch, slog.Default())

	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/containers/c1/logs?follow=true", nil), map[string]string{"id": "c1"})
	w := &sentHeaderWriter{header: http.Header{}}

	h.handleGetContainerLogs(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.status)
	assert.Equal(t, "application/json", w.contentType, "the refusal is not sent as an event stream")
	want := ErrContainerOperationFailed{Operation: "logs", Cause: errors.New("streaming not supported")}.Error()
	assert.Contains(t, w.body.String(), want)
	assert.NotContains(t, w.body.String(), "line 1", "no log line is streamed")
	assert.True(t, logs.closed, "the log stream is released")
}

// goneClientWriter is an event-stream writer whose client has disconnected:
// every write fails, and flushes are counted.
type goneClientWriter struct {
	header  http.Header
	flushes int
}

func (w *goneClientWriter) Header() http.Header       { return w.header }
func (w *goneClientWriter) WriteHeader(int)           {}
func (w *goneClientWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }
func (w *goneClientWriter) Flush()                    { w.flushes++ }

func TestContainerAPIRest_FollowLogsStopsWhenTheClientIsGone(t *testing.T) {
	orch := newStreamingMockOrchestrator()
	orch.addTestInstance("c1", "web", compute.StateRunning)
	logs := &closeTrackingReader{Reader: strings.NewReader("line 1\n")}
	orch.logsReader = logs
	h := NewContainerHandlers(orch, slog.Default())

	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/containers/c1/logs?follow=true", nil), map[string]string{"id": "c1"})
	w := &goneClientWriter{header: http.Header{}}

	h.handleGetContainerLogs(w, req)

	assert.Zero(t, w.flushes, "nothing is flushed after the first write fails")
	assert.True(t, logs.closed, "the log stream is released")
}

func TestContainerAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := NewContainerHandlers(newMockOrchestrator(), slog.Default())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	require.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
