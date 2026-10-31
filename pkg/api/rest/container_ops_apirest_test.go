package rest

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

// opsMockOrchestrator adds the ContainerOpsOrchestrator capability to the
// package's base container orchestrator mock.
type opsMockOrchestrator struct {
	*mockOrchestrator

	execResult *container.ExecResult
	execErr    error
	execOpts   container.ExecOptions
	execID     string

	stats      *container.ContainerStats
	metricsErr error

	session   *fakeAttachSession
	attachErr error
}

func (m *opsMockOrchestrator) Exec(_ context.Context, id string, opts container.ExecOptions) (*container.ExecResult, error) {
	m.execID = id
	m.execOpts = opts
	if m.execErr != nil {
		return nil, m.execErr
	}
	return m.execResult, nil
}

func (m *opsMockOrchestrator) Metrics(_ context.Context, _ string) (*container.ContainerStats, error) {
	if m.metricsErr != nil {
		return nil, m.metricsErr
	}
	return m.stats, nil
}

func (m *opsMockOrchestrator) Attach(_ context.Context, _ string, _ container.ExecOptions) (container.AttachSession, error) {
	if m.attachErr != nil {
		return nil, m.attachErr
	}
	return m.session, nil
}

// fakeAttachSession delivers a fixed channel of chunks and records Close.
type fakeAttachSession struct {
	output chan container.AttachChunk
	closed bool
}

func (s *fakeAttachSession) Output() <-chan container.AttachChunk { return s.output }
func (s *fakeAttachSession) Wait() (int, error)                   { return 0, nil }
func (s *fakeAttachSession) Close() error {
	s.closed = true
	return nil
}

// noFlushWriter is a ResponseWriter that cannot stream.
type noFlushWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *noFlushWriter) Header() http.Header         { return w.header }
func (w *noFlushWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *noFlushWriter) WriteHeader(status int)      { w.status = status }

func newOpsRouter(orch ContainerOrchestratorInterface) *mux.Router {
	h := NewContainerHandlers(orch, slog.Default())
	router := mux.NewRouter()
	h.RegisterOpsRoutes(router)
	return router
}

func serveOps(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var resp ErrorResponse
	decodeResponse(t, rec.Body, &resp)
	return resp
}

func TestHandleExecContainer_Success(t *testing.T) {
	orch := &opsMockOrchestrator{
		mockOrchestrator: newMockOrchestrator(),
		execResult:       &container.ExecResult{ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")},
	}
	router := newOpsRouter(orch)

	body := `{"command":["sh","-c","true"],"env":{"A":"1"},"working_dir":"/tmp","tty":true}`
	rec := serveOps(router, http.MethodPost, "/api/v1/containers/c1/exec", body)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp ExecContainerRESTResponse
	decodeResponse(t, rec.Body, &resp)
	assert.Equal(t, ExecContainerRESTResponse{ExitCode: 3, Stdout: "out", Stderr: "err"}, resp)
	assert.Equal(t, "c1", orch.execID)
	assert.Equal(t, []string{"sh", "-c", "true"}, orch.execOpts.Command)
	assert.Equal(t, []string{"A=1"}, orch.execOpts.Env)
	assert.Equal(t, "/tmp", orch.execOpts.WorkingDir)
	assert.True(t, orch.execOpts.TTY)
}

func TestHandleExecContainer_Errors(t *testing.T) {
	opsOrch := func(err error) *opsMockOrchestrator {
		return &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), execErr: err}
	}

	tests := []struct {
		name       string
		orch       ContainerOrchestratorInterface
		body       string
		wantStatus int
		wantErr    string
	}{
		{"no orchestrator", nil, `{"command":["ls"]}`, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{}.Error()},
		{"exec unsupported", newMockOrchestrator(), `{"command":["ls"]}`, http.StatusNotImplemented, "exec not supported"},
		{"malformed body", opsOrch(nil), `{`, http.StatusBadRequest, "invalid request body"},
		{"missing body", opsOrch(nil), ``, http.StatusBadRequest, "command is required"},
		{"empty command", opsOrch(nil), `{"command":[]}`, http.StatusBadRequest, "command is required"},
		{"container not found", opsOrch(container.ErrContainerNotFound), `{"command":["ls"]}`, http.StatusNotFound, "container operation exec failed"},
		{"container stopped", opsOrch(container.ErrContainerStopped), `{"command":["ls"]}`, http.StatusConflict, "container operation exec failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newOpsRouter(tt.orch)
			rec := serveOps(router, http.MethodPost, "/api/v1/containers/c1/exec", tt.body)
			require.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, decodeErrorResponse(t, rec).Error, tt.wantErr)
		})
	}
}

func TestHandleContainerMetrics_Success(t *testing.T) {
	stats := &container.ContainerStats{
		CPUUsagePercent:  12.5,
		MemoryUsedBytes:  1024,
		MemoryLimitBytes: 4096,
		DiskReadBytes:    10,
		DiskWriteBytes:   20,
		NetworkRxBytes:   30,
		NetworkTxBytes:   40,
		UptimeSeconds:    50,
	}
	orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), stats: stats}
	router := newOpsRouter(orch)

	rec := serveOps(router, http.MethodGet, "/api/v1/containers/c1/metrics", "")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerMetricsRESTResponse
	decodeResponse(t, rec.Body, &resp)
	assert.Equal(t, ContainerMetricsRESTResponse{
		CPUUsagePercent:  12.5,
		MemoryUsedBytes:  1024,
		MemoryLimitBytes: 4096,
		DiskReadBytes:    10,
		DiskWriteBytes:   20,
		NetworkRxBytes:   30,
		NetworkTxBytes:   40,
		UptimeSeconds:    50,
	}, resp)
}

func TestHandleContainerMetrics_Errors(t *testing.T) {
	tests := []struct {
		name       string
		orch       ContainerOrchestratorInterface
		wantStatus int
		wantErr    string
	}{
		{"no orchestrator", nil, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{}.Error()},
		{"metrics unsupported", newMockOrchestrator(), http.StatusNotImplemented, "metrics not supported"},
		{"container not found", &opsMockOrchestrator{
			mockOrchestrator: newMockOrchestrator(),
			metricsErr:       container.ErrContainerNotFound,
		}, http.StatusNotFound, "container operation metrics failed"},
		{"backend failure", &opsMockOrchestrator{
			mockOrchestrator: newMockOrchestrator(),
			metricsErr:       errors.New("cgroup read failed"),
		}, http.StatusInternalServerError, "cgroup read failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newOpsRouter(tt.orch)
			rec := serveOps(router, http.MethodGet, "/api/v1/containers/c1/metrics", "")
			require.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, decodeErrorResponse(t, rec).Error, tt.wantErr)
		})
	}
}

func TestHandleAttachContainer_StreamsUntilSessionEnds(t *testing.T) {
	session := &fakeAttachSession{output: make(chan container.AttachChunk, 2)}
	session.output <- container.AttachChunk{Stream: "console", Data: []byte("hello")}
	session.output <- container.AttachChunk{Stream: "console", Data: []byte("world")}
	close(session.output)
	orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), session: session}
	router := newOpsRouter(orch)

	rec := serveOps(router, http.MethodGet, "/api/v1/containers/c1/attach", "")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "data: hello\n\ndata: world\n\nevent: end\ndata: session ended\n\n", rec.Body.String())
	assert.True(t, session.closed, "attach session must be closed when the handler returns")
}

func TestHandleAttachContainer_StopsWhenTheClientIsGone(t *testing.T) {
	for name, chunks := range map[string][]string{
		"a data event":  {"hello"},
		"the end event": nil,
	} {
		t.Run(name, func(t *testing.T) {
			session := &fakeAttachSession{output: make(chan container.AttachChunk, len(chunks))}
			for _, c := range chunks {
				session.output <- container.AttachChunk{Stream: "console", Data: []byte(c)}
			}
			close(session.output)
			orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), session: session}
			router := newOpsRouter(orch)
			w := &goneClientWriter{header: http.Header{}}

			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/containers/c1/attach", nil))

			assert.Zero(t, w.flushes, "nothing is flushed after the first write fails")
		})
	}
}

func TestHandleAttachContainer_ClientDisconnect(t *testing.T) {
	session := &fakeAttachSession{output: make(chan container.AttachChunk)}
	orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), session: session}
	h := NewContainerHandlers(orch, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/c1/attach", nil).WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": "c1"})
	rec := httptest.NewRecorder()

	h.handleAttachContainer(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.True(t, session.closed)
}

func TestHandleAttachContainer_StreamingUnsupported(t *testing.T) {
	session := &fakeAttachSession{output: make(chan container.AttachChunk)}
	orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator(), session: session}
	h := NewContainerHandlers(orch, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/c1/attach", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "c1"})
	w := &noFlushWriter{header: http.Header{}}

	h.handleAttachContainer(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.status)
	assert.Contains(t, w.body.String(), "streaming not supported")
	assert.True(t, session.closed)
}

func TestHandleAttachContainer_Errors(t *testing.T) {
	tests := []struct {
		name       string
		orch       ContainerOrchestratorInterface
		wantStatus int
		wantErr    string
	}{
		{"no orchestrator", nil, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{}.Error()},
		{"attach unsupported", newMockOrchestrator(), http.StatusNotImplemented, "attach not supported"},
		{"container stopped", &opsMockOrchestrator{
			mockOrchestrator: newMockOrchestrator(),
			attachErr:        container.ErrContainerStopped,
		}, http.StatusConflict, "container operation attach failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newOpsRouter(tt.orch)
			rec := serveOps(router, http.MethodGet, "/api/v1/containers/c1/attach", "")
			require.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, decodeErrorResponse(t, rec).Error, tt.wantErr)
		})
	}
}

func TestContainerOpsHandlers_EmptyID(t *testing.T) {
	orch := &opsMockOrchestrator{mockOrchestrator: newMockOrchestrator()}
	h := NewContainerHandlers(orch, slog.Default())

	handlers := map[string]http.HandlerFunc{
		"exec":    h.handleExecContainer,
		"metrics": h.handleContainerMetrics,
		"attach":  h.handleAttachContainer,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": ""})
			rec := httptest.NewRecorder()
			handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrInvalidContainerID{}.Error(), decodeErrorResponse(t, rec).Error)
		})
	}
}
