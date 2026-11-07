package rest

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerAPIRest_EmptyID(t *testing.T) {
	h := NewContainerHandlers(newMockOrchestrator(), slog.Default())

	handlers := map[string]http.HandlerFunc{
		"get":    h.handleGetContainer,
		"start":  h.handleStartContainer,
		"stop":   h.handleStopContainer,
		"remove": h.handleRemoveContainer,
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

func TestContainerAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := NewContainerHandlers(newMockOrchestrator(), slog.Default())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	require.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
