package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// initBodyFault is a request body whose every read fails.
type initBodyFault struct{}

type initBodyFaultError struct{}

func (initBodyFaultError) Error() string { return "connection reset while reading body" }

func (initBodyFault) Read([]byte) (int, error) { return 0, initBodyFaultError{} }

func (initBodyFault) Close() error { return nil }

// initErrorMessage decodes the {"error": ...} body an init handler wrote.
func initErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	return body["error"]
}

// A service that reports success without a response still answers with the
// platform state, never with an empty body.
func TestInitAPIRest_NilServiceResponse(t *testing.T) {
	t.Parallel()

	t.Run("init", func(t *testing.T) {
		t.Parallel()
		svc := &fakeInitService{}
		h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateUninitialized), Init: svc})
		rec := httptest.NewRecorder()

		h.Init(rec, httptest.NewRequest(http.MethodPost, "/init", strings.NewReader("{}")))

		require.Equal(t, http.StatusOK, rec.Code)
		var resp BarrierInitResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, PlatformStateUninitialized, resp.State)
		assert.Empty(t, resp.CeremonyID)
		assert.Equal(t, int32(1), svc.called.Load())
	})

	t.Run("unseal", func(t *testing.T) {
		t.Parallel()
		svc := &fakeUnsealService{}
		h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateSealed), Unseal: svc})
		rec := httptest.NewRecorder()

		h.Unseal(rec, httptest.NewRequest(http.MethodPost, "/unseal", strings.NewReader("{}")))

		require.Equal(t, http.StatusOK, rec.Code)
		var resp BarrierUnsealResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, PlatformStateSealed, resp.State)
		assert.Zero(t, resp.SharesProvided)
		assert.Equal(t, int32(1), svc.called.Load())
	})
}

func TestInitAPIRest_UnsealMethodNotAllowed(t *testing.T) {
	t.Parallel()
	svc := &fakeUnsealService{}
	h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateSealed), Unseal: svc})
	rec := httptest.NewRecorder()

	h.Unseal(rec, httptest.NewRequest(http.MethodGet, "/unseal", nil))

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "method not allowed", initErrorMessage(t, rec))
	assert.Zero(t, svc.called.Load(), "a refused method never reaches the unseal service")
}

// A gRPC code the table does not map is the server's fault, not the caller's.
func TestInitAPIRest_UnmappedServiceErrorIs500(t *testing.T) {
	t.Parallel()
	svcErr := status.Error(codes.DeadlineExceeded, "ceremony timed out")
	svc := &fakeInitService{err: svcErr}
	h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateUninitialized), Init: svc})
	rec := httptest.NewRecorder()

	h.Init(rec, httptest.NewRequest(http.MethodPost, "/init", strings.NewReader("{}")))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, svcErr.Error(), initErrorMessage(t, rec))
}

func TestInitAPIRest_DecodeBody(t *testing.T) {
	t.Parallel()

	refusals := []struct {
		name string
		body func() *http.Request
		want string
	}{
		{
			name: "unreadable body",
			body: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/init", nil)
				req.Body = initBodyFault{}
				return req
			},
			want: ErrInvalidRequestBody{Reason: initBodyFaultError{}.Error()}.Error(),
		},
		{
			name: "body over the limit",
			body: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/init", strings.NewReader(`{"x":1}`))
			},
			want: ErrInvalidRequestBody{Reason: "request body exceeds maximum size"}.Error(),
		},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeInitService{}
			h := NewInitHandlers(InitHandlersConfig{
				State:        newFakeStateProvider(PlatformStateUninitialized),
				Init:         svc,
				MaxBodyBytes: 4,
			})
			rec := httptest.NewRecorder()

			h.Init(rec, tc.body())

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want, initErrorMessage(t, rec))
			assert.Zero(t, svc.called.Load(), "a refused body never reaches the init service")
		})
	}

	accepted := []struct {
		name string
		body func() *http.Request
	}{
		{
			name: "no body",
			body: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/init", nil)
				req.Body = nil
				return req
			},
		},
		{
			name: "empty body",
			body: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/init", http.NoBody)
			},
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeInitService{resp: &BarrierInitResponse{CeremonyID: "c-1"}}
			h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateUninitialized), Init: svc})
			rec := httptest.NewRecorder()

			h.Init(rec, tc.body())

			assert.Equal(t, http.StatusOK, rec.Code)
			require.NotNil(t, svc.last, "an absent body is an empty request, not a refusal")
			assert.Equal(t, BarrierInitRequest{}, *svc.last)
		})
	}
}

func TestInitAPIRest_WriteInitJSONNilBody(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()

	writeInitJSON(rec, http.StatusAccepted, nil)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Empty(t, rec.Body.String())
}
