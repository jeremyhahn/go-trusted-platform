package rest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// failingResponseWriter records the status but fails every body write, as a
// connection the client already closed does.
type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

type responseWriteFaultError struct{}

func (responseWriteFaultError) Error() string { return "client connection closed" }

func (failingResponseWriter) Write([]byte) (int, error) { return 0, responseWriteFaultError{} }

// bufferLogger returns a logger whose records land in the returned buffer.
func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// unmarshalableMessage is a response protojson refuses to encode: a string
// field that is not valid UTF-8.
func unmarshalableMessage(t *testing.T) (*wrapperspb.StringValue, error) {
	t.Helper()
	msg := wrapperspb.String("\xff")
	_, err := webserviceMarshalOptions.Marshal(msg)
	require.Error(t, err)
	return msg, err
}

func TestVPNAPIRest_SetPosturePolicyMalformedBody(t *testing.T) {
	t.Parallel()
	server := &fakeVPNServer{}
	want := vpnUnmarshalOptions.Unmarshal([]byte("{"), &platformv1.VPNPosturePolicy{})
	require.Error(t, want)

	recorder := serveVPN(server, http.MethodPut, "/api/v1/vpn/posture-policies/corp", "{")

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&resp))
	assert.Equal(t, ErrVPNInvalidRequestBody{Cause: want}.Error(), resp.Error)
	assert.Nil(t, server.last, "a refused body must not reach the service")
}

func TestVPNAPIRest_RespondEncodeFailure(t *testing.T) {
	t.Parallel()
	logger, logs := bufferLogger()
	h := NewVPNHandlers(&fakeVPNServer{}, operatorGuard(), logger)
	msg, encodeErr := unmarshalableMessage(t)
	rec := httptest.NewRecorder()

	h.respond(rec, http.StatusOK, msg, nil)

	assert.Equal(t, http.StatusInternalServerError, rec.Code, "an unencodable response is not sent as a success")
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, encodeErr.Error(), resp.Error)
	assert.Contains(t, logs.String(), "Failed to encode VPN response")
}

func TestVPNAPIRest_WriteFailuresAreLogged(t *testing.T) {
	t.Parallel()

	t.Run("response", func(t *testing.T) {
		t.Parallel()
		logger, logs := bufferLogger()
		h := NewVPNHandlers(&fakeVPNServer{}, operatorGuard(), logger)
		w := failingResponseWriter{httptest.NewRecorder()}

		h.respond(w, http.StatusCreated, &platformv1.VPNPosturePolicy{Name: "corp"}, nil)

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Contains(t, logs.String(), "Failed to write VPN response")
		assert.Contains(t, logs.String(), responseWriteFaultError{}.Error())
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		logger, logs := bufferLogger()
		h := NewVPNHandlers(&fakeVPNServer{}, operatorGuard(), logger)
		w := failingResponseWriter{httptest.NewRecorder()}

		h.writeError(w, http.StatusConflict, ErrVPNUnavailable{})

		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, logs.String(), "Failed to write VPN error response")
		assert.Contains(t, logs.String(), responseWriteFaultError{}.Error())
	})
}
