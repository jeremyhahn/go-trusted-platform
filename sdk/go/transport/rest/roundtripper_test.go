package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// handlerTransport serves each request with an in-memory handler: no
// listener, no port.
type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, r)
	return recorder.Result(), nil
}

func TestNewWithRoundTripper_SendsThroughTheRoundTripper(t *testing.T) {
	var gotPath, gotAuth string
	rt := handlerTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})}

	a, err := NewWithRoundTripper("https://daemon.invalid/", rt, "tok")
	require.NoError(t, err)

	err = a.Connection().Invoke(context.Background(), "/platform.v1.PlatformIAMService/ListUsers",
		&platformv1.ListIAMUsersRequest{TenantId: "acme"}, &platformv1.ListIAMUsersResponse{})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/iam/tenants/acme/users", gotPath)
	assert.Equal(t, "Bearer tok", gotAuth)
}

func TestNewWithRoundTripper_RefusesMissingInputs(t *testing.T) {
	rt := handlerTransport{handler: http.NotFoundHandler()}

	_, err := NewWithRoundTripper("", rt, "")
	assert.ErrorIs(t, err, platform.ErrEmptyAddress)

	_, err = NewWithRoundTripper("https://daemon.invalid", nil, "")
	var nilRT ErrNilRoundTripper
	assert.True(t, errors.As(err, &nilRT), "got %v", err)
}
