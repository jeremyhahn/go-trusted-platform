//go:build integration

package vtpm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRESTAdapterPayload checks that the REST adapter decodes both the
// webservice envelope ({code, success, payload}) and the daemon's bare object.
func TestRESTAdapterPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/vtpm/bundles":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"code":201,"success":true,"payload":{"id":"b-1","mode":"ephemeral"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/vtpm/bundles/b-1":
			_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":{"id":"b-1","mode":"ephemeral"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/vtpm/bundles/b-2":
			_, _ = w.Write([]byte(`{"id":"b-2","mode":"ephemeral"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
	ctx := context.Background()

	created, err := a.CreateBundle(ctx, CreateBundleOptions{Hostname: "host-1"})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.Bundle)
	require.Equal(t, "b-1", created.Bundle.ID)

	enveloped, err := a.GetBundle(ctx, GetBundleOptions{ID: "b-1"})
	require.NoError(t, err)
	require.NotNil(t, enveloped)
	require.NotNil(t, enveloped.Bundle)
	require.Equal(t, "b-1", enveloped.Bundle.ID)

	bare, err := a.GetBundle(ctx, GetBundleOptions{ID: "b-2"})
	require.NoError(t, err)
	require.NotNil(t, bare)
	require.NotNil(t, bare.Bundle)
	require.Equal(t, "b-2", bare.Bundle.ID)
}
