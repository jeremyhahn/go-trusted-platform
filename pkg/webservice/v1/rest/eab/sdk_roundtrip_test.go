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

package eab

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// recordingEABServer is the EAB service behind the router. It records the
// request each handler hands it, so a test can see which operation a REST call
// reached and with which credential id.
type recordingEABServer struct {
	platformv1.UnimplementedEABServiceServer
	calls []string
	get   *platformv1.GetEABCredentialRequest
	rev   *platformv1.RevokeEABCredentialRequest
}

func (s *recordingEABServer) GetCredential(
	_ context.Context, req *platformv1.GetEABCredentialRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	s.calls = append(s.calls, "GetCredential")
	s.get = req
	return &platformv1.GetEABCredentialResponse{
		Credential: &platformv1.EABCredential{Id: req.GetCredentialId(), KeyId: "kid-1"},
	}, nil
}

func (s *recordingEABServer) RevokeCredential(
	_ context.Context, req *platformv1.RevokeEABCredentialRequest,
) (*platformv1.RevokeEABCredentialResponse, error) {
	s.calls = append(s.calls, "RevokeCredential")
	s.rev = req
	return &platformv1.RevokeEABCredentialResponse{}, nil
}

// sdkAgainstEABRouter serves the real EAB router over TLS and connects the Go
// SDK's REST transport to it, so a call travels the SDK's route table, the
// wire and the server's router before it reaches the service.
func sdkAgainstEABRouter(t *testing.T) (*sdkrest.Adapter, *recordingEABServer, *httptest.Server) {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := &recordingEABServer{}

	parent := mux.NewRouter()
	parent.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewEABRouter(logger, svc, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(parent)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	a, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, a.Close()) })

	return a.(*sdkrest.Adapter), svc, server
}

func TestEABSDKRoundTrip_GetCredentialReachesItsHandlerByPath(t *testing.T) {
	a, svc, _ := sdkAgainstEABRouter(t)

	resp := &platformv1.GetEABCredentialResponse{}
	err := a.Connection().Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 42}, resp)
	require.NoError(t, err)

	assert.Equal(t, []string{"GetCredential"}, svc.calls)
	require.NotNil(t, svc.get)
	assert.Equal(t, uint64(42), svc.get.GetCredentialId(), "the id the handler parsed from the path")
	assert.Equal(t, uint64(42), resp.GetCredential().GetId())
	assert.Equal(t, "kid-1", resp.GetCredential().GetKeyId())
}

func TestEABSDKRoundTrip_RevokeCredentialReachesItsHandlerByPath(t *testing.T) {
	a, svc, _ := sdkAgainstEABRouter(t)

	err := a.Connection().Invoke(context.Background(), "/platform.v1.EABService/RevokeCredential",
		&platformv1.RevokeEABCredentialRequest{CredentialId: 7, RevokerId: 99},
		&platformv1.RevokeEABCredentialResponse{})
	require.NoError(t, err)

	assert.Equal(t, []string{"RevokeCredential"}, svc.calls)
	require.NotNil(t, svc.rev)
	// The handler overwrites credential_id with the path's id, so 7 here
	// proves the id travelled in the path; revoker_id is the body's.
	assert.Equal(t, uint64(7), svc.rev.GetCredentialId())
	assert.Equal(t, uint64(99), svc.rev.GetRevokerId())
}

func TestEABSDKRoundTrip_NonNumericIDIsRefused(t *testing.T) {
	_, svc, server := sdkAgainstEABRouter(t)

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/eab/credentials/abc"},
		{http.MethodDelete, "/api/v1/eab/credentials/abc"},
		{http.MethodPost, "/api/v1/eab/credentials/abc/revoke"},
		{http.MethodPost, "/api/v1/eab/credentials/-1/used"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tc.method, server.URL+tc.path, nil)
			require.NoError(t, err)
			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
	assert.Empty(t, svc.calls, "a non-numeric id must not reach any handler")
}
