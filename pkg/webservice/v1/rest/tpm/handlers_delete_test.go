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

package tpm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer captures the request each delete handler forwards, so the
// tests can assert what actually reached the service layer rather than only
// that the call returned 200.
type recordingServer struct {
	platformv1.UnimplementedTPMServiceServer

	ek  *platformv1.DeleteEKRequest
	srk *platformv1.DeleteSRKRequest
	ak  *platformv1.DeleteAKRequest
}

func (s *recordingServer) DeleteEK(_ context.Context, req *platformv1.DeleteEKRequest) (*platformv1.DeleteEKResponse, error) {
	s.ek = req
	return &platformv1.DeleteEKResponse{}, nil
}

func (s *recordingServer) DeleteSRK(_ context.Context, req *platformv1.DeleteSRKRequest) (*platformv1.DeleteSRKResponse, error) {
	s.srk = req
	return &platformv1.DeleteSRKResponse{}, nil
}

func (s *recordingServer) DeleteAK(_ context.Context, req *platformv1.DeleteAKRequest) (*platformv1.DeleteAKResponse, error) {
	s.ak = req
	return &platformv1.DeleteAKResponse{}, nil
}

func newRecordingRouter() (*recordingServer, *mux.Router) {
	srv := &recordingServer{}
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewTPMRouter(logging.NewLogger(slog.LevelError, io.Discard), srv, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return srv, parent
}

func do(t *testing.T, parent *mux.Router, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodDelete, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	return rec
}

// The defect: handle, algorithm and password are declared on all three delete
// messages in tpm.proto and were dropped by the REST handlers, so they worked
// over gRPC and silently did nothing over REST (#267).
const fullBody = `{"handle":2148073473,"algorithm":"KEY_ALGORITHM_ED25519","password":"s3cret"}`

func TestDeleteEK_ForwardsHandleAlgorithmAndPassword(t *testing.T) {
	srv, parent := newRecordingRouter()

	rec := do(t, parent, "/api/v1/tpm/ek", fullBody)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, srv.ek)
	assert.Equal(t, uint32(2148073473), srv.ek.GetHandle())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, srv.ek.GetAlgorithm())
	// The security-relevant one: key auth was silently discarded before.
	assert.Equal(t, "s3cret", srv.ek.GetPassword())
}

func TestDeleteSRK_ForwardsHandleAlgorithmAndPassword(t *testing.T) {
	srv, parent := newRecordingRouter()

	rec := do(t, parent, "/api/v1/tpm/srk", fullBody)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, srv.srk)
	assert.Equal(t, uint32(2148073473), srv.srk.GetHandle())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, srv.srk.GetAlgorithm())
	assert.Equal(t, "s3cret", srv.srk.GetPassword())
}

func TestDeleteAK_ForwardsHandleAlgorithmAndPassword(t *testing.T) {
	srv, parent := newRecordingRouter()

	rec := do(t, parent, "/api/v1/tpm/ak", fullBody)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, srv.ak)
	assert.Equal(t, uint32(2148073473), srv.ak.GetHandle())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, srv.ak.GetAlgorithm())
	assert.Equal(t, "s3cret", srv.ak.GetPassword())
}

// Backwards compatibility: these routes accepted no body before this change,
// and every existing caller sends none. An absent body must still succeed with
// a zero-valued request rather than becoming a 400.
func TestDelete_EmptyBodyStillSucceedsWithZeroValues(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		got        func(*recordingServer) (uint32, string, bool)
	}{
		{"ek", "/api/v1/tpm/ek", func(s *recordingServer) (uint32, string, bool) {
			return s.ek.GetHandle(), s.ek.GetPassword(), s.ek != nil
		}},
		{"srk", "/api/v1/tpm/srk", func(s *recordingServer) (uint32, string, bool) {
			return s.srk.GetHandle(), s.srk.GetPassword(), s.srk != nil
		}},
		{"ak", "/api/v1/tpm/ak", func(s *recordingServer) (uint32, string, bool) {
			return s.ak.GetHandle(), s.ak.GetPassword(), s.ak != nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, parent := newRecordingRouter()

			rec := do(t, parent, tc.path, "")

			require.Equal(t, http.StatusOK, rec.Code)
			handle, password, reached := tc.got(srv)
			assert.True(t, reached, "the handler must still call the service")
			assert.Zero(t, handle)
			assert.Empty(t, password)
		})
	}
}

// A malformed body must be rejected rather than silently ignored, matching
// Seal's existing behaviour in this package.
func TestDelete_MalformedBodyIsRejected(t *testing.T) {
	for _, path := range []string{"/api/v1/tpm/ek", "/api/v1/tpm/srk", "/api/v1/tpm/ak"} {
		t.Run(path, func(t *testing.T) {
			srv, parent := newRecordingRouter()

			rec := do(t, parent, path, `{"handle": "not-a-number"`)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, srv.ek)
			assert.Nil(t, srv.srk)
			assert.Nil(t, srv.ak)
		})
	}
}
