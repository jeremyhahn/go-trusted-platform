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

package tpm_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

func newTPMServedRouter(server platformv1.TPMServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	tpm.NewTPMRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

// TestDeleteAK_RefusedWith412 drives the daemon's own TPMGRPCService through
// DELETE /api/v1/tpm/ak. DeleteAK names the IAK, which is not evicted, so the
// service refuses and the route answers as the IAK delete route does: 412
// carrying the typed error's message.
func TestDeleteAK_RefusedWith412(t *testing.T) {
	router := newTPMServedRouter(daemon.NewTPMGRPCService(logging.NewLogger(slog.LevelError, io.Discard)))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/ak", nil))

	require.Equal(t, http.StatusPreconditionFailed, rec.Code)
	var body restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, http.StatusPreconditionFailed, body.Code)
	assert.False(t, body.Success)
	assert.Equal(t, daemon.ErrDeviceIdentityKeyNotDeletable{Key: "IAK"}.Error(), body.Error)
}

// TestDeleteAK_OtherFailuresKeepTheSharedMapping pins the 412 to the refusal
// alone: any other error from the service takes protorest's shared mapping,
// here Unimplemented as 501.
func TestDeleteAK_OtherFailuresKeepTheSharedMapping(t *testing.T) {
	router := newTPMServedRouter(platformv1.UnimplementedTPMServiceServer{})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/ak", nil))

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}
