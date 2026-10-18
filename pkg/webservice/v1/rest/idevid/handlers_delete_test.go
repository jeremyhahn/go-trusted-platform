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

package idevid_test

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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/idevid"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

func newServedRouter(server platformv1.IDevIDServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	idevid.NewIDevIDRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

// TestKeyDelete_RefusedWith412OnEveryPath drives the daemon's own
// IDevIDGRPCService through every web-service key-delete path. The refusal
// comes from the service, and each path answers it as the daemon listener
// does (pkg/api/daemon/rest_idevid.go): 412 carrying the typed error's
// message, which the SDK's REST transport reads back as FailedPrecondition.
func TestKeyDelete_RefusedWith412OnEveryPath(t *testing.T) {
	router := newServedRouter(daemon.NewIDevIDGRPCService(logging.NewLogger(slog.LevelError, io.Discard)))

	cases := []struct {
		path string
		key  string
	}{
		{"/api/v1/idevid", "IDevID"},
		{"/api/v1/tpm/idevid", "IDevID"},
		{"/api/v1/idevid/iak", "IAK"},
		{"/api/v1/tpm/iak", "IAK"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, tc.path, nil))

			require.Equal(t, http.StatusPreconditionFailed, rec.Code)
			var body restwire.WebServiceResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, http.StatusPreconditionFailed, body.Code)
			assert.False(t, body.Success)
			assert.Equal(t, daemon.ErrDeviceIdentityKeyNotDeletable{Key: tc.key}.Error(), body.Error)
		})
	}
}

// TestKeyDelete_OtherFailuresKeepTheSharedMapping pins the 412 to the
// refusal alone: any other error from the service is answered by protorest's
// shared mapping, here Unimplemented as 501.
func TestKeyDelete_OtherFailuresKeepTheSharedMapping(t *testing.T) {
	router := newServedRouter(platformv1.UnimplementedIDevIDServiceServer{})

	for _, path := range []string{"/api/v1/tpm/idevid", "/api/v1/tpm/iak"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
			assert.Equal(t, http.StatusNotImplemented, rec.Code)
		})
	}
}

// TestKeyDelete_NilServerIsUnavailable checks the new paths take the same
// availability guard as their neighbours.
func TestKeyDelete_NilServerIsUnavailable(t *testing.T) {
	router := newServedRouter(nil)

	for _, path := range []string{"/api/v1/tpm/idevid", "/api/v1/tpm/iak"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}
