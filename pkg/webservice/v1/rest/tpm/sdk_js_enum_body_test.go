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

// enumBodyServer records the decoded requests whose enums the JavaScript SDK
// sends (sdk/javascript/src/services/tpm-service.ts).
type enumBodyServer struct {
	platformv1.UnimplementedTPMServiceServer

	ek   *platformv1.CreateEKRequest
	seal *platformv1.SealRequest
}

func (s *enumBodyServer) CreateEK(_ context.Context, req *platformv1.CreateEKRequest) (*platformv1.CreateEKResponse, error) {
	s.ek = req
	return &platformv1.CreateEKResponse{}, nil
}

func (s *enumBodyServer) Seal(_ context.Context, req *platformv1.SealRequest) (*platformv1.SealResponse, error) {
	s.seal = req
	return &platformv1.SealResponse{}, nil
}

func newEnumBodyRouter() (*enumBodyServer, *mux.Router) {
	srv := &enumBodyServer{}
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	NewTPMRouter(logger, srv, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return srv, parent
}

func postJSON(router http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestCreateEK_JavaScriptSDKBody feeds the body createEK sends: the key
// algorithm must arrive as its full enum name.
func TestCreateEK_JavaScriptSDKBody(t *testing.T) {
	srv, router := newEnumBodyRouter()

	rec := postJSON(router, "/api/v1/tpm/ek",
		`{"attributes":{"cn":"ek","algorithm":"KEY_ALGORITHM_RSA_2048"},"persistent":true}`)

	assert.Equal(t, http.StatusCreated, rec.Code)
	require.NotNil(t, srv.ek)
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, srv.ek.GetAttributes().GetAlgorithm())
	assert.True(t, srv.ek.GetPersistent())
}

// TestSeal_JavaScriptSDKBody feeds the body seal sends: the PCR bank must
// arrive as its full enum name.
func TestSeal_JavaScriptSDKBody(t *testing.T) {
	srv, router := newEnumBodyRouter()

	rec := postJSON(router, "/api/v1/tpm/seal",
		`{"data":"ZGF0YQ==","cn":"secret","pcrIndices":[7],"pcrBank":"PCR_BANK_SHA256"}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, srv.seal)
	assert.Equal(t, platformv1.PCRBank_PCR_BANK_SHA256, srv.seal.GetPcrBank())
	assert.Equal(t, []uint32{7}, srv.seal.GetPcrIndices())
}

// TestSeal_ShortPCRBankIsLost pins why the SDK maps names: protojson discards
// the short bank the SDK used to send, so the seal is bound to no bank.
func TestSeal_ShortPCRBankIsLost(t *testing.T) {
	srv, router := newEnumBodyRouter()

	postJSON(router, "/api/v1/tpm/seal", `{"data":"ZGF0YQ==","cn":"secret","pcrBank":"SHA256"}`)

	require.NotNil(t, srv.seal)
	assert.Equal(t, platformv1.PCRBank_PCR_BANK_UNSPECIFIED, srv.seal.GetPcrBank())
}
