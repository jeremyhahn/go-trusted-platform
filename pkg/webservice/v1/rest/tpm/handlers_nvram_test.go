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

// nvServer records the NV requests the handlers forward.
type nvServer struct {
	platformv1.UnimplementedTPMServiceServer

	read  *platformv1.ReadNVRAMRequest
	write *platformv1.WriteNVRAMRequest
	undef *platformv1.UndefineNVRAMRequest
}

func (s *nvServer) ReadNVRAM(_ context.Context, req *platformv1.ReadNVRAMRequest) (*platformv1.ReadNVRAMResponse, error) {
	s.read = req
	return &platformv1.ReadNVRAMResponse{Data: []byte("nv")}, nil
}

func (s *nvServer) WriteNVRAM(_ context.Context, req *platformv1.WriteNVRAMRequest) (*platformv1.WriteNVRAMResponse, error) {
	s.write = req
	return &platformv1.WriteNVRAMResponse{}, nil
}

func (s *nvServer) UndefineNVRAM(_ context.Context, req *platformv1.UndefineNVRAMRequest) (*platformv1.UndefineNVRAMResponse, error) {
	s.undef = req
	return &platformv1.UndefineNVRAMResponse{}, nil
}

func newNVRouter() (*nvServer, *mux.Router) {
	srv := &nvServer{}
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewTPMRouter(logging.NewLogger(slog.LevelError, io.Discard), srv, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return srv, parent
}

func serveNV(parent *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	return rec
}

func TestReadNVRAM_PathIndexAndBodyFields(t *testing.T) {
	srv, parent := newNVRouter()

	// A body index is ignored: the path names the index.
	rec := serveNV(parent, http.MethodGet, "/api/v1/tpm/nvram/0x01c00002",
		`{"index": 1, "password": "pw", "offset": 4, "size": 16}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, srv.read)
	assert.Equal(t, uint32(0x01C00002), srv.read.GetIndex())
	assert.Equal(t, "pw", srv.read.GetPassword())
	assert.Equal(t, uint32(4), srv.read.GetOffset())
	assert.Equal(t, uint32(16), srv.read.GetSize())
	assert.Contains(t, rec.Body.String(), "bnY=") // base64("nv")
}

func TestReadNVRAM_EmptyBodyReadsTheWholeIndex(t *testing.T) {
	srv, parent := newNVRouter()

	rec := serveNV(parent, http.MethodGet, "/api/v1/tpm/nvram/29360130", "")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, uint32(0x01C00002), srv.read.GetIndex())
	assert.Zero(t, srv.read.GetSize())
}

func TestWriteNVRAM_PathIndexAndData(t *testing.T) {
	srv, parent := newNVRouter()

	rec := serveNV(parent, http.MethodPut, "/api/v1/tpm/nvram/0x01500000",
		`{"index": 1, "data": "cGF5bG9hZA==", "offset": 2, "password": "pw"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, srv.write)
	assert.Equal(t, uint32(0x01500000), srv.write.GetIndex())
	assert.Equal(t, []byte("payload"), srv.write.GetData())
	assert.Equal(t, uint32(2), srv.write.GetOffset())
	assert.Equal(t, "pw", srv.write.GetPassword())
}

func TestUndefineNVRAM_PathIndexAndPassword(t *testing.T) {
	srv, parent := newNVRouter()

	rec := serveNV(parent, http.MethodDelete, "/api/v1/tpm/nvram/0x01500000", `{"password": "pw"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, srv.undef)
	assert.Equal(t, uint32(0x01500000), srv.undef.GetIndex())
	assert.Equal(t, "pw", srv.undef.GetPassword())
}

func TestNVRAM_BadIndexIsRejected(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		for _, index := range []string{"nv-one", "0x1ffffffff", "-1"} {
			t.Run(method+"/"+index, func(t *testing.T) {
				srv, parent := newNVRouter()

				rec := serveNV(parent, method, "/api/v1/tpm/nvram/"+index, `{"data": "ZA=="}`)

				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Nil(t, srv.read)
				assert.Nil(t, srv.write)
				assert.Nil(t, srv.undef)
			})
		}
	}
}

func TestNVRAM_MalformedBodyIsRejected(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			srv, parent := newNVRouter()

			rec := serveNV(parent, method, "/api/v1/tpm/nvram/0x01500000", `{"size": "big"`)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, srv.read)
			assert.Nil(t, srv.write)
			assert.Nil(t, srv.undef)
		})
	}
}
