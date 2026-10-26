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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// wiredLDevIDService builds a fully-wired IDevIDGRPCService (proven IDevID +
// mock CA) that issues an LDevID certificate on the happy path. It reuses the
// mocks defined in idevid_ldevid_test.go.
func wiredLDevIDService(t *testing.T) *IDevIDGRPCService {
	t.Helper()
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))
	now := time.Now()
	svc.SetCAService(&ldevidMockCA{cert: ldevidTestCert(t, "device-01-ldevid", now, now.Add(90*24*time.Hour))})
	return svc
}

// -----------------------------------------------------------------------------
// REST
// -----------------------------------------------------------------------------

func TestREST_LDevIDCreate(t *testing.T) {
	t.Run("happy path delegates to shared service", func(t *testing.T) {
		s := &RESTServer{logger: slog.Default(), idevidService: wiredLDevIDService(t)}

		body, err := json.Marshal(&platformv1.CreateLDevIDRequest{
			Template: &platformv1.CSRTemplate{CommonName: "device-01-ldevid"},
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/idevid/ldevid", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.handleLDevIDCreate(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp platformv1.CreateLDevIDResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.NotEmpty(t, resp.GetCsrPem())
		assert.NotEmpty(t, resp.GetCertificatePem())
	})

	t.Run("nil service returns 503", func(t *testing.T) {
		s := &RESTServer{logger: slog.Default()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/idevid/ldevid", bytes.NewReader([]byte(`{}`)))
		w := httptest.NewRecorder()
		s.handleLDevIDCreate(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		s := &RESTServer{logger: slog.Default(), idevidService: wiredLDevIDService(t)}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/idevid/ldevid", bytes.NewReader([]byte(`{`)))
		w := httptest.NewRecorder()
		s.handleLDevIDCreate(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("no proven IDevID returns 409", func(t *testing.T) {
		svc := newLDevIDTestService(t)
		svc.SetTPM2Service(&ldevidMockTPM{idevidCert: nil, pks: &ldevidMockPKS{}})
		svc.SetCAService(&ldevidMockCA{})
		s := &RESTServer{logger: slog.Default(), idevidService: svc}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/idevid/ldevid", bytes.NewReader([]byte(`{}`)))
		w := httptest.NewRecorder()
		s.handleLDevIDCreate(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// -----------------------------------------------------------------------------
// QUIC
// -----------------------------------------------------------------------------

func TestQUIC_LDevIDCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path delegates and round-trips pb", func(t *testing.T) {
		h := newTestQUICServiceHandler(logging.DefaultLogger())
		h.SetIDevIDService(wiredLDevIDService(t))

		payload, err := quicwire.EncodePayload(&platformv1.CreateLDevIDRequest{
			Template: &platformv1.CSRTemplate{CommonName: "device-01-ldevid"},
		})
		require.NoError(t, err)

		resp := h.handleLDevIDCreate(ctx, payload)
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out platformv1.CreateLDevIDResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.True(t, out.GetStatus().GetSuccess())
		assert.NotEmpty(t, out.GetCertificatePem())
	})

	t.Run("nil service is unavailable", func(t *testing.T) {
		h := newTestQUICServiceHandler(logging.DefaultLogger())
		resp := h.handleLDevIDCreate(ctx, nil)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("no proven IDevID maps to failed precondition", func(t *testing.T) {
		svc := newLDevIDTestService(t)
		svc.SetTPM2Service(&ldevidMockTPM{idevidCert: nil, pks: &ldevidMockPKS{}})
		svc.SetCAService(&ldevidMockCA{})
		h := newTestQUICServiceHandler(logging.DefaultLogger())
		h.SetIDevIDService(svc)

		payload, err := quicwire.EncodePayload(&platformv1.CreateLDevIDRequest{})
		require.NoError(t, err)
		resp := h.handleLDevIDCreate(ctx, payload)
		assert.Equal(t, quicwire.StatusFailedPrecondition, resp.Status)
	})
}

// -----------------------------------------------------------------------------
// MCP
// -----------------------------------------------------------------------------

func TestMCP_LDevIDCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path delegates to shared service", func(t *testing.T) {
		p := &MCPServiceProvider{idevidService: wiredLDevIDService(t)}
		result, err := p.CreateLDevID(ctx, &mcp.CreateLDevIDMCPRequest{
			Algorithm: "ECDSA-P256",
			Template:  &mcp.LDevIDCSRTemplateMCP{CommonName: "device-01-ldevid"},
		})
		require.NoError(t, err)
		resp, ok := result.(*platformv1.CreateLDevIDResponse)
		require.True(t, ok)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.NotEmpty(t, resp.GetCertificatePem())
	})

	t.Run("nil service returns not configured", func(t *testing.T) {
		p := &MCPServiceProvider{}
		_, err := p.CreateLDevID(ctx, &mcp.CreateLDevIDMCPRequest{})
		require.Error(t, err)
		assert.IsType(t, ErrLDevIDServiceNotConfigured{}, err)
	})
}
