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

package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	pxeWebhookPath = "/api/v1/pxe/webhook/complete"
	pxeInstalling  = "installing"
	pxeInstalled   = "installed"
)

// recordingPXEServer holds one device mid-install. A completion that
// reaches it moves the device to installed, the state change an
// unauthenticated caller must not be able to force through the webhook.
type recordingPXEServer struct {
	platformv1.UnimplementedPXEServiceServer
	state string
	calls int
}

func (s *recordingPXEServer) WebhookComplete(
	_ context.Context,
	_ *platformv1.PXEWebhookCompleteRequest,
) (*platformv1.PXEWebhookCompleteResponse, error) {
	s.calls++
	s.state = pxeInstalled
	return &platformv1.PXEWebhookCompleteResponse{}, nil
}

// postPXEWebhook builds the web service router with the webhook switch set
// as given and posts one install completion to it, as a booting node would.
func postPXEWebhook(t *testing.T, server *recordingPXEServer, enabled bool, state *tls.ConnectionState) int {
	t.Helper()

	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{
		tokenHandler:      &anonymousAuth{},
		responseWriter:    respWriter,
		pxeService:        server,
		pxeWebhookEnabled: enabled,
	}
	root := mux.NewRouter()
	NewRouter(logger, nil, nil, nil, registry, respWriter).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	body := strings.NewReader(`{"mac_address":"52:54:00:12:34:56","success":true}`)
	req := httptest.NewRequest(http.MethodPost, pxeWebhookPath, body)
	req.Header.Set("Content-Type", "application/json")
	req.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

// nodeTLS is the connection of a node presenting its device certificate over
// mTLS, verified by the TLS stack.
func nodeTLS() *tls.ConnectionState {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "node"}}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}

// TestPXEWebhook_DisabledIsNotServed checks the webhook is off by default:
// unless the operator enabled it the path is unknown and the device cannot be
// moved by it, even by a node with a verified certificate.
func TestPXEWebhook_DisabledIsNotServed(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, false, nodeTLS())

	assert.Equal(t, http.StatusNotFound, code)
	assert.Zero(t, server.calls, "a disabled webhook reached WebhookComplete")
	assert.Equal(t, pxeInstalling, server.state)
}

func TestPXEWebhook_EnabledReachesTheHandler(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, true, nodeTLS())

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, 1, server.calls)
	assert.Equal(t, pxeInstalled, server.state)
}

// TestPXEWebhook_EnabledRefusesACallerWithNoCertificate checks the enabled
// webhook, as the v1 router mounts it, answers 401 to a caller presenting no
// client certificate and leaves the device where it was (#238).
func TestPXEWebhook_EnabledRefusesACallerWithNoCertificate(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, true, &tls.ConnectionState{})

	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Zero(t, server.calls, "a caller with no certificate reached WebhookComplete")
	assert.Equal(t, pxeInstalling, server.state)
}
