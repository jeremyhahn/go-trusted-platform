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
// anonymous caller could force through the unauthenticated webhook.
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
func postPXEWebhook(t *testing.T, server *recordingPXEServer, enabled bool) int {
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
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

// TestPXEWebhook_DisabledIsNotServed pins #238: the webhook authenticates
// nobody, so unless the operator enabled it the path is unknown and the
// device cannot be moved by it.
func TestPXEWebhook_DisabledIsNotServed(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, false)

	assert.Equal(t, http.StatusNotFound, code)
	assert.Zero(t, server.calls, "a disabled webhook reached WebhookComplete")
	assert.Equal(t, pxeInstalling, server.state)
}

func TestPXEWebhook_EnabledReachesTheHandler(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, true)

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, 1, server.calls)
	assert.Equal(t, pxeInstalled, server.state)
}
