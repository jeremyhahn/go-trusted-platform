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

package daemon

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestRESTServer_SetPXEHandlers_NilMountsNothing(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)

	server.SetPXEHandlers(nil, nil)

	assert.Equal(t, http.StatusNotFound, serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", "").Code)
}

func TestRESTServer_SetPXEHandlers_ServesAScopedToken(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"pxe:read"})
	other := key.sign(t, "operator", "", []string{"vm:read"})

	server := newTPMTestRESTServer(t)
	pxeService := NewPXEGRPCService(logging.DefaultLogger(), newMockPXEService())
	server.SetPXEHandlers(pxeService, restapi.NewScopeGuard(validator, nil, slog.Default()))

	t.Run("a pxe:read token reads the status through the PXE service", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", reader)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `"status"`)
	})

	t.Run("a token without pxe:read is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", other).Code)
	})

	t.Run("no token is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", "").Code)
	})

	t.Run("the provisioning gateway's device reports are mounted behind the guard", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodPost, "/api/v1/provisioning/devices/aa:bb:cc:dd:ee:ff/state", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	})
}

// A servicer without a backend answers the same refusal on REST as on gRPC,
// QUIC and MCP: 503 SERVICE_NOT_CONFIGURED, not a missing route.
func TestRESTServer_SetPXEHandlers_UnconfiguredAnswersNotConfigured(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"pxe:read"})

	server := newTPMTestRESTServer(t)
	server.SetPXEHandlers(NewPXEGRPCService(logging.DefaultLogger(), nil), restapi.NewScopeGuard(validator, nil, slog.Default()))

	w := serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", reader)

	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "SERVICE_NOT_CONFIGURED")
}

func TestRESTServer_SetPXEHandlers_NilGuardDeniesEveryRoute(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)
	server.SetPXEHandlers(NewPXEGRPCService(logging.DefaultLogger(), newMockPXEService()), nil)

	assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodGet, "/api/v1/pxe/status", "").Code)
}
