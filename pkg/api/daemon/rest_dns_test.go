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

//go:build codec_msgpack

package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdns "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/dns"
)

func TestRESTServer_SetDNSService_NilAnswersNotConfigured(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)
	server.SetDNSService(nil, nil)

	for _, path := range []string{"/api/v1/dns/zones", "/api/v1/dns/zones/example.com./records"} {
		w := serveTPMRoute(server, http.MethodGet, path, "")

		require.Equal(t, http.StatusServiceUnavailable, w.Code, path)
		assert.Contains(t, w.Body.String(), "SERVICE_NOT_CONFIGURED", path)
	}
}

func TestRESTServer_SetDNSService_EveryRouteRequiresAScope(t *testing.T) {
	t.Parallel()
	logger := logging.DefaultLogger()
	router := restdns.NewDNSRouter(logger, NewMockDNSService(), response.NewResponseWriter(logger, nil))

	for _, route := range router.Routes() {
		assert.NotEmpty(t, grpcapi.ScopeForMethod(route.RPC), "%s %s", route.Method, route.Path)
	}
}

func TestRESTServer_SetDNSService_ServesAScopedToken(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"dns:read"})
	writer := key.sign(t, "operator", "", []string{"dns:write"})
	deleter := key.sign(t, "operator", "", []string{"dns:delete"})

	svc := NewMockDNSService()
	svc.ZoneFunc = func(_ context.Context, zoneName string) (*entities.Zone, error) {
		if zoneName == "missing.example." {
			return nil, ErrDNSServiceNotAvailable{}
		}
		return &entities.Zone{Name: zoneName, TTL: 3600}, nil
	}
	server := newTPMTestRESTServer(t)
	server.SetDNSService(svc, restapi.NewScopeGuard(validator, nil, slog.Default()))

	t.Run("a dns:read token lists the zones", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/dns/zones", reader)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "internal.example.com.")
	})

	t.Run("a dns:read token reads one zone", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/dns/zones/example.org.", reader)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "example.org.")
	})

	t.Run("an unknown zone is not found", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/dns/zones/missing.example.", reader)

		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a dns:write token creates a zone", func(t *testing.T) {
		w := serveTPMBody(server, http.MethodPost, "/api/v1/dns/zones", writer, `{"name":"new.example.","ttl":300}`)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, svc.SavedZone)
		assert.Equal(t, "new.example.", svc.SavedZone.Name)
	})

	t.Run("a zone without a name is invalid", func(t *testing.T) {
		w := serveTPMBody(server, http.MethodPost, "/api/v1/dns/zones", writer, `{"ttl":300}`)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})

	t.Run("a dns:delete token deletes a zone", func(t *testing.T) {
		before := svc.CallCount("DeleteZone") + svc.CallCount("Delete")
		w := serveTPMRoute(server, http.MethodDelete, "/api/v1/dns/zones/example.org.", deleter)

		require.Less(t, w.Code, http.StatusBadRequest, w.Body.String())
		assert.Greater(t, svc.CallCount("DeleteZone")+svc.CallCount("Delete"), before)
	})

	t.Run("a dns:read token cannot create a zone", func(t *testing.T) {
		w := serveTPMBody(server, http.MethodPost, "/api/v1/dns/zones", reader, `{"name":"denied.example."}`)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("a dns:write token cannot delete a zone", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodDelete, "/api/v1/dns/zones/example.org.", writer).Code)
	})

	t.Run("no token is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, serveTPMRoute(server, http.MethodGet, "/api/v1/dns/zones", "").Code)
	})
}
