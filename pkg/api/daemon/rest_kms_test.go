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
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restkms "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

func TestRESTServer_SetKMSHandlers_EveryRouteRequiresAScope(t *testing.T) {
	t.Parallel()
	logger := logging.DefaultLogger()
	router := restkms.NewKMSRouter(logger, nil, nil, nil, nil, response.NewResponseWriter(logger, nil))

	for _, route := range router.Routes() {
		assert.NotEmpty(t, grpcapi.ScopeForMethod(route.RPC), "%s %s", route.Method, route.Path)
	}
}

func TestRESTServer_SetKMSHandlers_NilGuardRefuses(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)
	server.SetKMSHandlers(KMSRESTClients{}, nil)

	w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", "")
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestRESTServer_SetKMSHandlers_GuardsByScope(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	listScope := grpcapi.ScopeForMethod("/quicbaas.kms.v1.KeyManagement/ListKeys")
	scoped := key.sign(t, "operator", "", []string{listScope})
	unscoped := key.sign(t, "operator", "", []string{"dns:read"})

	server := newTPMTestRESTServer(t)
	server.SetKMSHandlers(KMSRESTClients{}, restapi.NewScopeGuard(validator, nil, slog.Default()))

	t.Run("a token with the ListKeys scope reaches the handler", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", scoped)
		assert.NotEqual(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.NotEqual(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a token without it is refused", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", unscoped)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}
