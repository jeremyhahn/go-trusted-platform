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
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// registryTokens maps a bearer token to the scopes its caller holds.
type registryTokens map[string][]string

func (s registryTokens) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	scopes, ok := s[token]
	if !ok {
		return nil, errors.New("unknown test token")
	}
	return &platformtoken.AuthorizedContext{Subject: token, Scopes: scopes}, nil
}

// statusOnlyRegistry answers Status; the other methods are not reached.
type statusOnlyRegistry struct {
	grpcapi.RegistryService
}

func (statusOnlyRegistry) Status(context.Context) (*grpcapi.RegistryStatusResponse, error) {
	return &grpcapi.RegistryStatusResponse{}, nil
}

// The daemon REST listener serves the registry image routes the SDK and
// the multi-protocol registry tests call, behind the gRPC registry
// scopes (#1690).
func TestDaemonREST_ServesRegistryImages(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	guard := restapi.NewScopeGuard(registryTokens{
		"reader":   {"registry:read"},
		"outsider": {"vm:read"},
	}, nil, nil)
	s.SetRegistryHandlers(statusOnlyRegistry{}, guard)

	get := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/images/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		return rec.Code
	}

	reader := get("reader")
	assert.NotEqual(t, http.StatusNotFound, reader, "the daemon mounts no /api/v1/compute/images/status")
	assert.Equal(t, http.StatusOK, reader)
	assert.Equal(t, http.StatusForbidden, get("outsider"), "a caller without registry:read reached the registry")
}
