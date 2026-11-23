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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// pushRecordingRegistry records whether a push reached the service.
type pushRecordingRegistry struct {
	grpcapi.RegistryService
	pushed bool
}

func (p *pushRecordingRegistry) PushStream(context.Context, *grpcapi.RegistryPushMetadata, io.Reader) (*grpcapi.RegistryPushResponse, error) {
	p.pushed = true
	return &grpcapi.RegistryPushResponse{}, nil
}

// The image push route on the daemon listener bounds its body: a
// registry:write caller posting past the push cap gets 413 and the
// registry never sees the upload (#1690, Codex round 6).
func TestDaemonREST_RegistryPushRefusesOversizedBody(t *testing.T) {
	const limit = 1024
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	s.registryMaxPushBytes = limit
	reg := &pushRecordingRegistry{}
	guard := restapi.NewScopeGuard(registryTokens{"writer": {"registry:write"}}, nil, nil)
	s.SetRegistryHandlers(reg, guard)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/images", strings.NewReader(strings.Repeat("x", limit+1)))
	req.Header.Set("Authorization", "Bearer writer")
	req.Header.Set("X-Trusted-Platform-Repository", "library/alpine")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
	assert.False(t, reg.pushed, "the registry received an oversized push")
}
