package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// lifecycleStubCA records the CA lifecycle calls the daemon REST routes make.
type lifecycleStubCA struct {
	platformv1.UnimplementedCAServiceServer

	initCalls      int
	installCalls   int
	uninstallCalls int
}

func (s *lifecycleStubCA) InitCA(ctx context.Context, req *platformv1.InitCARequest) (*platformv1.InitCAResponse, error) {
	s.initCalls++
	return &platformv1.InitCAResponse{}, nil
}

func (s *lifecycleStubCA) InstallCACertificates(ctx context.Context, req *platformv1.InstallCACertificatesRequest) (*platformv1.InstallCACertificatesResponse, error) {
	s.installCalls++
	return &platformv1.InstallCACertificatesResponse{}, nil
}

func (s *lifecycleStubCA) UninstallCACertificates(ctx context.Context, req *platformv1.UninstallCACertificatesRequest) (*platformv1.UninstallCACertificatesResponse, error) {
	s.uninstallCalls++
	return &platformv1.UninstallCACertificatesResponse{}, nil
}

// TestRESTServer_CALifecycleRoutesServedWithoutALoadedCA: a node whose CA
// failed to load still serves POST /api/v1/ca/init and the trust routes, so
// the operator can initialise the CA over REST.
func TestRESTServer_CALifecycleRoutesServedWithoutALoadedCA(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	guard := restapi.NewScopeGuard(scopedTokenValidator{scopes: []string{"ca:create", "trust:write"}}, nil, nil)
	stub := &lifecycleStubCA{}
	server.SetCAHolder(NewCAHolder(nil), guard)
	server.SetCALifecycle(stub, guard)

	post := func(path, bearer string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("init without a credential is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, post("/api/v1/ca/init", ""))
		assert.Zero(t, stub.initCalls)
	})
	t.Run("init reaches the CA service", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, post("/api/v1/ca/init", "t"))
		assert.Equal(t, 1, stub.initCalls)
	})
	t.Run("trust install reaches the CA service", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, post("/api/v1/ca/trust/install", "t"))
		assert.Equal(t, 1, stub.installCalls)
	})
	t.Run("trust uninstall reaches the CA service", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, post("/api/v1/ca/trust/uninstall", "t"))
		assert.Equal(t, 1, stub.uninstallCalls)
	})
}
