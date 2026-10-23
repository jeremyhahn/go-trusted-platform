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
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// namedTenantServer resolves the tenant names it holds, and answers NotFound
// for any other, the way TenantGRPCServer does.
type namedTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
	ids map[string]string // tenant name -> tenant id
}

func (s *namedTenantServer) GetTenantByName(
	_ context.Context, req *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {

	id, ok := s.ids[req.GetName()]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return &platformv1.GetTenantByNameResponse{
		Tenant: &platformv1.Tenant{Id: id, Name: req.GetName()},
	}, nil
}

// lookUpTenantByName sends GET /api/v1/tenants/by-name/{name} as an admin of
// callerTenant through the full v1 router: the session middleware, the admin
// gate and the by-name guard, as the daemon mounts them.
func lookUpTenantByName(t *testing.T, callerTenant, name string) *httptest.ResponseRecorder {
	t.Helper()
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: callerTenant},
		tenantService: &namedTenantServer{ids: map[string]string{
			"acme":   "tenant-a",
			"globex": "tenant-b",
		}},
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/by-name/"+name, nil))
	return rec
}

// TestTenantRoutes_ByNameResolvesOwnTenantOnly is the REST half of #304: the
// lookup by name applies the rule gRPC, QUIC, MCP and Unix apply, to the
// session's tenant claim.
func TestTenantRoutes_ByNameResolvesOwnTenantOnly(t *testing.T) {
	t.Run("a tenant resolves its own name", func(t *testing.T) {
		rec := lookUpTenantByName(t, "tenant-a", "acme")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "tenant-a")
	})

	t.Run("another tenant's name and an unknown name are refused alike", func(t *testing.T) {
		foreign := lookUpTenantByName(t, "tenant-a", "globex")
		unknown := lookUpTenantByName(t, "tenant-a", "no-such-tenant")

		assert.Equal(t, http.StatusForbidden, foreign.Code)
		assert.Equal(t, foreign.Code, unknown.Code)
		assert.Equal(t, foreign.Body.String(), unknown.Body.String(),
			"the answer must not say whether the name exists")
		assert.Contains(t, foreign.Body.String(), tenant.ErrNameLookupDenied{}.Error())
		assert.NotContains(t, foreign.Body.String(), "tenant-b")
	})

	t.Run("the system tenant resolves another tenant's name", func(t *testing.T) {
		rec := lookUpTenantByName(t, "system", "globex")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "tenant-b")
	})

	t.Run("the system tenant learns that a name does not exist", func(t *testing.T) {
		rec := lookUpTenantByName(t, "system", "no-such-tenant")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
