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
	"log/slog"
	"os"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	quicbaasiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Minimal stubs — the wiring test only needs construction to succeed;
// no DAO or IAM method is invoked during handler registration.
// ---------------------------------------------------------------------------

type stubDAO[E datastore.Entity] struct{}

func (s stubDAO[E]) Save(ctx context.Context, e E) error { return nil }
func (s stubDAO[E]) Get(ctx context.Context, id uint64) (E, error) {
	var zero E
	return zero, datastore.ErrRecordNotFound
}
func (s stubDAO[E]) Delete(ctx context.Context, e E) error { return nil }
func (s stubDAO[E]) Count(ctx context.Context) (int, error) {
	return 0, nil
}
func (s stubDAO[E]) Page(ctx context.Context, q datastore.PageQuery) (datastore.PageResult[E], error) {
	return datastore.PageResult[E]{}, nil
}
func (s stubDAO[E]) ForEachPage(ctx context.Context, q datastore.PageQuery, fn datastore.PagerFunc[E]) error {
	return nil
}

type stubInvitationDAO struct{ stubDAO[*entities.Invitation] }

func (s stubInvitationDAO) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	return nil, datastore.ErrRecordNotFound
}
func (s stubInvitationDAO) GetByEmail(ctx context.Context, email string) (*entities.Invitation, error) {
	return nil, datastore.ErrRecordNotFound
}
func (s stubInvitationDAO) GetByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	return nil, nil
}
func (s stubInvitationDAO) GetPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	return nil, nil
}

type stubRoleDAO struct{ stubDAO[*entities.Role] }

func (s stubRoleDAO) GetByName(ctx context.Context, name string) (*entities.Role, error) {
	return nil, datastore.ErrRecordNotFound
}

type stubDAOFactory struct{}

func (f stubDAOFactory) UserDAO() (datastore.UserDAO, error) {
	return stubDAO[*entities.User]{}, nil
}
func (f stubDAOFactory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	return stubDAO[*entities.Registration]{}, nil
}
func (f stubDAOFactory) InvitationDAO() (datastore.InvitationDAO, error) {
	return stubInvitationDAO{}, nil
}
func (f stubDAOFactory) RoleDAO() (datastore.RoleDAO, error) {
	return stubRoleDAO{}, nil
}
func (f stubDAOFactory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	return stubDAO[*entities.Blob]{}, nil
}
func (f stubDAOFactory) SerializerType() serializer.SerializerType {
	return serializer.SERIALIZER_JSON
}

type stubTenantClient struct{}

func (s stubTenantClient) Create(ctx context.Context, req *quicbaasiam.CreateTenantRequest) (*quicbaasiam.Tenant, error) {
	return &quicbaasiam.Tenant{}, nil
}
func (s stubTenantClient) Get(ctx context.Context, tenantID string) (*quicbaasiam.Tenant, error) {
	return &quicbaasiam.Tenant{}, nil
}
func (s stubTenantClient) Update(ctx context.Context, tenantID string, req *quicbaasiam.UpdateTenantRequest) (*quicbaasiam.Tenant, error) {
	return &quicbaasiam.Tenant{}, nil
}
func (s stubTenantClient) Delete(ctx context.Context, tenantID string) error { return nil }
func (s stubTenantClient) List(ctx context.Context, req *quicbaasiam.ListTenantsRequest) (*quicbaasiam.ListTenantsResponse, error) {
	return &quicbaasiam.ListTenantsResponse{}, nil
}

type stubWiringFIDO2Client struct{}

func (s stubWiringFIDO2Client) BeginRegistration(ctx context.Context, req *quicbaassdk.FIDO2BeginRegistrationRequest) (*quicbaassdk.FIDO2BeginRegistrationResponse, error) {
	return nil, nil
}
func (s stubWiringFIDO2Client) FinishRegistration(ctx context.Context, req *quicbaassdk.FIDO2FinishRegistrationRequest) (*quicbaassdk.FIDO2FinishRegistrationResponse, error) {
	return nil, nil
}
func (s stubWiringFIDO2Client) BeginAuthentication(ctx context.Context, req *quicbaassdk.FIDO2BeginAuthenticationRequest) (*quicbaassdk.FIDO2BeginAuthenticationResponse, error) {
	return nil, nil
}
func (s stubWiringFIDO2Client) FinishAuthentication(ctx context.Context, req *quicbaassdk.FIDO2FinishAuthenticationRequest) (*quicbaassdk.FIDO2FinishAuthenticationResponse, error) {
	return nil, nil
}

func newWiringTenantManager(t *testing.T) *tenant.Manager {
	t.Helper()
	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = false
	mgr, err := tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient: stubTenantClient{},
		Config:          cfg,
		Logger:          slog.Default(),
	})
	require.NoError(t, err)
	return mgr
}

func newWiringServiceRegistry(t *testing.T) *service.Registry {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	reg, err := service.NewRegistry(logger, nil, nil, nil, nil, stubDAOFactory{})
	require.NoError(t, err)
	return reg
}

func newWiringRegistry(t *testing.T, tenantManager *tenant.Manager, jwtService *jwt.Service) (*HandlerRegistry, *service.Registry) {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	svcReg := newWiringServiceRegistry(t)
	return &HandlerRegistry{
		params: RegistryParams{
			Logger:          logger,
			HTTPWriter:      response.NewResponseWriter(logger, nil),
			WebAuthnConfig:  &webauthn.Config{RPID: "cp.example.internal", RPOrigins: []string{"https://cp.example.internal:8443"}},
			FIDO2SDKClient:  stubWiringFIDO2Client{},
			TenantID:        "system",
			ServiceRegistry: svcReg,
			TenantManager:   tenantManager,
		},
		jwtService: jwtService,
	}, svcReg
}

// TestWebAuthnRestService_WiresTenantUserService is the regression test
// for the production late-wiring path: with a tenant manager supplied
// and every dependency present, building the WebAuthn handler must
// materialize the TenantUserService AND install it back into the
// platform service registry so all consumers share one instance.
func TestWebAuthnRestService_WiresTenantUserService(t *testing.T) {
	registry, svcReg := newWiringRegistry(t, newWiringTenantManager(t), &jwt.Service{})
	require.Nil(t, svcReg.TenantUserService(), "precondition: registry starts without a tenant user service")

	handler := registry.WebAuthnRestService()
	require.NotNil(t, handler)
	assert.NotNil(t, svcReg.TenantUserService(),
		"tenant user service must be materialized and pushed into the platform registry")
}

// TestWebAuthnRestService_NoTenantManager_LeavesServiceUnwired proves
// the dependency-missing case stays exactly as before: the handler is
// still built (registration works tenant-less) and nothing is wired.
func TestWebAuthnRestService_NoTenantManager_LeavesServiceUnwired(t *testing.T) {
	registry, svcReg := newWiringRegistry(t, nil, &jwt.Service{})

	handler := registry.WebAuthnRestService()
	require.NotNil(t, handler)
	assert.Nil(t, svcReg.TenantUserService())
}

// TestWebAuthnRestService_NoJWTService_LeavesServiceUnwired proves the
// wiring is gated on the token issuer's dependency: without a JWT
// service the tenant service is NOT constructed (a wired service whose
// issuer cannot sign would fail closed on every login under the #145
// empty-token rule).
func TestWebAuthnRestService_NoJWTService_LeavesServiceUnwired(t *testing.T) {
	registry, svcReg := newWiringRegistry(t, newWiringTenantManager(t), nil)

	handler := registry.WebAuthnRestService()
	require.NotNil(t, handler)
	assert.Nil(t, svcReg.TenantUserService())
}
