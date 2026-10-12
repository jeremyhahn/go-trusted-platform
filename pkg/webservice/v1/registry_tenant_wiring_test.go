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
	"errors"
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
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
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

type stubRoleClient struct{}

func (stubRoleClient) Reconcile(ctx context.Context, tenantID string) (*quicbaasiam.ReconcileRolesResponse, error) {
	return &quicbaasiam.ReconcileRolesResponse{TenantID: tenantID}, nil
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
		IAMRoleClient:   stubRoleClient{},
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
	return newWiringRegistryWithConfig(t, tenantManager, jwtService, nil)
}

func newWiringRegistryWithConfig(
	t *testing.T,
	tenantManager *tenant.Manager,
	jwtService *jwt.Service,
	cfg *Config) (*HandlerRegistry, *service.Registry) {

	t.Helper()
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	svcReg := newWiringServiceRegistry(t)
	return &HandlerRegistry{
		params: RegistryParams{
			WebServiceConfig: cfg,
			Logger:           logger,
			HTTPWriter:       response.NewResponseWriter(logger, nil),
			WebAuthnConfig:   &webauthn.Config{RPID: "cp.example.internal", RPOrigins: []string{"https://cp.example.internal:8443"}},
			FIDO2SDKClient:   stubWiringFIDO2Client{},
			AuthSDKClient:    stubWiringLoginClient{},
			TenantID:         "system",
			ServiceRegistry:  svcReg,
			TenantManager:    tenantManager,
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

func TestStartIAMUserReconcile_RunsInTheBackground(t *testing.T) {
	registry, _ := newWiringRegistry(t, newWiringTenantManager(t), &jwt.Service{})

	done := registry.startIAMUserReconcile(restiam.NewQuicBaaSUserMirror(nil))

	require.NotNil(t, done, "a wired registry starts the reconcile")
	<-done
}

func TestStartIAMUserReconcile_NotStartedWithoutDependencies(t *testing.T) {
	mirror := restiam.NewQuicBaaSUserMirror(nil)

	noTenantManager, _ := newWiringRegistry(t, nil, &jwt.Service{})
	assert.Nil(t, noTenantManager.startIAMUserReconcile(mirror))

	noUserStore, _ := newWiringRegistry(t, newWiringTenantManager(t), &jwt.Service{})
	noUserStore.params.ServiceRegistry = &service.Registry{}
	assert.Nil(t, noUserStore.startIAMUserReconcile(mirror))
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

// TestWebAuthnRestService_NoJWTService_DeclinesTheSurface proves the
// whole WebAuthn surface is gated on the signer, not just the tenant
// wiring. The signer is what issues the session credential a completed
// login hands back, and the seam every protected route runs validates
// exactly that signer's tokens — so without it the routes could only
// authenticate someone and then answer with a credential this same server
// rejects. Declining the surface is the same treatment every other
// unavailable seam gets here; serving a login that cannot produce a usable
// session is the failure mode #646 was opened on.
func TestWebAuthnRestService_NoJWTService_DeclinesTheSurface(t *testing.T) {
	registry, svcReg := newWiringRegistry(t, newWiringTenantManager(t), nil)

	assert.Nil(t, registry.WebAuthnRestService(),
		"no signer means no session credential, so no WebAuthn routes")
	assert.Nil(t, registry.LoginDriver(),
		"and no login driver either, for the same reason")
	assert.Nil(t, svcReg.TenantUserService())
}

// stubWiringLoginClient stands in for the unified login backbone. The
// wiring tests never run a ceremony; they only need the WebAuthn handler
// to be constructible, which now requires a login backbone because its
// login verbs run entirely on one.
type stubWiringLoginClient struct{}

func (stubWiringLoginClient) BeginLogin(
	context.Context, quicbaassdk.BeginLoginRequest) (*quicbaassdk.BeginLoginResponse, error) {
	return nil, errors.New("stub: BeginLogin is not exercised by the wiring tests")
}

func (stubWiringLoginClient) FinishLogin(
	context.Context, quicbaassdk.FinishLoginRequest) (*quicbaassdk.FinishLoginResponse, error) {
	return nil, errors.New("stub: FinishLogin is not exercised by the wiring tests")
}

// TestLoginDriver_RefusedWhenTheSeamIsTheBrokerValidator pins the same
// fail-closed gate the admin-claim ceremony has, for the same reason: a
// login completes by minting a platform-local session, and when
// JWT.PlatformToken.Enabled makes the broker validator the inbound seam
// that session is rejected by every protected route. Offering a login that
// hands the operator a credential the same server refuses is the defect
// #646 was opened on; declining the surface is the answer, and converging
// the two token types is #202.
func TestLoginDriver_RefusedWhenTheSeamIsTheBrokerValidator(t *testing.T) {
	cfg := &Config{}
	cfg.JWT.PlatformToken.Enabled = true
	cfg.JWT.PlatformToken.Issuer = "https://broker.example.com"
	cfg.JWT.PlatformToken.JWKSURL = "https://broker.example.com/.well-known/jwks.json"

	registry, _ := newWiringRegistryWithConfig(t, newWiringTenantManager(t), &jwt.Service{}, cfg)

	assert.Nil(t, registry.LoginDriver(),
		"the broker seam does not accept a platform-minted session")
	assert.Nil(t, registry.WebAuthnRestService(),
		"and the WebAuthn routes go with it, since their login verbs run on that driver")
}

// TestLoginDriver_BuiltOnTheDefaultSeam is the positive control: the gate
// above must be the seam, not something else missing from the fixture.
func TestLoginDriver_BuiltOnTheDefaultSeam(t *testing.T) {
	registry, _ := newWiringRegistry(t, newWiringTenantManager(t), &jwt.Service{})

	assert.NotNil(t, registry.LoginDriver(),
		"the default seam validates exactly what a login issues")
}
