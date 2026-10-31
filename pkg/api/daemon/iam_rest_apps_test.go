package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// memApps is an application store that behaves like the pinned SDK: List
// is tenant-scoped, while Get, Update, Delete and RotateSecret find a client
// ID in any tenant.
type memApps struct {
	sdkiam.AppClient

	mu   sync.Mutex
	apps map[string]*sdkiam.Application
}

func (a *memApps) Register(_ context.Context, tenantID string, req *sdkiam.RegisterAppRequest) (*sdkiam.Application, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	app := &sdkiam.Application{ClientID: "client-" + strconv.Itoa(len(a.apps)+1), TenantID: tenantID, Name: req.Name}
	a.apps[app.ClientID] = app
	return app, nil
}

func (a *memApps) lookup(tenantID, clientID string) (*sdkiam.Application, error) {
	app, ok := a.apps[clientID]
	if !ok {
		return nil, restiam.ErrAppNotFound{TenantID: tenantID, AppID: clientID}
	}
	return app, nil
}

func (a *memApps) Get(_ context.Context, tenantID, clientID string) (*sdkiam.Application, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lookup(tenantID, clientID)
}

func (a *memApps) Update(_ context.Context, tenantID, clientID string, req *sdkiam.UpdateAppRequest) (*sdkiam.Application, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	app, err := a.lookup(tenantID, clientID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		app.Name = req.Name
	}
	return app, nil
}

func (a *memApps) Delete(_ context.Context, tenantID, clientID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.lookup(tenantID, clientID); err != nil {
		return err
	}
	delete(a.apps, clientID)
	return nil
}

func (a *memApps) RotateSecret(_ context.Context, tenantID, clientID string) (*sdkiam.RotateSecretResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.lookup(tenantID, clientID); err != nil {
		return nil, err
	}
	return &sdkiam.RotateSecretResponse{ClientID: clientID, ClientSecret: "rotated"}, nil
}

func (a *memApps) List(_ context.Context, tenantID string) (*sdkiam.ListAppsResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	resp := &sdkiam.ListAppsResponse{}
	for _, app := range a.apps {
		if app.TenantID == tenantID {
			resp.Applications = append(resp.Applications, *app)
		}
	}
	resp.TotalCount = len(resp.Applications)
	return resp, nil
}

// memAppsIAM is the in-memory IAM with an application store.
type memAppsIAM struct {
	*memIAM
	apps *memApps
}

func (m memAppsIAM) App() sdkiam.AppClient { return m.apps }

func iamRESTServerWithApps(t *testing.T) (*RESTServer, *memApps) {
	t.Helper()
	iam := newMemIAM()
	apps := &memApps{apps: map[string]*sdkiam.Application{}}
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(memAppsIAM{memIAM: iam, apps: apps}), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant))
	return s, apps
}

// A tenant-a caller naming tenant-b's client ID under its own tenant path
// gets the not-found a missing app gets, and tenant-b's app is untouched.
func TestIAMREST_AppRoutesStayInTheURLTenant(t *testing.T) {
	s, apps := iamRESTServerWithApps(t)
	foreign, err := apps.Register(context.Background(), iamRESTTenantB, &sdkiam.RegisterAppRequest{Name: "billing"})
	require.NoError(t, err)
	own, err := apps.Register(context.Background(), iamRESTTenantA, &sdkiam.RegisterAppRequest{Name: "portal"})
	require.NoError(t, err)
	const tenantApps = "/api/v1/iam/tenants/" + iamRESTTenantA + "/apps/"

	for _, tc := range []struct {
		method string
		suffix string
	}{
		{http.MethodGet, ""},
		{http.MethodDelete, ""},
	} {
		t.Run(tc.method+tc.suffix, func(t *testing.T) {
			foreignResp := serveIAM(s, tc.method, tenantApps+foreign.ClientID+tc.suffix, "operator")
			missingResp := serveIAM(s, tc.method, tenantApps+"no-such-app"+tc.suffix, "operator")

			assert.Equal(t, http.StatusNotFound, foreignResp.Code, foreignResp.Body.String())
			assert.Equal(t, missingResp.Code, foreignResp.Code, "a foreign app must look like a missing one")
			assert.NotContains(t, foreignResp.Body.String(), "billing")
		})
	}

	stored, err := apps.Get(context.Background(), iamRESTTenantB, foreign.ClientID)
	require.NoError(t, err, "tenant-b's app must survive tenant-a's delete")
	assert.Equal(t, "billing", stored.Name)

	ownResp := serveIAM(s, http.MethodGet, tenantApps+own.ClientID, "operator")
	assert.Equal(t, http.StatusOK, ownResp.Code, ownResp.Body.String())
	assert.Contains(t, ownResp.Body.String(), "portal")
}
