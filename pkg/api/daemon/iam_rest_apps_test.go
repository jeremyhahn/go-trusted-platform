package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
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
	// order is the client IDs in registration order.
	order []string
	// listCap, when positive, is the most applications one List returns,
	// as the remote server stops at 100.
	listCap int
	// missing, when set, builds the error a missing client ID gets, in
	// place of restiam.ErrAppNotFound.
	missing func(clientID string) error
	// getErr, when set, is what Get returns.
	getErr error
}

func (a *memApps) Register(_ context.Context, tenantID string, req *sdkiam.RegisterAppRequest) (*sdkiam.Application, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	app := &sdkiam.Application{ClientID: "client-" + strconv.Itoa(len(a.apps)+1), TenantID: tenantID, Name: req.Name}
	a.apps[app.ClientID] = app
	a.order = append(a.order, app.ClientID)
	return app, nil
}

func (a *memApps) lookup(tenantID, clientID string) (*sdkiam.Application, error) {
	app, ok := a.apps[clientID]
	if !ok {
		if a.missing != nil {
			return nil, a.missing(clientID)
		}
		return nil, restiam.ErrAppNotFound{TenantID: tenantID, AppID: clientID}
	}
	return app, nil
}

func (a *memApps) Get(_ context.Context, tenantID, clientID string) (*sdkiam.Application, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.getErr != nil {
		return nil, a.getErr
	}
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
	for _, clientID := range a.order {
		app, ok := a.apps[clientID]
		if !ok || app.TenantID != tenantID {
			continue
		}
		resp.Applications = append(resp.Applications, *app)
		if a.listCap > 0 && len(resp.Applications) == a.listCap {
			break
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
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(memAppsIAM{memIAM: iam, apps: apps}), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant, true))
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

// iamRESTRemoteServerWithApps mounts the IAM routes over a remote (gRPC or
// Unix) QuicBaaS backend and returns its application store.
func iamRESTRemoteServerWithApps(t *testing.T) (*RESTServer, *memApps) {
	t.Helper()
	iam := newMemIAM()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewRemoteQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant, false))
	return s, iam.apps
}

// A remote backend lists at most 100 applications and the pinned SDK cannot
// ask for the next page, so the tenant's 101st application is on no list. It
// is still the tenant's own, and every instance route reaches it.
func TestIAMREST_AppRoutesReachAnAppPastTheFirstListPage(t *testing.T) {
	s, apps := iamRESTRemoteServerWithApps(t)
	apps.listCap = 100
	var subject *sdkiam.Application
	for i := 1; i <= 101; i++ {
		app, err := apps.Register(context.Background(), iamRESTTenantA, &sdkiam.RegisterAppRequest{Name: "app-" + strconv.Itoa(i)})
		require.NoError(t, err)
		subject = app
	}
	require.Equal(t, "client-101", subject.ClientID)
	path := "/api/v1/iam/tenants/" + iamRESTTenantA + "/apps/" + subject.ClientID

	got := serveIAM(s, http.MethodGet, path, "operator")
	assert.Equal(t, http.StatusOK, got.Code, got.Body.String())
	assert.Contains(t, got.Body.String(), "app-101")

	updated := serveIAMBody(s, http.MethodPut, path, "operator", `{"name":"renamed"}`)
	assert.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	stored, err := apps.Get(context.Background(), iamRESTTenantA, subject.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", stored.Name)

	rotated := serveIAM(s, http.MethodPost, path+"/rotate", "operator")
	assert.Equal(t, http.StatusOK, rotated.Code, rotated.Body.String())
	assert.Contains(t, rotated.Body.String(), "rotated")

	deleted := serveIAM(s, http.MethodDelete, path, "operator")
	assert.Equal(t, http.StatusOK, deleted.Code, deleted.Body.String())
	_, err = apps.Get(context.Background(), iamRESTTenantA, subject.ClientID)
	assert.Error(t, err, "the deleted application must be gone from the store")
}

// On a remote backend, too, a tenant-a caller naming tenant-b's client ID
// under its own tenant path gets exactly the not-found a missing application
// gets, however the backend reports a missing one, and tenant-b's application
// is untouched.
func TestIAMREST_RemoteAppRoutesStayInTheURLTenant(t *testing.T) {
	s, apps := iamRESTRemoteServerWithApps(t)
	foreign, err := apps.Register(context.Background(), iamRESTTenantB, &sdkiam.RegisterAppRequest{Name: "billing"})
	require.NoError(t, err)
	const tenantApps = "/api/v1/iam/tenants/" + iamRESTTenantA + "/apps/"
	const notFound = "application not found: tenant=" + iamRESTTenantA + ", app="

	routes := []struct {
		method string
		suffix string
		body   string
	}{
		{http.MethodGet, "", ""},
		{http.MethodPut, "", `{"name":"renamed"}`},
		{http.MethodPost, "/rotate", ""},
		{http.MethodDelete, "", ""},
	}
	missing := []struct {
		name string
		err  func(clientID string) error
	}{
		{"SDK not found", func(clientID string) error {
			return sdkerrors.NewNotFound("iam.app.get", clientID+" not found")
		}},
		{"database not found", func(string) error {
			return quicbaassdk.NewDatabaseError(quicbaassdk.ErrNotFound, "iam.app.get", "")
		}},
		{"adapter not found", nil},
	}

	for _, rt := range routes {
		t.Run(rt.method+rt.suffix+" foreign", func(t *testing.T) {
			apps.missing = nil
			resp := serveIAMBody(s, rt.method, tenantApps+foreign.ClientID+rt.suffix, "operator", rt.body)

			assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
			assert.Contains(t, resp.Body.String(), notFound+foreign.ClientID)
			assert.NotContains(t, resp.Body.String(), "billing")
		})
		for _, m := range missing {
			t.Run(rt.method+rt.suffix+" missing, "+m.name, func(t *testing.T) {
				apps.missing = m.err
				resp := serveIAMBody(s, rt.method, tenantApps+"no-such-app"+rt.suffix, "operator", rt.body)

				assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
				assert.Contains(t, resp.Body.String(), notFound+"no-such-app")
				assert.NotContains(t, resp.Body.String(), "billing")
			})
		}
	}

	apps.missing = nil
	stored, err := apps.Get(context.Background(), iamRESTTenantB, foreign.ClientID)
	require.NoError(t, err, "tenant-b's application must survive tenant-a's requests")
	assert.Equal(t, "billing", stored.Name)
}

// A lookup that fails for another reason than a missing application is a
// server error: it must not be answered as a not-found.
func TestIAMREST_AppLookupFailureIsNotANotFound(t *testing.T) {
	s, apps := iamRESTRemoteServerWithApps(t)
	own, err := apps.Register(context.Background(), iamRESTTenantA, &sdkiam.RegisterAppRequest{Name: "portal"})
	require.NoError(t, err)
	apps.getErr = errors.New("application store unavailable")

	resp := serveIAM(s, http.MethodGet, "/api/v1/iam/tenants/"+iamRESTTenantA+"/apps/"+own.ClientID, "operator")

	assert.Equal(t, http.StatusInternalServerError, resp.Code, resp.Body.String())
}
