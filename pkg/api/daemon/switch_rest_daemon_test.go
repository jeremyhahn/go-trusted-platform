package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// switchRESTProvider serves one in-memory switch, "sw1", with Eth1/3 on
// access VLAN 100.
type switchRESTProvider struct{}

func (switchRESTProvider) Manager(name string) (switchmgmt.Manager, error) {
	if name != "sw1" {
		return nil, fmt.Errorf("switch %q not configured", name)
	}
	return switchmgmt.NewMemoryManager(&switchmgmt.Config{
		Ports: []switchmgmt.PortConfig{{Port: "Eth1/3", AccessVLAN: 100}},
	})
}

func switchRESTGuard() *restapi.ScopeGuard {
	return restapi.NewScopeGuard(iamRESTTokens{
		"switch-reader": platformtoken.AuthorizedContext{Subject: "switch-reader", TenantID: iamRESTTenantA, Scopes: []string{"switch:read"}},
		"switch-writer": platformtoken.AuthorizedContext{Subject: "switch-writer", TenantID: iamRESTTenantA, Scopes: []string{"switch:write"}},
		"dns-reader":    platformtoken.AuthorizedContext{Subject: "dns-reader", TenantID: iamRESTTenantA, Scopes: []string{"dns:read"}},
	}, nil, nil)
}

func newSwitchRESTServer(t *testing.T) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetSwitchHandlers(switchRESTProvider{}, switchRESTGuard()))
	return s
}

// switchRouteScopes lists the switch routes the daemon REST listener mounts
// and the scope each needs (the scope of its SwitchService rpc).
var switchRouteScopes = []struct {
	method, template, path, scope string
}{
	{http.MethodGet, "/api/v1/switches/{switch}/ports", "/api/v1/switches/sw1/ports", "switch:read"},
	{http.MethodGet, "/api/v1/switches/{switch}/ports/{port}", "/api/v1/switches/sw1/ports/Eth1%2F3", "switch:read"},
	{http.MethodPost, "/api/v1/switches/{switch}/ports/{port}/vlan", "/api/v1/switches/sw1/ports/Eth1%2F3/vlan", "switch:write"},
	{http.MethodPost, "/api/v1/switches/{switch}/ports/{port}/enable", "/api/v1/switches/sw1/ports/Eth1%2F3/enable", "switch:write"},
	{http.MethodPost, "/api/v1/switches/{switch}/ports/{port}/disable", "/api/v1/switches/sw1/ports/Eth1%2F3/disable", "switch:write"},
}

func TestSwitchREST_DaemonListenerServesEveryRoute(t *testing.T) {
	s := newSwitchRESTServer(t)
	for _, r := range switchRouteScopes {
		name := r.method + " " + r.template
		t.Run(name, func(t *testing.T) {
			rec := serveIAM(s, r.method, r.path, "")
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "no token")

			rec = serveIAM(s, r.method, r.path, "dns-reader")
			assert.Equal(t, http.StatusForbidden, rec.Code, "wrong scope")
			assert.Contains(t, rec.Body.String(), r.scope, "the refusal names the scope")

			token := "switch-reader"
			if r.scope == "switch:write" {
				token = "switch-writer"
			}
			assertReachedHandler(t, serveIAM(s, r.method, r.path, token), name)
		})
	}
}

func TestSwitchREST_GetPortAnswersTheProvider(t *testing.T) {
	s := newSwitchRESTServer(t)
	rec := serveIAM(s, http.MethodGet, "/api/v1/switches/sw1/ports/Eth1%2F3", "switch-reader")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, strings.ReplaceAll(rec.Body.String(), " ", ""), `"access_vlan":100`)
}

func TestSetSwitchHandlers_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	err := s.SetSwitchHandlers(switchRESTProvider{}, nil)
	var unavailable ErrSwitchRESTUnavailable
	require.True(t, errors.As(err, &unavailable), "error = %v", err)
	assert.Empty(t, testWalkHandlers(t, s.router), "a nil guard mounts no route")

	require.NoError(t, s.SetSwitchHandlers(nil, switchRESTGuard()))
	assert.Empty(t, testWalkHandlers(t, s.router), "no switch service mounts no route")
}
