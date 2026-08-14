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

package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errFakeClient is the sentinel failure injected by the fake client.
var errFakeClient = errors.New("fake client failure")

// fakeCLIClient records invocations of the proxyClient interface.
type fakeCLIClient struct {
	err       error
	lastCall  string
	lastRoute *platformv1.ProxyRoute
	lastPool  *platformv1.ProxyPool
	lastID    string
}

func (f *fakeCLIClient) CreateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	f.lastCall, f.lastRoute = "CreateRoute", route
	return route, 1, f.err
}

func (f *fakeCLIClient) GetRoute(ctx context.Context, id string) (*platformv1.ProxyRoute, error) {
	f.lastCall, f.lastID = "GetRoute", id
	return &platformv1.ProxyRoute{Id: id}, f.err
}

func (f *fakeCLIClient) UpdateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	f.lastCall, f.lastRoute = "UpdateRoute", route
	return route, 2, f.err
}

func (f *fakeCLIClient) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	f.lastCall, f.lastID = "DeleteRoute", id
	return 3, f.err
}

func (f *fakeCLIClient) ListRoutes(ctx context.Context) ([]*platformv1.ProxyRoute, uint64, error) {
	f.lastCall = "ListRoutes"
	return []*platformv1.ProxyRoute{{Id: "web"}}, 4, f.err
}

func (f *fakeCLIClient) CreatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	f.lastCall, f.lastPool = "CreatePool", pool
	return pool, 5, f.err
}

func (f *fakeCLIClient) GetPool(ctx context.Context, id string) (*platformv1.ProxyPool, error) {
	f.lastCall, f.lastID = "GetPool", id
	return &platformv1.ProxyPool{Id: id}, f.err
}

func (f *fakeCLIClient) UpdatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	f.lastCall, f.lastPool = "UpdatePool", pool
	return pool, 6, f.err
}

func (f *fakeCLIClient) DeletePool(ctx context.Context, id string) (uint64, error) {
	f.lastCall, f.lastID = "DeletePool", id
	return 7, f.err
}

func (f *fakeCLIClient) ListPools(ctx context.Context) ([]*platformv1.ProxyPool, uint64, error) {
	f.lastCall = "ListPools"
	return []*platformv1.ProxyPool{{Id: "p"}}, 8, f.err
}

func (f *fakeCLIClient) Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error) {
	f.lastCall = "Config"
	return &platformv1.GetProxyConfigResponse{Version: 9}, f.err
}

func (f *fakeCLIClient) Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error) {
	f.lastCall = "Status"
	return &platformv1.GetProxyStatusResponse{Version: 9}, f.err
}

func (f *fakeCLIClient) Reload(ctx context.Context) (uint64, error) {
	f.lastCall = "Reload"
	return 10, f.err
}

func (f *fakeCLIClient) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	f.lastCall = "ZoneMatrix"
	return &platformv1.GetProxyZoneMatrixResponse{Zones: []string{"public"}}, f.err
}

var _ proxyClient = (*fakeCLIClient)(nil)

// withFakeClient swaps the client factory and output renderer for the test
// and restores them afterwards. It returns the fake client and a pointer to
// the last output value.
func withFakeClient(t *testing.T, fake *fakeCLIClient) *any {
	t.Helper()
	origFactory := newProxyClient
	origOutput := output
	var lastOutput any
	newProxyClient = func(flags *cli.CommonFlags) (proxyClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	output = func(flags *cli.CommonFlags, v any) error {
		lastOutput = v
		return nil
	}
	t.Cleanup(func() {
		newProxyClient = origFactory
		output = origOutput
	})
	return &lastOutput
}

// execute runs the proxy command tree with the given args.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	cmd := NewCommand(getFlags)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestNewCommand_Structure(t *testing.T) {
	cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	if cmd.Use != "proxy" {
		t.Errorf("Use = %q, want proxy", cmd.Use)
	}
	want := map[string]bool{
		"route": false, "pool": false, "status": false,
		"reload": false, "zone-matrix": false,
	}
	for _, sub := range cmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %s not registered", name)
		}
	}
}

func TestRouteAdd(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	err := execute(t, "route", "add",
		"--id", "web",
		"--host", "example.com",
		"--path-prefix", "/api",
		"--pool", "web-pool",
		"--auth-mode", "mtls",
		"--require-idevid",
		"--allowed-zone", "trusted",
		"--backend-zone", "internal",
		"--require-attestation",
		"--attestation-max-age", "5m",
		"--required-role", "admin",
		"--required-scope", "proxy:write",
		"--opa-policy", "policies/p.rego",
		"--strip-prefix",
		"--preserve-host")
	if err != nil {
		t.Fatalf("route add: %v", err)
	}
	if fake.lastCall != "CreateRoute" {
		t.Fatalf("client call = %s, want CreateRoute", fake.lastCall)
	}
	route := fake.lastRoute
	if route.GetId() != "web" || route.GetPoolId() != "web-pool" || route.GetPathPrefix() != "/api" {
		t.Errorf("route = %+v", route)
	}
	auth := route.GetAuth()
	if auth.GetMode() != "mtls" || !auth.GetRequireIdevid() || !auth.GetRequireAttestation() {
		t.Errorf("auth = %+v", auth)
	}
	if auth.GetAttestationMaxAgeNanos() != int64(5*time.Minute) {
		t.Errorf("attestation max age = %d, want %d", auth.GetAttestationMaxAgeNanos(), int64(5*time.Minute))
	}
	if len(auth.GetAllowedZones()) != 1 || auth.GetAllowedZones()[0] != "trusted" {
		t.Errorf("allowed zones = %v", auth.GetAllowedZones())
	}
	if !route.GetStripPrefix() || !route.GetPreserveHost() {
		t.Errorf("flags = strip %v preserve %v, want true true", route.GetStripPrefix(), route.GetPreserveHost())
	}
}

func TestRouteAdd_MissingRequiredFlags(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	var msgErr *MessageError
	if err := execute(t, "route", "add", "--pool", "p", "--auth-mode", "public"); !errors.As(err, &msgErr) {
		t.Errorf("missing --id err = %v, want MessageError", err)
	}
	if err := execute(t, "route", "add", "--id", "web", "--auth-mode", "public"); !errors.As(err, &msgErr) {
		t.Errorf("missing --pool err = %v, want MessageError", err)
	}
	if err := execute(t, "route", "add", "--id", "web", "--pool", "p"); !errors.As(err, &msgErr) {
		t.Errorf("missing --auth-mode err = %v, want MessageError", err)
	}
	if fake.lastCall != "" {
		t.Errorf("client invoked (%s) despite validation failure", fake.lastCall)
	}
}

func TestRouteGetUpdateDeleteList(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)

	if err := execute(t, "route", "get", "web"); err != nil {
		t.Fatalf("route get: %v", err)
	}
	if fake.lastCall != "GetRoute" || fake.lastID != "web" {
		t.Errorf("call = %s id %s, want GetRoute web", fake.lastCall, fake.lastID)
	}

	if err := execute(t, "route", "update", "--id", "web", "--pool", "p2", "--auth-mode", "public"); err != nil {
		t.Fatalf("route update: %v", err)
	}
	if fake.lastCall != "UpdateRoute" || fake.lastRoute.GetPoolId() != "p2" {
		t.Errorf("call = %s pool %s, want UpdateRoute p2", fake.lastCall, fake.lastRoute.GetPoolId())
	}

	if err := execute(t, "route", "delete", "web"); err != nil {
		t.Fatalf("route delete: %v", err)
	}
	if fake.lastCall != "DeleteRoute" || fake.lastID != "web" {
		t.Errorf("call = %s id %s, want DeleteRoute web", fake.lastCall, fake.lastID)
	}

	if err := execute(t, "route", "list"); err != nil {
		t.Fatalf("route list: %v", err)
	}
	if fake.lastCall != "ListRoutes" {
		t.Errorf("call = %s, want ListRoutes", fake.lastCall)
	}
	if *lastOutput == nil {
		t.Error("no output rendered for route list")
	}
}

func TestRouteGet_MissingArg(t *testing.T) {
	withFakeClient(t, &fakeCLIClient{})
	if err := execute(t, "route", "get"); err == nil {
		t.Error("expected arg validation error for route get without id")
	}
	if err := execute(t, "route", "delete"); err == nil {
		t.Error("expected arg validation error for route delete without id")
	}
}

func TestRouteCommands_ClientError(t *testing.T) {
	fake := &fakeCLIClient{err: errFakeClient}
	withFakeClient(t, fake)

	var wrapped *WrappedError
	if err := execute(t, "route", "get", "web"); !errors.As(err, &wrapped) || !errors.Is(err, errFakeClient) {
		t.Errorf("err = %v, want WrappedError wrapping fake failure", err)
	}
	if err := execute(t, "route", "list"); !errors.Is(err, errFakeClient) {
		t.Errorf("err = %v, want wrapped fake failure", err)
	}
}

func TestPoolAdd(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	err := execute(t, "pool", "add",
		"--id", "web-pool",
		"--backend", "https://10.0.0.10:8443=2",
		"--backend", "https://10.0.0.11:8443",
		"--balancer", "round-robin",
		"--trust-class", "internal",
		"--mtls-client-cert",
		"--max-idle-conns-per-host", "16",
		"--idle-conn-timeout", "90s")
	if err != nil {
		t.Fatalf("pool add: %v", err)
	}
	if fake.lastCall != "CreatePool" {
		t.Fatalf("client call = %s, want CreatePool", fake.lastCall)
	}
	pool := fake.lastPool
	if pool.GetId() != "web-pool" || len(pool.GetBackends()) != 2 {
		t.Fatalf("pool = %+v", pool)
	}
	if pool.GetBackends()[0].GetWeight() != 2 || pool.GetBackends()[0].GetUrl() != "https://10.0.0.10:8443" {
		t.Errorf("weighted backend = %+v", pool.GetBackends()[0])
	}
	if pool.GetBackends()[1].GetWeight() != 0 {
		t.Errorf("unweighted backend weight = %d, want 0", pool.GetBackends()[1].GetWeight())
	}
	if pool.GetTls().GetTrustClass() != "internal" || !pool.GetTls().GetMtlsClientCert() {
		t.Errorf("tls = %+v", pool.GetTls())
	}
	if pool.GetMaxIdleConnsPerHost() != 16 || pool.GetIdleConnTimeoutNanos() != int64(90*time.Second) {
		t.Errorf("transport tuning = %d / %d", pool.GetMaxIdleConnsPerHost(), pool.GetIdleConnTimeoutNanos())
	}
}

func TestPoolAdd_Validation(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	var msgErr *MessageError
	if err := execute(t, "pool", "add", "--backend", "https://b:8443"); !errors.As(err, &msgErr) {
		t.Errorf("missing --id err = %v, want MessageError", err)
	}
	if err := execute(t, "pool", "add", "--id", "p"); !errors.As(err, &msgErr) {
		t.Errorf("missing --backend err = %v, want MessageError", err)
	}
	if err := execute(t, "pool", "add", "--id", "p", "--backend", "https://b:8443=-1"); !errors.As(err, &msgErr) {
		t.Errorf("negative weight err = %v, want MessageError", err)
	}
	if fake.lastCall != "" {
		t.Errorf("client invoked (%s) despite validation failure", fake.lastCall)
	}
}

func TestPoolGetUpdateDeleteList(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	if err := execute(t, "pool", "get", "p"); err != nil {
		t.Fatalf("pool get: %v", err)
	}
	if fake.lastCall != "GetPool" || fake.lastID != "p" {
		t.Errorf("call = %s id %s, want GetPool p", fake.lastCall, fake.lastID)
	}

	if err := execute(t, "pool", "update", "--id", "p", "--backend", "https://b:8443"); err != nil {
		t.Fatalf("pool update: %v", err)
	}
	if fake.lastCall != "UpdatePool" {
		t.Errorf("call = %s, want UpdatePool", fake.lastCall)
	}

	if err := execute(t, "pool", "delete", "p"); err != nil {
		t.Fatalf("pool delete: %v", err)
	}
	if fake.lastCall != "DeletePool" || fake.lastID != "p" {
		t.Errorf("call = %s id %s, want DeletePool p", fake.lastCall, fake.lastID)
	}

	if err := execute(t, "pool", "list"); err != nil {
		t.Fatalf("pool list: %v", err)
	}
	if fake.lastCall != "ListPools" {
		t.Errorf("call = %s, want ListPools", fake.lastCall)
	}
}

func TestPoolCommands_ClientError(t *testing.T) {
	fake := &fakeCLIClient{err: errFakeClient}
	withFakeClient(t, fake)

	if err := execute(t, "pool", "get", "p"); !errors.Is(err, errFakeClient) {
		t.Errorf("err = %v, want wrapped fake failure", err)
	}
	if err := execute(t, "pool", "delete", "p"); !errors.Is(err, errFakeClient) {
		t.Errorf("err = %v, want wrapped fake failure", err)
	}
}

func TestStatusReloadZoneMatrix(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)

	if err := execute(t, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if fake.lastCall != "Status" {
		t.Errorf("call = %s, want Status", fake.lastCall)
	}

	if err := execute(t, "reload"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fake.lastCall != "Reload" {
		t.Errorf("call = %s, want Reload", fake.lastCall)
	}
	out, ok := (*lastOutput).(map[string]any)
	if !ok || out["version"] != uint64(10) {
		t.Errorf("reload output = %#v, want map with version 10", *lastOutput)
	}

	if err := execute(t, "zone-matrix"); err != nil {
		t.Fatalf("zone-matrix: %v", err)
	}
	if fake.lastCall != "ZoneMatrix" {
		t.Errorf("call = %s, want ZoneMatrix", fake.lastCall)
	}
}

func TestStatusReloadZoneMatrix_ClientError(t *testing.T) {
	fake := &fakeCLIClient{err: errFakeClient}
	withFakeClient(t, fake)

	if err := execute(t, "status"); !errors.Is(err, errFakeClient) {
		t.Errorf("status err = %v, want wrapped fake failure", err)
	}
	if err := execute(t, "reload"); !errors.Is(err, errFakeClient) {
		t.Errorf("reload err = %v, want wrapped fake failure", err)
	}
	if err := execute(t, "zone-matrix"); !errors.Is(err, errFakeClient) {
		t.Errorf("zone-matrix err = %v, want wrapped fake failure", err)
	}
}

func TestClientFactoryError(t *testing.T) {
	origFactory := newProxyClient
	factoryErr := errors.New("connect failed")
	newProxyClient = func(flags *cli.CommonFlags) (proxyClient, func() error, error) {
		return nil, nil, factoryErr
	}
	t.Cleanup(func() { newProxyClient = origFactory })

	if err := execute(t, "status"); !errors.Is(err, factoryErr) {
		t.Errorf("err = %v, want factory error", err)
	}
}

func TestParseBackend(t *testing.T) {
	tests := []struct {
		entry      string
		wantURL    string
		wantWeight int32
		wantErr    bool
	}{
		{"https://b:8443", "https://b:8443", 0, false},
		{"https://b:8443=3", "https://b:8443", 3, false},
		{"http://plain", "http://plain", 0, false},
		{"https://b:8443=notanumber", "https://b:8443=notanumber", 0, false},
		{"", "", 0, true},
		{"https://b:8443=-2", "", 0, true},
	}
	for _, tc := range tests {
		backend, err := parseBackend(tc.entry)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseBackend(%q) err = nil, want error", tc.entry)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBackend(%q): %v", tc.entry, err)
			continue
		}
		if backend.GetUrl() != tc.wantURL || backend.GetWeight() != tc.wantWeight {
			t.Errorf("parseBackend(%q) = (%q, %d), want (%q, %d)",
				tc.entry, backend.GetUrl(), backend.GetWeight(), tc.wantURL, tc.wantWeight)
		}
	}
}
