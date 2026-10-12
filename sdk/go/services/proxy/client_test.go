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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"google.golang.org/grpc"
)

// errFakeRPC is the sentinel failure injected by the fake gRPC client.
var errFakeRPC = errors.New("fake rpc failure")

// fakeProxyServiceClient implements platformv1.ProxyServiceClient with
// canned responses and an optional injected error.
type fakeProxyServiceClient struct {
	err        error
	lastMethod string
}

func (f *fakeProxyServiceClient) CreateRoute(ctx context.Context, in *platformv1.CreateProxyRouteRequest, opts ...grpc.CallOption) (*platformv1.CreateProxyRouteResponse, error) {
	f.lastMethod = "CreateRoute"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.CreateProxyRouteResponse{Route: in.GetRoute(), Version: 1}, nil
}

func (f *fakeProxyServiceClient) GetRoute(ctx context.Context, in *platformv1.GetProxyRouteRequest, opts ...grpc.CallOption) (*platformv1.GetProxyRouteResponse, error) {
	f.lastMethod = "GetRoute"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetProxyRouteResponse{Route: &platformv1.ProxyRoute{Id: in.GetId()}}, nil
}

func (f *fakeProxyServiceClient) UpdateRoute(ctx context.Context, in *platformv1.UpdateProxyRouteRequest, opts ...grpc.CallOption) (*platformv1.UpdateProxyRouteResponse, error) {
	f.lastMethod = "UpdateRoute"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.UpdateProxyRouteResponse{Route: in.GetRoute(), Version: 2}, nil
}

func (f *fakeProxyServiceClient) DeleteRoute(ctx context.Context, in *platformv1.DeleteProxyRouteRequest, opts ...grpc.CallOption) (*platformv1.DeleteProxyRouteResponse, error) {
	f.lastMethod = "DeleteRoute"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteProxyRouteResponse{Version: 3}, nil
}

func (f *fakeProxyServiceClient) ListRoutes(ctx context.Context, in *platformv1.ListProxyRoutesRequest, opts ...grpc.CallOption) (*platformv1.ListProxyRoutesResponse, error) {
	f.lastMethod = "ListRoutes"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListProxyRoutesResponse{
		Routes:  []*platformv1.ProxyRoute{{Id: "a"}, {Id: "b"}},
		Version: 4,
	}, nil
}

func (f *fakeProxyServiceClient) CreatePool(ctx context.Context, in *platformv1.CreateProxyPoolRequest, opts ...grpc.CallOption) (*platformv1.CreateProxyPoolResponse, error) {
	f.lastMethod = "CreatePool"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.CreateProxyPoolResponse{Pool: in.GetPool(), Version: 5}, nil
}

func (f *fakeProxyServiceClient) GetPool(ctx context.Context, in *platformv1.GetProxyPoolRequest, opts ...grpc.CallOption) (*platformv1.GetProxyPoolResponse, error) {
	f.lastMethod = "GetPool"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetProxyPoolResponse{Pool: &platformv1.ProxyPool{Id: in.GetId()}}, nil
}

func (f *fakeProxyServiceClient) UpdatePool(ctx context.Context, in *platformv1.UpdateProxyPoolRequest, opts ...grpc.CallOption) (*platformv1.UpdateProxyPoolResponse, error) {
	f.lastMethod = "UpdatePool"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.UpdateProxyPoolResponse{Pool: in.GetPool(), Version: 6}, nil
}

func (f *fakeProxyServiceClient) DeletePool(ctx context.Context, in *platformv1.DeleteProxyPoolRequest, opts ...grpc.CallOption) (*platformv1.DeleteProxyPoolResponse, error) {
	f.lastMethod = "DeletePool"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteProxyPoolResponse{Version: 7}, nil
}

func (f *fakeProxyServiceClient) ListPools(ctx context.Context, in *platformv1.ListProxyPoolsRequest, opts ...grpc.CallOption) (*platformv1.ListProxyPoolsResponse, error) {
	f.lastMethod = "ListPools"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListProxyPoolsResponse{
		Pools:   []*platformv1.ProxyPool{{Id: "p"}},
		Version: 8,
	}, nil
}

func (f *fakeProxyServiceClient) GetProxyConfig(ctx context.Context, in *platformv1.GetProxyConfigRequest, opts ...grpc.CallOption) (*platformv1.GetProxyConfigResponse, error) {
	f.lastMethod = "GetProxyConfig"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetProxyConfigResponse{Version: 9}, nil
}

func (f *fakeProxyServiceClient) GetProxyStatus(ctx context.Context, in *platformv1.GetProxyStatusRequest, opts ...grpc.CallOption) (*platformv1.GetProxyStatusResponse, error) {
	f.lastMethod = "GetProxyStatus"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetProxyStatusResponse{Version: 9, RouteCount: 2, PoolCount: 1}, nil
}

func (f *fakeProxyServiceClient) ReloadProxyConfig(ctx context.Context, in *platformv1.ReloadProxyConfigRequest, opts ...grpc.CallOption) (*platformv1.ReloadProxyConfigResponse, error) {
	f.lastMethod = "ReloadProxyConfig"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ReloadProxyConfigResponse{Version: 10}, nil
}

func (f *fakeProxyServiceClient) GetZoneMatrix(ctx context.Context, in *platformv1.GetProxyZoneMatrixRequest, opts ...grpc.CallOption) (*platformv1.GetProxyZoneMatrixResponse, error) {
	f.lastMethod = "GetZoneMatrix"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetProxyZoneMatrixResponse{Zones: []string{"public"}}, nil
}

var _ platformv1.ProxyServiceClient = (*fakeProxyServiceClient)(nil)

func TestNewClient_NilConnection(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("err = %v, want ErrNilConnection", err)
	}
}

func TestNewClientFromGRPC(t *testing.T) {
	c := NewClientFromGRPC(&fakeProxyServiceClient{})
	if c == nil || c.grpc == nil {
		t.Fatal("client not constructed")
	}
}

func TestClient_RouteOperations(t *testing.T) {
	ctx := context.Background()
	fake := &fakeProxyServiceClient{}
	c := NewClientFromGRPC(fake)

	route, version, err := c.CreateRoute(ctx, &platformv1.ProxyRoute{Id: "web"})
	if err != nil || route.GetId() != "web" || version != 1 {
		t.Fatalf("CreateRoute = (%v, %d, %v), want (web, 1, nil)", route.GetId(), version, err)
	}

	got, err := c.GetRoute(ctx, "web")
	if err != nil || got.GetId() != "web" {
		t.Fatalf("GetRoute = (%v, %v), want (web, nil)", got.GetId(), err)
	}

	updated, version, err := c.UpdateRoute(ctx, &platformv1.ProxyRoute{Id: "web"})
	if err != nil || updated.GetId() != "web" || version != 2 {
		t.Fatalf("UpdateRoute = (%v, %d, %v)", updated.GetId(), version, err)
	}

	version, err = c.DeleteRoute(ctx, "web")
	if err != nil || version != 3 {
		t.Fatalf("DeleteRoute = (%d, %v), want (3, nil)", version, err)
	}

	routes, version, err := c.ListRoutes(ctx)
	if err != nil || len(routes) != 2 || version != 4 {
		t.Fatalf("ListRoutes = (%d, v%d, %v), want (2, v4, nil)", len(routes), version, err)
	}
}

func TestClient_RouteOperations_Errors(t *testing.T) {
	ctx := context.Background()
	c := NewClientFromGRPC(&fakeProxyServiceClient{err: errFakeRPC})

	var createErr *ErrCreateRouteFailed
	if _, _, err := c.CreateRoute(ctx, &platformv1.ProxyRoute{Id: "web"}); !errors.As(err, &createErr) || !errors.Is(err, errFakeRPC) {
		t.Errorf("CreateRoute err = %v, want ErrCreateRouteFailed wrapping fake", err)
	}
	var getErr *ErrGetRouteFailed
	if _, err := c.GetRoute(ctx, "web"); !errors.As(err, &getErr) {
		t.Errorf("GetRoute err = %v, want ErrGetRouteFailed", err)
	}
	var updateErr *ErrUpdateRouteFailed
	if _, _, err := c.UpdateRoute(ctx, &platformv1.ProxyRoute{Id: "web"}); !errors.As(err, &updateErr) {
		t.Errorf("UpdateRoute err = %v, want ErrUpdateRouteFailed", err)
	}
	var deleteErr *ErrDeleteRouteFailed
	if _, err := c.DeleteRoute(ctx, "web"); !errors.As(err, &deleteErr) {
		t.Errorf("DeleteRoute err = %v, want ErrDeleteRouteFailed", err)
	}
	var listErr *ErrListRoutesFailed
	if _, _, err := c.ListRoutes(ctx); !errors.As(err, &listErr) {
		t.Errorf("ListRoutes err = %v, want ErrListRoutesFailed", err)
	}
}

func TestClient_PoolOperations(t *testing.T) {
	ctx := context.Background()
	c := NewClientFromGRPC(&fakeProxyServiceClient{})

	pool, version, err := c.CreatePool(ctx, &platformv1.ProxyPool{Id: "p"})
	if err != nil || pool.GetId() != "p" || version != 5 {
		t.Fatalf("CreatePool = (%v, %d, %v)", pool.GetId(), version, err)
	}
	got, err := c.GetPool(ctx, "p")
	if err != nil || got.GetId() != "p" {
		t.Fatalf("GetPool = (%v, %v)", got.GetId(), err)
	}
	if _, version, err := c.UpdatePool(ctx, &platformv1.ProxyPool{Id: "p"}); err != nil || version != 6 {
		t.Fatalf("UpdatePool = (v%d, %v)", version, err)
	}
	if version, err := c.DeletePool(ctx, "p"); err != nil || version != 7 {
		t.Fatalf("DeletePool = (v%d, %v)", version, err)
	}
	pools, version, err := c.ListPools(ctx)
	if err != nil || len(pools) != 1 || version != 8 {
		t.Fatalf("ListPools = (%d, v%d, %v)", len(pools), version, err)
	}
}

func TestClient_PoolOperations_Errors(t *testing.T) {
	ctx := context.Background()
	c := NewClientFromGRPC(&fakeProxyServiceClient{err: errFakeRPC})

	var createErr *ErrCreatePoolFailed
	if _, _, err := c.CreatePool(ctx, &platformv1.ProxyPool{Id: "p"}); !errors.As(err, &createErr) {
		t.Errorf("CreatePool err = %v, want ErrCreatePoolFailed", err)
	}
	var getErr *ErrGetPoolFailed
	if _, err := c.GetPool(ctx, "p"); !errors.As(err, &getErr) {
		t.Errorf("GetPool err = %v, want ErrGetPoolFailed", err)
	}
	var updateErr *ErrUpdatePoolFailed
	if _, _, err := c.UpdatePool(ctx, &platformv1.ProxyPool{Id: "p"}); !errors.As(err, &updateErr) {
		t.Errorf("UpdatePool err = %v, want ErrUpdatePoolFailed", err)
	}
	var deleteErr *ErrDeletePoolFailed
	if _, err := c.DeletePool(ctx, "p"); !errors.As(err, &deleteErr) {
		t.Errorf("DeletePool err = %v, want ErrDeletePoolFailed", err)
	}
	var listErr *ErrListPoolsFailed
	if _, _, err := c.ListPools(ctx); !errors.As(err, &listErr) {
		t.Errorf("ListPools err = %v, want ErrListPoolsFailed", err)
	}
}

func TestClient_ConfigStatusReloadMatrix(t *testing.T) {
	ctx := context.Background()
	c := NewClientFromGRPC(&fakeProxyServiceClient{})

	cfg, err := c.Config(ctx)
	if err != nil || cfg.GetVersion() != 9 {
		t.Fatalf("Config = (v%d, %v), want (v9, nil)", cfg.GetVersion(), err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.GetRouteCount() != 2 {
		t.Fatalf("Status = (%v, %v)", st, err)
	}
	version, err := c.Reload(ctx)
	if err != nil || version != 10 {
		t.Fatalf("Reload = (v%d, %v), want (v10, nil)", version, err)
	}
	matrix, err := c.ZoneMatrix(ctx)
	if err != nil || len(matrix.GetZones()) != 1 {
		t.Fatalf("ZoneMatrix = (%v, %v)", matrix, err)
	}
}

func TestClient_ConfigStatusReloadMatrix_Errors(t *testing.T) {
	ctx := context.Background()
	c := NewClientFromGRPC(&fakeProxyServiceClient{err: errFakeRPC})

	var cfgErr *ErrGetConfigFailed
	if _, err := c.Config(ctx); !errors.As(err, &cfgErr) {
		t.Errorf("Config err = %v, want ErrGetConfigFailed", err)
	}
	var stErr *ErrGetStatusFailed
	if _, err := c.Status(ctx); !errors.As(err, &stErr) {
		t.Errorf("Status err = %v, want ErrGetStatusFailed", err)
	}
	var reloadErr *ErrReloadFailed
	if _, err := c.Reload(ctx); !errors.As(err, &reloadErr) {
		t.Errorf("Reload err = %v, want ErrReloadFailed", err)
	}
	var matrixErr *ErrZoneMatrixFailed
	if _, err := c.ZoneMatrix(ctx); !errors.As(err, &matrixErr) {
		t.Errorf("ZoneMatrix err = %v, want ErrZoneMatrixFailed", err)
	}
}
