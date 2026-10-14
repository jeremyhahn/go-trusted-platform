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

package embedded

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// statsCacheServer answers GetStats and refuses Clear the way platformd's
// CacheService refuses a request that names no target.
type statsCacheServer struct {
	platformv1.UnimplementedCacheServiceServer
}

func (statsCacheServer) GetStats(context.Context, *platformv1.GetCacheStatsRequest) (*platformv1.GetCacheStatsResponse, error) {
	return &platformv1.GetCacheStatsResponse{Hits: 7}, nil
}

func (statsCacheServer) Clear(context.Context, *platformv1.ClearCacheRequest) (*platformv1.ClearCacheResponse, error) {
	return nil, status.Error(codes.InvalidArgument, "entity_type or all is required")
}

// appServices returns a registry holding the three application services,
// their service descriptors and the servers in descriptor order.
func appServices() (*ServiceRegistry, []grpc.ServiceDesc, []any) {
	cache := statsCacheServer{}
	scheduler := platformv1.UnimplementedSchedulerServiceServer{}
	messaging := platformv1.UnimplementedMessagingServiceServer{}
	reg := &ServiceRegistry{Cache: cache, Scheduler: scheduler, Messaging: messaging}
	descs := []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
	}
	return reg, descs, []any{cache, scheduler, messaging}
}

// TestBuildHandlerMap_AppServicesEveryMethodReachesItsServer drives every
// method of every descriptor, so a method added to a proto without a
// dispatch entry fails here.
func TestBuildHandlerMap_AppServicesEveryMethodReachesItsServer(t *testing.T) {
	reg, descs, servers := appServices()
	m := buildHandlerMap(reg)

	answered := map[string]bool{
		platformv1.CacheService_GetStats_FullMethodName: true,
		platformv1.CacheService_Clear_FullMethodName:    true,
	}
	for i, desc := range descs {
		for _, md := range desc.Methods {
			full := "/" + desc.ServiceName + "/" + md.MethodName
			t.Run(full, func(t *testing.T) {
				handler, ok := m[full]
				if !ok {
					t.Fatalf("%s is not registered", full)
				}
				_, err := handler(context.Background(), requestTypeOf(t, md, servers[i]))
				if answered[full] {
					return
				}
				st, _ := status.FromError(err)
				if st.Code() != codes.Unimplemented || !strings.Contains(st.Message(), "method "+md.MethodName+" ") {
					t.Errorf("%s reached %v, want the server's %s", full, err, md.MethodName)
				}
			})
		}
	}
}

func TestBuildHandlerMap_AppServicesNilRegisterNothing(t *testing.T) {
	_, descs, _ := appServices()
	m := buildHandlerMap(&ServiceRegistry{})

	for _, desc := range descs {
		for _, md := range desc.Methods {
			if _, ok := m["/"+desc.ServiceName+"/"+md.MethodName]; ok {
				t.Errorf("%s/%s registered without a service", desc.ServiceName, md.MethodName)
			}
		}
	}
}

func TestAdapter_CacheGetStatsRoundTrip(t *testing.T) {
	reg, _, _ := appServices()
	a, err := New(reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	reply, err := platformv1.NewCacheServiceClient(a.Connection()).GetStats(context.Background(), &platformv1.GetCacheStatsRequest{})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if reply.GetHits() != 7 {
		t.Errorf("hits = %d, want 7", reply.GetHits())
	}
}

func TestAdapter_CacheClearKeepsTheServersStatus(t *testing.T) {
	reg, _, _ := appServices()
	a, err := New(reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = platformv1.NewCacheServiceClient(a.Connection()).Clear(context.Background(), &platformv1.ClearCacheRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("Clear err = %v, want InvalidArgument", err)
	}
}
