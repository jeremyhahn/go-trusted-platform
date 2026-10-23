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

package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

type fakeMCPCache struct {
	platformv1.UnimplementedCacheServiceServer
	stats *platformv1.GetCacheStatsRequest
}

func (f *fakeMCPCache) GetStats(_ context.Context, in *platformv1.GetCacheStatsRequest) (*platformv1.GetCacheStatsResponse, error) {
	f.stats = in
	return &platformv1.GetCacheStatsResponse{HitRate: 0.5, Size: 1 << 40}, nil
}

type fakeMCPScheduler struct {
	platformv1.UnimplementedSchedulerServiceServer
	listed *platformv1.ListSchedulerJobsRequest
}

func (f *fakeMCPScheduler) ListJobs(_ context.Context, in *platformv1.ListSchedulerJobsRequest) (*platformv1.ListSchedulerJobsResponse, error) {
	f.listed = in
	return &platformv1.ListSchedulerJobsResponse{
		Jobs: []*platformv1.SchedulerJob{{JobId: "7", Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED}},
	}, nil
}

func (f *fakeMCPScheduler) GetJob(_ context.Context, in *platformv1.GetSchedulerJobRequest) (*platformv1.GetSchedulerJobResponse, error) {
	if in.GetJobId() == "bad" {
		return nil, status.Error(codes.InvalidArgument, "job ID is not decimal")
	}
	// A string that is not UTF-8 cannot be rendered in the JSON mapping.
	return &platformv1.GetSchedulerJobResponse{Job: &platformv1.SchedulerJob{Name: "\xff"}}, nil
}

type fakeMCPMessaging struct {
	platformv1.UnimplementedMessagingServiceServer
	published *platformv1.PublishMessageRequest
}

func (f *fakeMCPMessaging) Publish(_ context.Context, in *platformv1.PublishMessageRequest) (*platformv1.PublishMessageResponse, error) {
	f.published = in
	return &platformv1.PublishMessageResponse{}, nil
}

type fakeMCPObjectStorage struct {
	platformv1.UnimplementedObjectStorageServiceServer
	put *platformv1.PutObjectRequest
}

func (f *fakeMCPObjectStorage) PutObject(_ context.Context, in *platformv1.PutObjectRequest) (*platformv1.PutObjectResponse, error) {
	f.put = in
	return &platformv1.PutObjectResponse{Key: in.GetKey(), Version: 3}, nil
}

// appServiceTestProvider is a ServiceProvider that serves the application
// services.
type appServiceTestProvider struct {
	*mockServiceProvider
	servers AppServiceServers
}

func (p appServiceTestProvider) AppServiceServers() AppServiceServers { return p.servers }

func newAppServiceTestRegistry(servers AppServiceServers) *ToolRegistry {
	provider := appServiceTestProvider{mockServiceProvider: newMockServiceProvider(), servers: servers}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// Every RPC of the three services has exactly one tool, which requires the
// RPC's gRPC scope and which the SDK MCP transport maps the RPC to.
func TestAppServiceTools_MatchTheGRPCCatalogAndTheSDK(t *testing.T) {
	byMethod := map[string]string{}
	for name, tool := range appServiceTools {
		byMethod[tool.method] = name
	}
	permissions := toolPermissionCatalog()
	sdkTools := sdkmcp.MethodTools()

	declared := 0
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
		platformv1.ObjectStorageService_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			declared++
			method := "/" + desc.ServiceName + "/" + m.MethodName
			name, ok := byMethod[method]
			if !assert.True(t, ok, "%s has no MCP tool", method) {
				continue
			}
			want := grpcapi.ScopeForMethod(method)
			assert.NotEmpty(t, want, "%s is missing from the gRPC method catalog", method)
			assert.Equal(t, want, appServiceTools[name].scope, name)
			assert.Equal(t, want, permissions[name], "%s in the permission catalog", name)
			assert.Equal(t, name, sdkTools[method], "the SDK maps %s to another tool", method)
		}
	}
	assert.Len(t, appServiceTools, declared, "two tools serve one RPC, or a tool serves an RPC the services do not declare")
}

func TestAppServiceTools_AreRegisteredWithTheRequestSchema(t *testing.T) {
	registered := map[string]mcpwire.ToolDefinition{}
	for _, tool := range NewToolRegistry(nil, logging.DefaultLogger()).ListTools() {
		registered[tool.Name] = tool
	}

	for name, tool := range appServiceTools {
		definition, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
		properties, ok := definition.InputSchema["properties"].(map[string]interface{})
		require.True(t, ok, name)
		assert.Len(t, properties, tool.binding.request.Fields().Len(), name)
		for _, field := range tool.required {
			assert.Contains(t, properties, field, "%s requires %s, which its request lacks", name, field)
		}
	}

	publish := registered["messaging_publish"].InputSchema["properties"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"type": "string", "contentEncoding": "base64"}, publish["payload"])
	assert.Equal(t, map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "string"}},
		publish["metadata"])
	assert.Equal(t, []string{"channel"}, registered["messaging_publish"].InputSchema["required"])
	assert.Equal(t, []string{"key", "target_backend"}, registered["objectstorage_put"].InputSchema["required"])
}

func TestAppValueSchema_TypesEveryKind(t *testing.T) {
	for kind := protoreflect.BoolKind; kind <= protoreflect.Sint64Kind; kind++ {
		assert.Contains(t, appKindTypes, kind, "%s has no JSON schema type", kind)
	}

	fields := (&platformv1.ListSchedulerJobsRequest{}).ProtoReflect().Descriptor().Fields()
	status := appValueSchema(fields.ByName("status"))
	assert.Equal(t, "string", status["type"])
	assert.Contains(t, status["enum"], "SCHEDULER_JOB_STATUS_PAUSED")

	start := (&platformv1.GetSchedulerJobHistoryRequest{}).ProtoReflect().Descriptor().Fields().ByName("start_time_unix_ms")
	assert.Equal(t, []string{"integer", "string"}, appValueSchema(start)["type"], "64-bit integers are strings in the JSON mapping")

	jobs := (&platformv1.ListSchedulerJobsResponse{}).ProtoReflect().Descriptor().Fields().ByName("jobs")
	assert.Equal(t, map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object"}}, appFieldSchema(jobs))
}

// The arguments reach the server in the proto3 JSON mapping and the result
// comes back in it.
func TestAppServiceTools_CallTheServer(t *testing.T) {
	cacheServer, schedulerServer, messagingServer := &fakeMCPCache{}, &fakeMCPScheduler{}, &fakeMCPMessaging{}
	objectStorageServer := &fakeMCPObjectStorage{}
	registry := newAppServiceTestRegistry(AppServiceServers{
		Cache: cacheServer, Scheduler: schedulerServer, Messaging: messagingServer, ObjectStorage: objectStorageServer,
	})
	ctx := context.Background()

	result, err := registry.ExecuteTool(ctx, "cache_stats", map[string]interface{}{"entity_type": "users"})
	require.NoError(t, err)
	assert.Equal(t, "users", cacheServer.stats.GetEntityType())
	assert.Equal(t, map[string]interface{}{"hit_rate": 0.5, "size": "1099511627776"}, result)

	result, err = registry.ExecuteTool(ctx, "scheduler_job_list", map[string]interface{}{
		"status": "SCHEDULER_JOB_STATUS_FAILED",
		"tags":   map[string]interface{}{"env": "prod"},
		"limit":  10,
	})
	require.NoError(t, err)
	assert.Equal(t, platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED, schedulerServer.listed.GetStatus())
	assert.Equal(t, map[string]string{"env": "prod"}, schedulerServer.listed.GetTags())
	assert.Equal(t, int32(10), schedulerServer.listed.GetLimit())
	assert.Equal(t, map[string]interface{}{
		"jobs": []interface{}{map[string]interface{}{"job_id": "7", "status": "SCHEDULER_JOB_STATUS_PAUSED"}},
	}, result)

	result, err = registry.ExecuteTool(ctx, "messaging_publish", map[string]interface{}{"channel": "events", "payload": "aGk="})
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), messagingServer.published.GetPayload())
	assert.Equal(t, map[string]interface{}{}, result)

	result, err = registry.ExecuteTool(ctx, "objectstorage_put", map[string]interface{}{
		"key": "docs:a.txt", "value": "aGk=", "tags": map[string]interface{}{"env": "prod"}, "target_backend": "local",
		"replication_policy": map[string]interface{}{"mode": "quorum", "min_replicas": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), objectStorageServer.put.GetValue())
	assert.Equal(t, "quorum", objectStorageServer.put.GetReplicationPolicy().GetMode())
	assert.Equal(t, int32(2), objectStorageServer.put.GetReplicationPolicy().GetMinReplicas())
	assert.Equal(t, map[string]interface{}{"key": "docs:a.txt", "version": "3"}, result)

	// No arguments decode into an empty request.
	_, err = registry.ExecuteTool(ctx, "cache_stats", nil)
	require.NoError(t, err)
	assert.Empty(t, cacheServer.stats.GetEntityType())
}

func TestAppServiceTools_Errors(t *testing.T) {
	ctx := context.Background()

	// A provider that does not serve the application services, or serves
	// only some of them, answers Unavailable.
	for _, registry := range []*ToolRegistry{
		NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger()),
		newAppServiceTestRegistry(AppServiceServers{Cache: &fakeMCPCache{}}),
	} {
		_, err := registry.ExecuteTool(ctx, "scheduler_status", nil)
		var notConfigured ErrAppServiceNotConfigured
		require.True(t, errors.As(err, &notConfigured), "error = %v", err)
		assert.Equal(t, "scheduler", notConfigured.Service)
		assert.Equal(t, mcpwire.CodeForClass(codes.Unavailable), toolErrorCode(err))
	}

	registry := newAppServiceTestRegistry(AppServiceServers{Scheduler: &fakeMCPScheduler{}})
	for _, args := range []map[string]interface{}{
		{"job_identifier": "5"},
		{"job_id": 5},
		{"job_id": make(chan int)},
	} {
		_, err := registry.ExecuteTool(ctx, "scheduler_job_get", args)
		var invalid ErrInvalidArgument
		assert.True(t, errors.As(err, &invalid), "%v: error = %v", args, err)
		assert.Equal(t, mcpwire.CodeForClass(codes.InvalidArgument), toolErrorCode(err), "%v", args)
	}

	// The server's own status passes through.
	_, err := registry.ExecuteTool(ctx, "scheduler_job_get", map[string]interface{}{"job_id": "bad"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = registry.ExecuteTool(ctx, "scheduler_job_get", map[string]interface{}{"job_id": "5"})
	var encoding ErrAppResultEncoding
	require.True(t, errors.As(err, &encoding), "error = %v", err)
	assert.NotNil(t, errors.Unwrap(err))
	assert.Equal(t, mcpwire.CodeForClass(codes.Internal), toolErrorCode(err))

	// An RPC the server does not implement stays Unimplemented.
	_, err = registry.ExecuteTool(ctx, "scheduler_status", nil)
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	// The object storage tools answer Unavailable without their server.
	_, err = registry.ExecuteTool(ctx, "objectstorage_get", map[string]interface{}{"key": "docs:a.txt"})
	var notConfigured ErrAppServiceNotConfigured
	require.True(t, errors.As(err, &notConfigured), "error = %v", err)
	assert.Equal(t, "objectstorage", notConfigured.Service)
}
