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

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// connectAppServicesMCP serves the application service tools of a daemon MCP
// provider and connects the SDK MCP client to them.
func connectAppServicesMCP(t *testing.T, servers appServiceServers) grpc.ClientConnInterface {
	t.Helper()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	provider.SetAppServiceServers(servers.mcpServers())
	return serveMCPProvider(t, provider).Connection()
}

// Every method of the three services travels from the SDK MCP client through
// the daemon tools to the service layer and back.
func TestAppServicesMCPClientAgainstDaemonTools(t *testing.T) {
	cacheClient, schedulerClient, messagingClient := &fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}
	objectStorageClient := &fakeAppObjectStorage{}
	conn := connectAppServicesMCP(t, appServersWith(cacheClient, schedulerClient, messagingClient, objectStorageClient))

	for method, request := range appRESTRequests() {
		err := conn.Invoke(context.Background(), method, request, appRESTResponseFor(t, method))
		assert.NoError(t, err, method)
	}

	// The enum and map filters arrive intact.
	require.NotNil(t, schedulerClient.listed)
	require.NotNil(t, schedulerClient.listed.Status)
	assert.Equal(t, scheduler.JobStatusFailed, *schedulerClient.listed.Status)
	assert.Equal(t, map[string]string{"env": "prod", "team": "net"}, schedulerClient.listed.Tags)
	assert.Equal(t, 10, schedulerClient.listed.Limit)
	require.NotNil(t, messagingClient.published)
	assert.Equal(t, "b", messagingClient.published.Metadata["a"])

	// An object key holding ":", "/" and a space arrives intact.
	var head platformv1.HeadObjectResponse
	require.NoError(t, conn.Invoke(context.Background(), platformv1.ObjectStorageService_HeadObject_FullMethodName,
		&platformv1.HeadObjectRequest{Key: "docs:a/b c.txt"}, &head))
	assert.Equal(t, "docs:a/b c.txt", objectStorageClient.name)
	assert.Equal(t, int32(2), head.GetReplicaCount())

	var job platformv1.GetSchedulerJobResponse
	require.NoError(t, conn.Invoke(context.Background(), platformv1.SchedulerService_GetJob_FullMethodName,
		&platformv1.GetSchedulerJobRequest{JobId: "77"}, &job))
	assert.Equal(t, "77", job.GetJob().GetJobId())
}

// A daemon without the SDK answers every method Unavailable over MCP, as it
// does on gRPC, and a request the service refuses stays InvalidArgument.
func TestAppServicesMCPClientAgainstDaemonTools_Errors(t *testing.T) {
	unwired := connectAppServicesMCP(t, newAppServiceServers(nil, nil))
	// A provider the servers were never wired into answers the same.
	unset := serveMCPProvider(t, NewMCPServiceProvider(&MCPServiceProviderConfig{})).Connection()
	for method, request := range appRESTRequests() {
		err := unwired.Invoke(context.Background(), method, request, appRESTResponseFor(t, method))
		assert.Equal(t, codes.Unavailable, status.Code(err), method)
		err = unset.Invoke(context.Background(), method, request, appRESTResponseFor(t, method))
		assert.Equal(t, codes.Unavailable, status.Code(err), method)
	}

	conn := connectAppServicesMCP(t, appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	err := conn.Invoke(context.Background(), platformv1.SchedulerService_GetJob_FullMethodName,
		&platformv1.GetSchedulerJobRequest{JobId: "abc"}, &platformv1.GetSchedulerJobResponse{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a job ID that is not decimal")
}

func TestAppServiceServers_MCPServers(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}).mcpServers()
	assert.NotNil(t, servers.Cache)
	assert.NotNil(t, servers.Scheduler)
	assert.NotNil(t, servers.Messaging)

	// An unset server stays a nil interface, so its tools answer
	// Unavailable instead of calling through a typed nil.
	empty := appServiceServers{}.mcpServers()
	assert.Nil(t, empty.Cache)
	assert.Nil(t, empty.Scheduler)
	assert.Nil(t, empty.Messaging)
}
