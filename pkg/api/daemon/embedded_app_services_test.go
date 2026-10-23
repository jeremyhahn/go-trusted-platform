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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// embeddedAppConn starts an embedded host, optionally swaps its application
// services for ones backed by fakes, and returns the in-process connection.
func embeddedAppConn(t *testing.T, servers *appServiceServers) *embedded.Adapter {
	t.Helper()
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, host.Stop(context.Background())) })

	services := host.Services()
	if servers != nil {
		host.daemon.appServices = *servers
		services = host.daemon.embeddedServices()
	}
	adapter, err := embedded.New(services)
	require.NoError(t, err)
	return adapter
}

func TestNewEmbeddedHost_ServesTheAppServices(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{})
	conn := embeddedAppConn(t, &servers).Connection()
	ctx := context.Background()

	_, err := platformv1.NewCacheServiceClient(conn).GetStats(ctx, &platformv1.GetCacheStatsRequest{})
	assert.NoError(t, err, "cache")

	_, err = platformv1.NewSchedulerServiceClient(conn).GetStatus(ctx, &platformv1.GetSchedulerStatusRequest{})
	assert.NoError(t, err, "scheduler")

	channels, err := platformv1.NewMessagingServiceClient(conn).ListChannels(ctx, &platformv1.ListMessagingChannelsRequest{})
	require.NoError(t, err, "messaging")
	assert.Len(t, channels.GetChannels(), 2)

	head, err := platformv1.NewObjectStorageServiceClient(conn).HeadObject(ctx, &platformv1.HeadObjectRequest{Key: "docs:a.txt"})
	require.NoError(t, err, "object storage")
	assert.Equal(t, int32(2), head.GetReplicaCount())
}

func TestNewEmbeddedHost_AppServicesRefuseAnInvalidRequest(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{})
	conn := embeddedAppConn(t, &servers).Connection()

	_, err := platformv1.NewMessagingServiceClient(conn).GetChannel(context.Background(), &platformv1.GetMessagingChannelRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)

	_, err = platformv1.NewSchedulerServiceClient(conn).GetJob(context.Background(), &platformv1.GetSchedulerJobRequest{JobId: "x"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)

	_, err = platformv1.NewObjectStorageServiceClient(conn).GetObject(context.Background(), &platformv1.GetObjectRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
}

// A node without an SDK answers Unavailable naming the service, as the
// network transports do, never Unimplemented.
func TestNewEmbeddedHost_AppServicesWithoutAnSDKAreUnavailable(t *testing.T) {
	conn := embeddedAppConn(t, nil).Connection()
	ctx := context.Background()

	calls := map[string]func() error{
		"cache": func() error {
			_, err := platformv1.NewCacheServiceClient(conn).GetConfig(ctx, &platformv1.GetCacheConfigRequest{})
			return err
		},
		"scheduler": func() error {
			_, err := platformv1.NewSchedulerServiceClient(conn).ListJobs(ctx, &platformv1.ListSchedulerJobsRequest{})
			return err
		},
		"messaging": func() error {
			_, err := platformv1.NewMessagingServiceClient(conn).GetStats(ctx, &platformv1.GetMessagingStatsRequest{})
			return err
		},
		"objectstorage": func() error {
			_, err := platformv1.NewObjectStorageServiceClient(conn).ListObjects(ctx, &platformv1.ListObjectsRequest{})
			return err
		},
	}
	for service, call := range calls {
		st := status.Convert(call())
		require.Equal(t, codes.Unavailable, st.Code(), service)
		assert.Equal(t, service, notConfiguredServiceName(t, st), service)
	}
}
