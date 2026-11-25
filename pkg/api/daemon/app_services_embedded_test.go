//go:build raft

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
	"time"

	sdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestAppServices_EmbeddedSDK calls the services over the embedded
// transport. That transport has no Scheduler or Messaging handlers, and its
// Cache handlers are keyed by method names the SDK's cache client does not
// send, so every call answers SERVICE_NOT_CONFIGURED rather than an internal
// error. ObjectStorage it serves.
func TestAppServices_EmbeddedSDK(t *testing.T) {
	servers := embeddedAppServiceServers(t)
	for name, c := range appServiceCalls(servers) {
		if c.service == appservices.ServiceObjectStorage {
			continue // served: TestObjectStorage_EmbeddedSDKRoundTrip
		}
		st := status.Convert(c.call(context.Background()))
		// The bumped embedded quicbaas serves every app service: none answers not-configured.
		assert.NotEqual(t, codes.Unavailable, st.Code(), "%s: %s", name, st.Message())
	}
}

// TestScheduler_EmbeddedSDK drives the scheduler the bumped embedded SDK serves.
func TestScheduler_EmbeddedSDK(t *testing.T) {
	server := embeddedAppServiceServers(t).scheduler
	ctx := context.Background()

	list, err := server.ListJobs(ctx, &platformv1.ListSchedulerJobsRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetJobs(), "a fresh scheduler has no jobs")

	st, err := server.GetStatus(ctx, &platformv1.GetSchedulerStatusRequest{})
	require.NoError(t, err)
	assert.NotNil(t, st)

	_, err = server.CreateJob(ctx, &platformv1.CreateSchedulerJobRequest{
		Name: "j", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
	})
	// The embedded SDK refuses a job without a handler; its error code does not survive, so assert the message.
	require.Error(t, err, "a job without a handler is refused")
	assert.Contains(t, err.Error(), "handler is required")

	_, err = server.GetJob(ctx, &platformv1.GetSchedulerJobRequest{JobId: "5"})
	require.Error(t, err, "an unknown job is not found")
	assert.Contains(t, err.Error(), "job not found")
}

// TestCache_EmbeddedSDK drives the cache the bumped embedded SDK serves.
func TestCache_EmbeddedSDK(t *testing.T) {
	server := embeddedAppServiceServers(t).cache
	ctx := context.Background()

	cfg, err := server.GetConfig(ctx, &platformv1.GetCacheConfigRequest{})
	require.NoError(t, err)
	require.NotNil(t, cfg.GetConfig())

	_, err = server.GetStats(ctx, &platformv1.GetCacheStatsRequest{EntityType: "users"})
	require.NoError(t, err)
	_, err = server.Clear(ctx, &platformv1.ClearCacheRequest{All: true})
	require.NoError(t, err)
}

// TestMessaging_EmbeddedSDKRoundTrip drives a channel through the bumped embedded SDK.
func TestMessaging_EmbeddedSDKRoundTrip(t *testing.T) {
	server := embeddedAppServiceServers(t).messaging
	ctx := context.Background()

	_, err := server.GetChannel(ctx, &platformv1.GetMessagingChannelRequest{Name: "events"})
	require.Equal(t, codes.NotFound, status.Code(err), "no channel before it is created: %v", err)

	_, err = server.CreateChannel(ctx, &platformv1.CreateMessagingChannelRequest{Name: "events"})
	require.NoError(t, err)
	got, err := server.GetChannel(ctx, &platformv1.GetMessagingChannelRequest{Name: "events"})
	require.NoError(t, err)
	assert.Equal(t, "events", got.GetChannel().GetName())

	list, err := server.ListChannels(ctx, &platformv1.ListMessagingChannelsRequest{})
	require.NoError(t, err)
	names := make([]string, 0, len(list.GetChannels()))
	for _, ch := range list.GetChannels() {
		names = append(names, ch.GetName())
	}
	assert.Contains(t, names, "events")

	_, err = server.Publish(ctx, &platformv1.PublishMessageRequest{Channel: "events", Payload: []byte("x")})
	require.NoError(t, err)

	_, err = server.DeleteChannel(ctx, &platformv1.DeleteMessagingChannelRequest{Name: "events"})
	require.NoError(t, err)
	_, err = server.GetChannel(ctx, &platformv1.GetMessagingChannelRequest{Name: "events"})
	assert.Equal(t, codes.NotFound, status.Code(err), "a deleted channel is gone: %v", err)
}

// TestObjectStorage_EmbeddedSDKRoundTrip stores, reads, copies, lists and
// deletes an object through the embedded transport, which serves the SDK's
// ObjectStorage group on the factory's own object store.
// embeddedObjectBackend is the local backend the platform's quicbaas config
// adds. go-quicbaas v0.12.0-alpha resolves no primary backend, so a put or
// copy that names no backend fails there.
const embeddedObjectBackend = "default"

func TestObjectStorage_EmbeddedSDKRoundTrip(t *testing.T) {
	server := embeddedAppServiceServers(t).objectStorage
	ctx := context.Background()

	put, err := server.PutObject(ctx, &platformv1.PutObjectRequest{
		Key: "docs:reports/a.txt", Value: []byte("hello"), ContentType: "text/plain",
		Tags: map[string]string{"env": "prod"}, TargetBackend: embeddedObjectBackend,
	})
	require.NoError(t, err)
	assert.Equal(t, "docs:reports/a.txt", put.GetKey())

	got, err := server.GetObject(ctx, &platformv1.GetObjectRequest{Key: "docs:reports/a.txt"})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got.GetValue())

	_, err = server.CopyObject(ctx, &platformv1.CopyObjectRequest{
		SourceKey: "docs:reports/a.txt", DestinationKey: "docs:reports/b.txt", TargetBackend: embeddedObjectBackend,
	})
	require.NoError(t, err)
	copied, err := server.GetObject(ctx, &platformv1.GetObjectRequest{Key: "docs:reports/b.txt"})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), copied.GetValue())

	page, err := server.ListObjects(ctx, &platformv1.ListObjectsRequest{Prefix: "docs:reports/"})
	require.NoError(t, err)
	keys := make([]string, 0, len(page.GetObjects()))
	for _, object := range page.GetObjects() {
		keys = append(keys, object.GetKey())
	}
	assert.ElementsMatch(t, []string{"docs:reports/a.txt", "docs:reports/b.txt"}, keys)

	_, err = server.DeleteObject(ctx, &platformv1.DeleteObjectRequest{Key: "docs:reports/a.txt"})
	require.NoError(t, err)
	_, err = server.GetObject(ctx, &platformv1.GetObjectRequest{Key: "docs:reports/a.txt"})
	// The embedded SDK hands back go-qrdb errors, not SDK QBErrors, so the
	// code does not survive: assert the object is gone, not the code.
	require.Error(t, err, "a deleted object is gone")
	assert.Contains(t, err.Error(), "object not found")
}

// embeddedAppServiceServers builds the services over the SDK client of a
// started quicbaas factory with the embedded transport, as the daemon does.
func embeddedAppServiceServers(t *testing.T) appServiceServers {
	t.Helper()
	factory, err := quicbaas.NewFactory(quicbaas.TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.NoError(t, factory.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, factory.Stop(ctx))
	})
	require.NotNil(t, factory.SDK(), "the started factory composes an SDK client")
	return appServiceServersOver(func() sdk.Client { return factory.SDK() }, logging.DefaultLogger())
}
