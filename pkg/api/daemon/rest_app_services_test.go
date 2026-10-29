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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// appRESTRequests holds one valid request of every CacheService,
// SchedulerService and MessagingService method.
func appRESTRequests() map[string]proto.Message {
	size := int64(10)
	return map[string]proto.Message{
		platformv1.CacheService_GetStats_FullMethodName:     &platformv1.GetCacheStatsRequest{EntityType: "users"},
		platformv1.CacheService_GetConfig_FullMethodName:    &platformv1.GetCacheConfigRequest{},
		platformv1.CacheService_UpdateConfig_FullMethodName: &platformv1.UpdateCacheConfigRequest{L1Size: &size},
		platformv1.CacheService_Clear_FullMethodName:        &platformv1.ClearCacheRequest{All: true},

		platformv1.SchedulerService_CreateJob_FullMethodName: &platformv1.CreateSchedulerJobRequest{
			Name: "j", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
		},
		platformv1.SchedulerService_ListJobs_FullMethodName: &platformv1.ListSchedulerJobsRequest{
			Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED,
			Tags:   map[string]string{"env": "prod", "team": "net"},
			Limit:  10,
		},
		platformv1.SchedulerService_GetJob_FullMethodName:        &platformv1.GetSchedulerJobRequest{JobId: "5"},
		platformv1.SchedulerService_UpdateJob_FullMethodName:     &platformv1.UpdateSchedulerJobRequest{JobId: "5", Name: "n"},
		platformv1.SchedulerService_DeleteJob_FullMethodName:     &platformv1.DeleteSchedulerJobRequest{JobId: "5"},
		platformv1.SchedulerService_TriggerJob_FullMethodName:    &platformv1.TriggerSchedulerJobRequest{JobId: "5"},
		platformv1.SchedulerService_PauseJob_FullMethodName:      &platformv1.PauseSchedulerJobRequest{JobId: "5"},
		platformv1.SchedulerService_ResumeJob_FullMethodName:     &platformv1.ResumeSchedulerJobRequest{JobId: "5"},
		platformv1.SchedulerService_CancelJob_FullMethodName:     &platformv1.CancelSchedulerJobRequest{JobId: "5", Reason: "obsolete"},
		platformv1.SchedulerService_GetJobHistory_FullMethodName: &platformv1.GetSchedulerJobHistoryRequest{JobId: "5", Limit: 3},
		platformv1.SchedulerService_GetStatus_FullMethodName:     &platformv1.GetSchedulerStatusRequest{},

		platformv1.MessagingService_CreateChannel_FullMethodName: &platformv1.CreateMessagingChannelRequest{Name: "events"},
		platformv1.MessagingService_ListChannels_FullMethodName:  &platformv1.ListMessagingChannelsRequest{},
		platformv1.MessagingService_GetChannel_FullMethodName:    &platformv1.GetMessagingChannelRequest{Name: "events"},
		platformv1.MessagingService_DeleteChannel_FullMethodName: &platformv1.DeleteMessagingChannelRequest{Name: "events"},
		platformv1.MessagingService_Publish_FullMethodName: &platformv1.PublishMessageRequest{
			Channel: "events", Payload: []byte("x"), Metadata: map[string]string{"a": "b"},
		},
		platformv1.MessagingService_GetChannelStats_FullMethodName: &platformv1.GetMessagingChannelStatsRequest{Channel: "events"},
		platformv1.MessagingService_GetStats_FullMethodName:        &platformv1.GetMessagingStatsRequest{},
		platformv1.MessagingService_GetDedupStats_FullMethodName:   &platformv1.GetMessagingDedupStatsRequest{},

		platformv1.ObjectStorageService_PutObject_FullMethodName: &platformv1.PutObjectRequest{
			Key: "docs:reports/a.txt", Value: []byte("a"), Tags: map[string]string{"env": "prod"}, TargetBackend: "local",
			ReplicationPolicy: &platformv1.ObjectReplicationPolicy{Mode: "quorum", MinReplicas: 2},
		},
		platformv1.ObjectStorageService_GetObject_FullMethodName:    &platformv1.GetObjectRequest{Key: "docs:reports/a.txt", IncludeMetadata: true},
		platformv1.ObjectStorageService_DeleteObject_FullMethodName: &platformv1.DeleteObjectRequest{Key: "docs:reports/a.txt"},
		platformv1.ObjectStorageService_HeadObject_FullMethodName:   &platformv1.HeadObjectRequest{Key: "docs:reports/a.txt"},
		platformv1.ObjectStorageService_ListObjects_FullMethodName:  &platformv1.ListObjectsRequest{Prefix: "docs:", Limit: 5},
		platformv1.ObjectStorageService_CopyObject_FullMethodName: &platformv1.CopyObjectRequest{
			SourceKey: "docs:reports/a.txt", DestinationKey: "docs:reports/b.txt", TargetBackend: "local",
		},
		platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName:  &platformv1.ListObjectsByTagRequest{TagName: "env", TagValue: "prod"},
		platformv1.ObjectStorageService_ListTenantObjects_FullMethodName: &platformv1.ListTenantObjectsRequest{TenantId: "acme", Limit: 2},
	}
}

// appRESTResponseFor returns an empty response message of a gRPC method.
func appRESTResponseFor(t *testing.T, method string) proto.Message {
	t.Helper()
	name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(method, "/"), "/", "."))
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
	require.NoError(t, err, method)
	methodDesc, ok := desc.(protoreflect.MethodDescriptor)
	require.True(t, ok, "%s is not a method", method)
	response, err := protoregistry.GlobalTypes.FindMessageByName(methodDesc.Output().FullName())
	require.NoError(t, err, method)
	return response.New().Interface()
}

// connectAppServicesREST mounts the application service routes on a daemon
// REST server behind its mTLS scope guard and connects the SDK REST client as
// the operator certificate.
func connectAppServicesREST(t *testing.T, servers appServiceServers) grpc.ClientConnInterface {
	t.Helper()
	return connectPhase35REST(t, appServicesRESTHandler(t, servers)).Connection()
}

// appServicesRESTHandler serves servers on the daemon REST router, behind
// the mTLS scope guard, to a caller holding the operator certificate.
func appServicesRESTHandler(t *testing.T, servers appServiceServers) http.Handler {
	t.Helper()
	bundle := operatorTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = bundle.CAPool
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	guard, err := newRESTScopeGuard(config, nil, logging.DefaultLogger())
	require.NoError(t, err)

	s := newTestRESTServerForPhase35(t)
	s.SetAppServiceHandlers(servers.restServers(), guard)

	// The httptest listener does not ask for a client certificate, so the
	// operator chain the mTLS handshake would verify is set on each request.
	operator := []*x509.Certificate{leafOf(t, bundle.ClientCert), bundle.CACert}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS.VerifiedChains = [][]*x509.Certificate{operator}
		s.router.ServeHTTP(w, r)
	})
}

// TestAppServicesREST_SDKNotFoundIs404 answers the SDK's own typed NotFound
// error over REST: the client sees 404, not 500.
func TestAppServicesREST_SDKNotFoundIs404(t *testing.T) {
	notFound := sdkerrors.NewNotFound("Get", "no such resource")
	handler := appServicesRESTHandler(t, appServersWith(&fakeAppCache{err: notFound}, &fakeAppScheduler{err: notFound}, &fakeAppMessaging{err: notFound}, &fakeAppObjectStorage{err: notFound}))
	for _, path := range []string{"/api/v1/cache/config", "/api/v1/scheduler/jobs/7", "/api/v1/messaging/channels/orders"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://platformd"+path, nil))
		assert.Equal(t, http.StatusNotFound, recorder.Code, path)
		assert.Contains(t, recorder.Body.String(), "no such resource", path)
	}
}

// Every method of the three services travels from the SDK REST client through
// the daemon routes to the service layer and back.
func TestAppServicesRESTClientAgainstDaemonRouter(t *testing.T) {
	cacheClient, schedulerClient, messagingClient := &fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}
	objectStorageClient := &fakeAppObjectStorage{}
	conn := connectAppServicesREST(t, appServersWith(cacheClient, schedulerClient, messagingClient, objectStorageClient))

	for method, request := range appRESTRequests() {
		err := conn.Invoke(context.Background(), method, request, appRESTResponseFor(t, method))
		assert.NoError(t, err, method)
	}

	// The query string carries the enum and map filters intact.
	require.NotNil(t, schedulerClient.listed)
	require.NotNil(t, schedulerClient.listed.Status)
	assert.Equal(t, scheduler.JobStatusFailed, *schedulerClient.listed.Status)
	assert.Equal(t, map[string]string{"env": "prod", "team": "net"}, schedulerClient.listed.Tags)
	assert.Equal(t, 10, schedulerClient.listed.Limit)
	// The body and the path parameter both reach the request.
	require.NotNil(t, messagingClient.published)
	assert.Equal(t, "b", messagingClient.published.Metadata["a"])

	// An object key holding ":", "/" and a space arrives intact.
	var head platformv1.HeadObjectResponse
	require.NoError(t, conn.Invoke(context.Background(), platformv1.ObjectStorageService_HeadObject_FullMethodName,
		&platformv1.HeadObjectRequest{Key: "docs:a/b c.txt"}, &head))
	assert.Equal(t, "docs:a/b c.txt", objectStorageClient.name)
	assert.Equal(t, int32(2), head.GetReplicaCount())
	assert.Equal(t, "events", messagingClient.name)

	var job platformv1.GetSchedulerJobResponse
	require.NoError(t, conn.Invoke(context.Background(), platformv1.SchedulerService_GetJob_FullMethodName,
		&platformv1.GetSchedulerJobRequest{JobId: "77"}, &job))
	assert.Equal(t, "77", job.GetJob().GetJobId())
}

// A daemon without the SDK answers every method Unavailable over REST, as it
// does on gRPC, and a request the service refuses stays InvalidArgument.
func TestAppServicesRESTClientAgainstDaemonRouter_Errors(t *testing.T) {
	unwired := connectAppServicesREST(t, newAppServiceServers(nil, nil))
	for method, request := range appRESTRequests() {
		err := unwired.Invoke(context.Background(), method, request, appRESTResponseFor(t, method))
		assert.Equal(t, codes.Unavailable, status.Code(err), method)
	}

	conn := connectAppServicesREST(t, appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	err := conn.Invoke(context.Background(), platformv1.SchedulerService_GetJob_FullMethodName,
		&platformv1.GetSchedulerJobRequest{JobId: "abc"}, &platformv1.GetSchedulerJobResponse{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a job ID that is not decimal")
}

func TestAppServiceServers_RESTServers(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}).restServers()
	assert.NotNil(t, servers.Cache)
	assert.NotNil(t, servers.Scheduler)
	assert.NotNil(t, servers.Messaging)

	// An unset server stays a nil interface, never a typed nil, so the
	// REST routes answer 503 instead of dereferencing it.
	empty := appServiceServers{}.restServers()
	assert.Nil(t, empty.Cache)
	assert.Nil(t, empty.Scheduler)
	assert.Nil(t, empty.Messaging)
}

// The webservice listener is handed the daemon's own servers, never copies.
func TestDaemon_AppServiceRESTServers(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{})
	got := (&Daemon{appServices: servers}).AppServiceRESTServers()
	assert.Same(t, servers.cache, got.Cache)
	assert.Same(t, servers.scheduler, got.Scheduler)
	assert.Same(t, servers.messaging, got.Messaging)

	empty := (&Daemon{}).AppServiceRESTServers()
	assert.Nil(t, empty.Cache)
	assert.Nil(t, empty.Scheduler)
	assert.Nil(t, empty.Messaging)
}

// Without an authorization guard every application service route is
// refused before it reaches a server.
func TestRESTServer_SetAppServiceHandlers_NilGuardRefuses(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetAppServiceHandlers(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}).restServers(), nil)

	for _, path := range []string{"/api/v1/cache/config", "/api/v1/scheduler/status", "/api/v1/messaging/stats"} {
		code, _ := doJSON(t, s, http.MethodGet, path, nil)
		assert.Equal(t, http.StatusForbidden, code, path)
	}
}
