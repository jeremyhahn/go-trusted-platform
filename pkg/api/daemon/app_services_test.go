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
	"math"
	"testing"
	"time"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cache"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// errAppSDK is the failure the fake SDK clients answer with.
type errAppSDK struct{}

func (errAppSDK) Error() string { return "sdk unreachable" }

var appTestTime = time.UnixMilli(1_700_000_000_000)

type fakeAppCache struct {
	err    error
	update *cache.UpdateCacheConfigRequest
}

func (f *fakeAppCache) GetCacheStats(context.Context, *cache.GetCacheStatsRequest) (*cache.GetCacheStatsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cache.GetCacheStatsResponse{HitRate: 0.5, Size: 7, Hits: 3, Misses: 3}, nil
}

func (f *fakeAppCache) ClearCache(context.Context, *cache.ClearCacheRequest) (*cache.ClearCacheResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cache.ClearCacheResponse{EntriesCleared: 4}, nil
}

func (f *fakeAppCache) GetCacheConfig(context.Context, *cache.GetCacheConfigRequest) (*cache.GetCacheConfigResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cache.GetCacheConfigResponse{L1Size: 100, L1TTL: time.Minute, CleanupInterval: time.Second, Enabled: true}, nil
}

func (f *fakeAppCache) UpdateCacheConfig(_ context.Context, req *cache.UpdateCacheConfigRequest) (*cache.UpdateCacheConfigResponse, error) {
	f.update = req
	if f.err != nil {
		return nil, f.err
	}
	return &cache.UpdateCacheConfigResponse{Updated: true, NewConfig: &cache.GetCacheConfigResponse{L1Size: 200}}, nil
}

type fakeAppScheduler struct {
	// Client supplies the node and placement methods the scheduler
	// service never calls; reaching one panics on the nil interface.
	scheduler.Client

	err     error
	jobID   uint64
	created *scheduler.CreateJobRequest
	updated *scheduler.UpdateJobRequest
	listed  *scheduler.ListJobsOptions
	history *scheduler.HistoryOptions
}

func (f *fakeAppScheduler) job(jobID uint64) *scheduler.JobInfo {
	return &scheduler.JobInfo{
		JobID:     jobID,
		Name:      "backup",
		JobType:   scheduler.JobTypeRecurring,
		Status:    scheduler.JobStatusPaused,
		OwnerType: scheduler.OwnerTypeTenant,
		Timeout:   2 * time.Second,
		CreatedAt: appTestTime,
	}
}

func (f *fakeAppScheduler) CreateJob(_ context.Context, req *scheduler.CreateJobRequest) (*scheduler.CreateJobResponse, error) {
	f.created = req
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.CreateJobResponse{JobID: math.MaxUint64, NextRunAt: appTestTime}, nil
}

func (f *fakeAppScheduler) GetJob(_ context.Context, jobID uint64) (*scheduler.JobInfo, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return f.job(jobID), nil
}

func (f *fakeAppScheduler) UpdateJob(_ context.Context, req *scheduler.UpdateJobRequest) (*scheduler.JobInfo, error) {
	f.updated = req
	if f.err != nil {
		return nil, f.err
	}
	return f.job(req.JobID), nil
}

func (f *fakeAppScheduler) DeleteJob(_ context.Context, jobID uint64) error {
	f.jobID = jobID
	return f.err
}

func (f *fakeAppScheduler) ListJobs(_ context.Context, opts *scheduler.ListJobsOptions) (*scheduler.ListJobsResponse, error) {
	f.listed = opts
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.ListJobsResponse{Jobs: []scheduler.JobInfo{*f.job(1), *f.job(2)}, TotalCount: 2}, nil
}

func (f *fakeAppScheduler) TriggerJob(_ context.Context, jobID uint64) (*scheduler.TriggerJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.TriggerJobResponse{JobID: jobID, ExecutionID: 9, StartedAt: appTestTime}, nil
}

func (f *fakeAppScheduler) PauseJob(_ context.Context, jobID uint64) (*scheduler.PauseJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.PauseJobResponse{JobID: jobID, PausedAt: appTestTime}, nil
}

func (f *fakeAppScheduler) ResumeJob(_ context.Context, jobID uint64) (*scheduler.ResumeJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.ResumeJobResponse{JobID: jobID, ResumedAt: appTestTime}, nil
}

func (f *fakeAppScheduler) CancelJob(_ context.Context, jobID uint64, reason string) (*scheduler.CancelJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.CancelJobResponse{JobID: jobID, CanceledAt: appTestTime, Reason: reason}, nil
}

func (f *fakeAppScheduler) GetJobHistory(_ context.Context, jobID uint64, opts *scheduler.HistoryOptions) (*scheduler.JobHistoryResponse, error) {
	f.jobID, f.history = jobID, opts
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.JobHistoryResponse{
		JobID: jobID,
		Executions: []scheduler.JobExecution{{
			ExecutionID: 3, JobID: jobID, Status: scheduler.JobStatusFailed,
			StartedAt: appTestTime, Duration: 1500 * time.Millisecond, Error: "boom",
		}},
		TotalCount: 1,
	}, nil
}

func (f *fakeAppScheduler) GetStatus(context.Context) (*scheduler.SchedulerStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.SchedulerStatus{Healthy: true, TotalJobs: 3, WorkerCount: 4, UptimeDuration: time.Minute}, nil
}

// fakeAppMessaging embeds the interface: the subscription calls the daemon
// never makes stay nil.
type fakeAppMessaging struct {
	messaging.Client

	err       error
	name      string
	created   *messaging.CreateChannelRequest
	published *messaging.PublishRequest
}

func (f *fakeAppMessaging) CreateChannel(_ context.Context, req *messaging.CreateChannelRequest) (*messaging.Channel, error) {
	f.created = req
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Channel{Name: req.Name, Codec: req.Codec, TTL: req.TTL, MaxHistory: req.MaxHistory, CreatedAt: appTestTime}, nil
}

func (f *fakeAppMessaging) DeleteChannel(_ context.Context, name string) error {
	f.name = name
	return f.err
}

func (f *fakeAppMessaging) GetChannel(_ context.Context, name string) (*messaging.Channel, error) {
	f.name = name
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Channel{Name: name, Subscribers: 2}, nil
}

func (f *fakeAppMessaging) ListChannels(context.Context) (*messaging.ListChannelsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.ListChannelsResponse{Channels: []*messaging.Channel{{Name: "a"}, nil, {Name: "b"}}}, nil
}

func (f *fakeAppMessaging) Publish(_ context.Context, req *messaging.PublishRequest) error {
	f.published = req
	return f.err
}

func (f *fakeAppMessaging) GetStats(context.Context) (*messaging.Stats, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Stats{TotalChannels: 2, BufferUtilization: 0.25}, nil
}

func (f *fakeAppMessaging) GetDedupStats(context.Context) (*messaging.DedupStats, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.DedupStats{TotalChecks: 5, WindowDuration: time.Minute}, nil
}

func (f *fakeAppMessaging) GetChannelStats(_ context.Context, channel string) (*messaging.ChannelStats, error) {
	f.name = channel
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.ChannelStats{Name: channel, MessagesInHistory: 6}, nil
}

// fakeAppObjectStorage is the SDK's ObjectStorage group. The embedded
// interface is nil: an operation the tests do not exercise panics.
type fakeAppObjectStorage struct {
	objectstorage.Client

	err  error
	name string
}

func (f *fakeAppObjectStorage) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	f.name = req.Key
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.PutObjectResponse{Key: req.Key, Version: 3, CreatedAt: 5_000_000}, nil
}

func (f *fakeAppObjectStorage) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	f.name = req.Key
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: []byte("data"), Size: 4}, nil
}

func (f *fakeAppObjectStorage) DeleteObject(_ context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	f.name = req.Key
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: true}, nil
}

func (f *fakeAppObjectStorage) HeadObject(_ context.Context, req *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	f.name = req.Key
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.HeadObjectResponse{Key: req.Key, Exists: true, ReplicaCount: 2}, nil
}

func (f *fakeAppObjectStorage) ListObjects(_ context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	f.name = req.Prefix
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListObjectsResponse{TotalCount: 1, Objects: []*objectstorage.ObjectSummary{{Key: req.Prefix + "a"}}}, nil
}

func (f *fakeAppObjectStorage) CopyObject(_ context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	f.name = req.SourceKey
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.CopyObjectResponse{Key: req.DestinationKey}, nil
}

func (f *fakeAppObjectStorage) ListByTag(_ context.Context, req *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	f.name = req.TagName
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListByTagResponse{TotalCount: 2}, nil
}

func (f *fakeAppObjectStorage) ListByTenant(_ context.Context, req *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	f.name = req.TenantID
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListByTenantResponse{TotalCount: 3}, nil
}

// appServersWith builds the three gRPC services over the given fakes.
func appServersWith(c *fakeAppCache, s *fakeAppScheduler, m *fakeAppMessaging, o *fakeAppObjectStorage) appServiceServers {
	return appServiceServers{
		cache:         NewCacheGRPCService(nil, appservices.NewCacheService(func() cache.Client { return c })),
		scheduler:     NewSchedulerGRPCService(nil, appservices.NewSchedulerService(func() scheduler.Client { return s })),
		messaging:     NewMessagingGRPCService(nil, appservices.NewMessagingService(func() messaging.Client { return m })),
		objectStorage: NewObjectStorageGRPCService(nil, appservices.NewObjectStorageService(func() objectstorage.Client { return o })),
	}
}

// appServiceCall is one valid call of one RPC, labelled with the service
// that serves it.
type appServiceCall struct {
	service string
	call    func(ctx context.Context) error
}

// appServiceCalls returns one valid call of every RPC of the three services.
func appServiceCalls(servers appServiceServers) map[string]appServiceCall {
	c, s, m, o := servers.cache, servers.scheduler, servers.messaging, servers.objectStorage
	cacheCall := func(fn func(ctx context.Context) error) appServiceCall {
		return appServiceCall{service: appservices.ServiceCache, call: fn}
	}
	schedulerCall := func(fn func(ctx context.Context) error) appServiceCall {
		return appServiceCall{service: appservices.ServiceScheduler, call: fn}
	}
	messagingCall := func(fn func(ctx context.Context) error) appServiceCall {
		return appServiceCall{service: appservices.ServiceMessaging, call: fn}
	}
	objectStorageCall := func(fn func(ctx context.Context) error) appServiceCall {
		return appServiceCall{service: appservices.ServiceObjectStorage, call: fn}
	}
	size := int64(10)
	return map[string]appServiceCall{
		"cache.GetStats": cacheCall(func(ctx context.Context) error {
			_, err := c.GetStats(ctx, &platformv1.GetCacheStatsRequest{EntityType: "users"})
			return err
		}),
		"cache.Clear": cacheCall(func(ctx context.Context) error {
			_, err := c.Clear(ctx, &platformv1.ClearCacheRequest{All: true})
			return err
		}),
		"cache.GetConfig": cacheCall(func(ctx context.Context) error {
			_, err := c.GetConfig(ctx, &platformv1.GetCacheConfigRequest{})
			return err
		}),
		"cache.UpdateConfig": cacheCall(func(ctx context.Context) error {
			_, err := c.UpdateConfig(ctx, &platformv1.UpdateCacheConfigRequest{L1Size: &size})
			return err
		}),
		"scheduler.CreateJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.CreateJob(ctx, &platformv1.CreateSchedulerJobRequest{
				Name: "j", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
			})
			return err
		}),
		"scheduler.GetJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.GetJob(ctx, &platformv1.GetSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.UpdateJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.UpdateJob(ctx, &platformv1.UpdateSchedulerJobRequest{JobId: "5", Name: "n"})
			return err
		}),
		"scheduler.DeleteJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.DeleteJob(ctx, &platformv1.DeleteSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.ListJobs": schedulerCall(func(ctx context.Context) error {
			_, err := s.ListJobs(ctx, &platformv1.ListSchedulerJobsRequest{})
			return err
		}),
		"scheduler.TriggerJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.TriggerJob(ctx, &platformv1.TriggerSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.PauseJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.PauseJob(ctx, &platformv1.PauseSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.ResumeJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.ResumeJob(ctx, &platformv1.ResumeSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.CancelJob": schedulerCall(func(ctx context.Context) error {
			_, err := s.CancelJob(ctx, &platformv1.CancelSchedulerJobRequest{JobId: "5"})
			return err
		}),
		"scheduler.GetJobHistory": schedulerCall(func(ctx context.Context) error {
			_, err := s.GetJobHistory(ctx, &platformv1.GetSchedulerJobHistoryRequest{JobId: "5"})
			return err
		}),
		"scheduler.GetStatus": schedulerCall(func(ctx context.Context) error {
			_, err := s.GetStatus(ctx, &platformv1.GetSchedulerStatusRequest{})
			return err
		}),
		"messaging.CreateChannel": messagingCall(func(ctx context.Context) error {
			_, err := m.CreateChannel(ctx, &platformv1.CreateMessagingChannelRequest{Name: "events"})
			return err
		}),
		"messaging.DeleteChannel": messagingCall(func(ctx context.Context) error {
			_, err := m.DeleteChannel(ctx, &platformv1.DeleteMessagingChannelRequest{Name: "events"})
			return err
		}),
		"messaging.GetChannel": messagingCall(func(ctx context.Context) error {
			_, err := m.GetChannel(ctx, &platformv1.GetMessagingChannelRequest{Name: "events"})
			return err
		}),
		"messaging.ListChannels": messagingCall(func(ctx context.Context) error {
			_, err := m.ListChannels(ctx, &platformv1.ListMessagingChannelsRequest{})
			return err
		}),
		"messaging.Publish": messagingCall(func(ctx context.Context) error {
			_, err := m.Publish(ctx, &platformv1.PublishMessageRequest{Channel: "events", Payload: []byte("x")})
			return err
		}),
		"messaging.GetStats": messagingCall(func(ctx context.Context) error {
			_, err := m.GetStats(ctx, &platformv1.GetMessagingStatsRequest{})
			return err
		}),
		"messaging.GetDedupStats": messagingCall(func(ctx context.Context) error {
			_, err := m.GetDedupStats(ctx, &platformv1.GetMessagingDedupStatsRequest{})
			return err
		}),
		"messaging.GetChannelStats": messagingCall(func(ctx context.Context) error {
			_, err := m.GetChannelStats(ctx, &platformv1.GetMessagingChannelStatsRequest{Channel: "events"})
			return err
		}),
		"objectstorage.PutObject": objectStorageCall(func(ctx context.Context) error {
			_, err := o.PutObject(ctx, &platformv1.PutObjectRequest{Key: "docs:a.txt", Value: []byte("a"), TargetBackend: "local"})
			return err
		}),
		"objectstorage.GetObject": objectStorageCall(func(ctx context.Context) error {
			_, err := o.GetObject(ctx, &platformv1.GetObjectRequest{Key: "docs:a.txt"})
			return err
		}),
		"objectstorage.DeleteObject": objectStorageCall(func(ctx context.Context) error {
			_, err := o.DeleteObject(ctx, &platformv1.DeleteObjectRequest{Key: "docs:a.txt"})
			return err
		}),
		"objectstorage.HeadObject": objectStorageCall(func(ctx context.Context) error {
			_, err := o.HeadObject(ctx, &platformv1.HeadObjectRequest{Key: "docs:a.txt"})
			return err
		}),
		"objectstorage.ListObjects": objectStorageCall(func(ctx context.Context) error {
			_, err := o.ListObjects(ctx, &platformv1.ListObjectsRequest{Prefix: "docs:"})
			return err
		}),
		"objectstorage.CopyObject": objectStorageCall(func(ctx context.Context) error {
			_, err := o.CopyObject(ctx, &platformv1.CopyObjectRequest{SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", TargetBackend: "local"})
			return err
		}),
		"objectstorage.ListObjectsByTag": objectStorageCall(func(ctx context.Context) error {
			_, err := o.ListObjectsByTag(ctx, &platformv1.ListObjectsByTagRequest{TagName: "env"})
			return err
		}),
		"objectstorage.ListTenantObjects": objectStorageCall(func(ctx context.Context) error {
			_, err := o.ListTenantObjects(ctx, &platformv1.ListTenantObjectsRequest{TenantId: "acme"})
			return err
		}),
	}
}

func TestAppServices_EveryCallReachesTheSDK(t *testing.T) {
	servers := appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{})
	for name, c := range appServiceCalls(servers) {
		assert.NoError(t, c.call(context.Background()), name)
	}
}

func TestAppServices_NotConfiguredOnEveryCall(t *testing.T) {
	// A daemon whose DAO factory has no SDK: every call answers Unavailable
	// with the ErrorInfo detail naming its service.
	for name, c := range appServiceCalls(newAppServiceServers(nil, nil)) {
		st := status.Convert(c.call(context.Background()))
		require.Equal(t, codes.Unavailable, st.Code(), name)
		assert.Equal(t, c.service, notConfiguredServiceName(t, st), name)
	}
}

func TestAppServices_SDKFailureIsInternal(t *testing.T) {
	servers := appServersWith(&fakeAppCache{err: errAppSDK{}}, &fakeAppScheduler{err: errAppSDK{}}, &fakeAppMessaging{err: errAppSDK{}}, &fakeAppObjectStorage{err: errAppSDK{}})
	for name, c := range appServiceCalls(servers) {
		st := status.Convert(c.call(context.Background()))
		assert.Equal(t, codes.Internal, st.Code(), name)
		assert.Contains(t, st.Message(), "sdk unreachable", name)
	}
}

func TestAppServiceStatus(t *testing.T) {
	cases := map[string]struct {
		err  error
		code codes.Code
	}{
		"canceled":           {context.Canceled, codes.Canceled},
		"deadline":           {context.DeadlineExceeded, codes.DeadlineExceeded},
		"not configured":     {appservices.ErrNotConfigured{Service: "cache"}, codes.Unavailable},
		"invalid":            {appservices.ErrInvalidArgument{Service: "cache", Field: "f", Reason: "r"}, codes.InvalidArgument},
		"sdk status kept":    {appservices.ErrCallFailed{Service: "cache", Op: "clear", Cause: status.Error(codes.NotFound, "gone")}, codes.NotFound},
		"sdk unknown":        {appservices.ErrCallFailed{Service: "cache", Op: "clear", Cause: status.Error(codes.Unknown, "?")}, codes.Internal},
		"sdk not found":      {appservices.ErrCallFailed{Service: "scheduler", Op: "get job", Cause: sdkerrors.NewNotFound("GetJob", "no job 7")}, codes.NotFound},
		"sdk already exists": {appservices.ErrCallFailed{Service: "messaging", Op: "create channel", Cause: sdkerrors.NewAlreadyExists("CreateChannel", "orders")}, codes.AlreadyExists},
		"sdk invalid input":  {appservices.ErrCallFailed{Service: "cache", Op: "update config", Cause: sdkerrors.NewInvalidInput("UpdateConfig", "ttl")}, codes.InvalidArgument},
		"sdk unavailable":    {appservices.ErrCallFailed{Service: "cache", Op: "stats", Cause: sdkerrors.NewUnavailable("GetStats", "down")}, codes.Unavailable},
		"untyped failures":   {errAppSDK{}, codes.Internal},
	}
	for name, tc := range cases {
		assert.Equal(t, tc.code, appServiceStatus(tc.err).Code(), name)
	}
}

// TestAppServices_SDKErrorKeepsItsCode drives every call with the SDK's own
// typed NotFound error: it must reach the caller as NotFound, not Internal,
// on the servers every transport shares.
func TestAppServices_SDKErrorKeepsItsCode(t *testing.T) {
	notFound := sdkerrors.NewNotFound("Get", "no such resource")
	servers := appServersWith(&fakeAppCache{err: notFound}, &fakeAppScheduler{err: notFound}, &fakeAppMessaging{err: notFound}, &fakeAppObjectStorage{err: notFound})
	for name, c := range appServiceCalls(servers) {
		st := status.Convert(c.call(context.Background()))
		assert.Equal(t, codes.NotFound, st.Code(), name)
		assert.Contains(t, st.Message(), "no such resource", name)
	}
}

func TestPlatformSDK_NoFactoryIsNil(t *testing.T) {
	assert.Nil(t, platformSDK(nil))
	assert.Nil(t, platformSDK(&Config{}))
}

func TestAppTimeHelpers(t *testing.T) {
	assert.Equal(t, int64(0), appUnixMillis(time.Time{}), "the zero time is 0 on the wire")
	assert.True(t, appTime(0).IsZero(), "0 on the wire is the zero time")
	assert.Equal(t, appTestTime.UnixMilli(), appUnixMillis(appTime(appTestTime.UnixMilli())))
	assert.Equal(t, 1500*time.Millisecond, appDuration(1500))
}

func TestAppInt32_Saturates(t *testing.T) {
	assert.Equal(t, int32(7), appInt32(7))
	assert.Equal(t, int32(math.MaxInt32), appInt32(math.MaxInt32+1))
	assert.Equal(t, int32(math.MinInt32), appInt32(math.MinInt32-1))
}

func TestCacheGRPCService_ConvertsResponses(t *testing.T) {
	svc := appServersWith(&fakeAppCache{}, nil, nil, nil).cache
	stats, err := svc.GetStats(context.Background(), &platformv1.GetCacheStatsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0.5, stats.GetHitRate())
	assert.Equal(t, uint64(7), stats.GetSize())

	cfg, err := svc.GetConfig(context.Background(), &platformv1.GetCacheConfigRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(60_000), cfg.GetConfig().GetL1TtlMs())
	assert.Equal(t, int64(1_000), cfg.GetConfig().GetCleanupIntervalMs())
	assert.True(t, cfg.GetConfig().GetEnabled())
	assert.Nil(t, cacheConfigToPb(nil))
}

func TestCacheGRPCService_UpdateConfigSendsOnlySetFields(t *testing.T) {
	fake := &fakeAppCache{}
	svc := appServersWith(fake, nil, nil, nil).cache
	ttl := int64(2500)
	resp, err := svc.UpdateConfig(context.Background(), &platformv1.UpdateCacheConfigRequest{L1TtlMs: &ttl})
	require.NoError(t, err)
	assert.True(t, resp.GetUpdated())
	assert.Equal(t, int64(200), resp.GetConfig().GetL1Size())
	require.NotNil(t, fake.update.L1TTL)
	assert.Equal(t, 2500*time.Millisecond, *fake.update.L1TTL)
	assert.Nil(t, fake.update.L1Size, "an unset field is not sent")
	assert.Nil(t, fake.update.CleanupInterval, "an unset field is not sent")
}

func TestCacheGRPCService_RefusesInvalidRequests(t *testing.T) {
	fake := &fakeAppCache{}
	svc := appServersWith(fake, nil, nil, nil).cache
	_, err := svc.UpdateConfig(context.Background(), &platformv1.UpdateCacheConfigRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an update with no field set")
	_, err = svc.Clear(context.Background(), &platformv1.ClearCacheRequest{EntityType: "users", All: true})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an entity type and all at once")
	assert.Nil(t, fake.update)
}

func TestSchedulerGRPCService_CreateJobConverts(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	resp, err := svc.CreateJob(context.Background(), &platformv1.CreateSchedulerJobRequest{
		Name:      "later",
		JobType:   platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_DELAYED,
		DelayMs:   3000,
		TimeoutMs: 500,
	})
	require.NoError(t, err)
	assert.Equal(t, "18446744073709551615", resp.GetJobId(), "a 64-bit job ID survives as a decimal string")
	assert.Equal(t, appTestTime.UnixMilli(), resp.GetNextRunAtUnixMs())
	assert.Equal(t, scheduler.JobTypeDelayed, fake.created.JobType)
	assert.Equal(t, scheduler.OwnerTypeSystem, fake.created.OwnerType, "an unspecified owner is the system")
	assert.Equal(t, 3*time.Second, fake.created.Delay)
	assert.Equal(t, 500*time.Millisecond, fake.created.Timeout)
	assert.True(t, fake.created.ExecuteAt.IsZero())
}

func TestSchedulerGRPCService_UpdateJobConverts(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	_, err := svc.UpdateJob(context.Background(), &platformv1.UpdateSchedulerJobRequest{
		JobId:      "18446744073709551615",
		Name:       "renamed",
		DelayMs:    3000,
		TimeoutMs:  500,
		MaxRetries: 7,
	})
	require.NoError(t, err)
	require.NotNil(t, fake.updated)
	assert.Equal(t, uint64(18446744073709551615), fake.updated.JobID, "the decimal job ID parses to the full 64 bits")
	assert.Equal(t, "renamed", fake.updated.Name)
	assert.Equal(t, 3*time.Second, fake.updated.Delay)
	assert.Equal(t, 500*time.Millisecond, fake.updated.Timeout)
	assert.Equal(t, 7, fake.updated.MaxRetries)
}

func TestSchedulerGRPCService_CreateJobRefusesBadEnums(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	_, err := svc.CreateJob(context.Background(), &platformv1.CreateSchedulerJobRequest{Name: "j"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "job_type is required")
	_, err = svc.CreateJob(context.Background(), &platformv1.CreateSchedulerJobRequest{
		Name: "j", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT, OwnerType: 99,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an unknown owner type")
	assert.Nil(t, fake.created)
}

func TestSchedulerGRPCService_JobConversion(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	resp, err := svc.GetJob(context.Background(), &platformv1.GetSchedulerJobRequest{JobId: "77"})
	require.NoError(t, err)
	assert.Equal(t, uint64(77), fake.jobID)
	job := resp.GetJob()
	assert.Equal(t, "77", job.GetJobId())
	assert.Equal(t, platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_RECURRING, job.GetJobType())
	assert.Equal(t, platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED, job.GetStatus())
	assert.Equal(t, platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_TENANT, job.GetOwnerType())
	assert.Equal(t, int64(2000), job.GetTimeoutMs())
	assert.Equal(t, appTestTime.UnixMilli(), job.GetCreatedAtUnixMs())
	assert.Zero(t, job.GetNextRunAtUnixMs(), "an unset time is 0")
	assert.Nil(t, schedulerJobToPb(nil))
}

func TestSchedulerGRPCService_RefusesBadJobID(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	for _, id := range []string{"", "-1", "abc", "18446744073709551616"} {
		_, err := svc.GetJob(context.Background(), &platformv1.GetSchedulerJobRequest{JobId: id})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), id)
		_, err = svc.DeleteJob(context.Background(), &platformv1.DeleteSchedulerJobRequest{JobId: id})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), id)
	}
	assert.Zero(t, fake.jobID, "a bad job ID never reaches the SDK")
}

func TestSchedulerGRPCService_ListJobsFilters(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	resp, err := svc.ListJobs(context.Background(), &platformv1.ListSchedulerJobsRequest{
		Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED,
		Limit:  10,
	})
	require.NoError(t, err)
	assert.Len(t, resp.GetJobs(), 2)
	assert.Equal(t, int32(2), resp.GetTotalCount())
	require.NotNil(t, fake.listed.Status)
	assert.Equal(t, scheduler.JobStatusFailed, *fake.listed.Status)
	assert.Nil(t, fake.listed.OwnerType, "an unspecified filter is no filter")
	assert.Nil(t, fake.listed.JobType, "an unspecified filter is no filter")
	assert.Equal(t, 10, fake.listed.Limit)
}

func TestSchedulerGRPCService_ListJobsRefusesUnknownFilter(t *testing.T) {
	svc := appServersWith(nil, &fakeAppScheduler{}, nil, nil).scheduler
	for name, req := range map[string]*platformv1.ListSchedulerJobsRequest{
		"status":     {Status: 42},
		"job_type":   {JobType: 42},
		"owner_type": {OwnerType: 42},
		"limit":      {Limit: -1},
	} {
		_, err := svc.ListJobs(context.Background(), req)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), name)
	}
}

func TestSchedulerGRPCService_JobHistory(t *testing.T) {
	fake := &fakeAppScheduler{}
	svc := appServersWith(nil, fake, nil, nil).scheduler
	resp, err := svc.GetJobHistory(context.Background(), &platformv1.GetSchedulerJobHistoryRequest{
		JobId:           "4",
		StartTimeUnixMs: appTestTime.UnixMilli(),
	})
	require.NoError(t, err)
	require.NotNil(t, fake.history.StartTime)
	assert.True(t, appTestTime.Equal(*fake.history.StartTime))
	assert.Nil(t, fake.history.EndTime, "an unset bound is open")
	require.Len(t, resp.GetExecutions(), 1)
	execution := resp.GetExecutions()[0]
	assert.Equal(t, "3", execution.GetExecutionId())
	assert.Equal(t, platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED, execution.GetStatus())
	assert.Equal(t, int64(1500), execution.GetDurationMs())
	assert.Equal(t, "boom", execution.GetError())
}

func TestSchedulerGRPCService_JobHistoryRefusesBadRange(t *testing.T) {
	svc := appServersWith(nil, &fakeAppScheduler{}, nil, nil).scheduler
	_, err := svc.GetJobHistory(context.Background(), &platformv1.GetSchedulerJobHistoryRequest{
		JobId:           "4",
		StartTimeUnixMs: appTestTime.UnixMilli(),
		EndTimeUnixMs:   appTestTime.UnixMilli() - 1,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.GetJobHistory(context.Background(), &platformv1.GetSchedulerJobHistoryRequest{JobId: "4", Status: 42})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSchedulerGRPCService_LifecycleResponses(t *testing.T) {
	svc := appServersWith(nil, &fakeAppScheduler{}, nil, nil).scheduler
	ctx := context.Background()
	trigger, err := svc.TriggerJob(ctx, &platformv1.TriggerSchedulerJobRequest{JobId: "6"})
	require.NoError(t, err)
	assert.Equal(t, "9", trigger.GetExecutionId())
	cancel, err := svc.CancelJob(ctx, &platformv1.CancelSchedulerJobRequest{JobId: "6", Reason: "obsolete"})
	require.NoError(t, err)
	assert.Equal(t, "obsolete", cancel.GetReason())
	assert.Equal(t, appTestTime.UnixMilli(), cancel.GetCanceledAtUnixMs())
	st, err := svc.GetStatus(ctx, &platformv1.GetSchedulerStatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.GetHealthy())
	assert.Equal(t, int32(4), st.GetWorkerCount())
	assert.Equal(t, int64(60_000), st.GetUptimeMs())
}

func TestMessagingGRPCService_CreateChannelConverts(t *testing.T) {
	fake := &fakeAppMessaging{}
	svc := appServersWith(nil, nil, fake, nil).messaging
	resp, err := svc.CreateChannel(context.Background(), &platformv1.CreateMessagingChannelRequest{
		Name: "events", Codec: "json", MaxHistory: 50, MaxSubscribers: 3, TtlMs: 4000,
	})
	require.NoError(t, err)
	assert.Equal(t, 4*time.Second, fake.created.TTL)
	assert.Equal(t, 3, fake.created.MaxSubs)
	channel := resp.GetChannel()
	assert.Equal(t, "events", channel.GetName())
	assert.Equal(t, int64(4000), channel.GetTtlMs())
	assert.Equal(t, int32(50), channel.GetMaxHistory())
	assert.Equal(t, appTestTime.UnixMilli(), channel.GetCreatedAtUnixMs())
	assert.Nil(t, messagingChannelToPb(nil))
}

func TestMessagingGRPCService_RefusesInvalidRequests(t *testing.T) {
	fake := &fakeAppMessaging{}
	svc := appServersWith(nil, nil, fake, nil).messaging
	_, err := svc.CreateChannel(context.Background(), &platformv1.CreateMessagingChannelRequest{Name: "events", Codec: "xml"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an unknown codec")
	_, err = svc.Publish(context.Background(), &platformv1.PublishMessageRequest{Payload: []byte("x")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no channel")
	assert.Nil(t, fake.created)
	assert.Nil(t, fake.published)
}

func TestMessagingGRPCService_ConvertsResponses(t *testing.T) {
	fake := &fakeAppMessaging{}
	svc := appServersWith(nil, nil, fake, nil).messaging
	ctx := context.Background()

	list, err := svc.ListChannels(ctx, &platformv1.ListMessagingChannelsRequest{})
	require.NoError(t, err)
	assert.Len(t, list.GetChannels(), 2, "a nil channel is skipped")

	_, err = svc.Publish(ctx, &platformv1.PublishMessageRequest{
		Channel: "events", Payload: []byte("x"), DedupKey: "k", Metadata: map[string]string{"a": "b"},
	})
	require.NoError(t, err)
	assert.Equal(t, "k", fake.published.DedupKey)
	assert.Equal(t, "b", fake.published.Metadata["a"])

	stats, err := svc.GetStats(ctx, &platformv1.GetMessagingStatsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0.25, stats.GetBufferUtilization())

	dedup, err := svc.GetDedupStats(ctx, &platformv1.GetMessagingDedupStatsRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(60_000), dedup.GetWindowMs())

	channelStats, err := svc.GetChannelStats(ctx, &platformv1.GetMessagingChannelStatsRequest{Channel: "events"})
	require.NoError(t, err)
	assert.Equal(t, int32(6), channelStats.GetMessagesInHistory())
	assert.Equal(t, "events", fake.name)
}
