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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// appQUICOperation is one sub-operation of an appQUICCategories category with
// a request its service accepts.
type appQUICOperation struct {
	name    string
	opcode  byte
	sub     byte
	request interface{}
}

func appQUICOperations() []appQUICOperation {
	size := int64(10)
	return []appQUICOperation{
		{"cache.GetStats", quicwire.OpCacheCategory, quicwire.CacheSubGetStats, &platformv1.GetCacheStatsRequest{EntityType: "users"}},
		{"cache.Clear", quicwire.OpCacheCategory, quicwire.CacheSubClear, &platformv1.ClearCacheRequest{All: true}},
		{"cache.GetConfig", quicwire.OpCacheCategory, quicwire.CacheSubGetConfig, &platformv1.GetCacheConfigRequest{}},
		{"cache.UpdateConfig", quicwire.OpCacheCategory, quicwire.CacheSubUpdateConfig, &platformv1.UpdateCacheConfigRequest{L1Size: &size}},
		{"scheduler.CreateJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubCreateJob, &platformv1.CreateSchedulerJobRequest{
			Name: "j", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
		}},
		{"scheduler.GetJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJob, &platformv1.GetSchedulerJobRequest{JobId: "5"}},
		{"scheduler.UpdateJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubUpdateJob, &platformv1.UpdateSchedulerJobRequest{JobId: "5", Name: "n"}},
		{"scheduler.DeleteJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubDeleteJob, &platformv1.DeleteSchedulerJobRequest{JobId: "5"}},
		{"scheduler.ListJobs", quicwire.OpSchedulerCategory, quicwire.SchedulerSubListJobs, &platformv1.ListSchedulerJobsRequest{}},
		{"scheduler.TriggerJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubTriggerJob, &platformv1.TriggerSchedulerJobRequest{JobId: "5"}},
		{"scheduler.PauseJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubPauseJob, &platformv1.PauseSchedulerJobRequest{JobId: "5"}},
		{"scheduler.ResumeJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubResumeJob, &platformv1.ResumeSchedulerJobRequest{JobId: "5"}},
		{"scheduler.CancelJob", quicwire.OpSchedulerCategory, quicwire.SchedulerSubCancelJob, &platformv1.CancelSchedulerJobRequest{JobId: "5"}},
		{"scheduler.GetJobHistory", quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJobHistory, &platformv1.GetSchedulerJobHistoryRequest{JobId: "5"}},
		{"scheduler.GetStatus", quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetStatus, &platformv1.GetSchedulerStatusRequest{}},
		{"messaging.CreateChannel", quicwire.OpMessagingCategory, quicwire.MessagingSubCreateChannel, &platformv1.CreateMessagingChannelRequest{Name: "events"}},
		{"messaging.DeleteChannel", quicwire.OpMessagingCategory, quicwire.MessagingSubDeleteChannel, &platformv1.DeleteMessagingChannelRequest{Name: "events"}},
		{"messaging.GetChannel", quicwire.OpMessagingCategory, quicwire.MessagingSubGetChannel, &platformv1.GetMessagingChannelRequest{Name: "events"}},
		{"messaging.ListChannels", quicwire.OpMessagingCategory, quicwire.MessagingSubListChannels, &platformv1.ListMessagingChannelsRequest{}},
		{"messaging.Publish", quicwire.OpMessagingCategory, quicwire.MessagingSubPublish, &platformv1.PublishMessageRequest{Channel: "events", Payload: []byte("x")}},
		{"messaging.GetStats", quicwire.OpMessagingCategory, quicwire.MessagingSubGetStats, &platformv1.GetMessagingStatsRequest{}},
		{"messaging.GetDedupStats", quicwire.OpMessagingCategory, quicwire.MessagingSubGetDedupStats, &platformv1.GetMessagingDedupStatsRequest{}},
		{"messaging.GetChannelStats", quicwire.OpMessagingCategory, quicwire.MessagingSubGetChannelStats, &platformv1.GetMessagingChannelStatsRequest{Channel: "events"}},
		{"objectstorage.PutObject", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubPutObject, &platformv1.PutObjectRequest{Key: "docs:a.txt", Value: []byte("a"), TargetBackend: "local"}},
		{"objectstorage.GetObject", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubGetObject, &platformv1.GetObjectRequest{Key: "docs:a.txt"}},
		{"objectstorage.DeleteObject", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubDeleteObject, &platformv1.DeleteObjectRequest{Key: "docs:a.txt"}},
		{"objectstorage.HeadObject", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubHeadObject, &platformv1.HeadObjectRequest{Key: "docs:a.txt"}},
		{"objectstorage.ListObjects", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListObjects, &platformv1.ListObjectsRequest{Prefix: "docs:"}},
		{"objectstorage.CopyObject", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubCopyObject, &platformv1.CopyObjectRequest{SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", TargetBackend: "local"}},
		{"objectstorage.ListObjectsByTag", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListObjectsByTag, &platformv1.ListObjectsByTagRequest{TagName: "env"}},
		{"objectstorage.ListTenantObjects", quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListTenantObjects, &platformv1.ListTenantObjectsRequest{TenantId: "acme"}},
		{"switch.ListPorts", quicwire.OpSwitchCategory, quicwire.SwitchSubListPorts, &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"}},
		{"switch.GetPortStatus", quicwire.OpSwitchCategory, quicwire.SwitchSubGetPortStatus, &platformv1.GetSwitchPortStatusRequest{SwitchName: "core-1", PortName: "eth1"}},
		{"switch.SetPortVLAN", quicwire.OpSwitchCategory, quicwire.SwitchSubSetPortVLAN, &platformv1.SetSwitchPortVLANRequest{SwitchName: "core-1", PortName: "eth1", VlanId: 20}},
		{"switch.EnablePort", quicwire.OpSwitchCategory, quicwire.SwitchSubEnablePort, &platformv1.EnableSwitchPortRequest{SwitchName: "core-1", PortName: "eth1"}},
		{"switch.DisablePort", quicwire.OpSwitchCategory, quicwire.SwitchSubDisablePort, &platformv1.DisableSwitchPortRequest{SwitchName: "core-1", PortName: "eth1"}},
	}
}

func appQUICRequest(t *testing.T, opcode, sub byte, message interface{}) *quicwire.Request {
	t.Helper()
	body, err := quicwire.EncodePayload(message)
	require.NoError(t, err)
	return &quicwire.Request{Opcode: opcode, Payload: append([]byte{sub}, body...)}
}

// newAppQUICHandler serves servers, plus a switch servicer backed by the fake
// switch core-1, so every category in appQUICCategories is wired.
func newAppQUICHandler(servers appServiceServers) *QUICServiceHandler {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetAppServices(servers)
	handler.SetSwitchServer(NewSwitchGRPCService(logging.DefaultLogger(), newFakeSwitchService()))
	return handler
}

func TestQUICAppServices_EverySubOperationIsListed(t *testing.T) {
	listed := make(map[byte]map[byte]bool)
	for _, op := range appQUICOperations() {
		if listed[op.opcode] == nil {
			listed[op.opcode] = make(map[byte]bool)
		}
		listed[op.opcode][op.sub] = true
	}
	for opcode, category := range appQUICCategories {
		for sub := range category.handlers {
			assert.True(t, listed[opcode][sub], "opcode 0x%02X sub 0x%02X has no test operation", opcode, sub)
		}
		assert.Len(t, listed[opcode], len(category.handlers), "opcode 0x%02X", opcode)
	}
}

func TestQUICAppServices_ServeEverySubOperation(t *testing.T) {
	handler := newAppQUICHandler(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	for _, op := range appQUICOperations() {
		resp := handler.HandleRequest(context.Background(), appQUICRequest(t, op.opcode, op.sub, op.request))
		assert.Equal(t, quicwire.StatusOK, resp.Status, "%s: payload %q", op.name, resp.Payload)
	}
}

func TestQUICAppServices_DecodeReplies(t *testing.T) {
	handler := newAppQUICHandler(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	ctx := context.Background()

	var stats platformv1.GetCacheStatsResponse
	resp := handler.HandleRequest(ctx, appQUICRequest(t, quicwire.OpCacheCategory, quicwire.CacheSubGetStats, &platformv1.GetCacheStatsRequest{}))
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload %q", resp.Payload)
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &stats))
	assert.Equal(t, uint64(7), stats.GetSize())

	var job platformv1.GetSchedulerJobResponse
	resp = handler.HandleRequest(ctx, appQUICRequest(t, quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJob, &platformv1.GetSchedulerJobRequest{JobId: "5"}))
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload %q", resp.Payload)
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &job))
	assert.Equal(t, "5", job.GetJob().GetJobId())

	var channel platformv1.GetMessagingChannelResponse
	resp = handler.HandleRequest(ctx, appQUICRequest(t, quicwire.OpMessagingCategory, quicwire.MessagingSubGetChannel, &platformv1.GetMessagingChannelRequest{Name: "events"}))
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload %q", resp.Payload)
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &channel))
	assert.Equal(t, "events", channel.GetChannel().GetName())
}

func TestQUICAppServices_NotConfiguredIsUnavailable(t *testing.T) {
	// A daemon whose DAO factory has no SDK and that has no switch backend.
	handler := newAppQUICHandler(newAppServiceServers(nil, nil))
	handler.SetSwitchServer(NewSwitchGRPCService(logging.DefaultLogger(), nil))
	for _, op := range appQUICOperations() {
		resp := handler.HandleRequest(context.Background(), appQUICRequest(t, op.opcode, op.sub, op.request))
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "%s: payload %q", op.name, resp.Payload)
	}
}

func TestQUICAppServices_UnwiredCategoryIsUnavailable(t *testing.T) {
	handler := newAppQUICHandler(appServiceServers{})
	handler.SetSwitchServer(nil)
	for opcode, category := range appQUICCategories {
		for sub := range category.handlers {
			resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcode, Payload: []byte{sub}})
			assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "opcode 0x%02X sub 0x%02X", opcode, sub)
			assert.Equal(t, ErrQUICServiceUnavailable{Service: category.service}.Error(), string(resp.Payload))
		}
	}
}

func TestQUICAppServices_MapsServiceErrors(t *testing.T) {
	failing := newAppQUICHandler(appServersWith(
		&fakeAppCache{err: errAppSDK{}}, &fakeAppScheduler{err: errAppSDK{}}, &fakeAppMessaging{err: errAppSDK{}}, &fakeAppObjectStorage{err: errAppSDK{}}))
	working := newAppQUICHandler(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	ctx := context.Background()

	cases := []struct {
		name    string
		handler *QUICServiceHandler
		req     *quicwire.Request
		want    byte
	}{
		{
			name:    "sdk failure",
			handler: failing,
			req:     appQUICRequest(t, quicwire.OpCacheCategory, quicwire.CacheSubGetStats, &platformv1.GetCacheStatsRequest{}),
			want:    quicwire.StatusInternalError,
		},
		{
			name:    "bad job id",
			handler: working,
			req:     appQUICRequest(t, quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJob, &platformv1.GetSchedulerJobRequest{JobId: "x"}),
			want:    quicwire.StatusInvalidArgument,
		},
		{
			name:    "missing channel name",
			handler: working,
			req:     appQUICRequest(t, quicwire.OpMessagingCategory, quicwire.MessagingSubCreateChannel, &platformv1.CreateMessagingChannelRequest{}),
			want:    quicwire.StatusInvalidArgument,
		},
		{
			name:    "missing object key",
			handler: working,
			req:     appQUICRequest(t, quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubGetObject, &platformv1.GetObjectRequest{}),
			want:    quicwire.StatusInvalidArgument,
		},
		{
			name:    "undecodable request body",
			handler: working,
			req:     &quicwire.Request{Opcode: quicwire.OpCacheCategory, Payload: []byte{quicwire.CacheSubGetStats, 0xC1}},
			want:    quicwire.StatusInvalidRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.handler.HandleRequest(ctx, tc.req)
			assert.Equal(t, tc.want, resp.Status, "payload %q", resp.Payload)
		})
	}
}

func TestQUICAppServices_RefusesMalformedCategoryRequests(t *testing.T) {
	handler := newAppQUICHandler(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	ctx := context.Background()

	// The authorization guard refuses these before dispatch; the dispatcher
	// refuses them on its own as well.
	missing := &quicwire.Request{Opcode: quicwire.OpSchedulerCategory}
	assert.Equal(t, quicwire.StatusInvalidRequest, handler.handleAppServiceCategory(ctx, missing).Status)

	unknownSub := &quicwire.Request{Opcode: quicwire.OpMessagingCategory, Payload: []byte{0x7F}}
	assert.Equal(t, quicwire.StatusPermissionDenied, handler.HandleRequest(ctx, unknownSub).Status)
	assert.Equal(t, quicwire.StatusNotImplemented, handler.handleAppServiceCategory(ctx, unknownSub).Status)

	unknownCategory := &quicwire.Request{Opcode: quicwire.OpVPNCategory, Payload: []byte{quicwire.VPNSubGetStatus}}
	assert.Equal(t, quicwire.StatusNotImplemented, handler.handleAppServiceCategory(ctx, unknownCategory).Status)
}

func TestQUICServiceHandler_SetAppServices(t *testing.T) {
	handler := newAppQUICHandler(appServersWith(&fakeAppCache{}, &fakeAppScheduler{}, &fakeAppMessaging{}, &fakeAppObjectStorage{}))
	assert.NotNil(t, handler.cacheService)
	assert.NotNil(t, handler.schedulerService)
	assert.NotNil(t, handler.messagingService)
	assert.NotNil(t, handler.objectStorageService)

	// Missing servers leave nil interfaces, never typed nils, so the
	// category answers unavailable instead of panicking.
	handler.SetAppServices(appServiceServers{})
	assert.Nil(t, handler.cacheService)
	assert.Nil(t, handler.schedulerService)
	assert.Nil(t, handler.messagingService)
	assert.Nil(t, handler.objectStorageService)
}
