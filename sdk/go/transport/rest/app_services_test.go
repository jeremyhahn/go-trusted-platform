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

package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestAppServiceRoutesMatchTheDaemonHandlers pins the REST wire contract of
// CacheService, SchedulerService and MessagingService against the routes
// pkg/api/rest/app_service_handlers.go serves.
func TestAppServiceRoutesMatchTheDaemonHandlers(t *testing.T) {
	l1Size := int64(4096)
	cases := []struct {
		method   string
		args     proto.Message
		verb     string
		path     string
		wantBody proto.Message
	}{
		{
			method: platformv1.CacheService_GetStats_FullMethodName,
			args:   &platformv1.GetCacheStatsRequest{EntityType: "device"},
			verb:   http.MethodGet, path: "/api/v1/cache/stats?entity_type=device",
		},
		{
			method: platformv1.CacheService_GetConfig_FullMethodName,
			args:   &platformv1.GetCacheConfigRequest{},
			verb:   http.MethodGet, path: "/api/v1/cache/config",
		},
		{
			method: platformv1.CacheService_UpdateConfig_FullMethodName,
			args:   &platformv1.UpdateCacheConfigRequest{L1Size: &l1Size},
			verb:   http.MethodPatch, path: "/api/v1/cache/config",
			wantBody: &platformv1.UpdateCacheConfigRequest{L1Size: &l1Size},
		},
		{
			method: platformv1.CacheService_Clear_FullMethodName,
			args:   &platformv1.ClearCacheRequest{All: true},
			verb:   http.MethodDelete, path: "/api/v1/cache/entries?all=true",
		},
		{
			method: platformv1.SchedulerService_CreateJob_FullMethodName,
			args:   &platformv1.CreateSchedulerJobRequest{Name: "rotate", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_RECURRING, Schedule: "@hourly"},
			verb:   http.MethodPost, path: "/api/v1/scheduler/jobs",
			wantBody: &platformv1.CreateSchedulerJobRequest{Name: "rotate", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_RECURRING, Schedule: "@hourly"},
		},
		{
			method: platformv1.SchedulerService_ListJobs_FullMethodName,
			args: &platformv1.ListSchedulerJobsRequest{
				Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED,
				Tags:   map[string]string{"team": "net", "env": "prod"},
				Limit:  10,
			},
			verb: http.MethodGet,
			path: "/api/v1/scheduler/jobs?limit=10&status=SCHEDULER_JOB_STATUS_PAUSED&tags=env%3Dprod&tags=team%3Dnet",
		},
		{
			method: platformv1.SchedulerService_GetJob_FullMethodName,
			args:   &platformv1.GetSchedulerJobRequest{JobId: "j1"},
			verb:   http.MethodGet, path: "/api/v1/scheduler/jobs/j1",
		},
		{
			method: platformv1.SchedulerService_UpdateJob_FullMethodName,
			args:   &platformv1.UpdateSchedulerJobRequest{JobId: "j1", Schedule: "@daily"},
			verb:   http.MethodPatch, path: "/api/v1/scheduler/jobs/j1",
			wantBody: &platformv1.UpdateSchedulerJobRequest{Schedule: "@daily"},
		},
		{
			method: platformv1.SchedulerService_DeleteJob_FullMethodName,
			args:   &platformv1.DeleteSchedulerJobRequest{JobId: "j1"},
			verb:   http.MethodDelete, path: "/api/v1/scheduler/jobs/j1",
		},
		{
			method: platformv1.SchedulerService_TriggerJob_FullMethodName,
			args:   &platformv1.TriggerSchedulerJobRequest{JobId: "j1"},
			verb:   http.MethodPost, path: "/api/v1/scheduler/jobs/j1/trigger",
		},
		{
			method: platformv1.SchedulerService_PauseJob_FullMethodName,
			args:   &platformv1.PauseSchedulerJobRequest{JobId: "j1"},
			verb:   http.MethodPost, path: "/api/v1/scheduler/jobs/j1/pause",
		},
		{
			method: platformv1.SchedulerService_ResumeJob_FullMethodName,
			args:   &platformv1.ResumeSchedulerJobRequest{JobId: "j1"},
			verb:   http.MethodPost, path: "/api/v1/scheduler/jobs/j1/resume",
		},
		{
			method: platformv1.SchedulerService_CancelJob_FullMethodName,
			args:   &platformv1.CancelSchedulerJobRequest{JobId: "j1", Reason: "superseded"},
			verb:   http.MethodPost, path: "/api/v1/scheduler/jobs/j1/cancel",
			wantBody: &platformv1.CancelSchedulerJobRequest{Reason: "superseded"},
		},
		{
			method: platformv1.SchedulerService_GetJobHistory_FullMethodName,
			args:   &platformv1.GetSchedulerJobHistoryRequest{JobId: "j1", Limit: 5, StartTimeUnixMs: 1700000000000},
			verb:   http.MethodGet, path: "/api/v1/scheduler/jobs/j1/history?limit=5&start_time_unix_ms=1700000000000",
		},
		{
			method: platformv1.SchedulerService_GetStatus_FullMethodName,
			args:   &platformv1.GetSchedulerStatusRequest{},
			verb:   http.MethodGet, path: "/api/v1/scheduler/status",
		},
		{
			method: platformv1.MessagingService_CreateChannel_FullMethodName,
			args:   &platformv1.CreateMessagingChannelRequest{Name: "events", Persistent: true},
			verb:   http.MethodPost, path: "/api/v1/messaging/channels",
			wantBody: &platformv1.CreateMessagingChannelRequest{Name: "events", Persistent: true},
		},
		{
			method: platformv1.MessagingService_ListChannels_FullMethodName,
			args:   &platformv1.ListMessagingChannelsRequest{},
			verb:   http.MethodGet, path: "/api/v1/messaging/channels",
		},
		{
			method: platformv1.MessagingService_GetChannel_FullMethodName,
			args:   &platformv1.GetMessagingChannelRequest{Name: "events"},
			verb:   http.MethodGet, path: "/api/v1/messaging/channels/events",
		},
		{
			method: platformv1.MessagingService_DeleteChannel_FullMethodName,
			args:   &platformv1.DeleteMessagingChannelRequest{Name: "events"},
			verb:   http.MethodDelete, path: "/api/v1/messaging/channels/events",
		},
		{
			method: platformv1.MessagingService_Publish_FullMethodName,
			args:   &platformv1.PublishMessageRequest{Channel: "events", Payload: []byte("hello"), Metadata: map[string]string{"k": "v"}},
			verb:   http.MethodPost, path: "/api/v1/messaging/channels/events/messages",
			wantBody: &platformv1.PublishMessageRequest{Payload: []byte("hello"), Metadata: map[string]string{"k": "v"}},
		},
		{
			method: platformv1.MessagingService_GetChannelStats_FullMethodName,
			args:   &platformv1.GetMessagingChannelStatsRequest{Channel: "events"},
			verb:   http.MethodGet, path: "/api/v1/messaging/channels/events/stats",
		},
		{
			method: platformv1.MessagingService_GetStats_FullMethodName,
			args:   &platformv1.GetMessagingStatsRequest{},
			verb:   http.MethodGet, path: "/api/v1/messaging/stats",
		},
		{
			method: platformv1.MessagingService_GetDedupStats_FullMethodName,
			args:   &platformv1.GetMessagingDedupStatsRequest{},
			verb:   http.MethodGet, path: "/api/v1/messaging/dedup-stats",
		},
		{
			method: platformv1.ObjectStorageService_PutObject_FullMethodName,
			args:   &platformv1.PutObjectRequest{Key: "docs:a/b c.txt", Value: []byte("hi"), Tags: map[string]string{"env": "prod"}},
			verb:   http.MethodPost, path: "/api/v1/object-storage/objects",
			wantBody: &platformv1.PutObjectRequest{Key: "docs:a/b c.txt", Value: []byte("hi"), Tags: map[string]string{"env": "prod"}},
		},
		{
			// The key carries ":", "/" and a space, so it travels in the query.
			method: platformv1.ObjectStorageService_GetObject_FullMethodName,
			args:   &platformv1.GetObjectRequest{Key: "docs:a/b c.txt", IncludeMetadata: true},
			verb:   http.MethodGet, path: "/api/v1/object-storage/object?include_metadata=true&key=docs%3Aa%2Fb+c.txt",
		},
		{
			method: platformv1.ObjectStorageService_DeleteObject_FullMethodName,
			args:   &platformv1.DeleteObjectRequest{Key: "docs:a.txt", TenantId: "acme"},
			verb:   http.MethodDelete, path: "/api/v1/object-storage/object?key=docs%3Aa.txt&tenant_id=acme",
		},
		{
			method: platformv1.ObjectStorageService_HeadObject_FullMethodName,
			args:   &platformv1.HeadObjectRequest{Key: "docs:a.txt"},
			verb:   http.MethodGet, path: "/api/v1/object-storage/object/metadata?key=docs%3Aa.txt",
		},
		{
			method: platformv1.ObjectStorageService_ListObjects_FullMethodName,
			args:   &platformv1.ListObjectsRequest{Prefix: "docs:", Limit: 10, IncludeTags: true},
			verb:   http.MethodGet, path: "/api/v1/object-storage/objects?include_tags=true&limit=10&prefix=docs%3A",
		},
		{
			method: platformv1.ObjectStorageService_CopyObject_FullMethodName,
			args:   &platformv1.CopyObjectRequest{SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt"},
			verb:   http.MethodPost, path: "/api/v1/object-storage/objects/copy",
			wantBody: &platformv1.CopyObjectRequest{SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt"},
		},
		{
			method: platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName,
			args:   &platformv1.ListObjectsByTagRequest{TagName: "env", TagValue: "prod"},
			verb:   http.MethodGet, path: "/api/v1/object-storage/objects/by-tag?tag_name=env&tag_value=prod",
		},
		{
			method: platformv1.ObjectStorageService_ListTenantObjects_FullMethodName,
			args:   &platformv1.ListTenantObjectsRequest{TenantId: "acme", Limit: 5},
			verb:   http.MethodGet, path: "/api/v1/object-storage/tenants/acme/objects?limit=5",
		},
	}
	declared := 0
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
		platformv1.ObjectStorageService_ServiceDesc,
	} {
		declared += len(desc.Methods)
	}
	if declared != len(cases) || len(appServiceRoutes) != len(cases) {
		t.Fatalf("services declare %d methods, the route table maps %d, the test pins %d", declared, len(appServiceRoutes), len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			verb, path, body, err := route(tc.method, tc.args)
			if err != nil {
				t.Fatalf("route() error = %v", err)
			}
			if verb != tc.verb || path != tc.path {
				t.Fatalf("route() = %s %s, want %s %s", verb, path, tc.verb, tc.path)
			}
			if tc.wantBody == nil {
				return
			}

			// The daemon decodes the body with protojson into the request
			// and then fills the path parameter in.
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			got := tc.wantBody.ProtoReflect().New().Interface()
			if err := protojson.Unmarshal(encoded, got); err != nil {
				t.Fatalf("the daemon cannot decode body %s: %v", encoded, err)
			}
			if !proto.Equal(tc.wantBody, got) {
				t.Fatalf("body = %v, want %v", got, tc.wantBody)
			}
		})
	}
}

// TestAppServiceRoutesRefuseIncompleteRequests refuses an item route whose
// job or channel is missing rather than calling the collection route.
func TestAppServiceRoutesRefuseIncompleteRequests(t *testing.T) {
	cases := map[string]proto.Message{
		platformv1.SchedulerService_GetJob_FullMethodName:          &platformv1.GetSchedulerJobRequest{},
		platformv1.SchedulerService_CancelJob_FullMethodName:       &platformv1.CancelSchedulerJobRequest{Reason: "superseded"},
		platformv1.MessagingService_DeleteChannel_FullMethodName:   &platformv1.DeleteMessagingChannelRequest{},
		platformv1.MessagingService_Publish_FullMethodName:         &platformv1.PublishMessageRequest{Payload: []byte("hello")},
		platformv1.MessagingService_GetChannelStats_FullMethodName: &platformv1.GetMessagingChannelStatsRequest{},
	}
	for method, args := range cases {
		if _, _, _, err := route(method, args); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: route() error = %v, want InvalidArgument", method, err)
		}
	}
}

func TestEncodeQueryMapSortsTheEntries(t *testing.T) {
	request := &platformv1.ListSchedulerJobsRequest{Tags: map[string]string{"b": "2", "a": "1"}}
	values, err := encodeQueryField(request.ProtoReflect(), "tags")
	if err != nil {
		t.Fatalf("encodeQueryField() error = %v", err)
	}
	if len(values) != 2 || values[0] != "a=1" || values[1] != "b=2" {
		t.Fatalf("encodeQueryField() = %v, want [a=1 b=2]", values)
	}

	empty, err := encodeQueryField((&platformv1.ListSchedulerJobsRequest{}).ProtoReflect(), "tags")
	if err != nil || len(empty) != 0 {
		t.Fatalf("encodeQueryField(empty map) = %v, %v; want nothing", empty, err)
	}
}

func TestEncodeQueryFieldRefusesAnUnknownField(t *testing.T) {
	request := &platformv1.ListSchedulerJobsRequest{}
	if _, err := encodeQueryField(request.ProtoReflect(), "no_such_field"); err == nil {
		t.Fatal("encodeQueryField(unknown field) error = nil, want an error")
	}
}
