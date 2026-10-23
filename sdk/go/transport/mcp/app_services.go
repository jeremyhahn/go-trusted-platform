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

// The CacheService, SchedulerService and MessagingService tools (#704) take
// and return the proto3 JSON mapping with proto field names: enums travel as
// their names, 64-bit integers as strings and bytes as base64. One argument
// builder and one reply decoder therefore serve every method.

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// appServiceToolMap maps each application service gRPC method to the
// platformd MCP tool that serves it.
var appServiceToolMap = map[string]string{
	platformv1.CacheService_GetStats_FullMethodName:     "cache_stats",
	platformv1.CacheService_GetConfig_FullMethodName:    "cache_config_get",
	platformv1.CacheService_UpdateConfig_FullMethodName: "cache_config_update",
	platformv1.CacheService_Clear_FullMethodName:        "cache_clear",

	platformv1.SchedulerService_CreateJob_FullMethodName:     "scheduler_job_create",
	platformv1.SchedulerService_ListJobs_FullMethodName:      "scheduler_job_list",
	platformv1.SchedulerService_GetJob_FullMethodName:        "scheduler_job_get",
	platformv1.SchedulerService_UpdateJob_FullMethodName:     "scheduler_job_update",
	platformv1.SchedulerService_DeleteJob_FullMethodName:     "scheduler_job_delete",
	platformv1.SchedulerService_TriggerJob_FullMethodName:    "scheduler_job_trigger",
	platformv1.SchedulerService_PauseJob_FullMethodName:      "scheduler_job_pause",
	platformv1.SchedulerService_ResumeJob_FullMethodName:     "scheduler_job_resume",
	platformv1.SchedulerService_CancelJob_FullMethodName:     "scheduler_job_cancel",
	platformv1.SchedulerService_GetJobHistory_FullMethodName: "scheduler_job_history",
	platformv1.SchedulerService_GetStatus_FullMethodName:     "scheduler_status",

	platformv1.MessagingService_CreateChannel_FullMethodName:   "messaging_channel_create",
	platformv1.MessagingService_ListChannels_FullMethodName:    "messaging_channel_list",
	platformv1.MessagingService_GetChannel_FullMethodName:      "messaging_channel_get",
	platformv1.MessagingService_DeleteChannel_FullMethodName:   "messaging_channel_delete",
	platformv1.MessagingService_Publish_FullMethodName:         "messaging_publish",
	platformv1.MessagingService_GetChannelStats_FullMethodName: "messaging_channel_stats",
	platformv1.MessagingService_GetStats_FullMethodName:        "messaging_stats",
	platformv1.MessagingService_GetDedupStats_FullMethodName:   "messaging_dedup_stats",

	platformv1.ObjectStorageService_PutObject_FullMethodName:         "objectstorage_put",
	platformv1.ObjectStorageService_GetObject_FullMethodName:         "objectstorage_get",
	platformv1.ObjectStorageService_DeleteObject_FullMethodName:      "objectstorage_delete",
	platformv1.ObjectStorageService_HeadObject_FullMethodName:        "objectstorage_head",
	platformv1.ObjectStorageService_ListObjects_FullMethodName:       "objectstorage_list",
	platformv1.ObjectStorageService_CopyObject_FullMethodName:        "objectstorage_copy",
	platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName:  "objectstorage_list_by_tag",
	platformv1.ObjectStorageService_ListTenantObjects_FullMethodName: "objectstorage_list_tenant",
}

var appArgsJSON = protojson.MarshalOptions{UseProtoNames: true}

// protoJSONArgs renders a request message as tool arguments.
func protoJSONArgs(method string) mcpArgBuilder {
	return func(args interface{}) (map[string]interface{}, error) {
		request, ok := args.(proto.Message)
		if !ok || !request.ProtoReflect().IsValid() {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		data, err := appArgsJSON.Marshal(request)
		if err != nil {
			return nil, ErrMarshalFailed{Err: err}
		}
		var out map[string]interface{}
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		return out, nil
	}
}

// protoJSONReply decodes a tool result into the reply message.
func protoJSONReply(method string) mcpReplyDecoder {
	return func(result interface{}, reply interface{}) error {
		out, ok := reply.(proto.Message)
		if !ok || !out.ProtoReflect().IsValid() {
			return ErrUnexpectedReplyType{Method: method}
		}
		return decodeReportJSON(result, out)
	}
}

func init() {
	for method, tool := range appServiceToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
