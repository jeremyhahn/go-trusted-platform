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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every CacheService, SchedulerService and MessagingService method has a tool,
// an argument builder and a reply decoder.
func TestAppServiceTools_CoverEveryMethod(t *testing.T) {
	declared := 0
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			declared++
			method := "/" + desc.ServiceName + "/" + m.MethodName
			assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
			assert.Contains(t, mcpArgBuilders, method)
			assert.Contains(t, mcpReplyDecoders, method)
		}
	}
	assert.Len(t, appServiceToolMap, declared)
}

func TestProtoJSONArgs(t *testing.T) {
	build := mcpArgBuilders[platformv1.MessagingService_Publish_FullMethodName]
	args, err := build(&platformv1.PublishMessageRequest{
		Channel: "events", Payload: []byte("hi"), Metadata: map[string]string{"a": "b"},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"channel":  "events",
		"payload":  "aGk=",
		"metadata": map[string]interface{}{"a": "b"},
	}, args)

	build = mcpArgBuilders[platformv1.SchedulerService_GetJobHistory_FullMethodName]
	args, err = build(&platformv1.GetSchedulerJobHistoryRequest{JobId: "5", StartTimeUnixMs: 1 << 40})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"job_id": "5", "start_time_unix_ms": "1099511627776"}, args)

	build = mcpArgBuilders[platformv1.SchedulerService_ListJobs_FullMethodName]
	args, err = build(&platformv1.ListSchedulerJobsRequest{Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"status": "SCHEDULER_JOB_STATUS_PAUSED"}, args)
}

func TestProtoJSONArgs_RefusesWhatIsNotARequest(t *testing.T) {
	build := mcpArgBuilders[platformv1.MessagingService_Publish_FullMethodName]
	var nilRequest *platformv1.PublishMessageRequest
	for _, args := range []interface{}{"events", nil, nilRequest} {
		_, err := build(args)
		var unexpected ErrUnexpectedArgsType
		require.True(t, errors.As(err, &unexpected), "%#v: error = %v", args, err)
		assert.Equal(t, platformv1.MessagingService_Publish_FullMethodName, unexpected.Method)
	}
}

func TestProtoJSONReply(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.CacheService_GetStats_FullMethodName]
	reply := &platformv1.GetCacheStatsResponse{Misses: 9}
	// A field the client does not know yet is ignored, and the reply is
	// replaced, not merged.
	err := decode(map[string]interface{}{"hit_rate": 0.5, "size": "1099511627776", "added_later": true}, reply)
	require.NoError(t, err)
	assert.Equal(t, 0.5, reply.GetHitRate())
	assert.Equal(t, uint64(1<<40), reply.GetSize())
	assert.Zero(t, reply.GetMisses())
}

func TestProtoJSONReply_Errors(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.CacheService_GetStats_FullMethodName]

	var nilReply *platformv1.GetCacheStatsResponse
	for _, reply := range []interface{}{"stats", nil, nilReply} {
		var unexpected ErrUnexpectedReplyType
		err := decode(map[string]interface{}{}, reply)
		require.True(t, errors.As(err, &unexpected), "%#v: error = %v", reply, err)
		assert.Equal(t, platformv1.CacheService_GetStats_FullMethodName, unexpected.Method)
	}

	var unmarshal ErrUnmarshalFailed
	err := decode(map[string]interface{}{"size": "many"}, &platformv1.GetCacheStatsResponse{})
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)

	var marshal ErrMarshalFailed
	err = decode(map[string]interface{}{"size": make(chan int)}, &platformv1.GetCacheStatsResponse{})
	assert.True(t, errors.As(err, &marshal), "error = %v", err)
}
