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
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Application service tools: Cache, Scheduler and Messaging (#704)
// =============================================================================
//
// Every cache_*, scheduler_* and messaging_* tool is one RPC of
// CacheService, SchedulerService or MessagingService. Its arguments are the
// RPC request in the proto3 JSON mapping, under the proto field names, and
// its result is the RPC response in the same mapping. The tools call the
// same server instances the gRPC, REST, QUIC and Unix transports serve, so
// the three transports cannot drift apart (docs/sdk/api.md §3.5).

// AppServiceServers are the servers the application service tools call. A
// nil server leaves its tools answering ErrAppServiceNotConfigured.
type AppServiceServers struct {
	Cache     platformv1.CacheServiceServer
	Scheduler platformv1.SchedulerServiceServer
	Messaging platformv1.MessagingServiceServer
}

// AppServiceProvider is implemented by a ServiceProvider that serves the
// application services. A provider without it answers every application
// service tool ErrAppServiceNotConfigured.
type AppServiceProvider interface {
	AppServiceServers() AppServiceServers
}

// ErrAppServiceNotConfigured is returned by an application service tool
// whose server the provider does not supply. It is classed Unavailable, the
// code the other transports answer an unserved service with.
type ErrAppServiceNotConfigured struct {
	Service string
}

func (e ErrAppServiceNotConfigured) Error() string {
	return fmt.Sprintf("mcp: the %s service is not configured on this daemon", e.Service)
}

// GRPCStatus classes the error Unavailable.
func (e ErrAppServiceNotConfigured) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrAppResultEncoding is returned when an RPC response cannot be rendered
// as a tool result.
type ErrAppResultEncoding struct {
	Cause error
}

func (e ErrAppResultEncoding) Error() string {
	return fmt.Sprintf("mcp: encode the application service result: %v", e.Cause)
}

func (e ErrAppResultEncoding) Unwrap() error {
	return e.Cause
}

// GRPCStatus classes the error Internal: the server produced a result the
// JSON mapping cannot carry.
func (e ErrAppResultEncoding) GRPCStatus() *status.Status {
	return status.New(codes.Internal, e.Error())
}

// appToolCall runs one application service tool against the servers.
type appToolCall func(servers AppServiceServers, ctx context.Context, args map[string]interface{}) (interface{}, error)

// appToolBinding is the RPC a tool calls and the request it decodes into.
type appToolBinding struct {
	call    appToolCall
	request protoreflect.MessageDescriptor
}

// appTool is one application service tool.
type appTool struct {
	// method is the gRPC method the tool serves.
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go.
	scope       string
	description string
	required    []string
	binding     appToolBinding
}

func appCacheServer(s AppServiceServers) platformv1.CacheServiceServer         { return s.Cache }
func appSchedulerServer(s AppServiceServers) platformv1.SchedulerServiceServer { return s.Scheduler }
func appMessagingServer(s AppServiceServers) platformv1.MessagingServiceServer { return s.Messaging }

// appServiceTools maps each application service tool name to its RPC
// (map-based dispatch for O(1) routing per project conventions).
var appServiceTools = map[string]appTool{
	"cache_stats": {
		method: platformv1.CacheService_GetStats_FullMethodName, scope: "cache:read",
		description: "Report the cache statistics, of every entity type or of one",
		binding:     appToolMethod(appservices.ServiceCache, appCacheServer, platformv1.CacheServiceServer.GetStats),
	},
	"cache_config_get": {
		method: platformv1.CacheService_GetConfig_FullMethodName, scope: "cache:read",
		description: "Get the cache configuration",
		binding:     appToolMethod(appservices.ServiceCache, appCacheServer, platformv1.CacheServiceServer.GetConfig),
	},
	"cache_config_update": {
		method: platformv1.CacheService_UpdateConfig_FullMethodName, scope: "cache:write",
		description: "Change the cache configuration; only the fields that are set change, and at least one must be set",
		binding:     appToolMethod(appservices.ServiceCache, appCacheServer, platformv1.CacheServiceServer.UpdateConfig),
	},
	"cache_clear": {
		method: platformv1.CacheService_Clear_FullMethodName, scope: "cache:delete",
		description: "Clear the cache entries of one entity type, or every entry with all",
		binding:     appToolMethod(appservices.ServiceCache, appCacheServer, platformv1.CacheServiceServer.Clear),
	},

	"scheduler_job_create": {
		method: platformv1.SchedulerService_CreateJob_FullMethodName, scope: "scheduler:write",
		description: "Schedule a job: a one-shot job runs at execute_at_unix_ms, a recurring job on its cron schedule",
		required:    []string{"name", "job_type"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.CreateJob),
	},
	"scheduler_job_list": {
		method: platformv1.SchedulerService_ListJobs_FullMethodName, scope: "scheduler:read",
		description: "List the scheduled jobs; each filter applies only when it is set",
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.ListJobs),
	},
	"scheduler_job_get": {
		method: platformv1.SchedulerService_GetJob_FullMethodName, scope: "scheduler:read",
		description: "Get a scheduled job",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.GetJob),
	},
	"scheduler_job_update": {
		method: platformv1.SchedulerService_UpdateJob_FullMethodName, scope: "scheduler:write",
		description: "Change a scheduled job; only the fields set to a non-zero value change",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.UpdateJob),
	},
	"scheduler_job_delete": {
		method: platformv1.SchedulerService_DeleteJob_FullMethodName, scope: "scheduler:delete",
		description: "Delete a scheduled job",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.DeleteJob),
	},
	"scheduler_job_trigger": {
		method: platformv1.SchedulerService_TriggerJob_FullMethodName, scope: "scheduler:write",
		description: "Run a scheduled job now",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.TriggerJob),
	},
	"scheduler_job_pause": {
		method: platformv1.SchedulerService_PauseJob_FullMethodName, scope: "scheduler:write",
		description: "Pause a scheduled job",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.PauseJob),
	},
	"scheduler_job_resume": {
		method: platformv1.SchedulerService_ResumeJob_FullMethodName, scope: "scheduler:write",
		description: "Resume a paused job",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.ResumeJob),
	},
	"scheduler_job_cancel": {
		method: platformv1.SchedulerService_CancelJob_FullMethodName, scope: "scheduler:write",
		description: "Cancel a scheduled job",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.CancelJob),
	},
	"scheduler_job_history": {
		method: platformv1.SchedulerService_GetJobHistory_FullMethodName, scope: "scheduler:read",
		description: "List the runs of a scheduled job; the time and status filters apply only when set",
		required:    []string{"job_id"},
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.GetJobHistory),
	},
	"scheduler_status": {
		method: platformv1.SchedulerService_GetStatus_FullMethodName, scope: "scheduler:read",
		description: "Report the scheduler state and its job counts",
		binding:     appToolMethod(appservices.ServiceScheduler, appSchedulerServer, platformv1.SchedulerServiceServer.GetStatus),
	},

	"messaging_channel_create": {
		method: platformv1.MessagingService_CreateChannel_FullMethodName, scope: "messaging:write",
		description: "Create a messaging channel",
		required:    []string{"name"},
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.CreateChannel),
	},
	"messaging_channel_list": {
		method: platformv1.MessagingService_ListChannels_FullMethodName, scope: "messaging:read",
		description: "List the messaging channels",
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.ListChannels),
	},
	"messaging_channel_get": {
		method: platformv1.MessagingService_GetChannel_FullMethodName, scope: "messaging:read",
		description: "Get a messaging channel",
		required:    []string{"name"},
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.GetChannel),
	},
	"messaging_channel_delete": {
		method: platformv1.MessagingService_DeleteChannel_FullMethodName, scope: "messaging:delete",
		description: "Delete a messaging channel",
		required:    []string{"name"},
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.DeleteChannel),
	},
	"messaging_publish": {
		method: platformv1.MessagingService_Publish_FullMethodName, scope: "messaging:write",
		description: "Publish a message to a channel; the payload is base64",
		required:    []string{"channel"},
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.Publish),
	},
	"messaging_channel_stats": {
		method: platformv1.MessagingService_GetChannelStats_FullMethodName, scope: "messaging:read",
		description: "Report the statistics of one messaging channel",
		required:    []string{"channel"},
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.GetChannelStats),
	},
	"messaging_stats": {
		method: platformv1.MessagingService_GetStats_FullMethodName, scope: "messaging:read",
		description: "Report the messaging statistics",
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.GetStats),
	},
	"messaging_dedup_stats": {
		method: platformv1.MessagingService_GetDedupStats_FullMethodName, scope: "messaging:read",
		description: "Report the message deduplication statistics",
		binding:     appToolMethod(appservices.ServiceMessaging, appMessagingServer, platformv1.MessagingServiceServer.GetDedupStats),
	},
}

// appToolMethod binds a tool to one RPC of the server that server selects.
func appToolMethod[S any, Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	service string,
	server func(AppServiceServers) S,
	call func(S, context.Context, PReq) (Resp, error),
) appToolBinding {
	return appToolBinding{
		request: PReq(new(Req)).ProtoReflect().Descriptor(),
		call: func(servers AppServiceServers, ctx context.Context, args map[string]interface{}) (interface{}, error) {
			target := server(servers)
			if any(target) == nil {
				return nil, ErrAppServiceNotConfigured{Service: service}
			}
			request := PReq(new(Req))
			if err := decodeAppToolArgs(args, request); err != nil {
				return nil, err
			}
			response, err := call(target, ctx, request)
			if err != nil {
				return nil, err
			}
			return encodeAppToolResult(response)
		},
	}
}

// appResultJSON renders a response under the proto field names, the names
// the tool arguments use.
var appResultJSON = protojson.MarshalOptions{UseProtoNames: true}

// decodeAppToolArgs decodes the tool arguments into the RPC request with the
// proto3 JSON mapping. An argument the request does not declare is refused.
func decodeAppToolArgs(args map[string]interface{}, request proto.Message) error {
	if len(args) == 0 {
		return nil
	}
	data, err := json.Marshal(args)
	if err != nil {
		return ErrInvalidArgument{Msg: "the arguments are not JSON", Cause: err}
	}
	if err := protojson.Unmarshal(data, request); err != nil {
		return ErrInvalidArgument{
			Msg:   fmt.Sprintf("the arguments are not a %s", request.ProtoReflect().Descriptor().FullName()),
			Cause: err,
		}
	}
	return nil
}

// encodeAppToolResult renders the RPC response as the tool result.
func encodeAppToolResult(response proto.Message) (map[string]interface{}, error) {
	data, err := appResultJSON.Marshal(response)
	if err != nil {
		return nil, ErrAppResultEncoding{Cause: err}
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, ErrAppResultEncoding{Cause: err}
	}
	return result, nil
}

// appKindTypes is the JSON schema type of each proto field kind in the
// proto3 JSON mapping. 64-bit integers travel as decimal strings there, and
// bytes as base64 strings.
var appKindTypes = map[protoreflect.Kind]interface{}{
	protoreflect.BoolKind:     "boolean",
	protoreflect.Int32Kind:    "integer",
	protoreflect.Sint32Kind:   "integer",
	protoreflect.Uint32Kind:   "integer",
	protoreflect.Sfixed32Kind: "integer",
	protoreflect.Fixed32Kind:  "integer",
	protoreflect.Int64Kind:    []string{"integer", "string"},
	protoreflect.Sint64Kind:   []string{"integer", "string"},
	protoreflect.Uint64Kind:   []string{"integer", "string"},
	protoreflect.Sfixed64Kind: []string{"integer", "string"},
	protoreflect.Fixed64Kind:  []string{"integer", "string"},
	protoreflect.FloatKind:    "number",
	protoreflect.DoubleKind:   "number",
	protoreflect.StringKind:   "string",
	protoreflect.BytesKind:    "string",
	protoreflect.EnumKind:     "string",
	protoreflect.MessageKind:  "object",
	protoreflect.GroupKind:    "object",
}

// appToolSchema is the input schema of a tool: one property per request
// field, under its proto name.
func appToolSchema(request protoreflect.MessageDescriptor, required ...string) map[string]interface{} {
	fields := request.Fields()
	properties := make(map[string]interface{}, fields.Len())
	for i := range fields.Len() {
		field := fields.Get(i)
		properties[string(field.Name())] = appFieldSchema(field)
	}
	return vpnToolSchema(properties, required...)
}

// appFieldSchema is the schema of one request field.
func appFieldSchema(field protoreflect.FieldDescriptor) map[string]interface{} {
	if field.IsMap() {
		return map[string]interface{}{"type": "object", "additionalProperties": appValueSchema(field.MapValue())}
	}
	if field.IsList() {
		return map[string]interface{}{"type": "array", "items": appValueSchema(field)}
	}
	return appValueSchema(field)
}

// appValueSchema is the schema of a single value of a field; an enum lists
// its value names.
func appValueSchema(field protoreflect.FieldDescriptor) map[string]interface{} {
	schema := map[string]interface{}{"type": appKindTypes[field.Kind()]}
	switch field.Kind() {
	case protoreflect.EnumKind:
		values := field.Enum().Values()
		names := make([]string, 0, values.Len())
		for i := range values.Len() {
			names = append(names, string(values.Get(i).Name()))
		}
		schema["enum"] = names
	case protoreflect.BytesKind:
		schema["contentEncoding"] = "base64"
	}
	return schema
}

// registerAppServiceTools registers the cache_*, scheduler_* and
// messaging_* tools in name order.
func (r *ToolRegistry) registerAppServiceTools() {
	for _, name := range slices.Sorted(maps.Keys(appServiceTools)) {
		tool := appServiceTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: appToolSchema(tool.binding.request, tool.required...),
		})
	}
}

// appServiceServers returns the servers of an AppServiceProvider, or none.
func (r *ToolRegistry) appServiceServers() AppServiceServers {
	if provider, ok := r.service.(AppServiceProvider); ok {
		return provider.AppServiceServers()
	}
	return AppServiceServers{}
}

// dispatchAppServiceTool routes the application service tools through
// appServiceTools. It returns handled=false for any other tool.
func (r *ToolRegistry) dispatchAppServiceTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := appServiceTools[name]
	if !ok {
		return nil, false, nil
	}
	result, err := tool.binding.call(r.appServiceServers(), ctx, args)
	return result, true, err
}
