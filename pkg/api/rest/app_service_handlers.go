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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// REST roots of the application services the composed go-quicbaas SDK
// serves, relative to the versioned API root appAPIRoot.
const (
	appAPIRoot        = "/api/v1"
	cacheBasePath     = "/cache"
	schedulerBasePath = "/scheduler"
	messagingBasePath = "/messaging"

	objectStorageBasePath = "/object-storage"
)

// Application service route scopes; they match the CacheService,
// SchedulerService and MessagingService entries in the gRPC method catalog
// (pkg/api/grpc/method_permissions.go).
const (
	scopeCacheRead       = "cache:read"
	scopeCacheWrite      = "cache:write"
	scopeCacheDelete     = "cache:delete"
	scopeSchedulerRead   = "scheduler:read"
	scopeSchedulerWrite  = "scheduler:write"
	scopeSchedulerDelete = "scheduler:delete"
	scopeMessagingRead   = "messaging:read"
	scopeMessagingWrite  = "messaging:write"
	scopeMessagingDelete = "messaging:delete"

	scopeObjectStorageRead   = "objectstorage:read"
	scopeObjectStorageWrite  = "objectstorage:write"
	scopeObjectStorageDelete = "objectstorage:delete"
)

// appUnmarshalOptions decodes request bodies; unknown fields are refused so a
// misspelt field is an error rather than a silently dropped setting.
var appUnmarshalOptions = protojson.UnmarshalOptions{}

// ErrAppServiceUnavailable is returned when the daemon has no server wired
// for an application service.
type ErrAppServiceUnavailable struct {
	Service string
}

// Error implements the error interface.
func (e ErrAppServiceUnavailable) Error() string {
	return e.Service + " service is not configured on this node"
}

// ErrAppInvalidRequestBody is returned when a request body does not decode.
type ErrAppInvalidRequestBody struct {
	Cause error
}

// Error implements the error interface.
func (e ErrAppInvalidRequestBody) Error() string {
	return "invalid request body: " + e.Cause.Error()
}

// Unwrap returns the decode failure.
func (e ErrAppInvalidRequestBody) Unwrap() error { return e.Cause }

// ErrAppInvalidQuery is returned when a query parameter does not parse as
// the request field it names.
type ErrAppInvalidQuery struct {
	Param string
	Value string
}

// Error implements the error interface.
func (e ErrAppInvalidQuery) Error() string {
	return "invalid query parameter " + e.Param + "=" + strconv.Quote(e.Value)
}

// ErrAppPathMismatch is returned when the body names a different item than
// the path.
type ErrAppPathMismatch struct {
	Field string
	Path  string
	Body  string
}

// Error implements the error interface.
func (e ErrAppPathMismatch) Error() string {
	return e.Field + " " + strconv.Quote(e.Body) + " in the body does not match " + strconv.Quote(e.Path) + " in the path"
}

// ErrAppUnknownField is returned when a route binds a path or query
// parameter its request message does not declare.
type ErrAppUnknownField struct {
	Field string
}

// Error implements the error interface.
func (e ErrAppUnknownField) Error() string {
	return "the request has no field " + e.Field
}

// AppServiceServers are the in-process application service servers that
// also back gRPC, QUIC, MCP and the Unix socket. A nil server leaves its
// routes answering 503.
type AppServiceServers struct {
	Cache         platformv1.CacheServiceServer
	Scheduler     platformv1.SchedulerServiceServer
	Messaging     platformv1.MessagingServiceServer
	ObjectStorage platformv1.ObjectStorageServiceServer
}

// AppServiceHandlers binds the Cache, Scheduler, Messaging and ObjectStorage
// REST routes to their servers.
type AppServiceHandlers struct {
	servers AppServiceServers
	guard   RouteGuard
	logger  *slog.Logger
}

// RouteGuard checks a route's scope before its handler runs. ScopeGuard is
// the daemon REST listener's guard; the webservice listener supplies its own
// over the platform token middleware.
type RouteGuard interface {
	Require(scope string, next http.HandlerFunc) http.HandlerFunc
}

// NewAppServiceHandlers creates the application service REST handlers. Each
// route requires the scope its RPC requires on gRPC; a nil guard refuses
// every route with 403.
func NewAppServiceHandlers(servers AppServiceServers, guard RouteGuard, logger *slog.Logger) *AppServiceHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	if guard == nil {
		guard = (*ScopeGuard)(nil)
	}
	return &AppServiceHandlers{servers: servers, guard: guard, logger: logger}
}

// appRESTInvoker binds a request, calls the service and writes the response.
type appRESTInvoker func(h *AppServiceHandlers, w http.ResponseWriter, r *http.Request, route appRESTRoute)

// appRESTRoute is one application service route. Path parameters and query
// parameters are named after the request field they fill; a route with a
// body decodes the rest of the request from it.
type appRESTRoute struct {
	verb    string
	path    string
	scope   string
	query   []string
	body    bool
	success int
	invoke  appRESTInvoker
}

func cacheServer(s AppServiceServers) platformv1.CacheServiceServer         { return s.Cache }
func schedulerServer(s AppServiceServers) platformv1.SchedulerServiceServer { return s.Scheduler }
func messagingServer(s AppServiceServers) platformv1.MessagingServiceServer { return s.Messaging }
func objectStorageServer(s AppServiceServers) platformv1.ObjectStorageServiceServer {
	return s.ObjectStorage
}

// appRESTRoutes maps each gRPC method to its REST route.
//
//	GET    /api/v1/cache/stats?entity_type=                        - GetStats (cache:read)
//	GET    /api/v1/cache/config                                    - GetConfig (cache:read)
//	PATCH  /api/v1/cache/config                                    - UpdateConfig (cache:write)
//	DELETE /api/v1/cache/entries?entity_type=&all=                 - Clear (cache:delete)
//	POST   /api/v1/scheduler/jobs                                  - CreateJob (scheduler:write)
//	GET    /api/v1/scheduler/jobs?owner_type=&...&tags=k=v         - ListJobs (scheduler:read)
//	GET    /api/v1/scheduler/jobs/{job_id}                         - GetJob (scheduler:read)
//	PATCH  /api/v1/scheduler/jobs/{job_id}                         - UpdateJob (scheduler:write)
//	DELETE /api/v1/scheduler/jobs/{job_id}                         - DeleteJob (scheduler:delete)
//	POST   /api/v1/scheduler/jobs/{job_id}/trigger|pause|resume    - TriggerJob, PauseJob, ResumeJob (scheduler:write)
//	POST   /api/v1/scheduler/jobs/{job_id}/cancel                  - CancelJob (scheduler:write)
//	GET    /api/v1/scheduler/jobs/{job_id}/history?limit=&...      - GetJobHistory (scheduler:read)
//	GET    /api/v1/scheduler/status                                - GetStatus (scheduler:read)
//	POST   /api/v1/messaging/channels                              - CreateChannel (messaging:write)
//	GET    /api/v1/messaging/channels                              - ListChannels (messaging:read)
//	GET    /api/v1/messaging/channels/{name}                       - GetChannel (messaging:read)
//	DELETE /api/v1/messaging/channels/{name}                       - DeleteChannel (messaging:delete)
//	POST   /api/v1/messaging/channels/{channel}/messages           - Publish (messaging:write)
//	GET    /api/v1/messaging/channels/{channel}/stats              - GetChannelStats (messaging:read)
//	GET    /api/v1/messaging/stats                                 - GetStats (messaging:read)
//	GET    /api/v1/messaging/dedup-stats                           - GetDedupStats (messaging:read)
//	POST   /api/v1/object-storage/objects                          - PutObject (objectstorage:write)
//	GET    /api/v1/object-storage/objects?prefix=&tenant_id=&...   - ListObjects (objectstorage:read)
//	POST   /api/v1/object-storage/objects/copy                     - CopyObject (objectstorage:write)
//	GET    /api/v1/object-storage/objects/by-tag?tag_name=&...     - ListObjectsByTag (objectstorage:read)
//	GET    /api/v1/object-storage/object?key=&tenant_id=&...       - GetObject (objectstorage:read)
//	DELETE /api/v1/object-storage/object?key=&tenant_id=           - DeleteObject (objectstorage:delete)
//	GET    /api/v1/object-storage/object/metadata?key=&tenant_id=  - HeadObject (objectstorage:read)
//	GET    /api/v1/object-storage/tenants/{tenant_id}/objects      - ListTenantObjects (objectstorage:read)
//
// Object keys hold ':' and '/', so they travel in the query string or the
// body, never in the path.
var appRESTRoutes = map[string]appRESTRoute{
	platformv1.CacheService_GetStats_FullMethodName: {
		verb: http.MethodGet, path: cacheBasePath + "/stats", scope: scopeCacheRead, query: []string{"entity_type"},
		invoke: appRESTMethod(appservices.ServiceCache, cacheServer, platformv1.CacheServiceServer.GetStats),
	},
	platformv1.CacheService_GetConfig_FullMethodName: {
		verb: http.MethodGet, path: cacheBasePath + "/config", scope: scopeCacheRead,
		invoke: appRESTMethod(appservices.ServiceCache, cacheServer, platformv1.CacheServiceServer.GetConfig),
	},
	platformv1.CacheService_UpdateConfig_FullMethodName: {
		verb: http.MethodPatch, path: cacheBasePath + "/config", scope: scopeCacheWrite, body: true,
		invoke: appRESTMethod(appservices.ServiceCache, cacheServer, platformv1.CacheServiceServer.UpdateConfig),
	},
	platformv1.CacheService_Clear_FullMethodName: {
		verb: http.MethodDelete, path: cacheBasePath + "/entries", scope: scopeCacheDelete, query: []string{"entity_type", "all"},
		invoke: appRESTMethod(appservices.ServiceCache, cacheServer, platformv1.CacheServiceServer.Clear),
	},

	platformv1.SchedulerService_CreateJob_FullMethodName: {
		verb: http.MethodPost, path: schedulerBasePath + "/jobs", scope: scopeSchedulerWrite, body: true, success: http.StatusCreated,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.CreateJob),
	},
	platformv1.SchedulerService_ListJobs_FullMethodName: {
		verb: http.MethodGet, path: schedulerBasePath + "/jobs", scope: scopeSchedulerRead,
		query:  []string{"owner_type", "owner_id", "status", "job_type", "tags", "limit", "offset"},
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.ListJobs),
	},
	platformv1.SchedulerService_GetJob_FullMethodName: {
		verb: http.MethodGet, path: schedulerBasePath + "/jobs/{job_id}", scope: scopeSchedulerRead,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.GetJob),
	},
	platformv1.SchedulerService_UpdateJob_FullMethodName: {
		verb: http.MethodPatch, path: schedulerBasePath + "/jobs/{job_id}", scope: scopeSchedulerWrite, body: true,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.UpdateJob),
	},
	platformv1.SchedulerService_DeleteJob_FullMethodName: {
		verb: http.MethodDelete, path: schedulerBasePath + "/jobs/{job_id}", scope: scopeSchedulerDelete,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.DeleteJob),
	},
	platformv1.SchedulerService_TriggerJob_FullMethodName: {
		verb: http.MethodPost, path: schedulerBasePath + "/jobs/{job_id}/trigger", scope: scopeSchedulerWrite,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.TriggerJob),
	},
	platformv1.SchedulerService_PauseJob_FullMethodName: {
		verb: http.MethodPost, path: schedulerBasePath + "/jobs/{job_id}/pause", scope: scopeSchedulerWrite,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.PauseJob),
	},
	platformv1.SchedulerService_ResumeJob_FullMethodName: {
		verb: http.MethodPost, path: schedulerBasePath + "/jobs/{job_id}/resume", scope: scopeSchedulerWrite,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.ResumeJob),
	},
	platformv1.SchedulerService_CancelJob_FullMethodName: {
		verb: http.MethodPost, path: schedulerBasePath + "/jobs/{job_id}/cancel", scope: scopeSchedulerWrite, body: true,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.CancelJob),
	},
	platformv1.SchedulerService_GetJobHistory_FullMethodName: {
		verb: http.MethodGet, path: schedulerBasePath + "/jobs/{job_id}/history", scope: scopeSchedulerRead,
		query:  []string{"limit", "offset", "start_time_unix_ms", "end_time_unix_ms", "status"},
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.GetJobHistory),
	},
	platformv1.SchedulerService_GetStatus_FullMethodName: {
		verb: http.MethodGet, path: schedulerBasePath + "/status", scope: scopeSchedulerRead,
		invoke: appRESTMethod(appservices.ServiceScheduler, schedulerServer, platformv1.SchedulerServiceServer.GetStatus),
	},

	platformv1.MessagingService_CreateChannel_FullMethodName: {
		verb: http.MethodPost, path: messagingBasePath + "/channels", scope: scopeMessagingWrite, body: true, success: http.StatusCreated,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.CreateChannel),
	},
	platformv1.MessagingService_ListChannels_FullMethodName: {
		verb: http.MethodGet, path: messagingBasePath + "/channels", scope: scopeMessagingRead,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.ListChannels),
	},
	platformv1.MessagingService_GetChannel_FullMethodName: {
		verb: http.MethodGet, path: messagingBasePath + "/channels/{name}", scope: scopeMessagingRead,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.GetChannel),
	},
	platformv1.MessagingService_DeleteChannel_FullMethodName: {
		verb: http.MethodDelete, path: messagingBasePath + "/channels/{name}", scope: scopeMessagingDelete,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.DeleteChannel),
	},
	platformv1.MessagingService_Publish_FullMethodName: {
		verb: http.MethodPost, path: messagingBasePath + "/channels/{channel}/messages", scope: scopeMessagingWrite, body: true,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.Publish),
	},
	platformv1.MessagingService_GetChannelStats_FullMethodName: {
		verb: http.MethodGet, path: messagingBasePath + "/channels/{channel}/stats", scope: scopeMessagingRead,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.GetChannelStats),
	},
	platformv1.MessagingService_GetStats_FullMethodName: {
		verb: http.MethodGet, path: messagingBasePath + "/stats", scope: scopeMessagingRead,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.GetStats),
	},
	platformv1.MessagingService_GetDedupStats_FullMethodName: {
		verb: http.MethodGet, path: messagingBasePath + "/dedup-stats", scope: scopeMessagingRead,
		invoke: appRESTMethod(appservices.ServiceMessaging, messagingServer, platformv1.MessagingServiceServer.GetDedupStats),
	},
	platformv1.ObjectStorageService_PutObject_FullMethodName: {
		verb: http.MethodPost, path: objectStorageBasePath + "/objects", scope: scopeObjectStorageWrite, body: true, success: http.StatusCreated,
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.PutObject),
	},
	platformv1.ObjectStorageService_ListObjects_FullMethodName: {
		verb: http.MethodGet, path: objectStorageBasePath + "/objects", scope: scopeObjectStorageRead,
		query:  []string{"prefix", "tenant_id", "limit", "cursor", "include_tags"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.ListObjects),
	},
	platformv1.ObjectStorageService_CopyObject_FullMethodName: {
		verb: http.MethodPost, path: objectStorageBasePath + "/objects/copy", scope: scopeObjectStorageWrite, body: true, success: http.StatusCreated,
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.CopyObject),
	},
	platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName: {
		verb: http.MethodGet, path: objectStorageBasePath + "/objects/by-tag", scope: scopeObjectStorageRead,
		query:  []string{"tag_name", "tag_value", "tenant_id", "limit", "cursor"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.ListObjectsByTag),
	},
	platformv1.ObjectStorageService_GetObject_FullMethodName: {
		verb: http.MethodGet, path: objectStorageBasePath + "/object", scope: scopeObjectStorageRead,
		query:  []string{"key", "tenant_id", "include_metadata"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.GetObject),
	},
	platformv1.ObjectStorageService_DeleteObject_FullMethodName: {
		verb: http.MethodDelete, path: objectStorageBasePath + "/object", scope: scopeObjectStorageDelete,
		query:  []string{"key", "tenant_id"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.DeleteObject),
	},
	platformv1.ObjectStorageService_HeadObject_FullMethodName: {
		verb: http.MethodGet, path: objectStorageBasePath + "/object/metadata", scope: scopeObjectStorageRead,
		query:  []string{"key", "tenant_id"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.HeadObject),
	},
	platformv1.ObjectStorageService_ListTenantObjects_FullMethodName: {
		verb: http.MethodGet, path: objectStorageBasePath + "/tenants/{tenant_id}/objects", scope: scopeObjectStorageRead,
		query:  []string{"limit", "cursor", "include_tags"},
		invoke: appRESTMethod(appservices.ServiceObjectStorage, objectStorageServer, platformv1.ObjectStorageServiceServer.ListTenantObjects),
	},
}

// RegisterRoutes mounts the application service routes (appRESTRoutes) on
// a root router, under /api/v1.
func (h *AppServiceHandlers) RegisterRoutes(router *mux.Router) {
	h.registerUnder(router, appAPIRoot)
}

// RegisterVersionedRoutes mounts the same routes on a router already rooted
// at /api/v1, as the webservice listener's is.
func (h *AppServiceHandlers) RegisterVersionedRoutes(router *mux.Router) {
	h.registerUnder(router, "")
}

func (h *AppServiceHandlers) registerUnder(router *mux.Router, prefix string) {
	for _, route := range appRESTRoutes {
		handler := func(w http.ResponseWriter, r *http.Request) {
			route.invoke(h, w, r, route)
		}
		router.HandleFunc(prefix+route.path, h.guard.Require(route.scope, handler)).Methods(route.verb)
	}
}

// appRESTMethod adapts one service method to a route: it answers 503 when
// the service has no server, binds the request from the path, query and
// body, and writes the service's answer.
func appRESTMethod[S any, Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	service string,
	server func(AppServiceServers) S,
	call func(S, context.Context, PReq) (Resp, error),
) appRESTInvoker {
	return func(h *AppServiceHandlers, w http.ResponseWriter, r *http.Request, route appRESTRoute) {
		target := server(h.servers)
		if any(target) == nil {
			h.writeError(w, http.StatusServiceUnavailable, ErrAppServiceUnavailable{Service: service})
			return
		}
		request := PReq(new(Req))
		if err := bindAppRequest(r, route, request); err != nil {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		resp, err := call(target, r.Context(), request)
		h.respond(w, route.success, resp, err)
	}
}

// bindAppRequest fills msg from the body (when the route takes one), then
// from the path parameters, then from the route's query parameters.
func bindAppRequest(r *http.Request, route appRESTRoute, msg proto.Message) error {
	if route.body {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return ErrAppInvalidRequestBody{Cause: err}
		}
		if len(bytes.TrimSpace(data)) > 0 {
			if err := appUnmarshalOptions.Unmarshal(data, msg); err != nil {
				return ErrAppInvalidRequestBody{Cause: err}
			}
		}
	}

	rm := msg.ProtoReflect()
	for name, value := range mux.Vars(r) {
		if err := setAppPathField(rm, name, value); err != nil {
			return err
		}
	}
	query := r.URL.Query()
	for _, name := range route.query {
		raws, present := query[name]
		if !present {
			continue
		}
		if err := setAppQueryField(rm, name, raws); err != nil {
			return err
		}
	}
	return nil
}

// appField returns the descriptor of the request field name.
func appField(rm protoreflect.Message, name string) (protoreflect.FieldDescriptor, error) {
	fd := rm.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil {
		return nil, ErrAppUnknownField{Field: name}
	}
	return fd, nil
}

// setAppPathField sets the string field the path names. A body that already
// names a different item is refused.
func setAppPathField(rm protoreflect.Message, name, value string) error {
	fd, err := appField(rm, name)
	if err != nil {
		return err
	}
	if fd.Kind() != protoreflect.StringKind || fd.IsList() || fd.IsMap() {
		return ErrAppUnknownField{Field: name}
	}
	if current := rm.Get(fd).String(); current != "" && current != value {
		return ErrAppPathMismatch{Field: name, Path: value, Body: current}
	}
	rm.Set(fd, protoreflect.ValueOfString(value))
	return nil
}

// setAppQueryField parses the query values of one field. A map field takes
// one key=value pair per value; any other field takes the last value.
func setAppQueryField(rm protoreflect.Message, name string, raws []string) error {
	fd, err := appField(rm, name)
	if err != nil {
		return err
	}
	if fd.IsMap() {
		entries := rm.Mutable(fd).Map()
		for _, raw := range raws {
			key, value, found := strings.Cut(raw, "=")
			if !found {
				return ErrAppInvalidQuery{Param: name, Value: raw}
			}
			mapKey, err := parseAppScalar(fd.MapKey(), key)
			if err != nil {
				return appQueryError(name, raw, err)
			}
			mapValue, err := parseAppScalar(fd.MapValue(), value)
			if err != nil {
				return appQueryError(name, raw, err)
			}
			entries.Set(mapKey.MapKey(), mapValue)
		}
		return nil
	}
	if fd.IsList() {
		return ErrAppUnknownField{Field: name}
	}
	raw := raws[len(raws)-1]
	value, err := parseAppScalar(fd, raw)
	if err != nil {
		return appQueryError(name, raw, err)
	}
	rm.Set(fd, value)
	return nil
}

// appQueryError reports a value that does not parse as ErrAppInvalidQuery;
// a field of a kind no query can carry stays ErrAppUnknownField.
func appQueryError(name, raw string, err error) error {
	var unknown ErrAppUnknownField
	if errors.As(err, &unknown) {
		return unknown
	}
	return ErrAppInvalidQuery{Param: name, Value: raw}
}

// appScalarParser parses one query value as a field of its kind.
type appScalarParser func(fd protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error)

// appScalarParsers covers the field kinds the application service requests
// carry in their query (map-based for O(1) lookup).
var appScalarParsers = map[protoreflect.Kind]appScalarParser{
	protoreflect.StringKind: func(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
		return protoreflect.ValueOfString(raw), nil
	},
	protoreflect.BoolKind: func(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
		parsed, err := strconv.ParseBool(raw)
		return protoreflect.ValueOfBool(parsed), err
	},
	protoreflect.Int32Kind: func(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
		parsed, err := strconv.ParseInt(raw, 10, 32)
		return protoreflect.ValueOfInt32(int32(parsed)), err
	},
	protoreflect.Int64Kind: func(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		return protoreflect.ValueOfInt64(parsed), err
	},
	protoreflect.EnumKind: parseAppEnum,
}

// parseAppScalar parses raw as fd's kind.
func parseAppScalar(fd protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
	parse, ok := appScalarParsers[fd.Kind()]
	if !ok {
		return protoreflect.Value{}, ErrAppUnknownField{Field: string(fd.Name())}
	}
	return parse(fd, raw)
}

// parseAppEnum accepts an enum value by name or by number.
func parseAppEnum(fd protoreflect.FieldDescriptor, raw string) (protoreflect.Value, error) {
	values := fd.Enum().Values()
	if named := values.ByName(protoreflect.Name(raw)); named != nil {
		return protoreflect.ValueOfEnum(named.Number()), nil
	}
	number, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return protoreflect.Value{}, err
	}
	if values.ByNumber(protoreflect.EnumNumber(number)) == nil {
		return protoreflect.Value{}, ErrAppInvalidQuery{Param: string(fd.Name()), Value: raw}
	}
	return protoreflect.ValueOfEnum(protoreflect.EnumNumber(number)), nil
}

// respond writes the service result: the protojson body on success, the
// mapped HTTP status otherwise. A zero successCode answers 200.
func (h *AppServiceHandlers) respond(w http.ResponseWriter, successCode int, msg proto.Message, err error) {
	if err != nil {
		code := http.StatusInternalServerError
		if mapped, ok := protorestHTTPStatus[status.Code(err)]; ok {
			code = mapped
		}
		h.logger.Error("Application service request failed", "error", err, "http_status", code)
		h.writeError(w, code, err)
		return
	}
	payload, err := webserviceMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to encode application service response", "error", err)
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if successCode == 0 {
		successCode = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(successCode)
	if _, writeErr := w.Write(payload); writeErr != nil {
		h.logger.Error("Failed to write application service response", "error", writeErr)
	}
}

// writeError writes the standard REST error envelope.
func (h *AppServiceHandlers) writeError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := ErrorResponse{
		Error:     err.Error(),
		Code:      statusCode,
		Timestamp: time.Now().UTC(),
	}
	if encodeErr := json.NewEncoder(w).Encode(body); encodeErr != nil {
		h.logger.Error("Failed to write application service error response", "error", encodeErr)
	}
}
