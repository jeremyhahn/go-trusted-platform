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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeCacheServer records the request it receives.
type fakeCacheServer struct {
	platformv1.UnimplementedCacheServiceServer
	clear *platformv1.ClearCacheRequest
	err   error
}

func (f *fakeCacheServer) Clear(_ context.Context, req *platformv1.ClearCacheRequest) (*platformv1.ClearCacheResponse, error) {
	f.clear = req
	return &platformv1.ClearCacheResponse{}, f.err
}

func (f *fakeCacheServer) GetStats(_ context.Context, _ *platformv1.GetCacheStatsRequest) (*platformv1.GetCacheStatsResponse, error) {
	return nil, f.err
}

// fakeSchedulerServer records the requests it receives.
type fakeSchedulerServer struct {
	platformv1.UnimplementedSchedulerServiceServer
	created *platformv1.CreateSchedulerJobRequest
	listed  *platformv1.ListSchedulerJobsRequest
	history *platformv1.GetSchedulerJobHistoryRequest
	updated *platformv1.UpdateSchedulerJobRequest
}

func (f *fakeSchedulerServer) CreateJob(_ context.Context, req *platformv1.CreateSchedulerJobRequest) (*platformv1.CreateSchedulerJobResponse, error) {
	f.created = req
	return &platformv1.CreateSchedulerJobResponse{}, nil
}

func (f *fakeSchedulerServer) ListJobs(_ context.Context, req *platformv1.ListSchedulerJobsRequest) (*platformv1.ListSchedulerJobsResponse, error) {
	f.listed = req
	return &platformv1.ListSchedulerJobsResponse{}, nil
}

func (f *fakeSchedulerServer) GetJobHistory(_ context.Context, req *platformv1.GetSchedulerJobHistoryRequest) (*platformv1.GetSchedulerJobHistoryResponse, error) {
	f.history = req
	return &platformv1.GetSchedulerJobHistoryResponse{}, nil
}

func (f *fakeSchedulerServer) UpdateJob(_ context.Context, req *platformv1.UpdateSchedulerJobRequest) (*platformv1.UpdateSchedulerJobResponse, error) {
	f.updated = req
	return &platformv1.UpdateSchedulerJobResponse{}, nil
}

// fakeMessagingServer records the request it receives.
type fakeMessagingServer struct {
	platformv1.UnimplementedMessagingServiceServer
	published *platformv1.PublishMessageRequest
}

func (f *fakeMessagingServer) Publish(_ context.Context, req *platformv1.PublishMessageRequest) (*platformv1.PublishMessageResponse, error) {
	f.published = req
	return &platformv1.PublishMessageResponse{}, nil
}

type appServiceFakes struct {
	cache     *fakeCacheServer
	scheduler *fakeSchedulerServer
	messaging *fakeMessagingServer
}

// appServiceRouter mounts the application service routes on fakes behind an
// operator guard.
func appServiceRouter() (*mux.Router, appServiceFakes) {
	fakes := appServiceFakes{cache: &fakeCacheServer{}, scheduler: &fakeSchedulerServer{}, messaging: &fakeMessagingServer{}}
	router := mux.NewRouter()
	NewAppServiceHandlers(AppServiceServers{
		Cache:     fakes.cache,
		Scheduler: fakes.scheduler,
		Messaging: fakes.messaging,
	}, operatorGuard(), nil).RegisterRoutes(router)
	return router, fakes
}

func serveOperator(router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, operatorRequest(method, target, reader))
	return recorder
}

// TestAppRESTRoutes_ScopesMatchTheGRPCCatalog requires one route per
// CacheService, SchedulerService and MessagingService method, guarded by
// the scope its gRPC twin requires.
func TestAppRESTRoutes_ScopesMatchTheGRPCCatalog(t *testing.T) {
	declared := 0
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			declared++
			method := "/" + desc.ServiceName + "/" + m.MethodName
			route, ok := appRESTRoutes[method]
			if !assert.True(t, ok, "%s has no REST route", method) {
				continue
			}
			want := grpcapi.ScopeForMethod(method)
			assert.NotEmpty(t, want, "%s is missing from the gRPC method catalog", method)
			assert.Equal(t, want, route.scope, "%s %s", route.verb, route.path)
		}
	}
	assert.Len(t, appRESTRoutes, declared, "the route table maps a method the services do not declare")
}

// appRequestFor returns an empty request message of a gRPC method.
func appRequestFor(t *testing.T, method string) proto.Message {
	t.Helper()
	service, name, ok := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	require.True(t, ok, method)
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(service))
	require.NoError(t, err, method)
	input := desc.(protoreflect.ServiceDescriptor).Methods().ByName(protoreflect.Name(name)).Input()
	messageType, err := protoregistry.GlobalTypes.FindMessageByName(input.FullName())
	require.NoError(t, err, method)
	return messageType.New().Interface()
}

// TestAppRESTRoutes_BindOnlyFieldsTheirRequestDeclares fails a route whose
// path or query names a field its request message lacks.
func TestAppRESTRoutes_BindOnlyFieldsTheirRequestDeclares(t *testing.T) {
	for method, route := range appRESTRoutes {
		rm := appRequestFor(t, method).ProtoReflect()
		fields := slices.Clone(route.query)
		for _, segment := range strings.Split(route.path, "/") {
			if param, isParam := strings.CutPrefix(segment, "{"); isParam {
				fields = append(fields, strings.TrimSuffix(param, "}"))
			}
		}
		for _, field := range fields {
			_, err := appField(rm, field)
			assert.NoError(t, err, "%s binds %s", method, field)
		}
	}
}

func TestAppRESTRoutes_QueryFillsTheRequest(t *testing.T) {
	router, fakes := appServiceRouter()

	recorder := serveOperator(router, http.MethodGet,
		"/api/v1/scheduler/jobs?status=SCHEDULER_JOB_STATUS_PAUSED&owner_type=2&tags=env%3Dprod&tags=team%3Dnet&limit=10", "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED, fakes.scheduler.listed.GetStatus())
	assert.Equal(t, platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_TENANT, fakes.scheduler.listed.GetOwnerType())
	assert.Equal(t, map[string]string{"env": "prod", "team": "net"}, fakes.scheduler.listed.GetTags())
	assert.Equal(t, int32(10), fakes.scheduler.listed.GetLimit())

	recorder = serveOperator(router, http.MethodGet, "/api/v1/scheduler/jobs/j1/history?start_time_unix_ms=1700000000000&offset=5", "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, "j1", fakes.scheduler.history.GetJobId())
	assert.Equal(t, int64(1700000000000), fakes.scheduler.history.GetStartTimeUnixMs())
	assert.Equal(t, int32(5), fakes.scheduler.history.GetOffset())

	recorder = serveOperator(router, http.MethodDelete, "/api/v1/cache/entries?all=true", "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.True(t, fakes.cache.clear.GetAll())
}

func TestAppRESTRoutes_BodyAndPathFillTheRequest(t *testing.T) {
	router, fakes := appServiceRouter()

	recorder := serveOperator(router, http.MethodPost, "/api/v1/messaging/channels/events/messages",
		`{"payload":"aGVsbG8=","metadata":{"k":"v"}}`)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, "events", fakes.messaging.published.GetChannel())
	assert.Equal(t, []byte("hello"), fakes.messaging.published.GetPayload())
	assert.Equal(t, map[string]string{"k": "v"}, fakes.messaging.published.GetMetadata())

	recorder = serveOperator(router, http.MethodPatch, "/api/v1/scheduler/jobs/j1", `{"job_id":"j1","schedule":"@daily"}`)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, "j1", fakes.scheduler.updated.GetJobId())
	assert.Equal(t, "@daily", fakes.scheduler.updated.GetSchedule())

	recorder = serveOperator(router, http.MethodPost, "/api/v1/scheduler/jobs", `{"name":"rotate","job_type":"SCHEDULER_JOB_TYPE_RECURRING"}`)
	require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())
	assert.Equal(t, "rotate", fakes.scheduler.created.GetName())
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
}

func TestAppRESTRoutes_RefuseBadRequests(t *testing.T) {
	cases := []struct {
		name, grpcMethod, method, target, body string
		want                                   any
	}{
		{"malformed body", platformv1.SchedulerService_CreateJob_FullMethodName, http.MethodPost, "/api/v1/scheduler/jobs", `{"name":`, &ErrAppInvalidRequestBody{}},
		{"unknown body field", platformv1.SchedulerService_CreateJob_FullMethodName, http.MethodPost, "/api/v1/scheduler/jobs", `{"not_a_field":"rotate"}`, &ErrAppInvalidRequestBody{}},
		{"body names another job", platformv1.SchedulerService_UpdateJob_FullMethodName, http.MethodPatch, "/api/v1/scheduler/jobs/j1", `{"job_id":"j2"}`, &ErrAppPathMismatch{}},
		{"limit is not a number", platformv1.SchedulerService_ListJobs_FullMethodName, http.MethodGet, "/api/v1/scheduler/jobs?limit=ten", "", &ErrAppInvalidQuery{}},
		{"limit overflows int32", platformv1.SchedulerService_ListJobs_FullMethodName, http.MethodGet, "/api/v1/scheduler/jobs?limit=4294967296", "", &ErrAppInvalidQuery{}},
		{"tag without a value", platformv1.SchedulerService_ListJobs_FullMethodName, http.MethodGet, "/api/v1/scheduler/jobs?tags=env", "", &ErrAppInvalidQuery{}},
		{"unknown status name", platformv1.SchedulerService_ListJobs_FullMethodName, http.MethodGet, "/api/v1/scheduler/jobs?status=BOGUS", "", &ErrAppInvalidQuery{}},
		{"undeclared status number", platformv1.SchedulerService_ListJobs_FullMethodName, http.MethodGet, "/api/v1/scheduler/jobs?status=99", "", &ErrAppInvalidQuery{}},
		{"all is not a bool", platformv1.CacheService_Clear_FullMethodName, http.MethodDelete, "/api/v1/cache/entries?all=maybe", "", &ErrAppInvalidQuery{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := appServiceRouter()
			recorder := serveOperator(router, tc.method, tc.target, tc.body)
			assert.Equal(t, http.StatusBadRequest, recorder.Code)

			var body ErrorResponse
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.Equal(t, http.StatusBadRequest, body.Code)

			// The binder reports the typed error the handler answers with.
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			var matched mux.RouteMatch
			require.True(t, router.Match(req, &matched))
			req = mux.SetURLVars(req, matched.Vars)
			err := bindAppRequest(req, appRESTRoutes[tc.grpcMethod], appRequestFor(t, tc.grpcMethod))
			assert.True(t, errors.As(err, tc.want), "error = %v, want %T", err, tc.want)
			assert.Equal(t, err.Error(), body.Error)
		})
	}
}

func TestAppRESTRoutes_ServiceErrorsMapToHTTPStatus(t *testing.T) {
	cases := map[codes.Code]int{
		codes.Unavailable:     http.StatusServiceUnavailable,
		codes.NotFound:        http.StatusNotFound,
		codes.InvalidArgument: http.StatusBadRequest,
		codes.Internal:        http.StatusInternalServerError,
	}
	for code, want := range cases {
		router, fakes := appServiceRouter()
		fakes.cache.err = status.Error(code, "cache is not served by the go-quicbaas SDK on this node")
		recorder := serveOperator(router, http.MethodGet, "/api/v1/cache/stats", "")
		assert.Equal(t, want, recorder.Code, code.String())
		assert.Contains(t, recorder.Body.String(), "not served by the go-quicbaas SDK", code.String())
	}
}

func TestAppRESTRoutes_UnwiredServiceAnswers503(t *testing.T) {
	router := mux.NewRouter()
	NewAppServiceHandlers(AppServiceServers{}, operatorGuard(), nil).RegisterRoutes(router)
	for target, service := range map[string]string{
		"/api/v1/cache/config":     "cache",
		"/api/v1/scheduler/status": "scheduler",
		"/api/v1/messaging/stats":  "messaging",
	} {
		recorder := serveOperator(router, http.MethodGet, target, "")
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, target)
		assert.Contains(t, recorder.Body.String(), ErrAppServiceUnavailable{Service: service}.Error(), target)
	}
}

// scopeRecorder is a RouteGuard that admits every request and records the
// scope each one was checked against.
type scopeRecorder struct {
	scopes []string
}

func (g *scopeRecorder) Require(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.scopes = append(g.scopes, scope)
		next(w, r)
	}
}

// TestAppServiceHandlers_RegisterVersionedRoutes mounts the routes on a
// router already rooted at /api/v1, as the webservice listener does, behind
// a guard other than ScopeGuard.
func TestAppServiceHandlers_RegisterVersionedRoutes(t *testing.T) {
	guard := &scopeRecorder{}
	root := mux.NewRouter()
	NewAppServiceHandlers(AppServiceServers{}, guard, nil).RegisterVersionedRoutes(root.PathPrefix(appAPIRoot).Subrouter())
	for _, target := range []string{"/api/v1/cache/config", "/api/v1/scheduler/status", "/api/v1/messaging/stats"} {
		recorder := httptest.NewRecorder()
		root.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "%s must reach its handler", target)
	}
	assert.Equal(t, []string{scopeCacheRead, scopeSchedulerRead, scopeMessagingRead}, guard.scopes)
}

func TestNewAppServiceHandlers_NilGuardRefusesEveryRoute(t *testing.T) {
	router := mux.NewRouter()
	NewAppServiceHandlers(AppServiceServers{}, nil, nil).RegisterRoutes(router)
	recorder := serveOperator(router, http.MethodGet, "/api/v1/cache/config", "")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestSetAppFieldsRefuseFieldsTheRequestLacks(t *testing.T) {
	rm := (&platformv1.ListSchedulerJobsRequest{}).ProtoReflect()
	var unknown ErrAppUnknownField
	assert.ErrorAs(t, setAppPathField(rm, "job_id", "j1"), &unknown)
	assert.ErrorAs(t, setAppPathField(rm, "limit", "10"), &unknown, "a path parameter fills only a string field")
	assert.ErrorAs(t, setAppQueryField(rm, "no_such_field", []string{"x"}), &unknown)

	payload := (&platformv1.PublishMessageRequest{}).ProtoReflect()
	assert.ErrorAs(t, setAppQueryField(payload, "payload", []string{"x"}), &unknown, "bytes are not a query kind")
}

func TestParseAppEnumAcceptsNameOrNumber(t *testing.T) {
	fd := (&platformv1.ListSchedulerJobsRequest{}).ProtoReflect().Descriptor().Fields().ByName("status")
	byName, err := parseAppEnum(fd, "SCHEDULER_JOB_STATUS_RUNNING")
	require.NoError(t, err)
	byNumber, err := parseAppEnum(fd, "2")
	require.NoError(t, err)
	assert.Equal(t, byName.Enum(), byNumber.Enum())

	_, err = parseAppEnum(fd, "running")
	assert.Error(t, err)
}

func TestAppRESTErrors(t *testing.T) {
	cause := errors.New("unexpected EOF")
	bodyErr := ErrAppInvalidRequestBody{Cause: cause}
	assert.ErrorIs(t, bodyErr, cause)
	assert.Contains(t, bodyErr.Error(), "unexpected EOF")
	assert.Equal(t, `invalid query parameter limit="ten"`, ErrAppInvalidQuery{Param: "limit", Value: "ten"}.Error())
	assert.Equal(t, `job_id "j2" in the body does not match "j1" in the path`, ErrAppPathMismatch{Field: "job_id", Path: "j1", Body: "j2"}.Error())
	assert.Equal(t, "the request has no field x", ErrAppUnknownField{Field: "x"}.Error())
	assert.Equal(t, "cache service is not configured on this node", ErrAppServiceUnavailable{Service: "cache"}.Error())
}
