package rest

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonServicesRecorder records every request but the liveness probe and
// answers with a fixed body.
type daemonServicesRecorder struct {
	mu       sync.Mutex
	requests []string
	reply    string
}

func (r *daemonServicesRecorder) handle(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/health/live" {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, r.reply)
}

func (r *daemonServicesRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

const daemonActionReply = `{"service":"dns","action":"start","success":true,"message":"done"}`

const daemonSDNStatusReply = `{"name":"sdn","status":"running","started_at":"2026-01-02T03:04:05Z",` +
	`"uptime":"1h0m0s","start_count":2,"stop_count":1,"last_error":"x"}`

func TestDaemonServices_PathCarriesServiceName(t *testing.T) {
	dns := platformv1.ServiceType_SERVICE_TYPE_DNS
	cases := []struct {
		name   string
		method string
		req    proto.Message
		reply  proto.Message
		body   string
		want   string
	}{
		{"start", platformv1.PlatformDaemon_StartService_FullMethodName,
			&platformv1.StartServiceRequest{Service: dns}, &platformv1.StartServiceResponse{},
			daemonActionReply, "POST /api/v1/services/dns/start"},
		{"stop", platformv1.PlatformDaemon_StopService_FullMethodName,
			&platformv1.StopServiceRequest{Service: dns}, &platformv1.StopServiceResponse{},
			daemonActionReply, "POST /api/v1/services/dns/stop"},
		{"restart", platformv1.PlatformDaemon_RestartService_FullMethodName,
			&platformv1.RestartServiceRequest{Service: dns}, &platformv1.RestartServiceResponse{},
			daemonActionReply, "POST /api/v1/services/dns/restart"},
		{"status", platformv1.PlatformDaemon_GetServiceStatus_FullMethodName,
			&platformv1.GetServiceStatusRequest{Service: dns}, &platformv1.GetServiceStatusResponse{},
			`{"name":"dns","status":"running"}`, "GET /api/v1/services/dns"},
		{"list", platformv1.PlatformDaemon_ListServices_FullMethodName,
			&platformv1.ListServicesRequest{}, &platformv1.ListServicesResponse{},
			`{"services":[],"count":0}`, "GET /api/v1/services"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &daemonServicesRecorder{reply: tc.body}
			a, _ := adapterAgainst(t, rec.handle)
			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			got := rec.recorded()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("requests = %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestDaemonServices_StatusReplyFillsServiceInfo(t *testing.T) {
	rec := &daemonServicesRecorder{reply: daemonSDNStatusReply}
	a, _ := adapterAgainst(t, rec.handle)

	reply := &platformv1.GetServiceStatusResponse{}
	req := &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_SDN}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.PlatformDaemon_GetServiceStatus_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	info := reply.GetService()
	if info.GetType() != platformv1.ServiceType_SERVICE_TYPE_SDN {
		t.Errorf("type = %v, want SDN", info.GetType())
	}
	if info.GetName() != "sdn" {
		t.Errorf("name = %q, want sdn", info.GetName())
	}
	if info.GetStatus() != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
		t.Errorf("status = %v, want RUNNING", info.GetStatus())
	}
	if info.GetHealth() != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("health = %v, want HEALTHY", info.GetHealth())
	}
	wantStart := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !info.GetStartedAt().AsTime().Equal(wantStart) {
		t.Errorf("started_at = %v, want %v", info.GetStartedAt().AsTime(), wantStart)
	}
	if info.GetUptimeSeconds() != 3600 {
		t.Errorf("uptime_seconds = %d, want 3600", info.GetUptimeSeconds())
	}
	md := info.GetMetadata()
	if md["start_count"] != "2" || md["stop_count"] != "1" || md["last_error"] != "x" {
		t.Errorf("metadata = %v", md)
	}
}

func TestDaemonServices_StatusReplyUnknownStatusAndBadUptime(t *testing.T) {
	rec := &daemonServicesRecorder{reply: `{"name":"dns","status":"sleeping"}`}
	a, _ := adapterAgainst(t, rec.handle)
	req := &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS}

	reply := &platformv1.GetServiceStatusResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.PlatformDaemon_GetServiceStatus_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got := reply.GetService().GetStatus(); got != platformv1.ServiceStatus_SERVICE_STATUS_UNSPECIFIED {
		t.Errorf("status = %v, want UNSPECIFIED", got)
	}
	if reply.GetService().GetStartedAt() != nil {
		t.Errorf("started_at = %v, want unset", reply.GetService().GetStartedAt())
	}

	rec.reply = `{"name":"dns","status":"running","uptime":"forever"}`
	err := a.Connection().Invoke(context.Background(),
		platformv1.PlatformDaemon_GetServiceStatus_FullMethodName, req, &platformv1.GetServiceStatusResponse{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("bad uptime: code = %v (%v), want Internal", status.Code(err), err)
	}
}

func TestDaemonServices_ListDecodesEveryService(t *testing.T) {
	rec := &daemonServicesRecorder{reply: `{"services":[` + daemonSDNStatusReply +
		`,{"name":"dns","status":"stopped","start_count":0,"stop_count":3}],"count":2,` +
		`"timestamp":"2026-01-02T03:04:05Z"}`}
	a, _ := adapterAgainst(t, rec.handle)

	reply := &platformv1.ListServicesResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.PlatformDaemon_ListServices_FullMethodName, &platformv1.ListServicesRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	got := reply.GetServices()
	if len(got) != 2 {
		t.Fatalf("services = %d, want 2", len(got))
	}
	if got[0].GetType() != platformv1.ServiceType_SERVICE_TYPE_SDN ||
		got[0].GetStatus() != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
		t.Errorf("services[0] = %v", got[0])
	}
	if got[1].GetType() != platformv1.ServiceType_SERVICE_TYPE_DNS ||
		got[1].GetStatus() != platformv1.ServiceStatus_SERVICE_STATUS_STOPPED ||
		got[1].GetMetadata()["stop_count"] != "3" {
		t.Errorf("services[1] = %v", got[1])
	}
	if got[0].GetHealth() != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("services[0] health = %v, want HEALTHY", got[0].GetHealth())
	}
	if got[1].GetHealth() != platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED {
		t.Errorf("services[1] health = %v, want UNSPECIFIED", got[1].GetHealth())
	}
}

// TestDaemonServices_HealthFollowsStatus: the decoder derives ServiceInfo.Health
// from the decoded status as the gRPC handlers do (healthStatusFromServiceStatus).
func TestDaemonServices_HealthFollowsStatus(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   platformv1.HealthStatus
	}{
		{"running", platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		{"error", platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
		{"starting", platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{"stopping", platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{"stopped", platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
		{"sleeping", platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
	} {
		t.Run(tc.status, func(t *testing.T) {
			rec := &daemonServicesRecorder{reply: `{"name":"sdn","status":"` + tc.status + `","start_count":0,"stop_count":0}`}
			a, _ := adapterAgainst(t, rec.handle)
			reply := &platformv1.GetServiceStatusResponse{}
			req := &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_SDN}
			if err := a.Connection().Invoke(context.Background(),
				platformv1.PlatformDaemon_GetServiceStatus_FullMethodName, req, reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if got := reply.GetService().GetHealth(); got != tc.want {
				t.Errorf("health = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDaemonServices_ActionReplyFillsStatus(t *testing.T) {
	rec := &daemonServicesRecorder{reply: `{"service":"dns","action":"restart","success":false,"message":"busy"}`}
	a, _ := adapterAgainst(t, rec.handle)
	ctx := context.Background()

	restart := &platformv1.RestartServiceResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.PlatformDaemon_RestartService_FullMethodName,
		&platformv1.RestartServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS}, restart); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if restart.GetStatus().GetSuccess() || restart.GetStatus().GetMessage() != "busy" {
		t.Errorf("restart status = %v", restart.GetStatus())
	}
	if restart.GetService().GetType() != platformv1.ServiceType_SERVICE_TYPE_DNS ||
		restart.GetService().GetName() != "dns" {
		t.Errorf("restart service = %v", restart.GetService())
	}

	rec.reply = daemonActionReply
	start := &platformv1.StartServiceResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.PlatformDaemon_StartService_FullMethodName,
		&platformv1.StartServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS}, start); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !start.GetStatus().GetSuccess() || start.GetStatus().GetMessage() != "done" {
		t.Errorf("start status = %v", start.GetStatus())
	}
	if start.GetService().GetType() != platformv1.ServiceType_SERVICE_TYPE_DNS {
		t.Errorf("start service = %v", start.GetService())
	}

	stop := &platformv1.StopServiceResponse{}
	if err := a.Connection().Invoke(ctx, platformv1.PlatformDaemon_StopService_FullMethodName,
		&platformv1.StopServiceRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS}, stop); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !stop.GetStatus().GetSuccess() || stop.GetStatus().GetMessage() != "done" {
		t.Errorf("stop status = %v", stop.GetStatus())
	}
}

// TestDaemonServices_ConflictKeepsTheGRPCCode reads each 409 the daemon's
// service routes answer as the gRPC service's code: only a start of a running
// service is AlreadyExists; a stop of a stopped service and any action on a
// process-owned service are FailedPrecondition.
func TestDaemonServices_ConflictKeepsTheGRPCCode(t *testing.T) {
	var body string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, body)
	})
	ctx := context.Background()
	dns := platformv1.ServiceType_SERVICE_TYPE_DNS
	const owned = `{"error":"service compute is not controllable: owned by the process"}`
	cases := []struct {
		name   string
		method string
		req    proto.Message
		reply  proto.Message
		body   string
		want   codes.Code
	}{
		{"start running", platformv1.PlatformDaemon_StartService_FullMethodName,
			&platformv1.StartServiceRequest{Service: dns}, &platformv1.StartServiceResponse{},
			`{"error":"service already running: dns"}`, codes.AlreadyExists},
		{"start owned", platformv1.PlatformDaemon_StartService_FullMethodName,
			&platformv1.StartServiceRequest{Service: dns}, &platformv1.StartServiceResponse{},
			owned, codes.FailedPrecondition},
		{"stop stopped", platformv1.PlatformDaemon_StopService_FullMethodName,
			&platformv1.StopServiceRequest{Service: dns}, &platformv1.StopServiceResponse{},
			`{"error":"service is not running: dns"}`, codes.FailedPrecondition},
		{"stop owned", platformv1.PlatformDaemon_StopService_FullMethodName,
			&platformv1.StopServiceRequest{Service: dns}, &platformv1.StopServiceResponse{},
			owned, codes.FailedPrecondition},
		{"restart owned", platformv1.PlatformDaemon_RestartService_FullMethodName,
			&platformv1.RestartServiceRequest{Service: dns}, &platformv1.RestartServiceResponse{},
			owned, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		body = tc.body
		err := a.Connection().Invoke(ctx, tc.method, tc.req, tc.reply)
		if status.Code(err) != tc.want {
			t.Errorf("%s: code = %s (%v), want %s", tc.name, status.Code(err), err, tc.want)
		}
		if msg := status.Convert(err).Message(); msg == "" || msg[0] == '{' {
			t.Errorf("%s: message = %q, want the envelope's error", tc.name, msg)
		}
	}
}

func TestDaemonServices_RefusedBeforeTheWire(t *testing.T) {
	dns := platformv1.ServiceType_SERVICE_TYPE_DNS
	cases := []struct {
		name   string
		method string
		req    proto.Message
		reply  proto.Message
	}{
		{"start unspecified", platformv1.PlatformDaemon_StartService_FullMethodName,
			&platformv1.StartServiceRequest{}, &platformv1.StartServiceResponse{}},
		{"status unknown type", platformv1.PlatformDaemon_GetServiceStatus_FullMethodName,
			&platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType(99)}, &platformv1.GetServiceStatusResponse{}},
		{"list types filter", platformv1.PlatformDaemon_ListServices_FullMethodName,
			&platformv1.ListServicesRequest{Types: []platformv1.ServiceType{dns}}, &platformv1.ListServicesResponse{}},
		{"list statuses filter", platformv1.PlatformDaemon_ListServices_FullMethodName,
			&platformv1.ListServicesRequest{Statuses: []platformv1.ServiceStatus{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING}},
			&platformv1.ListServicesResponse{}},
		{"stop force", platformv1.PlatformDaemon_StopService_FullMethodName,
			&platformv1.StopServiceRequest{Service: dns, Force: true}, &platformv1.StopServiceResponse{}},
		{"stop timeout", platformv1.PlatformDaemon_StopService_FullMethodName,
			&platformv1.StopServiceRequest{Service: dns, TimeoutSeconds: 5}, &platformv1.StopServiceResponse{}},
		{"restart timeout", platformv1.PlatformDaemon_RestartService_FullMethodName,
			&platformv1.RestartServiceRequest{Service: dns, TimeoutSeconds: 5}, &platformv1.RestartServiceResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &daemonServicesRecorder{reply: daemonActionReply}
			a, _ := adapterAgainst(t, rec.handle)
			err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
			if got := rec.recorded(); len(got) != 0 {
				t.Fatalf("requests = %v, want none", got)
			}
		})
	}
}
