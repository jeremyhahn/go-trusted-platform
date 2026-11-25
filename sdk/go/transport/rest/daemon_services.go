package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonServicesBasePath is the daemon REST server's service-control root
// (pkg/api/daemon/rest_service.go, RESTServer.registerRoutes). The
// webservice router serves nothing under it.
const daemonServicesBasePath = "/api/v1/services"

// daemonServiceNames are the {service} names the daemon accepts, those of
// serviceNameFromType and serviceTypeFromName in pkg/api/daemon/service.go.
var daemonServiceNames = map[platformv1.ServiceType]string{
	platformv1.ServiceType_SERVICE_TYPE_TPM:         "tpm",
	platformv1.ServiceType_SERVICE_TYPE_SDN:         "sdn",
	platformv1.ServiceType_SERVICE_TYPE_COMPUTE:     "compute",
	platformv1.ServiceType_SERVICE_TYPE_DNS:         "dns",
	platformv1.ServiceType_SERVICE_TYPE_ACME:        "acme",
	platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE:  "webservice",
	platformv1.ServiceType_SERVICE_TYPE_ATTESTATION: "attestation",
}

// daemonServiceStatuses inverts the daemon's serviceStatusStringMap
// (pkg/api/daemon/rest_service.go).
var daemonServiceStatuses = map[string]platformv1.ServiceStatus{
	"stopped":  platformv1.ServiceStatus_SERVICE_STATUS_STOPPED,
	"starting": platformv1.ServiceStatus_SERVICE_STATUS_STARTING,
	"running":  platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
	"stopping": platformv1.ServiceStatus_SERVICE_STATUS_STOPPING,
	"error":    platformv1.ServiceStatus_SERVICE_STATUS_ERROR,
}

// daemonServiceInfoWire is the daemon's bare ServiceInfoResponse.
type daemonServiceInfoWire struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	Uptime     string    `json:"uptime"`
	StartCount uint64    `json:"start_count"`
	StopCount  uint64    `json:"stop_count"`
	LastError  string    `json:"last_error"`
}

// daemonServicesListWire is the daemon's bare ServicesListResponse.
type daemonServicesListWire struct {
	Services []daemonServiceInfoWire `json:"services"`
}

// daemonServiceActionWire is the daemon's bare ServiceActionResponse.
type daemonServiceActionWire struct {
	Service string `json:"service"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// daemonAlreadyRunningPrefix is the start of the envelope error the daemon
// writes with its 409 for a start of a running service: it mirrors the
// Error() text of pkg/api/daemon.ErrServiceAlreadyRunning. It is the one
// 409 the daemon's gRPC service answers with AlreadyExists.
const daemonAlreadyRunningPrefix = "service already running: "

// restConflictCodes maps a gRPC full method name to the code a 409 from its
// REST route takes, given the envelope's error message. The daemon answers
// 409 for refusals of the service's state (not running, owned by the
// process), which its gRPC service reports as FailedPrecondition, so the
// generic POST-409-is-AlreadyExists rule would break parity (docs/SPEC.md).
// A 409 from AttestDevice is the challenge refusing (FailedPrecondition, #2136).
// A 409 from the PXE service's start or stop is its state refusing (FailedPrecondition over gRPC).
var restConflictCodes = map[string]func(message string) codes.Code{
	platformv1.DeviceService_AttestDevice_FullMethodName: alwaysFailedPrecondition,
	platformv1.PXEService_StartService_FullMethodName:    alwaysFailedPrecondition,
	platformv1.PXEService_StopService_FullMethodName:     alwaysFailedPrecondition,
	platformv1.PlatformDaemon_StartService_FullMethodName: func(message string) codes.Code {
		if strings.HasPrefix(message, daemonAlreadyRunningPrefix) {
			return codes.AlreadyExists
		}
		return codes.FailedPrecondition
	},
	platformv1.PlatformDaemon_StopService_FullMethodName:    alwaysFailedPrecondition,
	platformv1.PlatformDaemon_RestartService_FullMethodName: alwaysFailedPrecondition,
}

// alwaysFailedPrecondition is the conflict code of a route whose every 409
// is the service's state refusing the action.
func alwaysFailedPrecondition(string) codes.Code { return codes.FailedPrecondition }

func init() {
	serviceParam := []pathParam{{placeholder: "{service}", field: "service", encode: encodeDaemonServiceName}}

	templatedRouteTable[platformv1.PlatformDaemon_ListServices_FullMethodName] = templatedRoute{
		path:   daemonServicesBasePath,
		method: http.MethodGet,
	}
	templatedRouteTable[platformv1.PlatformDaemon_GetServiceStatus_FullMethodName] = templatedRoute{
		path:       daemonServicesBasePath + "/{service}",
		method:     http.MethodGet,
		pathParams: serviceParam,
	}
	templatedRouteTable[platformv1.PlatformDaemon_StartService_FullMethodName] = templatedRoute{
		path:       daemonServicesBasePath + "/{service}/start",
		method:     http.MethodPost,
		pathParams: serviceParam,
	}
	templatedRouteTable[platformv1.PlatformDaemon_StopService_FullMethodName] = templatedRoute{
		path:       daemonServicesBasePath + "/{service}/stop",
		method:     http.MethodPost,
		pathParams: serviceParam,
	}
	templatedRouteTable[platformv1.PlatformDaemon_RestartService_FullMethodName] = templatedRoute{
		path:       daemonServicesBasePath + "/{service}/restart",
		method:     http.MethodPost,
		pathParams: serviceParam,
	}

	// The daemon's routes take no filter and ignore the request body, so a
	// request that asks for either is refused rather than silently widened.
	restRequestEncoders[platformv1.PlatformDaemon_ListServices_FullMethodName] = encodeDaemonListServices
	restRequestEncoders[platformv1.PlatformDaemon_StartService_FullMethodName] = encodeDaemonStartService
	restRequestEncoders[platformv1.PlatformDaemon_StopService_FullMethodName] = encodeDaemonStopService
	restRequestEncoders[platformv1.PlatformDaemon_RestartService_FullMethodName] = encodeDaemonRestartService

	restResponseDecoders[platformv1.PlatformDaemon_ListServices_FullMethodName] = decodeDaemonListServices
	restResponseDecoders[platformv1.PlatformDaemon_GetServiceStatus_FullMethodName] = decodeDaemonServiceStatus
	restResponseDecoders[platformv1.PlatformDaemon_StartService_FullMethodName] = decodeDaemonStartService
	restResponseDecoders[platformv1.PlatformDaemon_StopService_FullMethodName] = decodeDaemonStopService
	restResponseDecoders[platformv1.PlatformDaemon_RestartService_FullMethodName] = decodeDaemonRestartService
}

// encodeDaemonServiceName renders a ServiceType as the daemon's {service}
// name. UNSPECIFIED and unknown values render "", which refuses the request.
func encodeDaemonServiceName(v protoreflect.Value) string {
	return daemonServiceNames[platformv1.ServiceType(v.Enum())]
}

// daemonServiceTypeOf maps a daemon service name back to its ServiceType.
func daemonServiceTypeOf(name string) platformv1.ServiceType {
	for t, n := range daemonServiceNames {
		if n == name {
			return t
		}
	}
	return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED
}

func encodeDaemonListServices(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.ListServicesRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformDaemon_ListServices_FullMethodName}
	}
	if len(in.GetTypes()) > 0 || len(in.GetStatuses()) > 0 {
		return nil, fmt.Errorf("%s: the daemon REST route takes no types or statuses filter",
			platformv1.PlatformDaemon_ListServices_FullMethodName)
	}
	return body, nil
}

func encodeDaemonStartService(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.StartServiceRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformDaemon_StartService_FullMethodName}
	}
	if len(in.GetOptions()) > 0 {
		return nil, fmt.Errorf("%s: the daemon REST route honours no options",
			platformv1.PlatformDaemon_StartService_FullMethodName)
	}
	return body, nil
}

func encodeDaemonStopService(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.StopServiceRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformDaemon_StopService_FullMethodName}
	}
	if in.GetForce() || in.GetTimeoutSeconds() != 0 {
		return nil, fmt.Errorf("%s: the daemon REST route honours neither force nor timeout_seconds",
			platformv1.PlatformDaemon_StopService_FullMethodName)
	}
	return body, nil
}

func encodeDaemonRestartService(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.RestartServiceRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformDaemon_RestartService_FullMethodName}
	}
	if in.GetTimeoutSeconds() != 0 {
		return nil, fmt.Errorf("%s: the daemon REST route does not honour timeout_seconds",
			platformv1.PlatformDaemon_RestartService_FullMethodName)
	}
	return body, nil
}

// daemonServiceHealth derives a service's health from its status. It copies
// healthStatusFromServiceStatus in the daemon's gRPC service
// (pkg/api/daemon/service.go), since sdk/go imports nothing from the root
// module: RUNNING is HEALTHY, ERROR is UNHEALTHY, STARTING and STOPPING are
// DEGRADED, and any other status is UNSPECIFIED.
func daemonServiceHealth(s platformv1.ServiceStatus) platformv1.HealthStatus {
	switch s {
	case platformv1.ServiceStatus_SERVICE_STATUS_RUNNING:
		return platformv1.HealthStatus_HEALTH_STATUS_HEALTHY
	case platformv1.ServiceStatus_SERVICE_STATUS_ERROR:
		return platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY
	case platformv1.ServiceStatus_SERVICE_STATUS_STARTING,
		platformv1.ServiceStatus_SERVICE_STATUS_STOPPING:
		return platformv1.HealthStatus_HEALTH_STATUS_DEGRADED
	default:
		return platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED
	}
}

// serviceInfo converts the daemon's wire record into the proto ServiceInfo.
// An unknown status string maps to SERVICE_STATUS_UNSPECIFIED; Health is
// derived from the decoded status as the gRPC handlers derive it; an
// unparsable uptime is an error.
func (w daemonServiceInfoWire) serviceInfo() (*platformv1.ServiceInfo, error) {
	status := daemonServiceStatuses[w.Status]
	info := &platformv1.ServiceInfo{
		Type:   daemonServiceTypeOf(w.Name),
		Name:   w.Name,
		Status: status,
		Health: daemonServiceHealth(status),
		Metadata: map[string]string{
			"start_count": strconv.FormatUint(w.StartCount, 10),
			"stop_count":  strconv.FormatUint(w.StopCount, 10),
		},
	}
	if w.LastError != "" {
		info.Metadata["last_error"] = w.LastError
	}
	if !w.StartedAt.IsZero() {
		info.StartedAt = timestamppb.New(w.StartedAt)
	}
	if w.Uptime != "" {
		uptime, err := time.ParseDuration(w.Uptime)
		if err != nil {
			return nil, fmt.Errorf("service %q uptime: %w", w.Name, err)
		}
		if uptime > 0 {
			info.UptimeSeconds = uint64(uptime / time.Second)
		}
	}
	return info, nil
}

func decodeDaemonServiceInfo(raw []byte) (*platformv1.ServiceInfo, error) {
	var wire daemonServiceInfoWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	info, err := wire.serviceInfo()
	if err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return info, nil
}

func decodeDaemonListServices(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListServicesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.PlatformDaemon_ListServices_FullMethodName}
	}
	var wire daemonServicesListWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	services := make([]*platformv1.ServiceInfo, 0, len(wire.Services))
	for _, w := range wire.Services {
		info, err := w.serviceInfo()
		if err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
		services = append(services, info)
	}
	out.Services = services
	return nil
}

func decodeDaemonServiceStatus(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetServiceStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.PlatformDaemon_GetServiceStatus_FullMethodName}
	}
	info, err := decodeDaemonServiceInfo(raw)
	if err != nil {
		return err
	}
	out.Service = info
	return nil
}

// decodeDaemonServiceAction reads a ServiceActionResponse into a Status and
// the ServiceInfo{type, name} of the service it acted on.
func decodeDaemonServiceAction(raw []byte) (*platformv1.Status, *platformv1.ServiceInfo, error) {
	var wire daemonServiceActionWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.Status{Success: wire.Success, Message: wire.Message},
		&platformv1.ServiceInfo{Type: daemonServiceTypeOf(wire.Service), Name: wire.Service},
		nil
}

func decodeDaemonStartService(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.StartServiceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.PlatformDaemon_StartService_FullMethodName}
	}
	st, info, err := decodeDaemonServiceAction(raw)
	if err != nil {
		return err
	}
	out.Status, out.Service = st, info
	return nil
}

func decodeDaemonStopService(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.StopServiceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.PlatformDaemon_StopService_FullMethodName}
	}
	st, _, err := decodeDaemonServiceAction(raw)
	if err != nil {
		return err
	}
	out.Status = st
	return nil
}

func decodeDaemonRestartService(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.RestartServiceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.PlatformDaemon_RestartService_FullMethodName}
	}
	st, info, err := decodeDaemonServiceAction(raw)
	if err != nil {
		return err
	}
	out.Status, out.Service = st, info
	return nil
}
