// Package healthprobe projects the health probes (pkg/health Liveness,
// Readiness and Aggregate) onto the platform.v1 wire messages, and serves
// them over HTTP. Every transport answers the probes from these functions so
// that each gives the same answer for the same registry state.
//
// The projections carry the verdict only, never a component name or detail:
// probes are served without a credential (docs/health/api.md §7).
package healthprobe

import (
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The probe routes, unversioned at the host root so load balancers and
// orchestrators can be pointed at them without an API prefix.
const (
	HealthPath    = "/health"
	LivenessPath  = "/health/live"
	ReadinessPath = "/health/ready"
)

// marshalOptions emits false and zero fields so a refused probe still says
// "ready": false rather than leaving the field out.
var marshalOptions = protojson.MarshalOptions{EmitUnpopulated: true}

// StatusToProto maps the registry vocabulary onto the wire enum. The proto
// enum has no unknown value, so unknown maps to UNSPECIFIED.
func StatusToProto(status health.HealthStatus) platformv1.HealthStatus {
	switch status {
	case health.StatusHealthy:
		return platformv1.HealthStatus_HEALTH_STATUS_HEALTHY
	case health.StatusDegraded:
		return platformv1.HealthStatus_HEALTH_STATUS_DEGRADED
	case health.StatusUnhealthy:
		return platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY
	default:
		return platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED
	}
}

// LivenessResponse projects a liveness probe.
func LivenessResponse(probe health.Probe) *platformv1.LivenessResponse {
	return &platformv1.LivenessResponse{
		Alive:     probe.OK,
		Timestamp: timestamppb.New(probe.Timestamp),
	}
}

// ReadinessResponse projects a readiness probe.
func ReadinessResponse(probe health.Probe) *platformv1.ReadinessResponse {
	return &platformv1.ReadinessResponse{
		Ready:     probe.OK,
		Status:    StatusToProto(probe.Status),
		Timestamp: timestamppb.New(probe.Timestamp),
	}
}

// HealthSummaryResponse projects an aggregate probe as a GetHealthResponse
// with no components: the unauthenticated form of GetHealth.
func HealthSummaryResponse(probe health.Probe) *platformv1.GetHealthResponse {
	return &platformv1.GetHealthResponse{
		Status:    StatusToProto(probe.Status),
		Timestamp: timestamppb.New(probe.Timestamp),
	}
}

// RegistrySource returns the health registry the probes read. It may return
// nil, which the probes answer with the documented fail-open verdict.
type RegistrySource func() health.Registry

// Handlers serves the three probe routes.
type Handlers struct {
	registry RegistrySource
}

// NewHandlers returns probe handlers that read the registry from source on
// every request, so a registry wired after the routes are mounted is seen.
// A nil source behaves as one that returns no registry.
func NewHandlers(source RegistrySource) *Handlers {
	if source == nil {
		source = func() health.Registry { return nil }
	}
	return &Handlers{registry: source}
}

// RegisterRoutes mounts GET /health, /health/live and /health/ready on
// router. The routes are unauthenticated by design; mount them only on a
// router with no auth middleware.
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc(HealthPath, h.Health).Methods(http.MethodGet)
	router.HandleFunc(LivenessPath, h.Liveness).Methods(http.MethodGet)
	router.HandleFunc(ReadinessPath, h.Readiness).Methods(http.MethodGet)
}

// Liveness handles GET /health/live: 200 whenever the process answers.
func (h *Handlers) Liveness(w http.ResponseWriter, r *http.Request) {
	probe := health.Liveness()
	writeProbe(w, probe.OK, LivenessResponse(probe))
}

// Readiness handles GET /health/ready: 200 when ready, 503 when not.
func (h *Handlers) Readiness(w http.ResponseWriter, r *http.Request) {
	probe := health.Readiness(r.Context(), h.registry())
	writeProbe(w, probe.OK, ReadinessResponse(probe))
}

// Health handles GET /health: 200 when healthy, 503 when degraded,
// unhealthy or unknown. The body is the status only.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	probe := health.Aggregate(r.Context(), h.registry())
	writeProbe(w, probe.OK, HealthSummaryResponse(probe))
}

// writeProbe writes the probe body as protojson, which the SDK's REST
// transport decodes into the same message the gRPC rpc returns.
func writeProbe(w http.ResponseWriter, ok bool, message proto.Message) {
	body, err := MarshalJSON(message)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if _, err := w.Write(body); err != nil {
		// The client is gone; the status line is already sent.
		return
	}
}

// MarshalJSON renders a probe message as protojson with unpopulated fields
// emitted, the body every JSON transport (REST, MCP) sends for a probe.
func MarshalJSON(message proto.Message) ([]byte, error) {
	return marshalOptions.Marshal(message)
}
