package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/healthprobe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newProbeService returns a daemon Service whose health registry holds the
// given components.
func newProbeService(t *testing.T, components ...*stubRegistryComponent) *Service {
	t.Helper()
	registry := health.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	for _, c := range components {
		require.NoError(t, registry.Register(c))
	}
	svc, err := NewService(DefaultConfig())
	require.NoError(t, err)
	svc.SetHealthRegistry(registry)
	return svc
}

func TestService_Liveness_AlwaysAlive(t *testing.T) {
	svc := newProbeService(t, &stubRegistryComponent{name: "kms", status: health.StatusUnhealthy})

	resp, err := svc.Liveness(context.Background(), &platformv1.LivenessRequest{})

	require.NoError(t, err)
	assert.True(t, resp.GetAlive(), "an unhealthy component must not fail liveness")
	assert.NotNil(t, resp.GetTimestamp())
}

func TestService_Readiness_FollowsTheRegistry(t *testing.T) {
	cases := []struct {
		name       string
		components []*stubRegistryComponent
		wantReady  bool
		wantStatus platformv1.HealthStatus
	}{
		{"all healthy", []*stubRegistryComponent{
			{name: "ca", status: health.StatusHealthy},
		}, true, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		{"one degraded", []*stubRegistryComponent{
			{name: "ca", status: health.StatusHealthy},
			{name: "kms", status: health.StatusDegraded},
		}, true, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{"one unhealthy", []*stubRegistryComponent{
			{name: "ca", status: health.StatusHealthy},
			{name: "kms", status: health.StatusUnhealthy},
		}, false, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newProbeService(t, tc.components...)

			resp, err := svc.Readiness(context.Background(), &platformv1.ReadinessRequest{})

			require.NoError(t, err)
			assert.Equal(t, tc.wantReady, resp.GetReady())
			assert.Equal(t, tc.wantStatus, resp.GetStatus())
			assert.NotNil(t, resp.GetTimestamp())
		})
	}
}

// A service with no registry wired keeps the documented fail-open answer.
func TestService_Readiness_NoRegistryFailsOpen(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	require.NoError(t, err)

	resp, err := svc.Readiness(context.Background(), &platformv1.ReadinessRequest{})

	require.NoError(t, err)
	assert.True(t, resp.GetReady())
	assert.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, resp.GetStatus())
}

// A closed registry can answer for nothing, so the platform is not ready.
func TestService_Readiness_ClosedRegistryIsNotReady(t *testing.T) {
	registry := health.NewRegistry()
	require.NoError(t, registry.Close())
	svc, err := NewService(DefaultConfig())
	require.NoError(t, err)
	svc.SetHealthRegistry(registry)

	resp, err := svc.Readiness(context.Background(), &platformv1.ReadinessRequest{})

	require.NoError(t, err)
	assert.False(t, resp.GetReady())
}

// probeAnswers holds one transport's answers to the three probes.
type probeAnswers struct {
	health    *platformv1.GetHealthResponse
	liveness  *platformv1.LivenessResponse
	readiness *platformv1.ReadinessResponse
}

// quicProbe sends one probe opcode and decodes the answer into message.
func quicProbe(t *testing.T, h *QUICServiceHandler, opcode byte, message interface{}) {
	t.Helper()
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcode})
	require.Equal(t, quicwire.StatusOK, resp.Status, "a probe verdict travels in the payload, not the status")
	require.NoError(t, quicwire.DecodePayload(resp.Payload, message))
}

func quicProbeAnswers(t *testing.T, h *QUICServiceHandler) probeAnswers {
	t.Helper()
	answers := probeAnswers{
		health:    &platformv1.GetHealthResponse{},
		liveness:  &platformv1.LivenessResponse{},
		readiness: &platformv1.ReadinessResponse{},
	}
	quicProbe(t, h, quicwire.OpHealth, answers.health)
	quicProbe(t, h, quicwire.OpLiveness, answers.liveness)
	quicProbe(t, h, quicwire.OpReadiness, answers.readiness)
	return answers
}

// mcpProbe decodes one MCP probe result the way the SDK does: protojson.
func mcpProbe(t *testing.T, result interface{}, err error, message proto.Message) {
	t.Helper()
	require.NoError(t, err)
	raw, ok := result.(json.RawMessage)
	require.True(t, ok, "MCP probe result is %T, want json.RawMessage", result)
	require.NoError(t, protojson.Unmarshal(raw, message))
}

func mcpProbeAnswers(t *testing.T, p *MCPServiceProvider) probeAnswers {
	t.Helper()
	ctx := context.Background()
	answers := probeAnswers{
		health:    &platformv1.GetHealthResponse{},
		liveness:  &platformv1.LivenessResponse{},
		readiness: &platformv1.ReadinessResponse{},
	}
	result, err := p.Health(ctx)
	mcpProbe(t, result, err, answers.health)
	result, err = p.Liveness(ctx)
	mcpProbe(t, result, err, answers.liveness)
	result, err = p.Readiness(ctx)
	mcpProbe(t, result, err, answers.readiness)
	return answers
}

// withoutTimestamp asserts the answer is stamped, then drops the stamp so
// answers taken moments apart compare equal.
func withoutTimestamp[M interface {
	proto.Message
	GetTimestamp() *timestamppb.Timestamp
}](t *testing.T, message M) proto.Message {
	t.Helper()
	require.NotNil(t, message.GetTimestamp(), "probe answer carries no timestamp")
	clone := proto.Clone(message)
	clone.ProtoReflect().Clear(clone.ProtoReflect().Descriptor().Fields().ByName("timestamp"))
	return clone
}

// Every transport answers the probes from the same functions, so QUIC and MCP
// give the answer gRPC gives for the same registry state, and neither names a
// component: both serve the probes without a credential.
func TestProbes_QUICAndMCPAnswerAsGRPC(t *testing.T) {
	for _, status := range []health.HealthStatus{health.StatusHealthy, health.StatusDegraded, health.StatusUnhealthy} {
		t.Run(string(status), func(t *testing.T) {
			ctx := context.Background()
			svc := newProbeService(t,
				&stubRegistryComponent{name: "ca", status: health.StatusHealthy},
				&stubRegistryComponent{name: "kms", status: status})

			liveness, err := svc.Liveness(ctx, &platformv1.LivenessRequest{})
			require.NoError(t, err)
			readiness, err := svc.Readiness(ctx, &platformv1.ReadinessRequest{})
			require.NoError(t, err)
			detailed, err := svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
			require.NoError(t, err)
			require.NotEmpty(t, detailed.GetComponents(), "the authenticated GetHealth keeps its breakdown")
			grpcAnswers := probeAnswers{
				health:    &platformv1.GetHealthResponse{Status: detailed.GetStatus(), Timestamp: detailed.GetTimestamp()},
				liveness:  liveness,
				readiness: readiness,
			}

			quicHandler := newTestQUICServiceHandler(logging.NewLogger(slog.LevelError, nil),
				WithQUICHealthRegistry(svc.currentHealthRegistry()))
			mcpProvider := NewMCPServiceProvider(&MCPServiceProviderConfig{HealthService: svc, Logger: slog.Default()})

			for transport, got := range map[string]probeAnswers{
				"QUIC": quicProbeAnswers(t, quicHandler),
				"MCP":  mcpProbeAnswers(t, mcpProvider),
			} {
				assert.Empty(t, got.health.GetComponents(), "%s health names a component", transport)
				assert.True(t, proto.Equal(withoutTimestamp(t, grpcAnswers.health), withoutTimestamp(t, got.health)),
					"%s health = %v, gRPC = %v", transport, got.health, grpcAnswers.health)
				assert.True(t, proto.Equal(withoutTimestamp(t, grpcAnswers.liveness), withoutTimestamp(t, got.liveness)),
					"%s liveness = %v, gRPC = %v", transport, got.liveness, grpcAnswers.liveness)
				assert.True(t, proto.Equal(withoutTimestamp(t, grpcAnswers.readiness), withoutTimestamp(t, got.readiness)),
					"%s readiness = %v, gRPC = %v", transport, got.readiness, grpcAnswers.readiness)
			}
		})
	}
}

// The daemon REST stack serves the same root probes as the webservice
// listener: 503 when the probe fails, and no component in the body.
func TestRESTServer_RootProbes(t *testing.T) {
	cases := map[health.HealthStatus]map[string]int{
		health.StatusHealthy: {
			healthprobe.HealthPath: http.StatusOK, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusOK},
		health.StatusDegraded: {
			healthprobe.HealthPath: http.StatusServiceUnavailable, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusOK},
		health.StatusUnhealthy: {
			healthprobe.HealthPath: http.StatusServiceUnavailable, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusServiceUnavailable},
	}
	for status, want := range cases {
		t.Run(string(status), func(t *testing.T) {
			svc := newProbeService(t,
				&stubRegistryComponent{name: "ca", status: health.StatusHealthy},
				&stubRegistryComponent{name: "kms", status: status})
			server, err := NewRESTServer(DefaultConfig(), svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)

			for path, code := range want {
				recorder := httptest.NewRecorder()
				server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
				assert.Equal(t, code, recorder.Code, "GET %s", path)
				assert.NotContains(t, recorder.Body.String(), "kms", "GET %s names a component", path)
			}
		})
	}
}

// With no health service wired, the MCP probe tools refuse rather than
// invent an answer.
