// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"
	"log/slog"
	"sync"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// DefaultAuditService tags SDKAuditSink events with the originating
// service (AuditContext.Service) when SDKAuditSinkConfig.Service is empty.
const DefaultAuditService = "gatewayd-proxy"

// DefaultAuditTimeout bounds each detached RecordAsync call SDKAuditSink
// issues. Zero (unset) SDKAuditSinkConfig.Timeout defaults to this.
const DefaultAuditTimeout = 5 * time.Second

// AuditConfig is the proxy `audit:` section: it enables emitting routing/
// authentication decisions onto the platform audit chain (quicbaasd)
// through the quicbaas SDK IAM audit client (P5.3 — one audit plane, no
// local audit subsystem). Disabled, or unreachable at runtime, leaves the
// pkg/proxy no-op sink installed: the proxy always serves traffic
// regardless of the audit plane's health.
type AuditConfig struct {
	// Enabled activates the audit sink.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// QuicBaaSAddr is the address of quicbaasd, the platform audit chain
	// of record. Required when Enabled.
	QuicBaaSAddr string `yaml:"quicbaas-addr,omitempty" json:"quicbaas_addr,omitempty" mapstructure:"quicbaas-addr"`

	// QuicBaaSTransport selects the go-quicbaas SDK transport: unix, rest,
	// quic, or mcp. Empty (or grpc) lets the SDK auto-detect from
	// QuicBaaSAddr — gRPC is the default, a .sock path resolves to unix.
	QuicBaaSTransport string `yaml:"quicbaas-transport,omitempty" json:"quicbaas_transport,omitempty" mapstructure:"quicbaas-transport"`

	// Service tags every emitted event's AuditContext.Service. Empty
	// defaults to DefaultAuditService.
	Service string `yaml:"service,omitempty" json:"service,omitempty" mapstructure:"service"`
}

// Validate checks the audit section. Disabled sections are not validated.
func (c *AuditConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.QuicBaaSAddr == "" {
		return &ErrAuditConfig{Field: "quicbaas-addr", Reason: "required when audit.enabled is true"}
	}
	return nil
}

// AuditClient is the narrow surface of the quicbaas SDK IAM audit client
// SDKAuditSink consumes: fire-and-forget emission onto the platform audit
// chain. The client returned by quicbaassdk.Client.IAM().Audit() (the same
// quicbaassdk.NewClient plumbing IAMService.Audit() resolves to inside
// platformd, see pkg/api/daemon/iam_service.go) satisfies it; unit tests
// inject fakes.
type AuditClient interface {
	// RecordAsync fire-and-forgets event onto the platform audit chain.
	RecordAsync(ctx context.Context, event *iamsdk.AuditEvent) error
}

// AuditDialFunc lazily establishes the quicbaas SDK connection used to
// reach the platform audit chain (quicbaasd).
type AuditDialFunc func(ctx context.Context) (AuditClient, error)

// LazyAuditClient defers the quicbaasd connection until the first emitted
// event and retries on the next event after a failure, mirroring
// LazyAttestationClient / LazyControlPlaneClient so gatewayd starts (and
// SDKAuditSink fails open — see Record) while quicbaasd is down.
type LazyAuditClient struct {
	dial AuditDialFunc

	mu     sync.Mutex
	client AuditClient
}

// NewLazyAuditClient builds a lazy audit client around a dial function.
func NewLazyAuditClient(dial AuditDialFunc) (*LazyAuditClient, error) {
	if dial == nil {
		return nil, &ErrNilDialFunc{}
	}
	return &LazyAuditClient{dial: dial}, nil
}

// get returns the connected client, dialing on first use.
func (l *LazyAuditClient) get(ctx context.Context) (AuditClient, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	client, err := l.dial(ctx)
	if err != nil {
		return nil, &ErrAuditDialFailed{Cause: err}
	}
	l.client = client
	return client, nil
}

// RecordAsync implements AuditClient.
func (l *LazyAuditClient) RecordAsync(ctx context.Context, event *iamsdk.AuditEvent) error {
	client, err := l.get(ctx)
	if err != nil {
		return err
	}
	return client.RecordAsync(ctx, event)
}

// QuicBaaSAuditDial returns the lazy dial function SDKAuditSink uses to
// reach quicbaasd directly for audit emission. This is independent of the
// platformd connection gatewayd's control-plane sync loop and
// trusted-computing collaborators use: it is the same quicbaassdk.NewClient
// plumbing sdk/go's platform.Client.QuicBaaS() (and, inside platformd,
// IAMService.Audit()) resolves to, reached here without a platformd hop
// because gatewayd has no in-process DAOFactory to source it from.
func QuicBaaSAuditDial(addr, transport string) AuditDialFunc {
	return func(ctx context.Context) (AuditClient, error) {
		client, err := quicbaassdk.NewClient(addr, quicBaaSTransportOptions(addr, transport)...)
		if err != nil {
			return nil, err
		}
		iamClient := client.Identity().IAM()
		if iamClient == nil {
			return nil, &ErrNilAuditClient{}
		}
		auditClient := iamClient.Audit()
		if auditClient == nil {
			return nil, &ErrNilAuditClient{}
		}
		return auditClient, nil
	}
}

// quicBaaSTransportOptions maps a transport string to the go-quicbaas SDK
// option, mirroring sdk/go's own quicbaasTransportOptions (client.go):
// empty or unknown returns nil so the SDK auto-detects from addr.
func quicBaaSTransportOptions(addr, transport string) []quicbaassdk.Option {
	switch transport {
	case "unix":
		return []quicbaassdk.Option{quicbaassdk.WithUnix(addr)}
	case "rest":
		return []quicbaassdk.Option{quicbaassdk.WithREST()}
	case "quic":
		return []quicbaassdk.Option{quicbaassdk.WithQUIC()}
	case "mcp":
		return []quicbaassdk.Option{quicbaassdk.WithMCP()}
	default:
		return nil
	}
}

// SDKAuditSinkConfig configures NewSDKAuditSink.
type SDKAuditSinkConfig struct {
	// Client emits audit events onto quicbaasd's platform audit chain
	// (required).
	Client AuditClient
	// Service tags every emitted event's AuditContext.Service. Empty
	// defaults to DefaultAuditService.
	Service string
	// Environment tags every emitted event's AuditContext.Environment.
	Environment string
	// Timeout bounds each detached RecordAsync call. Zero defaults to
	// DefaultAuditTimeout.
	Timeout time.Duration
	// Logger is optional; nil uses slog.Default().
	Logger *slog.Logger
}

// SDKAuditSink is the production proxy.AuditSink. It converts a routing/
// authentication decision into a quicbaas SDK iam.AuditEvent and emits it
// fire-and-forget through RecordAsync on a detached goroutine, so a slow or
// unreachable audit chain never adds latency to the proxy data path (P5.3:
// one audit plane — routing decisions land on the same HMAC-chained qrdb
// audit log auth/authz decisions do). Emission failures, including a
// client that cannot be dialed, are logged at Warn and dropped: the proxy
// fails open on its audit plane, never on traffic.
type SDKAuditSink struct {
	client      AuditClient
	service     string
	environment string
	timeout     time.Duration
	logger      *slog.Logger
}

// NewSDKAuditSink validates the configuration and builds the sink.
func NewSDKAuditSink(cfg SDKAuditSinkConfig) (*SDKAuditSink, error) {
	if cfg.Client == nil {
		return nil, &ErrNilAuditClient{}
	}
	if cfg.Service == "" {
		cfg.Service = DefaultAuditService
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultAuditTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SDKAuditSink{
		client:      cfg.Client,
		service:     cfg.Service,
		environment: cfg.Environment,
		timeout:     cfg.Timeout,
		logger:      cfg.Logger,
	}, nil
}

// Record implements proxy.AuditSink. It never blocks the caller: the SDK
// emission runs on a detached goroutine against a context independent of
// the request context (which is typically canceled once the response
// finishes writing, before an async emission would complete).
func (s *SDKAuditSink) Record(ctx context.Context, ev proxy.AuditEvent) {
	event := toAuditEvent(ev, s.service, s.environment)
	go func() {
		actx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		if err := s.client.RecordAsync(actx, event); err != nil {
			s.logger.Warn("proxysvc: audit event emission failed",
				"route", ev.RouteID, "decision", ev.Decision, "error", err)
		}
	}()
}

// toAuditEvent converts a pkg/proxy routing decision into a quicbaas SDK
// audit event. Fields with a first-class AuditEvent home (actor, resource,
// request, outcome, message, timestamp) are mapped directly; the remaining
// TP-specific fields (route id, device id, zone, auth method, remote
// address) ride in Details, the SDK's documented extension point for
// fields with no separate schema.
func toAuditEvent(ev proxy.AuditEvent, service, environment string) *iamsdk.AuditEvent {
	return &iamsdk.AuditEvent{
		Timestamp: ev.Time,
		EventType: iamsdk.AuditEventTypeAuthorization,
		Action:    "proxy_route_decision",
		Outcome:   auditOutcome(ev.Decision),
		Message:   ev.Reason,
		Actor: &iamsdk.AuditActor{
			ID:        ev.ClientID,
			Type:      "device",
			IPAddress: ev.RemoteAddr,
		},
		Resource: &iamsdk.AuditResource{
			ID:   ev.RouteID,
			Type: "proxy_route",
		},
		Request: &iamsdk.AuditRequest{
			Method: ev.Method,
			Path:   ev.Path,
		},
		Context: &iamsdk.AuditContext{
			Service:     service,
			Environment: environment,
		},
		Details: map[string]any{
			"decision":    ev.Decision,
			"route_id":    ev.RouteID,
			"device_id":   ev.DeviceID,
			"zone":        ev.Zone,
			"auth_method": ev.AuthMethod,
		},
	}
}

// auditOutcome maps a pkg/proxy decision constant to the closest quicbaas
// SDK audit outcome.
func auditOutcome(decision string) iamsdk.AuditOutcome {
	switch decision {
	case proxy.DecisionAllow:
		return iamsdk.AuditOutcomeSuccess
	case proxy.DecisionDeny:
		return iamsdk.AuditOutcomeDenied
	case proxy.DecisionError:
		return iamsdk.AuditOutcomeError
	default:
		// DecisionNoRoute and any future decision constant: not a
		// rejection of a matched route, but not a clean success either.
		return iamsdk.AuditOutcomeFailure
	}
}

var (
	_ proxy.AuditSink = (*SDKAuditSink)(nil)
	_ AuditClient     = (*LazyAuditClient)(nil)
)
