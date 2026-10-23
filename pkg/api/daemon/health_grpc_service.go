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

package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	grpcstatus "google.golang.org/grpc/status"
)

// HealthServiceStatus represents the status of a service.
type HealthServiceStatus int32

const (
	// HealthServiceStatusUnknown indicates the service status is unknown.
	HealthServiceStatusUnknown HealthServiceStatus = iota
	// HealthServiceStatusServing indicates the service is serving.
	HealthServiceStatusServing
	// HealthServiceStatusNotServing indicates the service is not serving.
	HealthServiceStatusNotServing
	// HealthServiceStatusServiceUnknown indicates the service is not registered.
	HealthServiceStatusServiceUnknown
)

// HealthChecker is the interface for components that can report health status.
type HealthChecker interface {
	// HealthCheck returns nil if healthy, or an error describing the issue.
	HealthCheck(ctx context.Context) error
}

// HealthGRPCService implements the gRPC Health service (grpc.health.v1).
// This provides standard gRPC health checking for load balancers and service discovery.
type HealthGRPCService struct {
	grpc_health_v1.UnimplementedHealthServer

	logger *logging.Logger

	mu       sync.RWMutex
	services map[string]HealthServiceStatus
	checkers map[string]HealthChecker

	shutdown atomic.Bool
}

// NewHealthGRPCService creates a new Health gRPC service instance.
func NewHealthGRPCService(logger *logging.Logger) *HealthGRPCService {
	return &HealthGRPCService{
		logger:   logger,
		services: make(map[string]HealthServiceStatus),
		checkers: make(map[string]HealthChecker),
	}
}

// RegisterService registers a service with an initial status.
func (s *HealthGRPCService) RegisterService(serviceName string, initialStatus HealthServiceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.services[serviceName] = initialStatus
	s.logger.Debug("Health service registered", "service", serviceName, "status", initialStatus)
}

// RegisterHealthChecker registers a health checker for a service.
// The checker will be called during health checks to determine service status.
func (s *HealthGRPCService) RegisterHealthChecker(serviceName string, checker HealthChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkers[serviceName] = checker
	s.logger.Debug("Health checker registered", "service", serviceName)
}

// SetServingStatus sets the serving status of a service.
func (s *HealthGRPCService) SetServingStatus(serviceName string, servingStatus HealthServiceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.services[serviceName] = servingStatus
	s.logger.Debug("Health status updated", "service", serviceName, "status", servingStatus)
}

// SetAllServingStatus sets all registered services to the given status.
func (s *HealthGRPCService) SetAllServingStatus(servingStatus HealthServiceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.services {
		s.services[name] = servingStatus
	}
}

// Shutdown marks the service as shutting down.
// All future checks will return NOT_SERVING.
func (s *HealthGRPCService) Shutdown() {
	s.shutdown.Store(true)
	s.SetAllServingStatus(HealthServiceStatusNotServing)
}

// Check implements the gRPC Health Check method.
// This is the standard grpc.health.v1.Health/Check RPC.
func (s *HealthGRPCService) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if s.shutdown.Load() {
		return &grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
		}, nil
	}

	serviceName := req.GetService()

	// Empty service name means check overall health
	if serviceName == "" {
		return s.checkOverallHealth(ctx)
	}

	s.mu.RLock()
	svcStatus, exists := s.services[serviceName]
	checker, hasChecker := s.checkers[serviceName]
	s.mu.RUnlock()

	if !exists {
		return nil, grpcstatus.Error(codes.NotFound, "service not registered")
	}

	// If there's a dynamic health checker, use it
	if hasChecker {
		if err := checker.HealthCheck(ctx); err != nil {
			s.logger.Debug("Health check failed", "service", serviceName, "error", err)
			return &grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			}, nil
		}
		return &grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVING,
		}, nil
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: s.statusToProto(svcStatus),
	}, nil
}

// Watch implements the gRPC Health Watch method for streaming health updates.
// This is the standard grpc.health.v1.Health/Watch RPC.
func (s *HealthGRPCService) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	serviceName := req.GetService()

	// Send initial status
	resp, err := s.Check(stream.Context(), req)
	if err != nil {
		// For unknown services, send SERVICE_UNKNOWN and keep watching
		if grpcstatus.Code(err) == codes.NotFound {
			if sendErr := stream.Send(&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
			}); sendErr != nil {
				return sendErr
			}
		} else {
			return err
		}
	} else {
		if sendErr := stream.Send(resp); sendErr != nil {
			return sendErr
		}
	}

	// Poll for status changes
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastStatus := resp.GetStatus()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			if s.shutdown.Load() {
				if sendErr := stream.Send(&grpc_health_v1.HealthCheckResponse{
					Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
				}); sendErr != nil {
					return sendErr
				}
				return nil
			}

			resp, err := s.Check(stream.Context(), req)
			if err != nil {
				continue
			}

			// Only send updates when status changes
			if resp.Status != lastStatus {
				if sendErr := stream.Send(resp); sendErr != nil {
					return sendErr
				}
				lastStatus = resp.Status
				s.logger.Debug("Health watch status changed",
					"service", serviceName,
					"status", resp.Status,
				)
			}
		}
	}
}

// checkOverallHealth checks the health of all registered services.
func (s *HealthGRPCService) checkOverallHealth(ctx context.Context) (*grpc_health_v1.HealthCheckResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Nothing to report on at all: no named services AND no checkers.
	// The checker test matters -- a service configured with checkers but
	// no registered names is the non-enumerable configuration this daemon
	// ships (see NewRegistryHealthChecker), and short-circuiting on the
	// name map alone would answer SERVING forever no matter what the
	// checkers say.
	if len(s.services) == 0 && len(s.checkers) == 0 {
		return &grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVING,
		}, nil
	}

	// Check all dynamic health checkers
	for name, checker := range s.checkers {
		if err := checker.HealthCheck(ctx); err != nil {
			s.logger.Debug("Overall health check failed", "service", name, "error", err)
			return &grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			}, nil
		}
	}

	// Check all static service statuses
	for _, serviceStatus := range s.services {
		if serviceStatus != HealthServiceStatusServing {
			return &grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			}, nil
		}
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

// statusToProto converts internal status to gRPC health proto status.
func (s *HealthGRPCService) statusToProto(healthStatus HealthServiceStatus) grpc_health_v1.HealthCheckResponse_ServingStatus {
	switch healthStatus {
	case HealthServiceStatusServing:
		return grpc_health_v1.HealthCheckResponse_SERVING
	case HealthServiceStatusNotServing:
		return grpc_health_v1.HealthCheckResponse_NOT_SERVING
	case HealthServiceStatusServiceUnknown:
		return grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN
	default:
		return grpc_health_v1.HealthCheckResponse_UNKNOWN
	}
}

// RegisterHealthService registers the health service with a gRPC server.
func RegisterHealthService(server *grpc.Server, healthService *HealthGRPCService) {
	grpc_health_v1.RegisterHealthServer(server, healthService)
}

// daemonHealthCheckerName is the key the aggregate checker is registered
// under. It is never registered as a *service* name, so it is not
// discoverable through Check -- see NewRegistryHealthChecker.
const daemonHealthCheckerName = "platform"

// registryHealthChecker adapts the platform health.Registry to the
// HealthChecker interface consumed by HealthGRPCService.
type registryHealthChecker struct {
	registry health.Registry
}

// NewRegistryHealthChecker returns a HealthChecker reporting the aggregate
// status of every component registered with the platform health registry.
//
// Reporting one aggregate rather than per-service entries is deliberate and
// is a disclosure decision, not a convenience. Check answers
// codes.NotFound for any name it does not hold, so registering per-service
// names would let a caller enumerate the daemon's service inventory by
// guessing -- and on the TCP listener that caller is unauthenticated,
// because "/grpc.health.v1.Health/Check" sits in grpcTCPSkipMethods.
// Registering only through RegisterHealthChecker keeps the services map
// empty, so every name gets the same NOT_FOUND answer. See #337.
func NewRegistryHealthChecker(registry health.Registry) HealthChecker {
	return &registryHealthChecker{registry: registry}
}

// HealthCheck reports an error only when the registry considers the node
// unhealthy.
//
// Degraded keeps the node SERVING on purpose: a degraded node still answers
// requests, and pulling it out of a load balancer's rotation can cascade a
// partial degradation into an outage. Only an unhealthy verdict drains it.
func (c *registryHealthChecker) HealthCheck(ctx context.Context) error {
	if c.registry == nil {
		return nil
	}

	result := c.registry.Check(ctx)
	if result.Status == health.StatusUnhealthy {
		return ErrDaemonUnhealthy{UnhealthyCount: result.UnhealthyCount}
	}

	return nil
}
