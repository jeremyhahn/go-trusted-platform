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
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ManagedService represents a service that can be started/stopped by the daemon
type ManagedService interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
	Name() string
}

// Service implements the PlatformDaemon gRPC service
type Service struct {
	platformv1.UnimplementedPlatformDaemonServer

	config         *Config
	services       map[string]*serviceState
	healthRegistry health.Registry
	mu             sync.RWMutex

	// QuicBaaS factory for testing (optional, falls back to App.DAOFactory)
	quicbaasFactory quicbaas.FactoryInterface

	systemStatus atomic.Int32
	startTime    time.Time

	eventSubs  map[string]chan *platformv1.Event
	logSubs    map[string]chan *platformv1.LogEntry
	metricSubs map[string]chan *platformv1.MetricData
	subMu      sync.RWMutex

	// onSubscribe, when non-nil, is invoked after a Stream* call has
	// registered its subscription channel and is therefore able to receive a
	// publish. It turns registration — otherwise an invisible moment inside a
	// goroutine the caller does not control — into a synchronisation point the
	// package's own tests can wait on, instead of guessing how long the
	// goroutine needs with a sleep. Publishing before registration fans out to
	// nobody, which is what failed an unrelated PR (issue #255).
	//
	// It is nil on every production construction path, so it changes neither
	// the exported surface nor runtime behaviour, and it is set only before a
	// stream starts, so the read below needs no synchronisation of its own.
	onSubscribe func()
	subIDSeq    atomic.Uint64

	shutdownCh chan struct{}
	shutdownFn func() error

	// snapshotStore persists pre-reload snapshots so configuration
	// changes are reversible. Wired by the daemon boot path via
	// SetSnapshotStore; nil disables snapshot capture and the
	// rollback REST surface.
	snapshotStore tpconfig.SnapshotStore
}

// ServiceOption is a functional option for configuring the Service
type ServiceOption func(*Service)

// WithQuicBaaSFactory sets a custom QuicBaaS factory for testing
func WithQuicBaaSFactory(factory quicbaas.FactoryInterface) ServiceOption {
	return func(s *Service) {
		s.quicbaasFactory = factory
	}
}

// serviceState tracks the state of a managed service
type serviceState struct {
	service    ManagedService
	status     atomic.Int32 // platformv1.ServiceStatus
	lastError  string
	startedAt  time.Time
	mu         sync.RWMutex
	startCount atomic.Uint64
	stopCount  atomic.Uint64
}

// NewService creates a new daemon service
func NewService(config *Config, opts ...ServiceOption) (*Service, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	s := &Service{
		config:     config,
		services:   make(map[string]*serviceState),
		startTime:  time.Now(),
		eventSubs:  make(map[string]chan *platformv1.Event),
		logSubs:    make(map[string]chan *platformv1.LogEntry),
		metricSubs: make(map[string]chan *platformv1.MetricData),
		shutdownCh: make(chan struct{}),
	}

	// Apply functional options
	for _, opt := range opts {
		opt(s)
	}

	s.systemStatus.Store(int32(platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING))

	return s, nil
}

// RegisterService registers a managed service with the daemon
func (s *Service) RegisterService(svc ManagedService) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := svc.Name()
	if _, exists := s.services[name]; exists {
		return ErrServiceAlreadyRunning{ServiceName: name}
	}

	state := &serviceState{
		service: svc,
	}
	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPED))

	s.services[name] = state
	return nil
}

// SetShutdownHandler sets the function to call during shutdown
func (s *Service) SetShutdownHandler(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdownFn = fn
}

// SetHealthRegistry sets the health registry for enhanced health checks.
// If set, GetHealth will use the registry for more detailed health information.
func (s *Service) SetHealthRegistry(registry health.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthRegistry = registry
}

// MarkReady marks the daemon as ready after initialization
func (s *Service) MarkReady() {
	s.systemStatus.Store(int32(platformv1.SystemStatus_SYSTEM_STATUS_READY))
}

// GetStatus returns daemon status, platform info, and service list
func (s *Service) GetStatus(ctx context.Context, req *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	systemStatus := platformv1.SystemStatus(s.systemStatus.Load())

	var services []*platformv1.ServiceInfo
	for name, state := range s.services {
		state.mu.RLock()
		svcStatus := platformv1.ServiceStatus(state.status.Load())

		// Store start count, stop count, and last error in metadata
		metadata := make(map[string]string)
		if state.lastError != "" {
			metadata["last_error"] = state.lastError
		}
		metadata["start_count"] = formatUint64(state.startCount.Load())
		metadata["stop_count"] = formatUint64(state.stopCount.Load())

		var startedAt *timestamppb.Timestamp
		var uptimeSeconds uint64
		if !state.startedAt.IsZero() {
			startedAt = timestamppb.New(state.startedAt)
			uptimeSeconds = uint64(time.Since(state.startedAt).Seconds())
		}

		info := &platformv1.ServiceInfo{
			Name:          name,
			Type:          serviceTypeFromName(name),
			Status:        svcStatus,
			StartedAt:     startedAt,
			UptimeSeconds: uptimeSeconds,
			Health:        healthStatusFromServiceStatus(svcStatus),
			Metadata:      metadata,
		}
		state.mu.RUnlock()
		services = append(services, info)
	}

	// Get system info
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	systemInfo := &platformv1.SystemInfo{
		Os:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		NumCpus:           uint32(runtime.NumCPU()),
		TotalMemoryMb:     memStats.Sys / 1024 / 1024,
		AvailableMemoryMb: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
		BootTime:          timestamppb.New(s.startTime),
		UptimeSeconds:     uint64(time.Since(s.startTime).Seconds()),
	}

	appVersion := app.GetVersion()
	platformInfo := &platformv1.PlatformInfo{
		Hostname:   getHostname(),
		Version:    appVersion.Version,
		BuildTime:  appVersion.BuildDate,
		GitCommit:  appVersion.GitHash,
		SystemInfo: systemInfo,
	}

	return &platformv1.GetStatusResponse{
		Status:    systemStatus,
		Info:      platformInfo,
		Services:  services,
		Timestamp: timestamppb.New(time.Now()),
	}, nil
}

// GetHealth returns health status of all components.
// If a health registry is configured, it performs deep health checks on all
// registered components. Otherwise, it returns basic status based on service state.
func (s *Service) GetHealth(ctx context.Context, req *platformv1.GetHealthRequest) (*platformv1.GetHealthResponse, error) {
	s.mu.RLock()
	registry := s.healthRegistry
	s.mu.RUnlock()

	// If health registry is available, use it for comprehensive health checks
	if registry != nil {
		systemHealth := registry.Check(ctx)

		// Convert health.SystemHealth to proto response
		componentHealth := make([]*platformv1.ComponentHealth, 0, len(systemHealth.Components))
		for _, comp := range systemHealth.Components {
			pbHealth := &platformv1.ComponentHealth{
				Name:      comp.Name,
				Status:    healthStatusFromHealthStatus(comp.Status),
				Message:   comp.Message,
				LastCheck: timestamppb.New(comp.LastChecked),
			}
			componentHealth = append(componentHealth, pbHealth)
		}

		return &platformv1.GetHealthResponse{
			Status:     healthStatusFromHealthStatus(systemHealth.Status),
			Components: componentHealth,
			Timestamp:  timestamppb.New(systemHealth.Timestamp),
		}, nil
	}

	// Fallback to basic health check based on service state
	s.mu.RLock()
	defer s.mu.RUnlock()

	overallHealth := platformv1.HealthStatus_HEALTH_STATUS_HEALTHY

	var componentHealth []*platformv1.ComponentHealth
	for name, state := range s.services {
		state.mu.RLock()
		svcStatus := platformv1.ServiceStatus(state.status.Load())
		lastError := state.lastError
		state.mu.RUnlock()

		compHealth := &platformv1.ComponentHealth{
			Name:      name,
			Status:    healthStatusFromServiceStatus(svcStatus),
			Message:   lastError,
			LastCheck: timestamppb.New(time.Now()),
		}

		if compHealth.Status != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
			overallHealth = platformv1.HealthStatus_HEALTH_STATUS_DEGRADED
		}

		componentHealth = append(componentHealth, compHealth)
	}

	return &platformv1.GetHealthResponse{
		Status:     overallHealth,
		Components: componentHealth,
		Timestamp:  timestamppb.New(time.Now()),
	}, nil
}

// GetVersion returns version, build time, and git commit
func (s *Service) GetVersion(ctx context.Context, req *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	appVersion := app.GetVersion()

	// Build components map with service versions
	components := make(map[string]string)
	s.mu.RLock()
	for name := range s.services {
		components[name] = appVersion.Version
	}
	s.mu.RUnlock()

	return &platformv1.GetVersionResponse{
		Version:    appVersion.Version,
		BuildTime:  appVersion.BuildDate,
		GitCommit:  appVersion.GitHash,
		GoVersion:  runtime.Version(),
		Components: components,
	}, nil
}

// Shutdown performs graceful shutdown
func (s *Service) Shutdown(ctx context.Context, req *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error) {
	s.systemStatus.Store(int32(platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN))

	graceful := req.GetGraceful()
	timeout := s.config.ShutdownTimeout
	if req.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(req.GetTimeoutSeconds()) * time.Second
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Stop all services
	s.mu.RLock()
	serviceNames := make([]string, 0, len(s.services))
	for name := range s.services {
		serviceNames = append(serviceNames, name)
	}
	s.mu.RUnlock()

	var errors []string
	for _, name := range serviceNames {
		svcType := serviceTypeFromName(name)
		if _, err := s.StopService(shutdownCtx, &platformv1.StopServiceRequest{
			Service:        svcType,
			Force:          !graceful,
			TimeoutSeconds: uint32(timeout.Seconds()),
		}); err != nil {
			errors = append(errors, name+": "+err.Error())
		}
	}

	// Call shutdown handler if set
	if s.shutdownFn != nil {
		if err := s.shutdownFn(); err != nil && graceful {
			errors = append(errors, "shutdown handler: "+err.Error())
		}
	}

	// Signal shutdown
	select {
	case <-s.shutdownCh:
		// Already closed
	default:
		close(s.shutdownCh)
	}

	shutdownStatus := &platformv1.Status{
		Success: true,
		Message: "shutdown completed successfully",
	}

	if len(errors) > 0 {
		shutdownStatus.Success = false
		shutdownStatus.Message = "shutdown completed with errors"
		shutdownStatus.Error = &platformv1.ErrorDetail{
			Code:    platformv1.ErrorCode_ERROR_CODE_INTERNAL,
			Message: "errors occurred during shutdown: " + formatErrors(errors),
		}
	}

	return &platformv1.ShutdownResponse{
		Status: shutdownStatus,
	}, nil
}

// GetConfig returns the current configuration
func (s *Service) GetConfig(ctx context.Context, req *platformv1.GetConfigRequest) (*platformv1.GetConfigResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert config to ConfigSection format
	sections := []*platformv1.ConfigSection{
		{
			Section: "daemon",
			Values: map[string]string{
				"socket_path":      s.config.SocketPath,
				"socket_group":     s.config.SocketGroup,
				"shutdown_timeout": s.config.ShutdownTimeout.String(),
			},
		},
	}

	// If a specific section is requested, filter it
	if req.GetSection() != "" {
		for _, section := range sections {
			if section.Section == req.GetSection() {
				return &platformv1.GetConfigResponse{
					Sections: []*platformv1.ConfigSection{section},
				}, nil
			}
		}
		return nil, status.Error(codes.NotFound, "section not found: "+req.GetSection())
	}

	return &platformv1.GetConfigResponse{
		Sections: sections,
	}, nil
}

// UpdateConfig applies a single configuration section override to the
// live daemon. The section's key/value pairs are merged into the active
// viper state and re-decoded into the bound *app.App so the running
// daemon observes the change immediately. When req.Persist is set the
// merged configuration is also written back to the active config file
// so it survives a restart.
//
// This shares the config subsystem with ReloadConfig / snapshots: a
// pre-change snapshot is captured (when a snapshot store is wired) so
// the change is auditable and reversible via RollbackConfig.
func (s *Service) UpdateConfig(ctx context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error) {
	section := req.GetSection()
	if section == nil || section.GetSection() == "" {
		return nil, status.Error(codes.InvalidArgument, "section is required")
	}

	// Capture a pre-change snapshot for audit / rollback when a store
	// is configured. Snapshot failures are non-fatal — they must not
	// block an operator-requested config change — but are surfaced in
	// the daemon log.
	if s.snapshotStore != nil {
		if _, err := tpconfig.CaptureCurrent(s.snapshotStore, "pre-update", "daemon"); err != nil && s.config != nil && s.config.Logger != nil {
			s.config.Logger.Warnf("config: pre-update snapshot failed: %v", err)
		}
	}

	var target interface{}
	if s.config != nil && s.config.App != nil {
		target = s.config.App
	}

	if _, err := tpconfig.ApplySection(target, section.GetSection(), section.GetValues(), req.GetPersist()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	msg := "configuration section applied"
	if req.GetPersist() {
		msg = "configuration section applied and persisted to disk"
	}
	return &platformv1.UpdateConfigResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: msg,
		},
	}, nil
}

// ReloadConfig reloads the configuration from disk and reflects the
// updated values into the bound *app.App. The list of top-level
// sections that were reloaded is returned for downstream broadcast.
//
// This RPC is best-effort: a partial unmarshal failure mid-way is
// reported as Internal and the *app.App may be left in an
// inconsistent state. Callers that need atomicity should
// ValidateConfig first against the proposed body and only call
// ReloadConfig once it returns clean.
func (s *Service) ReloadConfig(ctx context.Context, req *platformv1.ReloadConfigRequest) (*platformv1.ReloadConfigResponse, error) {
	sections, err := s.ReloadConfigFromDisk()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &platformv1.ReloadConfigResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "configuration reloaded from disk",
		},
		ReloadedSections: sections,
	}, nil
}

// StartService starts a managed service
func (s *Service) StartService(ctx context.Context, req *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error) {
	serviceName := serviceNameFromType(req.GetService())

	s.mu.RLock()
	state, exists := s.services[serviceName]
	s.mu.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, ErrServiceNotFound{ServiceName: serviceName}.Error())
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	currentStatus := platformv1.ServiceStatus(state.status.Load())
	if currentStatus == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
		return nil, status.Error(codes.AlreadyExists, ErrServiceAlreadyRunning{ServiceName: serviceName}.Error())
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STARTING))
	state.lastError = ""

	if err := state.service.Start(ctx); err != nil {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = err.Error()
		return nil, status.Error(codes.Internal, err.Error())
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	state.startedAt = time.Now()
	state.startCount.Add(1)

	// Build service info for response
	metadata := make(map[string]string)
	metadata["start_count"] = formatUint64(state.startCount.Load())
	metadata["stop_count"] = formatUint64(state.stopCount.Load())

	serviceInfo := &platformv1.ServiceInfo{
		Type:          req.GetService(),
		Name:          serviceName,
		Status:        platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		StartedAt:     timestamppb.New(state.startedAt),
		UptimeSeconds: 0,
		Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Metadata:      metadata,
	}

	return &platformv1.StartServiceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "service started successfully",
		},
		Service: serviceInfo,
	}, nil
}

// StopService stops a managed service
func (s *Service) StopService(ctx context.Context, req *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error) {
	serviceName := serviceNameFromType(req.GetService())

	s.mu.RLock()
	state, exists := s.services[serviceName]
	s.mu.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, ErrServiceNotFound{ServiceName: serviceName}.Error())
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	currentStatus := platformv1.ServiceStatus(state.status.Load())
	if currentStatus == platformv1.ServiceStatus_SERVICE_STATUS_STOPPED {
		return nil, status.Error(codes.FailedPrecondition, ErrServiceNotRunning{ServiceName: serviceName}.Error())
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPING))

	// Use timeout if specified
	stopCtx := ctx
	if req.GetTimeoutSeconds() > 0 {
		var cancel context.CancelFunc
		stopCtx, cancel = context.WithTimeout(ctx, time.Duration(req.GetTimeoutSeconds())*time.Second)
		defer cancel()
	}

	if err := state.service.Stop(stopCtx); err != nil && !req.GetForce() {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = err.Error()
		return nil, status.Error(codes.Internal, err.Error())
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPED))
	state.stopCount.Add(1)

	return &platformv1.StopServiceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "service stopped successfully",
		},
	}, nil
}

// RestartService restarts a managed service
func (s *Service) RestartService(ctx context.Context, req *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error) {
	// Stop the service
	if _, err := s.StopService(ctx, &platformv1.StopServiceRequest{
		Service:        req.GetService(),
		Force:          false,
		TimeoutSeconds: req.GetTimeoutSeconds(),
	}); err != nil {
		return nil, err
	}

	// Start the service
	if _, err := s.StartService(ctx, &platformv1.StartServiceRequest{
		Service: req.GetService(),
	}); err != nil {
		return nil, err
	}

	return &platformv1.RestartServiceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "service restarted successfully",
		},
	}, nil
}

// GetServiceStatus returns the status of a specific service
func (s *Service) GetServiceStatus(ctx context.Context, req *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error) {
	serviceName := serviceNameFromType(req.GetService())

	s.mu.RLock()
	state, exists := s.services[serviceName]
	s.mu.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, ErrServiceNotFound{ServiceName: serviceName}.Error())
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	metadata := make(map[string]string)
	if state.lastError != "" {
		metadata["last_error"] = state.lastError
	}
	metadata["start_count"] = formatUint64(state.startCount.Load())
	metadata["stop_count"] = formatUint64(state.stopCount.Load())

	var startedAt *timestamppb.Timestamp
	var uptimeSeconds uint64
	if !state.startedAt.IsZero() {
		startedAt = timestamppb.New(state.startedAt)
		uptimeSeconds = uint64(time.Since(state.startedAt).Seconds())
	}

	serviceInfo := &platformv1.ServiceInfo{
		Type:          req.GetService(),
		Name:          serviceName,
		Status:        platformv1.ServiceStatus(state.status.Load()),
		StartedAt:     startedAt,
		UptimeSeconds: uptimeSeconds,
		Health:        healthStatusFromServiceStatus(platformv1.ServiceStatus(state.status.Load())),
		Metadata:      metadata,
	}

	return &platformv1.GetServiceStatusResponse{
		Service: serviceInfo,
	}, nil
}

// ListServices returns a list of all managed services
func (s *Service) ListServices(ctx context.Context, req *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make([]*platformv1.ServiceInfo, 0, len(s.services))
	for name, state := range s.services {
		state.mu.RLock()

		metadata := make(map[string]string)
		if state.lastError != "" {
			metadata["last_error"] = state.lastError
		}
		metadata["start_count"] = formatUint64(state.startCount.Load())
		metadata["stop_count"] = formatUint64(state.stopCount.Load())

		var startedAt *timestamppb.Timestamp
		var uptimeSeconds uint64
		if !state.startedAt.IsZero() {
			startedAt = timestamppb.New(state.startedAt)
			uptimeSeconds = uint64(time.Since(state.startedAt).Seconds())
		}

		info := &platformv1.ServiceInfo{
			Name:          name,
			Type:          serviceTypeFromName(name),
			Status:        platformv1.ServiceStatus(state.status.Load()),
			StartedAt:     startedAt,
			UptimeSeconds: uptimeSeconds,
			Health:        healthStatusFromServiceStatus(platformv1.ServiceStatus(state.status.Load())),
			Metadata:      metadata,
		}
		state.mu.RUnlock()
		services = append(services, info)
	}

	return &platformv1.ListServicesResponse{
		Services: services,
	}, nil
}

// StreamEvents streams daemon events to clients
func (s *Service) StreamEvents(req *platformv1.StreamEventsRequest, stream platformv1.PlatformDaemon_StreamEventsServer) error {
	if !s.config.EnableEvents {
		return status.Error(codes.FailedPrecondition, "event streaming is disabled")
	}

	subID := s.generateSubscriptionID()
	eventCh := make(chan *platformv1.Event, 100)

	s.subMu.Lock()
	s.eventSubs[subID] = eventCh
	s.subMu.Unlock()
	if s.onSubscribe != nil {
		s.onSubscribe()
	}

	defer func() {
		s.subMu.Lock()
		delete(s.eventSubs, subID)
		s.subMu.Unlock()
		close(eventCh)
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-eventCh:
			if err := stream.Send(event); err != nil {
				return err
			}
		case <-s.shutdownCh:
			return nil
		}
	}
}

// StreamLogs streams daemon logs to clients
func (s *Service) StreamLogs(req *platformv1.StreamLogsRequest, stream platformv1.PlatformDaemon_StreamLogsServer) error {
	subID := s.generateSubscriptionID()
	logCh := make(chan *platformv1.LogEntry, 100)

	s.subMu.Lock()
	s.logSubs[subID] = logCh
	s.subMu.Unlock()
	if s.onSubscribe != nil {
		s.onSubscribe()
	}

	defer func() {
		s.subMu.Lock()
		delete(s.logSubs, subID)
		s.subMu.Unlock()
		close(logCh)
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case entry := <-logCh:
			if err := stream.Send(entry); err != nil {
				return err
			}
		case <-s.shutdownCh:
			return nil
		}
	}
}

// StreamMetrics streams daemon metrics to clients
func (s *Service) StreamMetrics(req *platformv1.StreamMetricsRequest, stream platformv1.PlatformDaemon_StreamMetricsServer) error {
	if !s.config.EnableMetrics {
		return status.Error(codes.FailedPrecondition, "metrics streaming is disabled")
	}

	subID := s.generateSubscriptionID()
	metricCh := make(chan *platformv1.MetricData, 100)

	s.subMu.Lock()
	s.metricSubs[subID] = metricCh
	s.subMu.Unlock()
	if s.onSubscribe != nil {
		s.onSubscribe()
	}

	defer func() {
		s.subMu.Lock()
		delete(s.metricSubs, subID)
		s.subMu.Unlock()
		close(metricCh)
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case metric := <-metricCh:
			if err := stream.Send(metric); err != nil {
				return err
			}
		case <-s.shutdownCh:
			return nil
		}
	}
}

// PublishEvent publishes an event to all subscribed clients
func (s *Service) PublishEvent(event *platformv1.Event) {
	if !s.config.EnableEvents {
		return
	}

	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for _, ch := range s.eventSubs {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
}

// PublishLog publishes a log entry to all subscribed clients
func (s *Service) PublishLog(entry *platformv1.LogEntry) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for _, ch := range s.logSubs {
		select {
		case ch <- entry:
		default:
			// Channel full, skip
		}
	}
}

// PublishMetric publishes a metric to all subscribed clients
func (s *Service) PublishMetric(metric *platformv1.MetricData) {
	if !s.config.EnableMetrics {
		return
	}

	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for _, ch := range s.metricSubs {
		select {
		case ch <- metric:
		default:
			// Channel full, skip
		}
	}
}

// ListEntityTypes returns all entity types and their entity counts.
// Entity types are dynamically discovered from QuicBaaS using key prefix scanning.
func (s *Service) ListEntityTypes(ctx context.Context, req *platformv1.ListEntityTypesRequest) (*platformv1.ListEntityTypesResponse, error) {
	// Get QuicBaaS client from app
	client, databasePath, err := s.getQuicBaaSClient()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Discover entity types dynamically from QuicBaaS
	entityTypeNames, _, _, err := client.ListEntityTypes(ctx, 1000, "")
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list entity types: "+err.Error())
	}

	var entityTypes []*platformv1.EntityTypeInfo
	var totalEntities uint64
	var activeTypes uint32

	for _, entityType := range entityTypeNames {
		count := uint64(0)
		typeStatus := "empty"

		// Count entities of this type using pagination
		pageToken := ""
		for {
			entities, nextToken, listErr := client.List(ctx, entityType, 100, pageToken, 0)
			if listErr != nil {
				// Log the error but continue with other entity types
				typeStatus = "error"
				break
			}
			count += uint64(len(entities))
			if nextToken == "" {
				break
			}
			pageToken = nextToken
		}

		if count > 0 {
			typeStatus = "active"
			activeTypes++
		}
		totalEntities += count

		entityTypes = append(entityTypes, &platformv1.EntityTypeInfo{
			Name:        entityType,
			EntityCount: count,
			Status:      typeStatus,
		})
	}

	return &platformv1.ListEntityTypesResponse{
		EntityTypes:   entityTypes,
		TotalEntities: totalEntities,
		ActiveTypes:   activeTypes,
		DatabasePath:  databasePath,
	}, nil
}

// DumpEntityType streams entities from entity types.
// If no entity type is specified, all entity types are dumped using dynamic discovery.
func (s *Service) DumpEntityType(req *platformv1.DumpEntityTypeRequest, stream platformv1.PlatformDaemon_DumpEntityTypeServer) error {
	ctx := stream.Context()

	// Get QuicBaaS client from app
	client, _, err := s.getQuicBaaSClient()
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	// Determine which entity types to dump
	var entityTypes []string
	if req.EntityType != "" {
		entityTypes = []string{req.EntityType}
	} else {
		// Discover entity types dynamically from QuicBaaS
		discoveredTypes, _, _, listErr := client.ListEntityTypes(ctx, 1000, "")
		if listErr != nil {
			return status.Error(codes.Internal, "failed to list entity types: "+listErr.Error())
		}
		entityTypes = discoveredTypes
	}

	for _, entityType := range entityTypes {
		// List all entities of this type
		pageToken := ""
		for {
			entities, nextToken, listErr := client.List(ctx, entityType, 100, pageToken, 0)
			if listErr != nil {
				// Skip entity type on error but continue with others
				break
			}

			for _, entity := range entities {
				resp := &platformv1.DumpEntityTypeResponse{
					EntityType: entityType,
					EntityId:   entity.ID,
					Data:       entity.Data,
				}
				if err := stream.Send(resp); err != nil {
					return err
				}
			}

			if nextToken == "" {
				break
			}
			pageToken = nextToken
		}
	}

	return nil
}

// getQuicBaaSClient returns the QuicBaaS client from the app.
// It uses the FactoryInterface to enable mocking in unit tests.
func (s *Service) getQuicBaaSClient() (quicbaas.ClientInterface, string, error) {
	// Use injected factory if available (for testing)
	if s.quicbaasFactory != nil {
		client := s.quicbaasFactory.QuicBaaSClient()
		if client == nil {
			return nil, "", ErrDatabaseNotAvailable{Reason: "QuicBaaS client not available"}
		}
		if !client.IsStarted() {
			return nil, "", ErrDatabaseNotAvailable{Reason: "QuicBaaS client not started"}
		}
		return client, s.quicbaasFactory.DataDir(), nil
	}

	// Fall back to App.DAOFactory()
	if s.config.App == nil {
		return nil, "", ErrDatabaseNotAvailable{Reason: "application not configured"}
	}

	daoFactory := s.config.App.DAOFactory()
	if daoFactory == nil {
		return nil, "", ErrDatabaseNotAvailable{Reason: "datastore factory not initialized"}
	}

	// Try interface (enables mocking)
	dbFactory, ok := daoFactory.(quicbaas.FactoryInterface)
	if !ok {
		return nil, "", ErrDatabaseNotAvailable{Reason: "datastore does not implement QuicBaaS interface"}
	}

	client := dbFactory.QuicBaaSClient()
	if client == nil {
		return nil, "", ErrDatabaseNotAvailable{Reason: "QuicBaaS client not available"}
	}

	if !client.IsStarted() {
		return nil, "", ErrDatabaseNotAvailable{Reason: "QuicBaaS client not started"}
	}

	// Get QuicBaaS data directory path from factory
	datastorePath := dbFactory.DataDir()

	return client, datastorePath, nil
}

// Helper functions

// generateSubscriptionID returns a unique identifier for a stream subscription.
//
// The counter is FORMATTED, not converted. It previously read
// string(rune(id)), which maps the counter through Unicode instead: every
// value in the UTF-16 surrogate range D800-DFFF and every value above
// 0x10FFFF becomes U+FFFD, so 87,936 of the first 1.2M counter values
// collapsed onto one character. With a second-resolution timestamp, any two
// of them in the same second produced an identical ID -- and past 1,114,111
// every ID collided. Low counters also emitted control characters (\x01,
// \n) into a string that reaches logs and protocol fields.
//
// The rune() wrapper was load-bearing in the wrong direction: string(int) is
// a go vet diagnostic, and rune() silenced the diagnostic while keeping
// exactly the behaviour it warns about.
func (s *Service) generateSubscriptionID() string {
	id := s.subIDSeq.Add(1)
	return time.Now().Format("20060102150405") + "-" + strconv.FormatUint(id, 10)
}

func serviceTypeFromName(name string) platformv1.ServiceType {
	switch name {
	case "tpm":
		return platformv1.ServiceType_SERVICE_TYPE_TPM
	case "sdn":
		return platformv1.ServiceType_SERVICE_TYPE_SDN
	case "compute":
		return platformv1.ServiceType_SERVICE_TYPE_COMPUTE
	case "dns":
		return platformv1.ServiceType_SERVICE_TYPE_DNS
	case "acme":
		return platformv1.ServiceType_SERVICE_TYPE_ACME
	case "webservice":
		return platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE
	case "attestation":
		return platformv1.ServiceType_SERVICE_TYPE_ATTESTATION
	default:
		return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED
	}
}

func serviceNameFromType(svcType platformv1.ServiceType) string {
	switch svcType {
	case platformv1.ServiceType_SERVICE_TYPE_TPM:
		return "tpm"
	case platformv1.ServiceType_SERVICE_TYPE_SDN:
		return "sdn"
	case platformv1.ServiceType_SERVICE_TYPE_COMPUTE:
		return "compute"
	case platformv1.ServiceType_SERVICE_TYPE_DNS:
		return "dns"
	case platformv1.ServiceType_SERVICE_TYPE_ACME:
		return "acme"
	case platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE:
		return "webservice"
	case platformv1.ServiceType_SERVICE_TYPE_ATTESTATION:
		return "attestation"
	default:
		return "unknown"
	}
}

func healthStatusFromServiceStatus(svcStatus platformv1.ServiceStatus) platformv1.HealthStatus {
	switch svcStatus {
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

func healthStatusFromHealthStatus(status health.HealthStatus) platformv1.HealthStatus {
	switch status {
	case health.StatusHealthy:
		return platformv1.HealthStatus_HEALTH_STATUS_HEALTHY
	case health.StatusDegraded:
		return platformv1.HealthStatus_HEALTH_STATUS_DEGRADED
	case health.StatusUnhealthy:
		return platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY
	case health.StatusUnknown:
		return platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED
	default:
		return platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err == nil {
		return hostname
	}
	return "unknown"
}

func formatUint64(val uint64) string {
	return strconv.FormatUint(val, 10)
}

func formatErrors(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	result := ""
	for i, err := range errors {
		if i > 0 {
			result += "; "
		}
		result += err
	}
	return result
}
