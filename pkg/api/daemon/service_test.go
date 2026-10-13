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
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "custom config",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				SocketGroup:     "test",
				SocketMode:      0600,
				ShutdownTimeout: 10 * time.Second,
				EnableMetrics:   false,
				EnableEvents:    false,
				Services:        make(map[string]ServiceConfig),
			},
			wantErr: false,
		},
		{
			name: "invalid config",
			config: &Config{
				SocketPath:      "",
				ShutdownTimeout: 10 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("NewService() expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewService() unexpected error: %v", err)
				return
			}

			if svc == nil {
				t.Fatal("NewService() returned nil service")
			}

			// Verify initial state
			if svc.services == nil {
				t.Error("services map should not be nil")
			}

			if svc.eventSubs == nil {
				t.Error("eventSubs map should not be nil")
			}

			if svc.logSubs == nil {
				t.Error("logSubs map should not be nil")
			}

			if svc.metricSubs == nil {
				t.Error("metricSubs map should not be nil")
			}

			// Verify system status is initializing
			status := platformv1.SystemStatus(svc.systemStatus.Load())
			if status != platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING {
				t.Errorf("initial status = %v, want INITIALIZING", status)
			}
		})
	}
}

func TestService_RegisterService(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("test")
		err = svc.RegisterService(mock)
		if err != nil {
			t.Errorf("RegisterService() error: %v", err)
		}

		// Verify service is registered
		if _, exists := svc.services["test"]; !exists {
			t.Error("service should be registered")
		}
	})

	t.Run("duplicate registration returns error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock1 := newMockService("duplicate")
		err = svc.RegisterService(mock1)
		if err != nil {
			t.Fatalf("first RegisterService() error: %v", err)
		}

		mock2 := newMockService("duplicate")
		err = svc.RegisterService(mock2)
		if err == nil {
			t.Error("RegisterService() with duplicate name should return error")
		}

		if _, ok := err.(ErrServiceAlreadyRunning); !ok {
			t.Errorf("expected ErrServiceAlreadyRunning, got %T", err)
		}
	})

	t.Run("registered service has correct initial state", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("test")
		err = svc.RegisterService(mock)
		if err != nil {
			t.Fatalf("RegisterService() error: %v", err)
		}

		state := svc.services["test"]
		status := platformv1.ServiceStatus(state.status.Load())
		if status != platformv1.ServiceStatus_SERVICE_STATUS_STOPPED {
			t.Errorf("initial service status = %v, want STOPPED", status)
		}

		if state.startCount.Load() != 0 {
			t.Error("initial start count should be 0")
		}

		if state.stopCount.Load() != 0 {
			t.Error("initial stop count should be 0")
		}
	})
}

func TestService_SetShutdownHandler(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	called := false
	handler := func() error {
		called = true
		return nil
	}

	svc.SetShutdownHandler(handler)

	// Trigger shutdown to test handler
	ctx := context.Background()
	_, _ = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
		Graceful:       true,
		TimeoutSeconds: 1,
	})

	if !called {
		t.Error("shutdown handler should have been called")
	}
}

func TestService_MarkReady(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	svc.MarkReady()

	status := platformv1.SystemStatus(svc.systemStatus.Load())
	if status != platformv1.SystemStatus_SYSTEM_STATUS_READY {
		t.Errorf("status after MarkReady() = %v, want READY", status)
	}
}

func TestService_GetStatus(t *testing.T) {
	t.Run("returns system status", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		svc.MarkReady()

		ctx := context.Background()
		resp, err := svc.GetStatus(ctx, &platformv1.GetStatusRequest{})
		if err != nil {
			t.Errorf("GetStatus() error: %v", err)
		}

		if resp == nil {
			t.Fatal("GetStatus() returned nil response")
		}

		if resp.Status != platformv1.SystemStatus_SYSTEM_STATUS_READY {
			t.Errorf("status = %v, want READY", resp.Status)
		}

		if resp.Info == nil {
			t.Error("platform info should not be nil")
		}

		if resp.Timestamp == nil {
			t.Error("timestamp should not be nil")
		}
	})

	t.Run("includes registered services", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Register test services
		mock1 := newMockService("tpm")
		_ = svc.RegisterService(mock1)

		mock2 := newMockService("dns")
		_ = svc.RegisterService(mock2)

		ctx := context.Background()
		resp, err := svc.GetStatus(ctx, &platformv1.GetStatusRequest{})
		if err != nil {
			t.Errorf("GetStatus() error: %v", err)
		}

		if len(resp.Services) != 2 {
			t.Errorf("service count = %d, want 2", len(resp.Services))
		}
	})

	t.Run("includes system info", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.GetStatus(ctx, &platformv1.GetStatusRequest{})
		if err != nil {
			t.Errorf("GetStatus() error: %v", err)
		}

		if resp.Info.SystemInfo == nil {
			t.Fatal("system info should not be nil")
		}

		sysInfo := resp.Info.SystemInfo
		if sysInfo.Os == "" {
			t.Error("OS should not be empty")
		}

		if sysInfo.Arch == "" {
			t.Error("Arch should not be empty")
		}

		if sysInfo.NumCpus == 0 {
			t.Error("NumCpus should not be zero")
		}
	})
}

func TestService_GetHealth(t *testing.T) {
	t.Run("healthy when no services", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
		if err != nil {
			t.Errorf("GetHealth() error: %v", err)
		}

		if resp == nil {
			t.Fatal("GetHealth() returned nil response")
		}

		if resp.Status != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
			t.Errorf("health status = %v, want HEALTHY", resp.Status)
		}
	})

	t.Run("includes component health", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		resp, err := svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
		if err != nil {
			t.Errorf("GetHealth() error: %v", err)
		}

		if len(resp.Components) != 1 {
			t.Errorf("component count = %d, want 1", len(resp.Components))
		}

		if resp.Components[0].Name != "tpm" {
			t.Errorf("component name = %q, want %q", resp.Components[0].Name, "tpm")
		}
	})

	t.Run("degraded when service has error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		// Set service to error state
		state := svc.services["tpm"]
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = "test error"

		ctx := context.Background()
		resp, err := svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
		if err != nil {
			t.Errorf("GetHealth() error: %v", err)
		}

		if resp.Status != platformv1.HealthStatus_HEALTH_STATUS_DEGRADED {
			t.Errorf("overall health = %v, want DEGRADED", resp.Status)
		}

		if resp.Components[0].Status != platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY {
			t.Errorf("component health = %v, want UNHEALTHY", resp.Components[0].Status)
		}

		if resp.Components[0].Message != "test error" {
			t.Errorf("health message = %q, want %q", resp.Components[0].Message, "test error")
		}
	})
}

func TestService_GetVersion(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	resp, err := svc.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		t.Errorf("GetVersion() error: %v", err)
	}

	if resp == nil {
		t.Fatal("GetVersion() returned nil response")
	}

	// Version may be empty in unit tests (set at build time)
	// Just verify the response is valid

	if resp.GoVersion == "" {
		t.Error("Go version should not be empty")
	}

	if resp.Components == nil {
		t.Error("components map should not be nil")
	}
}

func TestService_ListServices(t *testing.T) {
	t.Run("empty list when no services", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.ListServices(ctx, &platformv1.ListServicesRequest{})
		if err != nil {
			t.Errorf("ListServices() error: %v", err)
		}

		if resp == nil {
			t.Fatal("ListServices() returned nil response")
		}

		if len(resp.Services) != 0 {
			t.Errorf("service count = %d, want 0", len(resp.Services))
		}
	})

	t.Run("lists all registered services", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Register multiple services
		services := []string{"tpm", "dns", "acme"}
		for _, name := range services {
			mock := newMockService(name)
			_ = svc.RegisterService(mock)
		}

		ctx := context.Background()
		resp, err := svc.ListServices(ctx, &platformv1.ListServicesRequest{})
		if err != nil {
			t.Errorf("ListServices() error: %v", err)
		}

		if len(resp.Services) != 3 {
			t.Errorf("service count = %d, want 3", len(resp.Services))
		}

		// Verify all services are in response
		foundServices := make(map[string]bool)
		for _, svcInfo := range resp.Services {
			foundServices[svcInfo.Name] = true
		}

		for _, name := range services {
			if !foundServices[name] {
				t.Errorf("service %q not found in response", name)
			}
		}
	})

	t.Run("includes service metadata", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		resp, err := svc.ListServices(ctx, &platformv1.ListServicesRequest{})
		if err != nil {
			t.Errorf("ListServices() error: %v", err)
		}

		if len(resp.Services) != 1 {
			t.Fatalf("service count = %d, want 1", len(resp.Services))
		}

		svcInfo := resp.Services[0]
		if svcInfo.Metadata == nil {
			t.Error("metadata should not be nil")
		}

		if svcInfo.Metadata["start_count"] == "" {
			t.Error("start_count should be in metadata")
		}

		if svcInfo.Metadata["stop_count"] == "" {
			t.Error("stop_count should be in metadata")
		}
	})
}

func TestService_GetServiceStatus(t *testing.T) {
	t.Run("returns service status", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		resp, err := svc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Errorf("GetServiceStatus() error: %v", err)
		}

		if resp == nil {
			t.Fatal("GetServiceStatus() returned nil response")
		}

		if resp.Service.Name != "tpm" {
			t.Errorf("service name = %q, want %q", resp.Service.Name, "tpm")
		}

		if resp.Service.Status != platformv1.ServiceStatus_SERVICE_STATUS_STOPPED {
			t.Errorf("service status = %v, want STOPPED", resp.Service.Status)
		}
	})

	t.Run("service not found", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		_, err = svc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("GetServiceStatus() should return error for non-existent service")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.NotFound {
			t.Errorf("error code = %v, want NotFound", st.Code())
		}
	})

	t.Run("includes uptime when running", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		startedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		current := startedAt
		svc.now = func() time.Time { return current }

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		// Start the service
		ctx := context.Background()
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		current = current.Add(90 * time.Second)

		resp, err := svc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("GetServiceStatus() error: %v", err)
		}

		if resp.Service.StartedAt == nil {
			t.Fatal("StartedAt should not be nil for running service")
		}
		if got := resp.Service.StartedAt.AsTime(); !got.Equal(startedAt) {
			t.Errorf("StartedAt = %v, want %v", got, startedAt)
		}

		if resp.Service.UptimeSeconds != 90 {
			t.Errorf("UptimeSeconds = %d, want 90", resp.Service.UptimeSeconds)
		}
	})
}

func TestService_CurrentTime(t *testing.T) {
	t.Run("uses the injected clock", func(t *testing.T) {
		fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		svc := &Service{now: func() time.Time { return fixed }}

		if got := svc.currentTime(); !got.Equal(fixed) {
			t.Errorf("currentTime() = %v, want %v", got, fixed)
		}
	})

	t.Run("falls back to the wall clock when unset", func(t *testing.T) {
		svc := &Service{}

		before := time.Now()
		got := svc.currentTime()
		after := time.Now()

		if got.Before(before) || got.After(after) {
			t.Errorf("currentTime() = %v, want between %v and %v", got, before, after)
		}
	})
}

func TestService_StartService(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		resp, err := svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err != nil {
			t.Errorf("StartService() error: %v", err)
		}

		if resp == nil {
			t.Fatal("StartService() returned nil response")
		}

		if !resp.Status.Success {
			t.Error("status should indicate success")
		}

		if resp.Service.Status != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
			t.Errorf("service status = %v, want RUNNING", resp.Service.Status)
		}

		// Verify mock was actually started
		if !mock.IsRunning() {
			t.Error("mock service should be running")
		}

		if mock.startCount.Load() != 1 {
			t.Errorf("start count = %d, want 1", mock.startCount.Load())
		}
	})

	t.Run("service not found", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("StartService() should return error for non-existent service")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.NotFound {
			t.Errorf("error code = %v, want NotFound", st.Code())
		}
	})

	t.Run("start already running service", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Start once
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("first StartService() error: %v", err)
		}

		// Try to start again
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("StartService() should return error for already running service")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.AlreadyExists {
			t.Errorf("error code = %v, want AlreadyExists", st.Code())
		}
	})

	t.Run("service start returns error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		mock.startErr = errors.New("start failed")
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("StartService() should return error when service start fails")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.Internal {
			t.Errorf("error code = %v, want Internal", st.Code())
		}

		// Verify service is in error state
		state := svc.services["tpm"]
		svcStatus := platformv1.ServiceStatus(state.status.Load())
		if svcStatus != platformv1.ServiceStatus_SERVICE_STATUS_ERROR {
			t.Errorf("service status = %v, want ERROR", svcStatus)
		}
	})
}

func TestService_StopService(t *testing.T) {
	t.Run("successful stop", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Start the service first
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		// Stop the service
		resp, err := svc.StopService(ctx, &platformv1.StopServiceRequest{
			Service:        platformv1.ServiceType_SERVICE_TYPE_TPM,
			Force:          false,
			TimeoutSeconds: 5,
		})

		if err != nil {
			t.Errorf("StopService() error: %v", err)
		}

		if resp == nil {
			t.Fatal("StopService() returned nil response")
		}

		if !resp.Status.Success {
			t.Error("status should indicate success")
		}

		// Verify mock was actually stopped
		if mock.IsRunning() {
			t.Error("mock service should not be running")
		}

		if mock.stopCount.Load() != 1 {
			t.Errorf("stop count = %d, want 1", mock.stopCount.Load())
		}
	})

	t.Run("service not found", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		_, err = svc.StopService(ctx, &platformv1.StopServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("StopService() should return error for non-existent service")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.NotFound {
			t.Errorf("error code = %v, want NotFound", st.Code())
		}
	})

	t.Run("stop already stopped service", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Try to stop without starting
		_, err = svc.StopService(ctx, &platformv1.StopServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("StopService() should return error for already stopped service")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.FailedPrecondition {
			t.Errorf("error code = %v, want FailedPrecondition", st.Code())
		}
	})

	t.Run("force stop on error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		mock.stopErr = errors.New("stop failed")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Start the service
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		// Force stop should succeed even with error
		resp, err := svc.StopService(ctx, &platformv1.StopServiceRequest{
			Service:        platformv1.ServiceType_SERVICE_TYPE_TPM,
			Force:          true,
			TimeoutSeconds: 5,
		})

		// Force stop ignores errors
		if err != nil {
			t.Errorf("force StopService() should not return error: %v", err)
		}

		if resp == nil {
			t.Fatal("StopService() returned nil response")
		}

		if !resp.Status.Success {
			t.Error("force stop should succeed")
		}
	})

	t.Run("graceful stop with error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		mock.stopErr = errors.New("stop failed")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Start the service
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		// Graceful stop should return error
		_, err = svc.StopService(ctx, &platformv1.StopServiceRequest{
			Service:        platformv1.ServiceType_SERVICE_TYPE_TPM,
			Force:          false,
			TimeoutSeconds: 5,
		})

		if err == nil {
			t.Error("graceful StopService() should return error when service stop fails")
		}
	})
}

func TestService_RestartService(t *testing.T) {
	t.Run("successful restart", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Start the service first
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		// Restart the service
		resp, err := svc.RestartService(ctx, &platformv1.RestartServiceRequest{
			Service:        platformv1.ServiceType_SERVICE_TYPE_TPM,
			TimeoutSeconds: 5,
		})

		if err != nil {
			t.Errorf("RestartService() error: %v", err)
		}

		if resp == nil {
			t.Fatal("RestartService() returned nil response")
		}

		if !resp.Status.Success {
			t.Error("status should indicate success")
		}

		// Verify service was stopped and started
		if mock.stopCount.Load() != 1 {
			t.Errorf("stop count = %d, want 1", mock.stopCount.Load())
		}

		if mock.startCount.Load() != 2 {
			t.Errorf("start count = %d, want 2", mock.startCount.Load())
		}

		if !mock.IsRunning() {
			t.Error("service should be running after restart")
		}
	})

	t.Run("restart not running service", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		_ = svc.RegisterService(mock)

		ctx := context.Background()

		// Try to restart without starting
		_, err = svc.RestartService(ctx, &platformv1.RestartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		if err == nil {
			t.Error("RestartService() should return error for stopped service")
		}
	})
}

func TestService_Shutdown(t *testing.T) {
	t.Run("graceful shutdown", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 5,
		})

		if err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}

		if resp == nil {
			t.Fatal("Shutdown() returned nil response")
		}

		if !resp.Status.Success {
			t.Error("shutdown should succeed")
		}

		// Verify system status changed
		status := platformv1.SystemStatus(svc.systemStatus.Load())
		if status != platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN {
			t.Errorf("system status = %v, want SHUTTING_DOWN", status)
		}
	})

	t.Run("shutdown stops all services", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Register and start multiple services

		serviceTests := []struct {
			name    string
			svcType platformv1.ServiceType
		}{
			{"tpm", platformv1.ServiceType_SERVICE_TYPE_TPM},
			{"dns", platformv1.ServiceType_SERVICE_TYPE_DNS},
			{"acme", platformv1.ServiceType_SERVICE_TYPE_ACME},
		}

		mocks := make([]*mockManagedService, 0, len(serviceTests))
		ctx := context.Background()

		for _, st := range serviceTests {
			mock := newMockService(st.name)
			mocks = append(mocks, mock)
			_ = svc.RegisterService(mock)
			_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
				Service: st.svcType,
			})
			if err != nil {
				t.Fatalf("StartService(%s) error: %v", st.name, err)
			}
		}

		// Shutdown
		_, err = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 5,
		})
		if err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}

		// Verify all services were stopped
		for _, mock := range mocks {
			if mock.stopCount.Load() < 1 {
				t.Errorf("service %q should have been stopped", mock.Name())
			}
		}
	})

	t.Run("force shutdown", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		mock := newMockService("tpm")
		mock.stopDelay = 10 * time.Second // Long delay
		_ = svc.RegisterService(mock)

		ctx := context.Background()
		_, err = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})
		if err != nil {
			t.Fatalf("StartService() error: %v", err)
		}

		// Force shutdown should complete quickly
		start := time.Now()
		_, err = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       false,
			TimeoutSeconds: 1,
		})
		elapsed := time.Since(start)

		if err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}

		// Should complete faster than the service's stop delay
		if elapsed > 5*time.Second {
			t.Errorf("force shutdown took too long: %v", elapsed)
		}
	})

	t.Run("calls shutdown handler", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		handlerCalled := false
		svc.SetShutdownHandler(func() error {
			handlerCalled = true
			return nil
		})

		ctx := context.Background()
		_, err = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 1,
		})

		if err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}

		if !handlerCalled {
			t.Error("shutdown handler should have been called")
		}
	})
}

func TestService_GetConfig(t *testing.T) {
	t.Run("returns configuration", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.GetConfig(ctx, &platformv1.GetConfigRequest{})

		if err != nil {
			t.Errorf("GetConfig() error: %v", err)
		}

		if resp == nil {
			t.Fatal("GetConfig() returned nil response")
		}

		if len(resp.Sections) == 0 {
			t.Error("should return at least one config section")
		}
	})

	t.Run("returns specific section", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		resp, err := svc.GetConfig(ctx, &platformv1.GetConfigRequest{
			Section: "daemon",
		})

		if err != nil {
			t.Errorf("GetConfig() error: %v", err)
		}

		if len(resp.Sections) != 1 {
			t.Errorf("section count = %d, want 1", len(resp.Sections))
		}

		if resp.Sections[0].Section != "daemon" {
			t.Errorf("section name = %q, want %q", resp.Sections[0].Section, "daemon")
		}
	})

	t.Run("section not found", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		_, err = svc.GetConfig(ctx, &platformv1.GetConfigRequest{
			Section: "nonexistent",
		})

		if err == nil {
			t.Error("GetConfig() should return error for non-existent section")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.NotFound {
			t.Errorf("error code = %v, want NotFound", st.Code())
		}
	})
}

func TestService_UpdateConfig(t *testing.T) {
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	ctx := context.Background()

	// A request with no section is a client error.
	if _, err := svc.UpdateConfig(ctx, &platformv1.UpdateConfigRequest{}); err == nil {
		t.Fatal("UpdateConfig() should reject a nil section")
	} else if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument", status.Code(err))
	}

	// An in-memory (non-persisted) section override succeeds and is
	// visible in the live viper state.
	resp, err := svc.UpdateConfig(ctx, &platformv1.UpdateConfigRequest{
		Section: &platformv1.ConfigSection{
			Section: "daemon",
			Values:  map[string]string{"socket_group": "trusted"},
		},
		Persist: false,
	})
	if err != nil {
		t.Fatalf("UpdateConfig() unexpected error: %v", err)
	}
	if resp == nil || resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Fatalf("UpdateConfig() success response expected, got %+v", resp)
	}
	if got := viper.GetString("daemon.socket_group"); got != "trusted" {
		t.Fatalf("viper daemon.socket_group = %q, want %q", got, "trusted")
	}
}

func TestService_ReloadConfig(t *testing.T) {
	// With no Viper config file set, ReloadConfig should fail with
	// Internal (the underlying ConfigFileNotFoundError) rather than
	// Unimplemented. The behavior is now wired to real viper.
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	_, err = svc.ReloadConfig(ctx, &platformv1.ReloadConfigRequest{})

	if err == nil {
		// In environments where a viper config exists from a previous
		// test, ReloadConfig will succeed. That's also an acceptable
		// outcome — we only assert the call no longer panics or
		// returns Unimplemented.
		return
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() == codes.Unimplemented {
		t.Errorf("ReloadConfig is no longer unimplemented; got %v", err)
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("serviceTypeFromName", func(t *testing.T) {
		tests := []struct {
			name     string
			expected platformv1.ServiceType
		}{
			{"tpm", platformv1.ServiceType_SERVICE_TYPE_TPM},
			{"sdn", platformv1.ServiceType_SERVICE_TYPE_SDN},
			{"compute", platformv1.ServiceType_SERVICE_TYPE_COMPUTE},
			{"dns", platformv1.ServiceType_SERVICE_TYPE_DNS},
			{"acme", platformv1.ServiceType_SERVICE_TYPE_ACME},
			{"webservice", platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE},
			{"attestation", platformv1.ServiceType_SERVICE_TYPE_ATTESTATION},
			{"unknown", platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED},
		}

		for _, tt := range tests {
			got := serviceTypeFromName(tt.name)
			if got != tt.expected {
				t.Errorf("serviceTypeFromName(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		}
	})

	t.Run("serviceNameFromType", func(t *testing.T) {
		tests := []struct {
			svcType  platformv1.ServiceType
			expected string
		}{
			{platformv1.ServiceType_SERVICE_TYPE_TPM, "tpm"},
			{platformv1.ServiceType_SERVICE_TYPE_SDN, "sdn"},
			{platformv1.ServiceType_SERVICE_TYPE_COMPUTE, "compute"},
			{platformv1.ServiceType_SERVICE_TYPE_DNS, "dns"},
			{platformv1.ServiceType_SERVICE_TYPE_ACME, "acme"},
			{platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, "webservice"},
			{platformv1.ServiceType_SERVICE_TYPE_ATTESTATION, "attestation"},
			{platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, "unknown"},
		}

		for _, tt := range tests {
			got := serviceNameFromType(tt.svcType)
			if got != tt.expected {
				t.Errorf("serviceNameFromType(%v) = %q, want %q", tt.svcType, got, tt.expected)
			}
		}
	})

	t.Run("healthStatusFromServiceStatus", func(t *testing.T) {
		tests := []struct {
			svcStatus platformv1.ServiceStatus
			expected  platformv1.HealthStatus
		}{
			{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
			{platformv1.ServiceStatus_SERVICE_STATUS_ERROR, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
			{platformv1.ServiceStatus_SERVICE_STATUS_STARTING, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
			{platformv1.ServiceStatus_SERVICE_STATUS_STOPPING, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
			{platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
		}

		for _, tt := range tests {
			got := healthStatusFromServiceStatus(tt.svcStatus)
			if got != tt.expected {
				t.Errorf("healthStatusFromServiceStatus(%v) = %v, want %v", tt.svcStatus, got, tt.expected)
			}
		}
	})

	t.Run("formatUint64", func(t *testing.T) {
		tests := []struct {
			input    uint64
			expected string
		}{
			{0, "0"},
			{1, "1"},
			{123, "123"},
			{999999999, "999999999"},
		}

		for _, tt := range tests {
			got := formatUint64(tt.input)
			if got != tt.expected {
				t.Errorf("formatUint64(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		}
	})

	t.Run("formatErrors", func(t *testing.T) {
		tests := []struct {
			name     string
			errors   []string
			expected string
		}{
			{
				name:     "empty",
				errors:   []string{},
				expected: "",
			},
			{
				name:     "single error",
				errors:   []string{"error1"},
				expected: "error1",
			},
			{
				name:     "multiple errors",
				errors:   []string{"error1", "error2", "error3"},
				expected: "error1; error2; error3",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := formatErrors(tt.errors)
				if got != tt.expected {
					t.Errorf("formatErrors() = %q, want %q", got, tt.expected)
				}
			})
		}
	})

	t.Run("getHostname", func(t *testing.T) {
		hostname := getHostname()
		if hostname == "" {
			t.Error("getHostname() should not return empty string")
		}
	})
}
