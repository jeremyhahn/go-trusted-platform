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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestService_SetHealthRegistry_Extended(t *testing.T) {
	t.Run("sets health registry", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		registry := health.NewRegistry()
		svc.SetHealthRegistry(registry)

		if svc.healthRegistry != registry {
			t.Error("SetHealthRegistry() did not set the registry")
		}

		_ = registry.Close()
	})
}

func TestService_GetHealth_WithRegistry(t *testing.T) {
	t.Run("uses health registry when available", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		registry := health.NewRegistry()
		defer registry.Close()

		// Register a health checker
		mockSvc := newMockService("registry-svc")
		mockSvc.running.Store(true)
		checker := NewServiceHealthChecker(mockSvc)
		_ = registry.Register(checker)

		svc.SetHealthRegistry(registry)

		ctx := context.Background()
		resp, err := svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
		if err != nil {
			t.Fatalf("GetHealth() error: %v", err)
		}

		// Should have component from registry
		if len(resp.Components) < 1 {
			t.Error("expected at least 1 component from registry")
		}
	})
}

func TestService_getQuicBaaSClient_Extended(t *testing.T) {
	t.Run("returns error when app is nil", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		_, _, err = svc.getQuicBaaSClient()
		if err == nil {
			t.Error("getQuicBaaSClient() with nil app should return error")
		}

		if _, ok := err.(ErrDatabaseNotAvailable); !ok {
			t.Errorf("expected ErrDatabaseNotAvailable, got %T", err)
		}
	})
}

func TestService_ListEntityTypes_Extended(t *testing.T) {
	t.Run("returns error when database not available", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		_, err = svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
		if err == nil {
			t.Error("ListEntityTypes() without database should return error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.Internal {
			t.Errorf("expected Internal, got %v", st.Code())
		}
	})
}

func TestService_healthStatusFromHealthStatus_Extended(t *testing.T) {
	tests := []struct {
		status   health.HealthStatus
		expected platformv1.HealthStatus
	}{
		{health.StatusHealthy, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		{health.StatusDegraded, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{health.StatusUnhealthy, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
		{health.StatusUnknown, platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
		// Test default case with an invalid status
		{health.HealthStatus("invalid"), platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := healthStatusFromHealthStatus(tt.status)
			if result != tt.expected {
				t.Errorf("healthStatusFromHealthStatus(%v) = %v, want %v", tt.status, result, tt.expected)
			}
		})
	}
}

func TestService_ShutdownWithErrors(t *testing.T) {
	t.Run("reports errors during shutdown", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Register and start a service that will fail to stop
		mockSvc := newMockService("tpm")
		_ = svc.RegisterService(mockSvc)

		ctx := context.Background()
		_, _ = svc.StartService(ctx, &platformv1.StartServiceRequest{
			Service: platformv1.ServiceType_SERVICE_TYPE_TPM,
		})

		// Set the service to fail on stop
		mockSvc.stopErr = errors.New("stop failed")

		// Shutdown
		resp, err := svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 1,
		})
		if err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}

		// Should report the error
		if resp.Status.Success {
			t.Error("expected shutdown to report failure due to service stop error")
		}

		if resp.Status.Error == nil {
			t.Error("expected error detail to be set")
		}
	})
}

func TestService_ConcurrentAccess_Extended(t *testing.T) {
	t.Run("handles concurrent operations", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Register some services
		for i := 0; i < 5; i++ {
			mockSvc := newMockService("test-svc-" + formatUint64(uint64(i)))
			_ = svc.RegisterService(mockSvc)
		}

		ctx := context.Background()
		done := make(chan bool)

		// Concurrent GetStatus
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = svc.GetStatus(ctx, &platformv1.GetStatusRequest{})
			}
			done <- true
		}()

		// Concurrent GetHealth
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = svc.GetHealth(ctx, &platformv1.GetHealthRequest{})
			}
			done <- true
		}()

		// Concurrent ListServices
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = svc.ListServices(ctx, &platformv1.ListServicesRequest{})
			}
			done <- true
		}()

		// Wait for all goroutines
		for i := 0; i < 3; i++ {
			<-done
		}
	})
}

func TestService_DumpEntityType(t *testing.T) {
	t.Run("returns error when database not available", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Create a mock stream that just returns an error
		mockStream := &mockDumpEntityTypeStream{}

		err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, mockStream)
		if err == nil {
			t.Error("DumpEntityType() without database should return error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.Internal {
			t.Errorf("expected Internal, got %v", st.Code())
		}
	})
}

// mockDumpEntityTypeStream implements the DumpEntityType stream for testing
type mockDumpEntityTypeStream struct {
	platformv1.PlatformDaemon_DumpEntityTypeServer
	responses []*platformv1.DumpEntityTypeResponse
}

func (m *mockDumpEntityTypeStream) Send(resp *platformv1.DumpEntityTypeResponse) error {
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockDumpEntityTypeStream) Context() context.Context {
	return context.Background()
}
