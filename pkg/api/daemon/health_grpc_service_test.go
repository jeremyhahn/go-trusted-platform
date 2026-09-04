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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Health Checker
// =============================================================================

// mockHealthChecker implements HealthChecker for testing.
type mockHealthChecker struct {
	mu        sync.RWMutex
	checkFunc func(ctx context.Context) error
}

func newMockHealthChecker() *mockHealthChecker {
	return &mockHealthChecker{}
}

func (m *mockHealthChecker) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.checkFunc != nil {
		return m.checkFunc(ctx)
	}
	return nil
}

func (m *mockHealthChecker) setCheckFunc(f func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkFunc = f
}

// Verify interface compliance at compile time
var _ HealthChecker = (*mockHealthChecker)(nil)

// =============================================================================
// Mock Watch Server
// =============================================================================

// mockWatchServer implements grpc_health_v1.Health_WatchServer for testing.
type mockWatchServer struct {
	grpc_health_v1.Health_WatchServer
	ctx       context.Context
	cancel    context.CancelFunc
	responses []*grpc_health_v1.HealthCheckResponse
	sendErr   error
	mu        sync.Mutex

	// sends carries one pending notification per delivered response. The
	// responses slice above is authoritative; this only nudges a waiter, so a
	// notification dropped while nobody is waiting cannot lose a send —
	// awaitResponses re-counts on every wakeup.
	//
	// The send is non-blocking, so a Watch implementation whose caller is not
	// waiting is never stalled by the mock.
	sends chan struct{}

	// attempts counts every Send CALL, including ones that return sendErr and
	// therefore append no response. A test that installs a send error needs to
	// wait for the service to hit it, and responseCount cannot see that: a
	// failed send delivers nothing.
	attempts int
}

func newMockWatchServer() *mockWatchServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &mockWatchServer{
		ctx:       ctx,
		cancel:    cancel,
		responses: make([]*grpc_health_v1.HealthCheckResponse, 0),
		sends:     make(chan struct{}, 1),
	}
}

// sendAttempts returns how many times Watch has CALLED Send, successful or not.
func (m *mockWatchServer) sendAttempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts
}

// awaitSendAttempts blocks until Watch has called Send at least want times.
//
// Used where a send error is installed: the service's next poll calls Send,
// gets the error, and delivers nothing — so the response count never moves and
// only the attempt count records that the error was reached.
func (m *mockWatchServer) awaitSendAttempts(t *testing.T, want int) {
	t.Helper()

	deadline := time.After(daemonTestDeadline)
	for {
		if m.sendAttempts() >= want {
			return
		}
		select {
		case <-m.sends:
		case <-deadline:
			// Errorf, not Fatalf: these helpers are called from the goroutine
			// that drives the stream, and FailNow must be called from the
			// goroutine running the test — from anywhere else it exits only
			// that goroutine and leaves Watch blocked, turning a failure into
			// a hang. Cancelling unblocks Watch so the test fails and reports.
			t.Errorf("Watch attempted %d of %d sends within %s",
				m.sendAttempts(), want, daemonTestDeadline)
			m.cancel()
			return
		}
	}
}

// responseCount returns how many responses Watch has delivered so far.
func (m *mockWatchServer) responseCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.responses)
}

// awaitResponses blocks until Watch has delivered at least want responses.
//
// This is what the sleeps in this file were approximating. The 1200ms one was
// waiting for the service's poll ticker to notice a status change; waiting for
// the response the change produces is the same event, observed rather than
// estimated, and it does not take 1200ms.
func (m *mockWatchServer) awaitResponses(t *testing.T, want int) {
	t.Helper()

	deadline := time.After(daemonTestDeadline)
	for {
		if m.responseCount() >= want {
			return
		}
		select {
		case <-m.sends:
		case <-deadline:
			// See awaitSendAttempts: Errorf and cancel, never Fatalf, because
			// this runs on the stream-driving goroutine.
			t.Errorf("Watch delivered %d of %d responses within %s",
				m.responseCount(), want, daemonTestDeadline)
			m.cancel()
			return
		}
	}
}

func (m *mockWatchServer) Send(resp *grpc_health_v1.HealthCheckResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts++
	notify(m.sends)
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	notify(m.sends)
	return nil
}

func (m *mockWatchServer) Context() context.Context {
	return m.ctx
}

func (m *mockWatchServer) setSendError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendErr = err
}

func (m *mockWatchServer) getResponses() []*grpc_health_v1.HealthCheckResponse {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*grpc_health_v1.HealthCheckResponse, len(m.responses))
	copy(result, m.responses)
	return result
}

// =============================================================================
// Helper Functions
// =============================================================================

func createTestHealthService(t *testing.T) *HealthGRPCService {
	t.Helper()
	logger := logging.DefaultLogger()
	return NewHealthGRPCService(logger)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewHealthGRPCService(t *testing.T) {
	t.Run("creates service with logger", func(t *testing.T) {
		logger := logging.DefaultLogger()
		svc := NewHealthGRPCService(logger)

		assert.NotNil(t, svc)
		assert.Equal(t, logger, svc.logger)
		assert.NotNil(t, svc.services)
		assert.NotNil(t, svc.checkers)
	})
}

// =============================================================================
// RegisterService Tests
// =============================================================================

func TestHealthGRPCService_RegisterService(t *testing.T) {
	t.Run("registers service with initial status", func(t *testing.T) {
		svc := createTestHealthService(t)

		svc.RegisterService("test-service", HealthServiceStatusServing)

		svc.mu.RLock()
		status, exists := svc.services["test-service"]
		svc.mu.RUnlock()

		assert.True(t, exists)
		assert.Equal(t, HealthServiceStatusServing, status)
	})

	t.Run("registers multiple services", func(t *testing.T) {
		svc := createTestHealthService(t)

		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterService("service-2", HealthServiceStatusNotServing)
		svc.RegisterService("service-3", HealthServiceStatusUnknown)

		svc.mu.RLock()
		assert.Len(t, svc.services, 3)
		svc.mu.RUnlock()
	})

	t.Run("overwrites existing service status", func(t *testing.T) {
		svc := createTestHealthService(t)

		svc.RegisterService("test-service", HealthServiceStatusServing)
		svc.RegisterService("test-service", HealthServiceStatusNotServing)

		svc.mu.RLock()
		status := svc.services["test-service"]
		svc.mu.RUnlock()

		assert.Equal(t, HealthServiceStatusNotServing, status)
	})
}

// =============================================================================
// RegisterHealthChecker Tests
// =============================================================================

func TestHealthGRPCService_RegisterHealthChecker(t *testing.T) {
	t.Run("registers health checker for service", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker := newMockHealthChecker()

		svc.RegisterHealthChecker("test-service", checker)

		svc.mu.RLock()
		registeredChecker, exists := svc.checkers["test-service"]
		svc.mu.RUnlock()

		assert.True(t, exists)
		assert.Equal(t, checker, registeredChecker)
	})

	t.Run("registers multiple health checkers", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker1 := newMockHealthChecker()
		checker2 := newMockHealthChecker()

		svc.RegisterHealthChecker("service-1", checker1)
		svc.RegisterHealthChecker("service-2", checker2)

		svc.mu.RLock()
		assert.Len(t, svc.checkers, 2)
		svc.mu.RUnlock()
	})
}

// =============================================================================
// SetServingStatus Tests
// =============================================================================

func TestHealthGRPCService_SetServingStatus(t *testing.T) {
	t.Run("updates service status", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		svc.SetServingStatus("test-service", HealthServiceStatusNotServing)

		svc.mu.RLock()
		status := svc.services["test-service"]
		svc.mu.RUnlock()

		assert.Equal(t, HealthServiceStatusNotServing, status)
	})

	t.Run("can set status for unregistered service", func(t *testing.T) {
		svc := createTestHealthService(t)

		svc.SetServingStatus("new-service", HealthServiceStatusServing)

		svc.mu.RLock()
		status, exists := svc.services["new-service"]
		svc.mu.RUnlock()

		assert.True(t, exists)
		assert.Equal(t, HealthServiceStatusServing, status)
	})
}

// =============================================================================
// SetAllServingStatus Tests
// =============================================================================

func TestHealthGRPCService_SetAllServingStatus(t *testing.T) {
	t.Run("updates all services to same status", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterService("service-2", HealthServiceStatusServing)
		svc.RegisterService("service-3", HealthServiceStatusNotServing)

		svc.SetAllServingStatus(HealthServiceStatusNotServing)

		svc.mu.RLock()
		for _, status := range svc.services {
			assert.Equal(t, HealthServiceStatusNotServing, status)
		}
		svc.mu.RUnlock()
	})

	t.Run("no-op when no services registered", func(t *testing.T) {
		svc := createTestHealthService(t)

		svc.SetAllServingStatus(HealthServiceStatusNotServing)

		svc.mu.RLock()
		assert.Empty(t, svc.services)
		svc.mu.RUnlock()
	})
}

// =============================================================================
// Shutdown Tests
// =============================================================================

func TestHealthGRPCService_Shutdown(t *testing.T) {
	t.Run("sets shutdown flag", func(t *testing.T) {
		svc := createTestHealthService(t)

		assert.False(t, svc.shutdown.Load())

		svc.Shutdown()

		assert.True(t, svc.shutdown.Load())
	})

	t.Run("sets all services to not serving", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterService("service-2", HealthServiceStatusServing)

		svc.Shutdown()

		svc.mu.RLock()
		for _, status := range svc.services {
			assert.Equal(t, HealthServiceStatusNotServing, status)
		}
		svc.mu.RUnlock()
	})
}

// =============================================================================
// Check Tests
// =============================================================================

func TestHealthGRPCService_Check(t *testing.T) {
	ctx := context.Background()

	t.Run("returns NOT_SERVING when shutdown", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)
		svc.Shutdown()

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("checks overall health with empty service name", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("service-1", HealthServiceStatusServing)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns NotFound for unregistered service", func(t *testing.T) {
		svc := createTestHealthService(t)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "unregistered",
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns SERVING for healthy dynamic checker", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker := newMockHealthChecker()
		checker.setCheckFunc(func(ctx context.Context) error {
			return nil
		})

		svc.RegisterService("test-service", HealthServiceStatusUnknown)
		svc.RegisterHealthChecker("test-service", checker)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns NOT_SERVING for unhealthy dynamic checker", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker := newMockHealthChecker()
		checker.setCheckFunc(func(ctx context.Context) error {
			return errors.New("unhealthy")
		})

		svc.RegisterService("test-service", HealthServiceStatusServing)
		svc.RegisterHealthChecker("test-service", checker)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("returns static status when no checker", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns NOT_SERVING status for static not serving", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusNotServing)

		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		})

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})
}

// =============================================================================
// Watch Tests
// =============================================================================

func TestHealthGRPCService_Watch(t *testing.T) {
	t.Run("sends initial status", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()

		// Start watch in goroutine and cancel after receiving initial status
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Cancel once the initial status has actually been delivered,
			// rather than after a duration chosen to be probably long enough.
			stream.awaitResponses(t, 1)
			stream.cancel()
		}()

		_ = svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)
		<-done

		responses := stream.getResponses()
		assert.NotEmpty(t, responses)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, responses[0].Status)
	})

	t.Run("sends SERVICE_UNKNOWN for unregistered service", func(t *testing.T) {
		svc := createTestHealthService(t)

		stream := newMockWatchServer()

		// Start watch in goroutine and cancel after receiving initial status
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Cancel once the initial status has actually been delivered,
			// rather than after a duration chosen to be probably long enough.
			stream.awaitResponses(t, 1)
			stream.cancel()
		}()

		_ = svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "unregistered",
		}, stream)
		<-done

		responses := stream.getResponses()
		assert.NotEmpty(t, responses)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN, responses[0].Status)
	})

	t.Run("returns error on send failure for initial status", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()
		stream.setSendError(errors.New("send failed"))

		err := svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)

		require.Error(t, err)
	})

	t.Run("returns error on send failure for SERVICE_UNKNOWN", func(t *testing.T) {
		svc := createTestHealthService(t)

		stream := newMockWatchServer()
		stream.setSendError(errors.New("send failed"))

		err := svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "unregistered",
		}, stream)

		require.Error(t, err)
	})

	t.Run("sends NOT_SERVING on shutdown", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()

		// Start watch in goroutine and shutdown after some time
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Act once the initial status has been delivered.
			stream.awaitResponses(t, 1)
			svc.Shutdown()
		}()

		err := svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)
		<-done

		assert.NoError(t, err)
		responses := stream.getResponses()
		assert.NotEmpty(t, responses)
		// Last response should be NOT_SERVING
		lastResp := responses[len(responses)-1]
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, lastResp.Status)
	})

	t.Run("sends update when status changes", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()

		// Change status and then cancel
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Wait for the initial status, change it, then wait for the change
			// to be DELIVERED. The 1200ms this replaces was waiting for the
			// service's poll ticker to notice; the second response is that
			// same event, observed instead of estimated.
			stream.awaitResponses(t, 1)
			svc.SetServingStatus("test-service", HealthServiceStatusNotServing)
			stream.awaitResponses(t, 2)
			stream.cancel()
		}()

		_ = svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)
		<-done

		responses := stream.getResponses()
		assert.NotEmpty(t, responses)
		// Should have at least initial status and one update
		if len(responses) >= 2 {
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, responses[0].Status)
			// Later response should be NOT_SERVING
			found := false
			for _, r := range responses {
				if r.Status == grpc_health_v1.HealthCheckResponse_NOT_SERVING {
					found = true
					break
				}
			}
			assert.True(t, found, "expected to find NOT_SERVING status after change")
		}
	})

	t.Run("returns error on send failure during status change", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()

		// Change status then set send error, then cancel
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Act once the initial status has been delivered.
			stream.awaitResponses(t, 1)
			// Install the send error BEFORE changing the status, then change it.
			//
			// Watch only sends when the status DIFFERS from the last one it
			// sent (health_grpc_service.go: `if resp.Status != lastStatus`), so
			// a status change is the only thing that produces a send here. The
			// sleeps this replaces installed the error after the change and
			// hoped 100ms was short enough that the change had not been
			// delivered yet — if it had been, no further send would ever occur
			// and the 1500ms wait was watching for something that could not
			// happen. Ordering the two explicitly removes the race instead of
			// timing it.
			before := stream.sendAttempts()
			stream.setSendError(errors.New("send failed on status change"))
			svc.SetServingStatus("test-service", HealthServiceStatusNotServing)

			// A failed send appends no response, so only the attempt count
			// records that the error was reached.
			stream.awaitSendAttempts(t, before+1)
			stream.cancel()
		}()

		err := svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)
		<-done

		// Either returns send error or context cancel - both are acceptable
		_ = err
	})

	t.Run("returns error on send failure during shutdown", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("test-service", HealthServiceStatusServing)

		stream := newMockWatchServer()

		// Start watch, wait for initial send, set error, then shutdown
		// done joins this goroutine before the subtest returns. The await
		// helpers call t.Errorf, and calling that after a subtest has
		// completed panics the whole package — so the goroutine must not
		// outlive it.
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Cancel once the initial status has actually been delivered,
			// rather than after a duration chosen to be probably long enough.
			stream.awaitResponses(t, 1)
			stream.setSendError(errors.New("send failed on shutdown"))
			svc.Shutdown()
		}()

		err := svc.Watch(&grpc_health_v1.HealthCheckRequest{
			Service: "test-service",
		}, stream)
		<-done

		require.Error(t, err)
	})
}

// =============================================================================
// checkOverallHealth Tests
// =============================================================================

func TestHealthGRPCService_CheckOverallHealth(t *testing.T) {
	ctx := context.Background()

	t.Run("returns SERVING when no services registered", func(t *testing.T) {
		svc := createTestHealthService(t)

		resp, err := svc.checkOverallHealth(ctx)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns SERVING when all services healthy", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterService("service-2", HealthServiceStatusServing)

		resp, err := svc.checkOverallHealth(ctx)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns NOT_SERVING when any service not serving", func(t *testing.T) {
		svc := createTestHealthService(t)
		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterService("service-2", HealthServiceStatusNotServing)

		resp, err := svc.checkOverallHealth(ctx)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("returns NOT_SERVING when any checker fails", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker := newMockHealthChecker()
		checker.setCheckFunc(func(ctx context.Context) error {
			return errors.New("unhealthy")
		})

		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterHealthChecker("service-1", checker)

		resp, err := svc.checkOverallHealth(ctx)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("returns SERVING when all checkers pass", func(t *testing.T) {
		svc := createTestHealthService(t)
		checker := newMockHealthChecker()
		checker.setCheckFunc(func(ctx context.Context) error {
			return nil
		})

		svc.RegisterService("service-1", HealthServiceStatusServing)
		svc.RegisterHealthChecker("service-1", checker)

		resp, err := svc.checkOverallHealth(ctx)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})
}

// =============================================================================
// statusToProto Tests
// =============================================================================

func TestHealthGRPCService_StatusToProto(t *testing.T) {
	svc := createTestHealthService(t)

	tests := []struct {
		name     string
		status   HealthServiceStatus
		expected grpc_health_v1.HealthCheckResponse_ServingStatus
	}{
		{"serving", HealthServiceStatusServing, grpc_health_v1.HealthCheckResponse_SERVING},
		{"not_serving", HealthServiceStatusNotServing, grpc_health_v1.HealthCheckResponse_NOT_SERVING},
		{"service_unknown", HealthServiceStatusServiceUnknown, grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN},
		{"unknown", HealthServiceStatusUnknown, grpc_health_v1.HealthCheckResponse_UNKNOWN},
		{"invalid", HealthServiceStatus(999), grpc_health_v1.HealthCheckResponse_UNKNOWN},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.statusToProto(tc.status)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestHealthGRPCService_ConcurrentAccess(t *testing.T) {
	svc := createTestHealthService(t)
	ctx := context.Background()

	// Pre-register services
	for i := 0; i < 10; i++ {
		svc.RegisterService("service-"+string(rune('0'+i)), HealthServiceStatusServing)
	}

	done := make(chan bool, 40)

	// Concurrent reads via Check
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_, _ = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{
				Service: "service-" + string(rune('0'+idx%10)),
			})
			done <- true
		}(i)
	}

	// Concurrent writes via SetServingStatus
	for i := 0; i < 10; i++ {
		go func(idx int) {
			svc.SetServingStatus("service-"+string(rune('0'+idx%10)), HealthServiceStatusServing)
			done <- true
		}(i)
	}

	// Concurrent RegisterHealthChecker
	for i := 0; i < 10; i++ {
		go func(idx int) {
			svc.RegisterHealthChecker("service-"+string(rune('0'+idx%10)), newMockHealthChecker())
			done <- true
		}(i)
	}

	// Concurrent RegisterService
	for i := 0; i < 10; i++ {
		go func(idx int) {
			svc.RegisterService("new-service-"+string(rune('0'+idx)), HealthServiceStatusServing)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 40; i++ {
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestHealthGRPCService_Integration(t *testing.T) {
	t.Run("full lifecycle", func(t *testing.T) {
		svc := createTestHealthService(t)
		ctx := context.Background()

		// Register services
		svc.RegisterService("api", HealthServiceStatusServing)
		svc.RegisterService("database", HealthServiceStatusServing)

		// Check overall health
		resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)

		// Check individual service
		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "api"})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)

		// Mark database as not serving
		svc.SetServingStatus("database", HealthServiceStatusNotServing)

		// Check database
		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "database"})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)

		// Check overall health again - should be NOT_SERVING
		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)

		// Register dynamic checker for database
		dbChecker := newMockHealthChecker()
		healthy := true
		dbChecker.setCheckFunc(func(ctx context.Context) error {
			if !healthy {
				return errors.New("database connection failed")
			}
			return nil
		})
		svc.RegisterHealthChecker("database", dbChecker)

		// Check database with healthy checker (overrides static status)
		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "database"})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)

		// Make checker unhealthy
		healthy = false
		dbChecker.setCheckFunc(func(ctx context.Context) error {
			return errors.New("database connection failed")
		})

		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "database"})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)

		// Shutdown
		svc.Shutdown()

		// All checks should return NOT_SERVING
		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)

		resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "api"})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
	})
}

// =============================================================================
// RegisterHealthService Tests
// =============================================================================

func TestRegisterHealthService(t *testing.T) {
	t.Run("registers health service with gRPC server", func(t *testing.T) {
		server := grpc.NewServer()
		defer server.Stop()

		logger := logging.DefaultLogger()
		healthService := NewHealthGRPCService(logger)

		// This should not panic and should register the service
		RegisterHealthService(server, healthService)

		// Service info should contain the health service
		info := server.GetServiceInfo()
		assert.NotNil(t, info)

		// Verify health service is registered
		_, exists := info["grpc.health.v1.Health"]
		assert.True(t, exists, "health service should be registered")
	})
}
