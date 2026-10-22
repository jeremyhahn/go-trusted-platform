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

// Package daemon KMSService Coverage Tests
//
// This file contains comprehensive unit tests for the KMSService targeting
// the following functions with low coverage:
//   - NewKMSService (line 50) - target: 80%+
//   - initializeServers (line 69) - target: 80%+
//   - RegisterServices (line 135) - target: 80%+
//   - RegisterGRPCServices (line 159) - target: 80%+
//
// Test Strategy:
// We use mock implementations and struct manipulation to exercise code paths
// that would otherwise require a full QuicBaaS setup. This includes:
//   - Testing nil parameter validation
//   - Testing error paths when services return nil
//   - Testing idempotency (already initialized cases)
//   - Testing with pre-initialized servers
//
// Coverage Approach:
// Since the QuicBaaS integration requires complex setup, we focus on:
// 1. All nil/error validation paths
// 2. Idempotent behavior (already initialized)
// 3. Registration with pre-initialized servers (bypassing initializeServers errors)

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// =============================================================================
// NewKMSService Tests
// =============================================================================

func TestNewKMSService_NilApplication(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	svc, err := NewKMSService(nil, logger)

	if err == nil {
		t.Fatal("expected error for nil application")
	}

	if svc != nil {
		t.Error("expected nil service on error")
	}

	// Verify error type
	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}

	// Verify error message contains expected reason
	errStr := err.Error()
	if errStr == "" {
		t.Error("expected non-empty error message")
	}
}

func TestNewKMSService_NilLogger(t *testing.T) {
	t.Parallel()

	// When application is nil, logger doesn't matter - should still fail
	svc, err := NewKMSService(nil, nil)

	if err == nil {
		t.Fatal("expected error for nil application")
	}

	if svc != nil {
		t.Error("expected nil service on error")
	}
}

func TestNewKMSService_NilApp_ErrorMessageFormat(t *testing.T) {
	t.Parallel()

	_, err := NewKMSService(nil, slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify full error message format
	errStr := err.Error()
	expectedPrefix := "invalid configuration: "
	if len(errStr) < len(expectedPrefix) {
		t.Errorf("error message too short: %s", errStr)
	}
	if errStr[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("expected error message to start with '%s', got '%s'", expectedPrefix, errStr)
	}
}

func TestNewKMSService_NilApp_ReasonField(t *testing.T) {
	t.Parallel()

	_, err := NewKMSService(nil, slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}

	expectedReason := "application is required for KMS service"
	if errConfig.Reason != expectedReason {
		t.Errorf("expected reason '%s', got '%s'", expectedReason, errConfig.Reason)
	}
}

// =============================================================================
// initializeServers Tests
// =============================================================================

func TestKMSService_initializeServers_AlreadyInitialized(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Mark as already initialized
	svc.initialized.Store(true)

	// Should return nil immediately
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected no error for already initialized service, got: %v", err)
	}
}

func TestKMSService_initializeServers_AlreadyInitialized_Idempotent(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Mark as already initialized
	svc.initialized.Store(true)

	// Multiple calls should all succeed without error
	for i := 0; i < 10; i++ {
		err := svc.initializeServers()
		if err != nil {
			t.Errorf("call %d: expected no error, got: %v", i, err)
		}
	}
}

func TestKMSService_initializeServers_AlreadyInitialized_SkipsLogic(t *testing.T) {
	t.Parallel()

	// Create service with nil app - this would panic if initializeServers
	// didn't short-circuit on the initialized flag
	svc := &KMSService{
		logger: slog.Default(),
		app:    nil, // Would cause panic if not short-circuited
	}

	// Mark as initialized
	svc.initialized.Store(true)

	// Should return immediately without accessing app
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected no error when already initialized, got: %v", err)
	}
}

func TestKMSService_initializeServers_AtomicFlagCheck(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Verify initial state
	if svc.initialized.Load() {
		t.Error("expected initialized to be false initially")
	}

	// Set to true
	svc.initialized.Store(true)

	// initializeServers should return nil immediately
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	// Flag should remain true
	if !svc.initialized.Load() {
		t.Error("expected initialized to remain true")
	}
}

func TestKMSService_initializeServers_ConcurrentCalls(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Mark as already initialized
	svc.initialized.Store(true)

	// Multiple concurrent calls should all return nil (idempotent)
	var wg sync.WaitGroup
	errCount := atomic.Int32{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.initializeServers(); err != nil {
				errCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if errCount.Load() > 0 {
		t.Errorf("expected no errors for already initialized service, got %d errors", errCount.Load())
	}
}

func TestKMSService_initializeServers_InitializedFlagBehavior(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Initially not initialized
	if svc.initialized.Load() {
		t.Error("expected initialized to be false initially")
	}

	// Set initialized to true
	svc.initialized.Store(true)

	// initializeServers should return immediately
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected no error when already initialized, got: %v", err)
	}

	// Flag should still be true
	if !svc.initialized.Load() {
		t.Error("initialized flag should remain true")
	}
}

// =============================================================================
// RegisterGRPCServices Tests
// =============================================================================

func TestKMSService_RegisterGRPCServices_NilServer_Coverage(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	err := svc.RegisterGRPCServices(nil)
	if err == nil {
		t.Fatal("expected error for nil gRPC server")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestKMSService_RegisterGRPCServices_NilServer_Coverage_ErrorMessage(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	err := svc.RegisterGRPCServices(nil)
	if err == nil {
		t.Fatal("expected error")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}

	expectedReason := "gRPC server is required"
	if errConfig.Reason != expectedReason {
		t.Errorf("expected reason '%s', got '%s'", expectedReason, errConfig.Reason)
	}
}

func TestKMSService_RegisterGRPCServices_WithPreInitializedServers(t *testing.T) {
	t.Parallel()

	// Create a KMSService with pre-initialized servers to bypass initializeServers
	svc := &KMSService{
		logger:        slog.Default(),
		kmsAdapter:    &KMSServerAdapter{},
		secretsServer: &SecretsServerAdapter{},
		cryptoServer:  &CryptoServerAdapter{},
		dekServer:     &DEKServerAdapter{},
	}
	svc.initialized.Store(true) // Mark as initialized

	// Create a gRPC server for testing
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	// RegisterGRPCServices should succeed with pre-initialized servers
	err := svc.RegisterGRPCServices(grpcServer)
	if err != nil {
		t.Errorf("unexpected error with pre-initialized servers: %v", err)
	}
}

func TestKMSService_RegisterGRPCServices_InitializedState(t *testing.T) {
	t.Parallel()

	// Test that RegisterGRPCServices properly checks initialized state
	svc := &KMSService{
		logger: slog.Default(),
	}

	svc.initialized.Store(true)
	svc.kmsAdapter = &KMSServerAdapter{}
	svc.secretsServer = &SecretsServerAdapter{}
	svc.cryptoServer = &CryptoServerAdapter{}
	svc.dekServer = &DEKServerAdapter{}

	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	err := svc.RegisterGRPCServices(grpcServer)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// Start/Stop/IsRunning Tests
// =============================================================================

func TestKMSService_Start_Success(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	err := svc.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error on Start: %v", err)
	}

	if !svc.IsRunning() {
		t.Error("expected service to be running after Start")
	}
}

func TestKMSService_Start_AlreadyRunning(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start once
	err := svc.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error on first Start: %v", err)
	}

	// Start again - should be idempotent
	err = svc.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error on second Start: %v", err)
	}

	if !svc.IsRunning() {
		t.Error("expected service to still be running")
	}
}

func TestKMSService_Stop_Success(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start first
	err := svc.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error on Start: %v", err)
	}

	// Stop
	err = svc.Stop(ctx)
	if err != nil {
		t.Fatalf("unexpected error on Stop: %v", err)
	}

	if svc.IsRunning() {
		t.Error("expected service to not be running after Stop")
	}
}

func TestKMSService_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Stop without starting - should be idempotent
	err := svc.Stop(ctx)
	if err != nil {
		t.Fatalf("unexpected error on Stop when not running: %v", err)
	}

	if svc.IsRunning() {
		t.Error("expected service to not be running")
	}
}

func TestKMSService_Stop_MultipleStops(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start
	_ = svc.Start(ctx)

	// Stop multiple times
	err := svc.Stop(ctx)
	if err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	err = svc.Stop(ctx)
	if err != nil {
		t.Fatalf("unexpected error on second Stop: %v", err)
	}

	if svc.IsRunning() {
		t.Error("expected service to not be running after multiple stops")
	}
}

func TestKMSService_IsRunning_InitialState(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	if svc.IsRunning() {
		t.Error("expected service to not be running initially")
	}
}

func TestKMSService_IsRunning_AfterStartStop(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Initially not running
	if svc.IsRunning() {
		t.Error("expected service to not be running initially")
	}

	// After Start
	_ = svc.Start(ctx)
	if !svc.IsRunning() {
		t.Error("expected service to be running after Start")
	}

	// After Stop
	_ = svc.Stop(ctx)
	if svc.IsRunning() {
		t.Error("expected service to not be running after Stop")
	}

	// After restart
	_ = svc.Start(ctx)
	if !svc.IsRunning() {
		t.Error("expected service to be running after restart")
	}
}

// =============================================================================
// Name Tests
// =============================================================================

func TestKMSService_Name_ReturnsKMS(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	name := svc.Name()
	if name != "kms" {
		t.Errorf("expected name 'kms', got '%s'", name)
	}
}

func TestKMSService_Name_Consistent(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Call multiple times to ensure consistency
	name1 := svc.Name()
	name2 := svc.Name()
	name3 := svc.Name()

	if name1 != name2 || name2 != name3 {
		t.Error("expected consistent name across multiple calls")
	}
}

// =============================================================================
// Server Accessor Tests
// =============================================================================

func TestKMSService_KMSServer_NilBeforeInit(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	server := svc.KMSServer()
	if server != nil {
		t.Error("expected nil KMSServer before initialization")
	}
}

func TestKMSService_SecretsServer_NilBeforeInit(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	server := svc.SecretsServer()
	if server != nil {
		t.Error("expected nil SecretsServer before initialization")
	}
}

func TestKMSService_CryptoServer_NilBeforeInit(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	server := svc.CryptoServer()
	if server != nil {
		t.Error("expected nil CryptoServer before initialization")
	}
}

func TestKMSService_DEKServer_NilBeforeInit(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	server := svc.DEKServer()
	if server != nil {
		t.Error("expected nil DEKServer before initialization")
	}
}

func TestKMSService_AllServersNilBeforeInit(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// All servers should be nil before initialization
	if svc.KMSServer() != nil {
		t.Error("expected nil KMSServer")
	}
	if svc.SecretsServer() != nil {
		t.Error("expected nil SecretsServer")
	}
	if svc.CryptoServer() != nil {
		t.Error("expected nil CryptoServer")
	}
	if svc.DEKServer() != nil {
		t.Error("expected nil DEKServer")
	}
}

func TestKMSService_ServerAccessors_AfterInit(t *testing.T) {
	t.Parallel()

	// Create service with pre-initialized servers
	kmsServer := &KMSServerAdapter{}
	secretsServer := &SecretsServerAdapter{}
	cryptoServer := &CryptoServerAdapter{}
	dekServer := &DEKServerAdapter{}

	svc := &KMSService{
		logger:        slog.Default(),
		kmsAdapter:    kmsServer,
		secretsServer: secretsServer,
		cryptoServer:  cryptoServer,
		dekServer:     dekServer,
	}

	if svc.KMSServer() != kmsServer {
		t.Error("expected KMSServer to match")
	}
	if svc.SecretsServer() != secretsServer {
		t.Error("expected SecretsServer to match")
	}
	if svc.CryptoServer() != cryptoServer {
		t.Error("expected CryptoServer to match")
	}
	if svc.DEKServer() != dekServer {
		t.Error("expected DEKServer to match")
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestKMSService_Start_WithCanceledContext(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Start should still work since it doesn't use context currently
	err := svc.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKMSService_Stop_WithCanceledContext(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	_ = svc.Start(ctx)

	// Create canceled context for Stop
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// Stop should still work since it doesn't use context currently
	err := svc.Stop(cancelCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// Lifecycle Integration Tests
// =============================================================================

func TestKMSService_FullLifecycle(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Initial state
	if svc.IsRunning() {
		t.Error("expected not running initially")
	}
	if svc.Name() != "kms" {
		t.Error("expected name to be 'kms'")
	}

	// Start
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !svc.IsRunning() {
		t.Error("expected running after Start")
	}

	// Stop
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if svc.IsRunning() {
		t.Error("expected not running after Stop")
	}

	// Restart
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if !svc.IsRunning() {
		t.Error("expected running after restart")
	}

	// Final stop
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Final Stop failed: %v", err)
	}
}

func TestKMSService_ConcurrentStartStop(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start multiple goroutines that call Start/Stop
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = svc.Start(ctx)
			done <- true
		}()
		go func() {
			_ = svc.Stop(ctx)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Service should be in a consistent state (running or not)
	_ = svc.IsRunning()
}

// =============================================================================
// KMSService Struct Field Tests
// =============================================================================

func TestKMSService_ZeroValue(t *testing.T) {
	t.Parallel()

	// Test that a zero-value KMSService behaves correctly
	var svc KMSService

	// IsRunning should return false for zero value
	if svc.IsRunning() {
		t.Error("expected zero-value service to not be running")
	}

	// Name should still work
	if svc.Name() != "kms" {
		t.Errorf("expected name 'kms', got '%s'", svc.Name())
	}

	// Server accessors should return nil
	if svc.KMSServer() != nil {
		t.Error("expected nil KMSServer")
	}
	if svc.SecretsServer() != nil {
		t.Error("expected nil SecretsServer")
	}
	if svc.CryptoServer() != nil {
		t.Error("expected nil CryptoServer")
	}
	if svc.DEKServer() != nil {
		t.Error("expected nil DEKServer")
	}
}

func TestKMSService_InitializedFlag(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Initially not initialized
	if svc.initialized.Load() {
		t.Error("expected initialized to be false initially")
	}

	// Manually set initialized
	svc.initialized.Store(true)
	if !svc.initialized.Load() {
		t.Error("expected initialized to be true after Store(true)")
	}

	// Reset
	svc.initialized.Store(false)
	if svc.initialized.Load() {
		t.Error("expected initialized to be false after Store(false)")
	}
}

func TestKMSService_RunningFlag(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Initially not running
	if svc.running.Load() {
		t.Error("expected running to be false initially")
	}

	// Manually set running
	svc.running.Store(true)
	if !svc.running.Load() {
		t.Error("expected running to be true after Store(true)")
	}

	// Reset
	svc.running.Store(false)
	if svc.running.Load() {
		t.Error("expected running to be false after Store(false)")
	}
}

// =============================================================================
// Concurrency Safety Tests
// =============================================================================

func TestKMSService_ConcurrentIsRunning(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	_ = svc.Start(ctx)

	// Multiple concurrent reads of IsRunning
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_ = svc.IsRunning()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	_ = svc.Stop(ctx)
}

func TestKMSService_ConcurrentServerAccessors(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Multiple concurrent reads of server accessors
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_ = svc.KMSServer()
			_ = svc.SecretsServer()
			_ = svc.CryptoServer()
			_ = svc.DEKServer()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestKMSService_ConcurrentName(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Multiple concurrent reads of Name
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			name := svc.Name()
			if name != "kms" {
				t.Errorf("got unexpected name: %s", name)
			}
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

func TestKMSService_StartStopRapidCycles(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Rapid start/stop cycles
	for i := 0; i < 50; i++ {
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start failed on cycle %d: %v", i, err)
		}
		if !svc.IsRunning() {
			t.Errorf("expected running after Start on cycle %d", i)
		}
		if err := svc.Stop(ctx); err != nil {
			t.Fatalf("Stop failed on cycle %d: %v", i, err)
		}
		if svc.IsRunning() {
			t.Errorf("expected not running after Stop on cycle %d", i)
		}
	}
}

func TestKMSService_StopStartSequence(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Stop when not running (should be no-op)
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Stop when not running should not error: %v", err)
	}

	// Start
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Double start (should be idempotent)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Double Start should not error: %v", err)
	}

	// Stop
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Double stop (should be idempotent)
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Double Stop should not error: %v", err)
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrInvalidConfig_Error_KMS(t *testing.T) {
	t.Parallel()

	err := ErrInvalidConfig{Reason: "test reason"}
	errStr := err.Error()

	if errStr == "" {
		t.Error("expected non-empty error message")
	}

	if errStr != "invalid configuration: test reason" {
		t.Errorf("unexpected error message: %s", errStr)
	}
}

func TestErrInvalidConfig_EmptyReason_KMS(t *testing.T) {
	t.Parallel()

	err := ErrInvalidConfig{Reason: ""}
	errStr := err.Error()

	if errStr != "invalid configuration: " {
		t.Errorf("unexpected error message for empty reason: %s", errStr)
	}
}

// =============================================================================
// Registration with gRPC Service Descriptors
// =============================================================================

func TestKMSService_RegisterGRPCServices_VerifyRegistration(t *testing.T) {
	t.Parallel()

	// Create service with pre-initialized servers
	svc := &KMSService{
		logger:        slog.Default(),
		kmsAdapter:    &KMSServerAdapter{},
		secretsServer: &SecretsServerAdapter{},
		cryptoServer:  &CryptoServerAdapter{},
		dekServer:     &DEKServerAdapter{},
	}
	svc.initialized.Store(true)

	// Create gRPC server
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	// Register services
	err := svc.RegisterGRPCServices(grpcServer)
	if err != nil {
		t.Fatalf("failed to register gRPC services: %v", err)
	}

	// Verify the services were registered by getting service info
	info := grpcServer.GetServiceInfo()
	if len(info) == 0 {
		t.Error("expected services to be registered")
	}

	// Check for expected service names
	expectedServices := []string{
		pb.KeyManagement_ServiceDesc.ServiceName,
		pb.SecretsManagement_ServiceDesc.ServiceName,
		pb.Crypto_ServiceDesc.ServiceName,
		pb.DEKManagement_ServiceDesc.ServiceName,
	}

	for _, expected := range expectedServices {
		if _, ok := info[expected]; !ok {
			t.Errorf("expected service %s to be registered", expected)
		}
	}
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestNewKMSService_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		logger      *slog.Logger
		expectErr   bool
		expectedMsg string
	}{
		{
			name:        "nil application with default logger",
			logger:      slog.Default(),
			expectErr:   true,
			expectedMsg: "application is required for KMS service",
		},
		{
			name:        "nil application with nil logger",
			logger:      nil,
			expectErr:   true,
			expectedMsg: "application is required for KMS service",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewKMSService(nil, tc.logger)

			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else {
					errConfig, ok := err.(ErrInvalidConfig)
					if !ok {
						t.Errorf("expected ErrInvalidConfig, got %T", err)
					} else if errConfig.Reason != tc.expectedMsg {
						t.Errorf("expected reason '%s', got '%s'", tc.expectedMsg, errConfig.Reason)
					}
				}
				if svc != nil {
					t.Error("expected nil service on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if svc == nil {
					t.Error("expected non-nil service")
				}
			}
		})
	}
}

func TestKMSService_RegisterGRPCServices_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		server       *grpc.Server
		initialized  bool
		expectErr    bool
		expectedMsg  string
		setupServers bool
	}{
		{
			name:        "nil server",
			server:      nil,
			initialized: false,
			expectErr:   true,
			expectedMsg: "gRPC server is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &KMSService{
				logger: slog.Default(),
			}

			if tc.setupServers {
				svc.kmsAdapter = &KMSServerAdapter{}
				svc.secretsServer = &SecretsServerAdapter{}
				svc.cryptoServer = &CryptoServerAdapter{}
				svc.dekServer = &DEKServerAdapter{}
			}

			if tc.initialized {
				svc.initialized.Store(true)
			}

			err := svc.RegisterGRPCServices(tc.server)

			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else {
					errConfig, ok := err.(ErrInvalidConfig)
					if !ok {
						t.Errorf("expected ErrInvalidConfig, got %T", err)
					} else if errConfig.Reason != tc.expectedMsg {
						t.Errorf("expected reason '%s', got '%s'", tc.expectedMsg, errConfig.Reason)
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestKMSService_Lifecycle_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		startErr  bool
		stopErr   bool
		runAfter  bool
		runBefore bool
	}{
		{
			name:      "start then stop",
			startErr:  false,
			stopErr:   false,
			runBefore: false,
			runAfter:  false,
		},
		{
			name:      "stop when not running",
			startErr:  false,
			stopErr:   false,
			runBefore: false,
			runAfter:  false,
		},
		{
			name:      "double start",
			startErr:  false,
			stopErr:   false,
			runBefore: false,
			runAfter:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &KMSService{
				logger: slog.Default(),
			}
			ctx := context.Background()

			// Set running state before test if needed
			if tc.runBefore {
				svc.running.Store(true)
			}

			// Test lifecycle
			err := svc.Start(ctx)
			if tc.startErr {
				if err == nil {
					t.Error("expected start error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected start error: %v", err)
				}
			}

			err = svc.Stop(ctx)
			if tc.stopErr {
				if err == nil {
					t.Error("expected stop error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected stop error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// Algorithm Conversion Tests
// =============================================================================

func TestPbAlgorithmToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    pb.KeyAlgorithm
		expected quicbaas.KeyAlgorithm
	}{
		{"AES_256_GCM", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, quicbaas.AlgorithmAES256GCM},
		{"CHACHA20_POLY1305", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, quicbaas.AlgorithmChaCha20Poly1305},
		{"RSA_2048", pb.KeyAlgorithm_KEY_ALG_RSA_2048, quicbaas.AlgorithmRSA2048},
		{"RSA_4096", pb.KeyAlgorithm_KEY_ALG_RSA_4096, quicbaas.AlgorithmRSA4096},
		{"ECDSA_P256", pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, quicbaas.AlgorithmECDSAP256},
		{"ECDSA_P384", pb.KeyAlgorithm_KEY_ALG_ECDSA_P384, quicbaas.AlgorithmECDSAP384},
		{"ED25519", pb.KeyAlgorithm_KEY_ALG_ED25519, quicbaas.AlgorithmED25519},
		{"UNSPECIFIED defaults to AES", pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, quicbaas.AlgorithmAES256GCM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := pbAlgorithmToSDK(tc.input)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestSdkAlgorithmToPb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    quicbaas.KeyAlgorithm
		expected pb.KeyAlgorithm
	}{
		{"AES256GCM", quicbaas.AlgorithmAES256GCM, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"ChaCha20Poly1305", quicbaas.AlgorithmChaCha20Poly1305, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{"RSA2048", quicbaas.AlgorithmRSA2048, pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"RSA4096", quicbaas.AlgorithmRSA4096, pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{"ECDSAP256", quicbaas.AlgorithmECDSAP256, pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"ECDSAP384", quicbaas.AlgorithmECDSAP384, pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{"ED25519", quicbaas.AlgorithmED25519, pb.KeyAlgorithm_KEY_ALG_ED25519},
		{"Unknown defaults to UNSPECIFIED", quicbaas.KeyAlgorithm(999), pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sdkAlgorithmToPb(tc.input)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestPbUsagesToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []pb.KeyUsage
		expected []quicbaas.KeyUsage
	}{
		{
			"empty slice",
			[]pb.KeyUsage{},
			[]quicbaas.KeyUsage{},
		},
		{
			"single usage",
			[]pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT},
			[]quicbaas.KeyUsage{quicbaas.KeyUsageEncrypt},
		},
		{
			"multiple usages",
			[]pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_DECRYPT, pb.KeyUsage_KEY_USAGE_SIGN},
			[]quicbaas.KeyUsage{quicbaas.KeyUsageEncrypt, quicbaas.KeyUsageDecrypt, quicbaas.KeyUsageSign},
		},
		{
			"all usages",
			[]pb.KeyUsage{
				pb.KeyUsage_KEY_USAGE_ENCRYPT,
				pb.KeyUsage_KEY_USAGE_DECRYPT,
				pb.KeyUsage_KEY_USAGE_SIGN,
				pb.KeyUsage_KEY_USAGE_VERIFY,
				pb.KeyUsage_KEY_USAGE_WRAP_KEY,
			},
			[]quicbaas.KeyUsage{
				quicbaas.KeyUsageEncrypt,
				quicbaas.KeyUsageDecrypt,
				quicbaas.KeyUsageSign,
				quicbaas.KeyUsageVerify,
				quicbaas.KeyUsageWrap,
			},
		},
		{
			// The SDK has no MAC usage: an HMAC key is generated with
			// sign and verify, as the REST surface does. Dropping the MAC
			// usages instead left the request with none at all.
			"mac usages map to sign and verify",
			[]pb.KeyUsage{pb.KeyUsage_KEY_USAGE_GENERATE_MAC, pb.KeyUsage_KEY_USAGE_VERIFY_MAC},
			[]quicbaas.KeyUsage{quicbaas.KeyUsageSign, quicbaas.KeyUsageVerify},
		},
		{
			// The proto zero value carries no usage and grants nothing.
			"unspecified grants nothing",
			[]pb.KeyUsage{pb.KeyUsage_KEY_USAGE_UNSPECIFIED, pb.KeyUsage_KEY_USAGE_SIGN},
			[]quicbaas.KeyUsage{quicbaas.KeyUsageSign},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pbUsagesToSDK(tc.input)
			if err != nil {
				t.Fatalf("usages refused: %v", err)
			}
			if len(result) != len(tc.expected) {
				t.Errorf("expected length %d, got %d", len(tc.expected), len(result))
				return
			}
			for i, v := range result {
				if v != tc.expected[i] {
					t.Errorf("at index %d: expected %v, got %v", i, tc.expected[i], v)
				}
			}
		})
	}
}

// TestPbUsagesToSDKRefusesUnmappedUsages pins the refusal of a usage the
// SDK cannot express. DERIVE_KEY used to be dropped silently, which
// generated a key without the usage the caller asked for; it is refused
// as InvalidArgument now, as the REST surface refuses an unknown usage.
func TestPbUsagesToSDKRefusesUnmappedUsages(t *testing.T) {
	t.Parallel()

	for _, usage := range []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_DERIVE_KEY, pb.KeyUsage(99)} {
		_, err := pbUsagesToSDK([]pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, usage})
		var unsupported ErrKMSUnsupportedValue
		if !errors.As(err, &unsupported) {
			t.Fatalf("usage %v: expected ErrKMSUnsupportedValue, got %T: %v", usage, err, err)
		}
		if code := status.Code(err); code != codes.InvalidArgument {
			t.Fatalf("usage %v: gRPC code %v, want InvalidArgument", usage, code)
		}
	}
}

// TestKMSServerAdapterGenerateKeyRefusesDerive checks the refusal reaches
// the gRPC caller before the SDK is called.
func TestKMSServerAdapterGenerateKeyRefusesDerive(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{client: &platformMockKMSClient{}}
	_, err := adapter.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Name:    "derive-key",
		KeySpec: &pb.KeySpec{Usage: []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_DERIVE_KEY}},
	})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("gRPC code %v, want InvalidArgument (err %v)", code, err)
	}
}

func TestPbHashAlgorithmToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    pb.HashAlgorithm
		expected quicbaas.HashAlgorithm
	}{
		{"SHA256", pb.HashAlgorithm_HASH_ALG_SHA256, quicbaas.HashSHA256},
		{"SHA384", pb.HashAlgorithm_HASH_ALG_SHA384, quicbaas.HashSHA384},
		{"SHA512", pb.HashAlgorithm_HASH_ALG_SHA512, quicbaas.HashSHA512},
		{"UNSPECIFIED defaults to SHA256", pb.HashAlgorithm_HASH_ALG_UNSPECIFIED, quicbaas.HashSHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := pbHashAlgorithmToSDK(tc.input)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// =============================================================================
// Adapter Nil Client Error Tests
// =============================================================================

// Helper function to check for gRPC Unavailable status error
func isUnavailableStatus(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.Unavailable
}

func TestKMSServerAdapter_GenerateKey_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{logger: slog.Default()}
	_, err := adapter.GenerateKey(context.Background(), &pb.GenerateKeyRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestKMSServerAdapter_GetKey_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{logger: slog.Default()}
	_, err := adapter.GetKey(context.Background(), &pb.GetKeyRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

// classedKMSClient answers every key lookup with one error.
type classedKMSClient struct {
	mockSDKKMSClient
	err error
}

func (c *classedKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	return nil, c.err
}

func (c *classedKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	return nil, c.err
}

func (c *classedKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	return nil, c.err
}

// TestKMSServerAdapter_ErrorClasses: the adapter behind the QUIC KMS
// handlers answers each SDK error with its class (#304), and an error that
// names no class with Internal, never a guessed NotFound.
func TestKMSServerAdapter_ErrorClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found", sdkerrors.NewNotFound("kms", "no key"), codes.NotFound},
		{"database not found", quicbaas.NewDatabaseError(quicbaas.ErrNotFound, "kms", "no key"), codes.NotFound},
		{"invalid input", sdkerrors.NewInvalidInput("kms", "bad key id"), codes.InvalidArgument},
		{"already exists", sdkerrors.NewAlreadyExists("kms", "dup"), codes.AlreadyExists},
		{"precondition", sdkerrors.NewPreconditionFailed("kms", "disabled"), codes.FailedPrecondition},
		{"forbidden", sdkerrors.NewForbidden("kms", "no"), codes.PermissionDenied},
		{"unimplemented", sdkerrors.NewUnimplemented("kms", "later"), codes.Unimplemented},
		{"unavailable", sdkerrors.NewUnavailable("kms", "down"), codes.Unavailable},
		{"no class", errors.New("key not found"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			keys := NewKMSServerAdapter(&classedKMSClient{err: tt.err}, slog.Default())
			crypto := NewCryptoServerAdapter(&platformMockCryptoClient{
				encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
					return nil, tt.err
				},
			}, slog.Default())

			_, err := keys.GetKey(ctx, &pb.GetKeyRequest{KeyId: "k"})
			if got := status.Code(err); got != tt.want {
				t.Errorf("GetKey: %v, want %v (%v)", got, tt.want, err)
			}
			_, err = keys.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "k"})
			if got := status.Code(err); got != tt.want {
				t.Errorf("GetKeyMetadata: %v, want %v (%v)", got, tt.want, err)
			}
			_, err = keys.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "k"})
			if got := status.Code(err); got != tt.want {
				t.Errorf("GetKeyPolicy: %v, want %v (%v)", got, tt.want, err)
			}
			_, err = crypto.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: "k", Plaintext: []byte("p")})
			if got := status.Code(err); got != tt.want {
				t.Errorf("Encrypt: %v, want %v (%v)", got, tt.want, err)
			}
		})
	}
}

func TestKMSServerAdapter_ListKeys_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{logger: slog.Default()}
	_, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestKMSServerAdapter_RotateKey_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{logger: slog.Default()}
	_, err := adapter.RotateKey(context.Background(), &pb.RotateKeyRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestKMSServerAdapter_DeleteKey_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &KMSServerAdapter{logger: slog.Default()}
	_, err := adapter.DeleteKey(context.Background(), &pb.DeleteKeyRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestSecretsServerAdapter_StoreSecret_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &SecretsServerAdapter{logger: slog.Default()}
	_, err := adapter.StoreSecret(context.Background(), &pb.StoreSecretRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestSecretsServerAdapter_GetSecret_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &SecretsServerAdapter{logger: slog.Default()}
	_, err := adapter.GetSecret(context.Background(), &pb.GetSecretRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestSecretsServerAdapter_ListSecrets_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &SecretsServerAdapter{logger: slog.Default()}
	_, err := adapter.ListSecrets(context.Background(), &pb.ListSecretsRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestSecretsServerAdapter_DeleteSecret_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &SecretsServerAdapter{logger: slog.Default()}
	_, err := adapter.DeleteSecret(context.Background(), &pb.DeleteSecretRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestCryptoServerAdapter_Encrypt_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &CryptoServerAdapter{logger: slog.Default()}
	_, err := adapter.Encrypt(context.Background(), &pb.CryptoEncryptRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestCryptoServerAdapter_Decrypt_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &CryptoServerAdapter{logger: slog.Default()}
	_, err := adapter.Decrypt(context.Background(), &pb.CryptoDecryptRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestCryptoServerAdapter_Sign_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &CryptoServerAdapter{logger: slog.Default()}
	_, err := adapter.Sign(context.Background(), &pb.SignRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestCryptoServerAdapter_Verify_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &CryptoServerAdapter{logger: slog.Default()}
	_, err := adapter.Verify(context.Background(), &pb.VerifyRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestDEKServerAdapter_CreateDEK_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &DEKServerAdapter{logger: slog.Default()}
	_, err := adapter.CreateDEK(context.Background(), &pb.CreateDEKRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestDEKServerAdapter_GetDEK_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &DEKServerAdapter{logger: slog.Default()}
	_, err := adapter.GetDEK(context.Background(), &pb.GetDEKRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestDEKServerAdapter_RotateDEK_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &DEKServerAdapter{logger: slog.Default()}
	_, err := adapter.RotateDEK(context.Background(), &pb.RotateDEKRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}

func TestDEKServerAdapter_DeleteDEK_NilClient(t *testing.T) {
	t.Parallel()

	adapter := &DEKServerAdapter{logger: slog.Default()}
	_, err := adapter.DeleteDEK(context.Background(), &pb.DeleteDEKRequest{})
	if err == nil {
		t.Error("expected error for nil client")
	}
	if !isUnavailableStatus(err) {
		t.Errorf("expected gRPC Unavailable status, got %T: %v", err, err)
	}
}
