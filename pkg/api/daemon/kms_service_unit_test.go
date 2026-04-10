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

// Package daemon KMSService Unit Tests
//
// This file contains unit tests for the KMSService that use mock App
// implementations to test initialization flows and error paths that
// cannot be exercised with nil parameters alone.
//
// Test Coverage Targets:
//   - NewKMSService: Test with App that returns nil vs non-nil KMS
//   - initializeServers: Test various QuicBaaS error paths
//   - RegisterServices: Test initializeServers error propagation
//   - RegisterGRPCServices: Test initializeServers error propagation

package daemon

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// testAppWithLogger returns an empty app.App with a logger set to avoid nil panics.
func testAppWithLogger() *app.App {
	return &app.App{
		Logger: logging.DefaultLogger(),
	}
}

// =============================================================================
// NewKMSService Tests with Mock App
// =============================================================================

func TestNewKMSService_NilApplicationReturnsError(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	svc, err := NewKMSService(nil, logger)

	if err == nil {
		t.Fatal("expected error for nil application, got nil")
	}

	if svc != nil {
		t.Error("expected nil service when error returned")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}

	if errConfig.Reason != "application is required for KMS service" {
		t.Errorf("unexpected error reason: %s", errConfig.Reason)
	}
}

func TestNewKMSService_AppWithNilKMSReturnsError(t *testing.T) {
	t.Parallel()

	// Create app that returns nil from KMS() - needs Logger to avoid panic
	mockApplication := testAppWithLogger()

	logger := slog.Default()
	svc, err := NewKMSService(mockApplication, logger)

	if err == nil {
		t.Fatal("expected error when app.KMS() returns nil")
	}

	if svc != nil {
		t.Error("expected nil service when error returned")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}

	if errConfig.Reason != "QuicBaaS backend not available for KMS" {
		t.Errorf("unexpected error reason: %s", errConfig.Reason)
	}
}

func TestNewKMSService_TableDrivenNilCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		app            *app.App
		expectedReason string
	}{
		{
			name:           "nil application",
			app:            nil,
			expectedReason: "application is required for KMS service",
		},
		{
			name:           "app with nil KMS service",
			app:            testAppWithLogger(),
			expectedReason: "QuicBaaS backend not available for KMS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewKMSService(tc.app, slog.Default())

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if svc != nil {
				t.Error("expected nil service on error")
			}

			errConfig, ok := err.(ErrInvalidConfig)
			if !ok {
				t.Fatalf("expected ErrInvalidConfig, got %T: %v", err, err)
			}

			if errConfig.Reason != tc.expectedReason {
				t.Errorf("expected reason %q, got %q", tc.expectedReason, errConfig.Reason)
			}
		})
	}
}

// =============================================================================
// initializeServers Tests - Error Paths
// =============================================================================

func TestKMSServiceUnit_initializeServers_NilApp(t *testing.T) {
	t.Parallel()

	// Create service with nil app directly - this should fail when
	// initializeServers tries to access app.DAOFactory()
	svc := &KMSService{
		app:    nil,
		logger: slog.Default(),
	}

	// This will panic if we call initializeServers with nil app
	// So we test the early return path instead
	svc.initialized.Store(true)
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected no error when already initialized, got: %v", err)
	}
}

func TestKMSServiceUnit_initializeServers_NonQuicBaaSFactory(t *testing.T) {
	t.Parallel()

	// Create a mock app with a non-QuicBaaS factory
	mockApplication := testAppWithLogger()

	// For unit testing, we test the type assertion failure path by
	// creating a KMSService with an app that would fail the type assertion
	svc := &KMSService{
		app:    mockApplication,
		logger: slog.Default(),
	}

	// Since app.DAOFactory() returns nil for empty App,
	// initializeServers will fail at the type assertion
	err := svc.initializeServers()
	if err == nil {
		t.Fatal("expected error for non-QuicBaaS factory")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}

	// The error should indicate datastore is not QuicBaaS
	if errConfig.Reason != "datastore is not QuicBaaS" {
		t.Errorf("unexpected error reason: %s", errConfig.Reason)
	}
}

func TestKMSServiceUnit_initializeServers_AlreadyInitializedReturnsNil(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Set initialized flag
	svc.initialized.Store(true)

	// Should return nil immediately without accessing app
	err := svc.initializeServers()
	if err != nil {
		t.Errorf("expected nil error when already initialized, got: %v", err)
	}
}

func TestKMSServiceUnit_initializeServers_ConcurrentCallsWithInitializedFlag(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Mark as initialized
	svc.initialized.Store(true)

	// Run concurrent calls - all should return nil
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.initializeServers(); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent initializeServers returned error: %v", err)
	}
}

// =============================================================================
// RegisterGRPCServices Tests - Error Propagation
// =============================================================================

func TestKMSServiceUnit_RegisterGRPCServices_NilServerError(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	err := svc.RegisterGRPCServices(nil)
	if err == nil {
		t.Fatal("expected error for nil gRPC server")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}

	if errConfig.Reason != "gRPC server is required" {
		t.Errorf("expected 'gRPC server is required', got '%s'", errConfig.Reason)
	}
}

func TestKMSServiceUnit_RegisterGRPCServices_InitializeServersError(t *testing.T) {
	t.Parallel()

	// Create service with app that will fail initializeServers
	mockApplication := testAppWithLogger()
	svc := &KMSService{
		app:    mockApplication,
		logger: slog.Default(),
	}

	// Create real gRPC server
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	// RegisterGRPCServices should propagate the initializeServers error
	err := svc.RegisterGRPCServices(grpcServer)
	if err == nil {
		t.Fatal("expected error from initializeServers")
	}

	errConfig, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}

	// Should get datastore error since DAOFactory returns nil
	if errConfig.Reason != "datastore is not QuicBaaS" {
		t.Errorf("unexpected error reason: %s", errConfig.Reason)
	}
}

// =============================================================================
// Service Registration with Pre-Initialized Servers
// =============================================================================

func TestKMSServiceUnit_RegisterGRPCServices_SuccessWithPreInitializedServers(t *testing.T) {
	t.Parallel()

	// Create service with pre-initialized servers (bypass initializeServers)
	svc := &KMSService{
		logger:        slog.Default(),
		kmsAdapter:    &KMSServerAdapter{},
		secretsServer: &SecretsServerAdapter{},
		cryptoServer:  &CryptoServerAdapter{},
		dekServer:     &DEKServerAdapter{},
	}
	svc.initialized.Store(true)

	// Create real gRPC server
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	err := svc.RegisterGRPCServices(grpcServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify services were registered by checking service info
	info := grpcServer.GetServiceInfo()
	if len(info) != 4 {
		t.Errorf("expected 4 services registered, got %d", len(info))
	}
}

// =============================================================================
// Lifecycle Tests with Context
// =============================================================================

func TestKMSServiceUnit_StartStop_WithNilContext(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Start with context.TODO() to satisfy static analysis
	err := svc.Start(context.TODO())
	if err != nil {
		t.Errorf("Start with context.TODO() should work: %v", err)
	}

	if !svc.IsRunning() {
		t.Error("service should be running after Start")
	}

	// Stop with nil context should work
	err = svc.Stop(context.TODO())
	if err != nil {
		t.Errorf("Stop with nil context should work: %v", err)
	}

	if svc.IsRunning() {
		t.Error("service should not be running after Stop")
	}
}

func TestKMSServiceUnit_Start_IdempotentBehavior(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start multiple times - should be idempotent
	for i := 0; i < 5; i++ {
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("Start call %d failed: %v", i, err)
		}
		if !svc.IsRunning() {
			t.Errorf("service should be running after Start call %d", i)
		}
	}
}

func TestKMSServiceUnit_Stop_IdempotentBehavior(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Start first
	_ = svc.Start(ctx)

	// Stop multiple times - should be idempotent
	for i := 0; i < 5; i++ {
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("Stop call %d failed: %v", i, err)
		}
		if svc.IsRunning() {
			t.Errorf("service should not be running after Stop call %d", i)
		}
	}
}

// =============================================================================
// Server Accessor Tests
// =============================================================================

func TestKMSServiceUnit_ServerAccessors_NilByDefault(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	if svc.KMSServer() != nil {
		t.Error("KMSServer should be nil by default")
	}
	if svc.SecretsServer() != nil {
		t.Error("SecretsServer should be nil by default")
	}
	if svc.CryptoServer() != nil {
		t.Error("CryptoServer should be nil by default")
	}
	if svc.DEKServer() != nil {
		t.Error("DEKServer should be nil by default")
	}
}

func TestKMSServiceUnit_ServerAccessors_ReturnSetValues(t *testing.T) {
	t.Parallel()

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
		t.Error("KMSServer accessor returned wrong value")
	}
	if svc.SecretsServer() != secretsServer {
		t.Error("SecretsServer accessor returned wrong value")
	}
	if svc.CryptoServer() != cryptoServer {
		t.Error("CryptoServer accessor returned wrong value")
	}
	if svc.DEKServer() != dekServer {
		t.Error("DEKServer accessor returned wrong value")
	}
}

// =============================================================================
// Name Method Tests
// =============================================================================

func TestKMSServiceUnit_Name_ReturnsConstant(t *testing.T) {
	t.Parallel()

	svc := &KMSService{}
	name := svc.Name()

	if name != "kms" {
		t.Errorf("Name() should return 'kms', got '%s'", name)
	}
}

func TestKMSServiceUnit_Name_IsIdempotent(t *testing.T) {
	t.Parallel()

	svc := &KMSService{}

	// Call Name multiple times
	name1 := svc.Name()
	name2 := svc.Name()
	name3 := svc.Name()

	if name1 != name2 || name2 != name3 {
		t.Error("Name() should be idempotent and return same value")
	}
}

// =============================================================================
// Error Type Verification
// =============================================================================

func TestNewKMSService_ErrorType_NilApp(t *testing.T) {
	t.Parallel()

	_, err := NewKMSService(nil, slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify it's the correct error type
	var errConfig ErrInvalidConfig
	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected error to be ErrInvalidConfig, got %T", err)
	}

	// Verify error message format
	errConfig = err.(ErrInvalidConfig)
	errStr := errConfig.Error()
	expectedPrefix := "invalid configuration: "
	if len(errStr) < len(expectedPrefix) || errStr[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("error message should start with '%s', got '%s'", expectedPrefix, errStr)
	}
}

func TestNewKMSService_ErrorType_NilKMS(t *testing.T) {
	t.Parallel()

	mockApplication := testAppWithLogger()
	_, err := NewKMSService(mockApplication, slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify it's the correct error type
	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected error to be ErrInvalidConfig, got %T", err)
	}
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestKMSServiceUnit_ConcurrentAccessors(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger:        slog.Default(),
		kmsAdapter:    &KMSServerAdapter{},
		secretsServer: &SecretsServerAdapter{},
		cryptoServer:  &CryptoServerAdapter{},
		dekServer:     &DEKServerAdapter{},
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.KMSServer()
			_ = svc.SecretsServer()
			_ = svc.CryptoServer()
			_ = svc.DEKServer()
			_ = svc.Name()
			_ = svc.IsRunning()
		}()
	}
	wg.Wait()
}

func TestKMSServiceUnit_ConcurrentStartStopIsRunning(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	var wg sync.WaitGroup

	// Mix of Start, Stop, and IsRunning calls
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = svc.Start(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = svc.Stop(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = svc.IsRunning()
		}()
	}

	wg.Wait()

	// Service should be in a consistent state (either running or not)
	// The key is that no data race occurred
}

// =============================================================================
// Initialization State Tests
// =============================================================================

func TestKMSServiceUnit_InitializedFlag_DefaultFalse(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	if svc.initialized.Load() {
		t.Error("initialized flag should be false by default")
	}
}

func TestKMSServiceUnit_RunningFlag_DefaultFalse(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	if svc.running.Load() {
		t.Error("running flag should be false by default")
	}
}

func TestKMSServiceUnit_InitializedFlag_ManualSet(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Set to true
	svc.initialized.Store(true)
	if !svc.initialized.Load() {
		t.Error("initialized flag should be true after Store(true)")
	}

	// Set back to false
	svc.initialized.Store(false)
	if svc.initialized.Load() {
		t.Error("initialized flag should be false after Store(false)")
	}
}

// =============================================================================
// Adapter Constructor Tests
// =============================================================================

func TestKMSServerAdapter_NewKMSServerAdapter(t *testing.T) {
	t.Parallel()

	adapter := NewKMSServerAdapter(nil, slog.Default())
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.client != nil {
		t.Error("expected nil client when passing nil")
	}
}

func TestSecretsServerAdapter_NewSecretsServerAdapter(t *testing.T) {
	t.Parallel()

	adapter := NewSecretsServerAdapter(nil, slog.Default())
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.client != nil {
		t.Error("expected nil client when passing nil")
	}
}

func TestCryptoServerAdapter_NewCryptoServerAdapter(t *testing.T) {
	t.Parallel()

	adapter := NewCryptoServerAdapter(nil, slog.Default())
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.client != nil {
		t.Error("expected nil client when passing nil")
	}
}

func TestDEKServerAdapter_NewDEKServerAdapter(t *testing.T) {
	t.Parallel()

	adapter := NewDEKServerAdapter(nil, slog.Default())
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.client != nil {
		t.Error("expected nil client when passing nil")
	}
}
