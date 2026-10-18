package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Health Checker for Health gRPC Service Tests
// =============================================================================

type boostMockHealthChecker struct {
	err error
}

func (m *boostMockHealthChecker) HealthCheck(ctx context.Context) error {
	return m.err
}

// =============================================================================
// Mock KMS/Crypto/Secrets Clients for KMS Service Adapter Tests
// =============================================================================

type boostMockCryptoClient struct {
	encryptFn func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error)
	decryptFn func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error)
	signFn    func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error)
	verifyFn  func(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error)
}

func (m *boostMockCryptoClient) Encrypt(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req)
	}
	return &quicbaas.EncryptResponse{Ciphertext: []byte("encrypted"), KeyVersion: 1}, nil
}

func (m *boostMockCryptoClient) Decrypt(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req)
	}
	return &quicbaas.DecryptResponse{Plaintext: []byte("decrypted")}, nil
}

func (m *boostMockCryptoClient) Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 1}, nil
}

func (m *boostMockCryptoClient) Verify(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	return &quicbaas.VerifyResponse{Valid: true}, nil
}

func (m *boostMockCryptoClient) Rewrap(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
	return &quicbaas.RewrapResponse{}, nil
}

func (m *boostMockCryptoClient) EncryptBatch(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
	return &quicbaas.EncryptBatchResponse{}, nil
}

func (m *boostMockCryptoClient) DecryptBatch(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error) {
	return &quicbaas.DecryptBatchResponse{}, nil
}

func (m *boostMockCryptoClient) GenerateDataKey(ctx context.Context, req *quicbaas.GenerateDataKeyRequest) (*quicbaas.GenerateDataKeyResponse, error) {
	return &quicbaas.GenerateDataKeyResponse{}, nil
}

func (m *boostMockCryptoClient) GenerateWrappedDataKey(ctx context.Context, req *quicbaas.GenerateWrappedDataKeyRequest) (*quicbaas.GenerateWrappedDataKeyResponse, error) {
	return &quicbaas.GenerateWrappedDataKeyResponse{}, nil
}

func (m *boostMockCryptoClient) GenerateHMAC(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
	return &quicbaas.GenerateHMACResponse{}, nil
}

func (m *boostMockCryptoClient) VerifyHMAC(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
	return &quicbaas.VerifyHMACResponse{}, nil
}

func (m *boostMockCryptoClient) GenerateRandom(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
	return &quicbaas.GenerateRandomResponse{}, nil
}

func (m *boostMockCryptoClient) Hash(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
	return &quicbaas.HashResponse{}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func boostLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func boostSlogLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// Health gRPC Service Tests
// =============================================================================

func TestBoost_HealthGRPCService_NewHealthGRPCService(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)
	if svc == nil {
		t.Fatal("expected non-nil HealthGRPCService")
	}
	if svc.services == nil {
		t.Fatal("expected services map to be initialized")
	}
	if svc.checkers == nil {
		t.Fatal("expected checkers map to be initialized")
	}
}

func TestBoost_HealthGRPCService_RegisterService(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("test-svc", HealthServiceStatusServing)

	svc.mu.RLock()
	s, ok := svc.services["test-svc"]
	svc.mu.RUnlock()

	if !ok {
		t.Fatal("expected service to be registered")
	}
	if s != HealthServiceStatusServing {
		t.Fatalf("expected serving status, got %d", s)
	}
}

func TestBoost_HealthGRPCService_RegisterHealthChecker(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	checker := &boostMockHealthChecker{}
	svc.RegisterHealthChecker("test-svc", checker)

	svc.mu.RLock()
	c, ok := svc.checkers["test-svc"]
	svc.mu.RUnlock()

	if !ok {
		t.Fatal("expected checker to be registered")
	}
	if c == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestBoost_HealthGRPCService_SetServingStatus(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.SetServingStatus("svc1", HealthServiceStatusNotServing)

	svc.mu.RLock()
	s := svc.services["svc1"]
	svc.mu.RUnlock()

	if s != HealthServiceStatusNotServing {
		t.Fatalf("expected not-serving status, got %d", s)
	}
}

func TestBoost_HealthGRPCService_SetAllServingStatus(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterService("svc2", HealthServiceStatusServing)
	svc.SetAllServingStatus(HealthServiceStatusNotServing)

	svc.mu.RLock()
	for name, s := range svc.services {
		if s != HealthServiceStatusNotServing {
			t.Fatalf("expected not-serving for %s, got %d", name, s)
		}
	}
	svc.mu.RUnlock()
}

func TestBoost_HealthGRPCService_Shutdown(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.Shutdown()

	if !svc.shutdown.Load() {
		t.Fatal("expected shutdown flag to be true")
	}

	// After shutdown, Check should return NOT_SERVING
	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING after shutdown, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_Check_EmptyServiceName(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING for empty service name, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_Check_RegisteredService(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: "svc1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_Check_UnregisteredService(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	_, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: "unknown"})
	if err == nil {
		t.Fatal("expected error for unregistered service")
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound code, got %v", status.Code(err))
	}
}

func TestBoost_HealthGRPCService_Check_WithChecker_Healthy(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterHealthChecker("svc1", &boostMockHealthChecker{err: nil})

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: "svc1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_Check_WithChecker_Unhealthy(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterHealthChecker("svc1", &boostMockHealthChecker{
		err: ErrHealthCheckFailed{Component: "svc1", Reason: "down"},
	})

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: "svc1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_checkOverallHealth_AllServing(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterService("svc2", HealthServiceStatusServing)

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_checkOverallHealth_OneNotServing(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterService("svc2", HealthServiceStatusNotServing)

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_checkOverallHealth_FailingChecker(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	svc.RegisterService("svc1", HealthServiceStatusServing)
	svc.RegisterHealthChecker("svc1", &boostMockHealthChecker{
		err: ErrHealthCheckFailed{Component: "svc1", Reason: "fail"},
	})

	resp, err := svc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING when checker fails, got %v", resp.Status)
	}
}

func TestBoost_HealthGRPCService_statusToProto(t *testing.T) {
	logger := boostLogger()
	svc := NewHealthGRPCService(logger)

	tests := []struct {
		name     string
		input    HealthServiceStatus
		expected grpc_health_v1.HealthCheckResponse_ServingStatus
	}{
		{"serving", HealthServiceStatusServing, grpc_health_v1.HealthCheckResponse_SERVING},
		{"not-serving", HealthServiceStatusNotServing, grpc_health_v1.HealthCheckResponse_NOT_SERVING},
		{"service-unknown", HealthServiceStatusServiceUnknown, grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN},
		{"unknown-default", HealthServiceStatusUnknown, grpc_health_v1.HealthCheckResponse_UNKNOWN},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := svc.statusToProto(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

// =============================================================================
// Compute gRPC Service Tests - Nil Orchestrator and Conversion Helpers
// =============================================================================

func TestBoost_ComputeGRPCService_NewAndSetOrchestrator(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)
	if svc == nil {
		t.Fatal("expected non-nil ComputeGRPCService")
	}
	if svc.orchestrator != nil {
		t.Fatal("expected nil orchestrator initially")
	}

	// Use the existing mockOrchestrator from compute_adapter_test.go
	orch := &mockOrchestrator{}
	svc.SetOrchestrator(orch)
	if svc.orchestrator == nil {
		t.Fatal("expected orchestrator to be set")
	}
}

func TestBoost_ComputeGRPCService_NilOrchestrator_VMOps(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CreateVM", func() error {
			_, err := svc.CreateVM(ctx, nil)
			return err
		}},
		{"StartVM", func() error {
			_, err := svc.StartVM(ctx, nil)
			return err
		}},
		{"StopVM", func() error {
			_, err := svc.StopVM(ctx, nil)
			return err
		}},
		{"RebootVM", func() error {
			_, err := svc.RebootVM(ctx, nil)
			return err
		}},
		{"DeleteVM", func() error {
			_, err := svc.DeleteVM(ctx, nil)
			return err
		}},
		{"GetVM", func() error {
			_, err := svc.GetVM(ctx, nil)
			return err
		}},
		{"ListVMs", func() error {
			_, err := svc.ListVMs(ctx, nil)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error for nil orchestrator")
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
			}
		})
	}
}

func TestBoost_ComputeGRPCService_NilOrchestrator_ContainerOps(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CreateContainer", func() error {
			_, err := svc.CreateContainer(ctx, nil)
			return err
		}},
		{"StartContainer", func() error {
			_, err := svc.StartContainer(ctx, nil)
			return err
		}},
		{"StopContainer", func() error {
			_, err := svc.StopContainer(ctx, nil)
			return err
		}},
		{"DeleteContainer", func() error {
			_, err := svc.DeleteContainer(ctx, nil)
			return err
		}},
		{"GetContainer", func() error {
			_, err := svc.GetContainer(ctx, nil)
			return err
		}},
		{"ListContainers", func() error {
			_, err := svc.ListContainers(ctx, nil)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error for nil orchestrator")
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
			}
		})
	}
}

func TestBoost_ComputeGRPCService_UnimplementedStubs(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GetVMMetrics", func() error {
			_, err := svc.GetVMMetrics(ctx, nil)
			return err
		}},
		{"AttachDisk", func() error {
			_, err := svc.AttachDisk(ctx, nil)
			return err
		}},
		{"DetachDisk", func() error {
			_, err := svc.DetachDisk(ctx, nil)
			return err
		}},
		{"ResizeDisk", func() error {
			_, err := svc.ResizeDisk(ctx, nil)
			return err
		}},
		// The VM/container operational RPCs are now implemented; a nil
		// orchestrator yields FailedPrecondition ("orchestrator not
		// initialized"), not Unimplemented. (MigrateVM is covered by the
		// migration suite once wired.)
		{"ExecContainer", func() error {
			_, err := svc.ExecContainer(ctx, nil)
			return err
		}},
		{"GetContainerMetrics", func() error {
			_, err := svc.GetContainerMetrics(ctx, nil)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected FailedPrecondition error")
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("expected FailedPrecondition code, got %v", status.Code(err))
			}
		})
	}
}

func TestBoost_ComputeGRPCService_InstanceToVMProto_NilInstance(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	result := svc.instanceToVMProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil instance")
	}
}

func TestBoost_ComputeGRPCService_InstanceToVMProto_WithConfig(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	now := time.Now()
	instance := &compute.Instance{
		ID:    "vm-1",
		Name:  "test-vm",
		State: compute.StateRunning,
		Config: &compute.InstanceConfig{
			Memory:     2048,
			CPUs:       4,
			SecureBoot: true,
			TPMEnabled: true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	vm := svc.instanceToVMProto(instance)
	if vm == nil {
		t.Fatal("expected non-nil VM proto")
	}
	if vm.Id != "vm-1" {
		t.Fatalf("expected id vm-1, got %s", vm.Id)
	}
	if vm.Config == nil {
		t.Fatal("expected non-nil VM config")
	}
	if vm.Config.Name != "test-vm" {
		t.Fatalf("expected name test-vm, got %s", vm.Config.Name)
	}
	if vm.Config.Memory == nil || vm.Config.Memory.SizeMb != 2048 {
		t.Fatal("expected memory 2048")
	}
	if vm.Config.Cpu == nil || vm.Config.Cpu.Cores != 4 {
		t.Fatal("expected 4 CPU cores")
	}
	if !vm.Config.SecureBoot {
		t.Fatal("expected secure boot enabled")
	}
	if vm.Config.Tpm == nil || !vm.Config.Tpm.Enabled {
		t.Fatal("expected TPM enabled")
	}
}

func TestBoost_ComputeGRPCService_InstanceToVMProto_NoConfigWithName(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	instance := &compute.Instance{
		ID:   "vm-2",
		Name: "named-vm",
	}

	vm := svc.instanceToVMProto(instance)
	if vm == nil {
		t.Fatal("expected non-nil VM proto")
	}
	if vm.Config == nil {
		t.Fatal("expected config to be populated from name")
	}
	if vm.Config.Name != "named-vm" {
		t.Fatalf("expected name named-vm, got %s", vm.Config.Name)
	}
}

func TestBoost_ComputeGRPCService_InstanceStateToVMState(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	tests := []struct {
		name  string
		input compute.InstanceState
	}{
		{"stopped", compute.StateStopped},
		{"starting", compute.StateStarting},
		{"running", compute.StateRunning},
		{"stopping", compute.StateStopping},
		{"error", compute.StateError},
		{"unknown", compute.StateUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Just verify it does not panic and returns a valid value
			got := svc.instanceStateToVMState(tc.input)
			_ = got
		})
	}
}

func TestBoost_ComputeGRPCService_InstanceToContainerProto_NilInstance(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	result := svc.instanceToContainerProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil instance")
	}
}

func TestBoost_ComputeGRPCService_InstanceToContainerProto_WithName(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	instance := &compute.Instance{
		ID:    "ctr-1",
		Name:  "test-container",
		State: compute.StateRunning,
	}

	container := svc.instanceToContainerProto(instance)
	if container == nil {
		t.Fatal("expected non-nil container proto")
	}
	if container.Id != "ctr-1" {
		t.Fatalf("expected id ctr-1, got %s", container.Id)
	}
	if container.Config == nil {
		t.Fatal("expected config with name")
	}
	if container.Config.Name != "test-container" {
		t.Fatalf("expected name test-container, got %s", container.Config.Name)
	}
}

func TestBoost_ComputeGRPCService_StreamingStubs(t *testing.T) {
	logger := boostLogger()
	svc := NewComputeGRPCService(logger, nil)

	t.Run("AttachVMConsole", func(t *testing.T) {
		err := svc.AttachVMConsole(nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
		}
	})

	t.Run("SendVMConsoleInput", func(t *testing.T) {
		err := svc.SendVMConsoleInput(nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GetVMLogs", func(t *testing.T) {
		err := svc.GetVMLogs(nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("AttachContainer", func(t *testing.T) {
		err := svc.AttachContainer(nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GetContainerLogs", func(t *testing.T) {
		err := svc.GetContainerLogs(nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// =============================================================================
// KMS Server Adapter Tests - Sign PreHashed passthrough
// =============================================================================

func TestBoost_CryptoServerAdapter_Sign_PreHashedPassthrough(t *testing.T) {
	var captured *quicbaas.SignRequest
	mock := &boostMockCryptoClient{
		signFn: func(_ context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
			captured = req
			return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 1}, nil
		},
	}
	adapter := NewCryptoServerAdapter(mock, boostSlogLogger())

	digest := []byte{0xde, 0xad, 0xbe, 0xef}
	_, err := adapter.Sign(context.Background(), &pb.SignRequest{
		KeyId:     "db-key",
		Message:   digest,
		PreHashed: true,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if captured == nil {
		t.Fatal("SDK client Sign was not called")
	}
	if !captured.PreHashed {
		t.Error("PreHashed = false on SDK request, want true: the KMS would double-hash the digest")
	}
}

func TestBoost_CryptoServerAdapter_Sign_NotPreHashedByDefault(t *testing.T) {
	var captured *quicbaas.SignRequest
	mock := &boostMockCryptoClient{
		signFn: func(_ context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
			captured = req
			return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 1}, nil
		},
	}
	adapter := NewCryptoServerAdapter(mock, boostSlogLogger())

	_, err := adapter.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "db-key",
		Message: []byte("raw message"),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if captured == nil {
		t.Fatal("SDK client Sign was not called")
	}
	if captured.PreHashed {
		t.Error("PreHashed = true on SDK request, want false for a raw message")
	}
}

// =============================================================================
// KMS Server Adapter Tests - BatchEncrypt, BatchDecrypt, Rewrap
// =============================================================================

func TestBoost_CryptoServerAdapter_BatchEncrypt_NilClient(t *testing.T) {
	adapter := NewCryptoServerAdapter(nil, boostSlogLogger())

	_, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{})
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchEncrypt_EmptyKeyID(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{KeyId: ""})
	if err == nil {
		t.Fatal("expected error for empty key_id")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchEncrypt_EmptyItems(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchEncryptItem{},
	})
	if err == nil {
		t.Fatal("expected error for empty items")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchEncrypt_ExceedsMaxBatch(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	items := make([]*pb.BatchEncryptItem, maxBatchSize+1)
	for i := range items {
		items[i] = &pb.BatchEncryptItem{Plaintext: []byte("data")}
	}

	_, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{
		KeyId: "key-1",
		Items: items,
	})
	if err == nil {
		t.Fatal("expected error for exceeding max batch size")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchEncrypt_Success(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	resp, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchEncryptItem{
			{Plaintext: []byte("hello")},
			{Plaintext: []byte("world")},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.KeyId != "key-1" {
		t.Fatalf("expected key-1, got %s", resp.KeyId)
	}
}

func TestBoost_CryptoServerAdapter_BatchEncrypt_PartialFailure(t *testing.T) {
	callCount := 0
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{
		encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
			callCount++
			if callCount == 2 {
				return nil, ErrServiceUnavailable{Service: "crypto"}
			}
			return &quicbaas.EncryptResponse{Ciphertext: []byte("enc"), KeyVersion: 1}, nil
		},
	}, boostSlogLogger())

	resp, err := adapter.BatchEncrypt(context.Background(), &pb.EncryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchEncryptItem{
			{Plaintext: []byte("ok")},
			{Plaintext: []byte("fail")},
			{Plaintext: []byte("ok2")},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}
	if resp.Results[1].Error == "" {
		t.Fatal("expected error in second result")
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_NilClient(t *testing.T) {
	adapter := NewCryptoServerAdapter(nil, boostSlogLogger())

	_, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{})
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_EmptyKeyID(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{KeyId: ""})
	if err == nil {
		t.Fatal("expected error for empty key_id")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_EmptyItems(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchDecryptItem{},
	})
	if err == nil {
		t.Fatal("expected error for empty items")
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_ExceedsMaxBatch(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	items := make([]*pb.BatchDecryptItem, maxBatchSize+1)
	for i := range items {
		items[i] = &pb.BatchDecryptItem{Ciphertext: []byte("data")}
	}

	_, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{
		KeyId: "key-1",
		Items: items,
	})
	if err == nil {
		t.Fatal("expected error for exceeding max batch")
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_Success(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	resp, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchDecryptItem{
			{Ciphertext: []byte("ct1")},
			{Ciphertext: []byte("ct2")},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
}

func TestBoost_CryptoServerAdapter_BatchDecrypt_PartialFailure(t *testing.T) {
	callCount := 0
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{
		decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
			callCount++
			if callCount == 1 {
				return nil, ErrServiceUnavailable{Service: "crypto"}
			}
			return &quicbaas.DecryptResponse{Plaintext: []byte("pt")}, nil
		},
	}, boostSlogLogger())

	resp, err := adapter.BatchDecrypt(context.Background(), &pb.DecryptBatchRequest{
		KeyId: "key-1",
		Items: []*pb.BatchDecryptItem{
			{Ciphertext: []byte("fail")},
			{Ciphertext: []byte("ok")},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Results[0].Error == "" {
		t.Fatal("expected error in first result")
	}
	if len(resp.Results[1].Plaintext) == 0 {
		t.Fatal("expected plaintext in second result")
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_NilClient(t *testing.T) {
	adapter := NewCryptoServerAdapter(nil, boostSlogLogger())

	_, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{})
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_EmptyKeyID(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{KeyId: ""})
	if err == nil {
		t.Fatal("expected error for empty key_id")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_EmptyCiphertext(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	_, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{
		KeyId:      "key-1",
		Ciphertext: nil,
	})
	if err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_Success(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{}, boostSlogLogger())

	resp, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{
		KeyId:      "key-1",
		Ciphertext: []byte("old-ct"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.KeyId != "key-1" {
		t.Fatalf("expected key-1, got %s", resp.KeyId)
	}
	if len(resp.Ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_DecryptFailure(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{
		decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
			return nil, ErrServiceUnavailable{Service: "crypto"}
		},
	}, boostSlogLogger())

	_, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{
		KeyId:      "key-1",
		Ciphertext: []byte("ct"),
	})
	if err == nil {
		t.Fatal("expected error when decrypt fails")
	}
}

func TestBoost_CryptoServerAdapter_Rewrap_EncryptFailure(t *testing.T) {
	adapter := NewCryptoServerAdapter(&boostMockCryptoClient{
		encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
			return nil, ErrServiceUnavailable{Service: "crypto"}
		},
	}, boostSlogLogger())

	_, err := adapter.Rewrap(context.Background(), &pb.RewrapRequest{
		KeyId:      "key-1",
		Ciphertext: []byte("ct"),
	})
	if err == nil {
		t.Fatal("expected error when encrypt fails")
	}
}

// =============================================================================
// IAM Service Stub Tests (build without iam tag)
// =============================================================================

func TestBoost_IAMServiceStub_AllAccessorsReturnNil(t *testing.T) {
	stub := &IAMService{}

	if stub.Client() != nil {
		t.Fatal("expected nil Client()")
	}
	if stub.Tenant() != nil {
		t.Fatal("expected nil Tenant()")
	}
	if stub.User() != nil {
		t.Fatal("expected nil User()")
	}
	if stub.Role() != nil {
		t.Fatal("expected nil Role()")
	}
	if stub.Policy() != nil {
		t.Fatal("expected nil Policy()")
	}
	if stub.PEP() != nil {
		t.Fatal("expected nil PEP()")
	}
	if stub.App() != nil {
		t.Fatal("expected nil App()")
	}
	if stub.Session() != nil {
		t.Fatal("expected nil Session()")
	}
	if stub.Audit() != nil {
		t.Fatal("expected nil Audit()")
	}
	if stub.GDPR() != nil {
		t.Fatal("expected nil GDPR()")
	}
	if stub.Admin() != nil {
		t.Fatal("expected nil Admin()")
	}
}

func TestBoost_IAMServiceStub_CheckAccess_ReturnsError(t *testing.T) {
	stub := &IAMService{}
	_, err := stub.CheckAccess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from CheckAccess")
	}
	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// Managed Service Tests
// =============================================================================

// =============================================================================
// KMS Algorithm Conversion Helper Tests
// =============================================================================

func TestBoost_PbAlgorithmToSDK_AllMappings(t *testing.T) {
	tests := []struct {
		name string
		pb   pb.KeyAlgorithm
		sdk  kms.KeyAlgorithm
	}{
		{"AES256GCM", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, kms.AlgorithmAES256GCM},
		{"ChaCha20", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, kms.AlgorithmChaCha20Poly1305},
		{"RSA2048", pb.KeyAlgorithm_KEY_ALG_RSA_2048, kms.AlgorithmRSA2048},
		{"RSA4096", pb.KeyAlgorithm_KEY_ALG_RSA_4096, kms.AlgorithmRSA4096},
		{"ECDSAP256", pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, kms.AlgorithmECDSAP256},
		{"ECDSAP384", pb.KeyAlgorithm_KEY_ALG_ECDSA_P384, kms.AlgorithmECDSAP384},
		{"ED25519", pb.KeyAlgorithm_KEY_ALG_ED25519, kms.AlgorithmED25519},
		{"default", pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, kms.AlgorithmAES256GCM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pbAlgorithmToSDK(tc.pb)
			if got != tc.sdk {
				t.Fatalf("expected %v, got %v", tc.sdk, got)
			}
		})
	}
}

func TestBoost_SdkAlgorithmToPb_AllMappings(t *testing.T) {
	tests := []struct {
		name string
		sdk  kms.KeyAlgorithm
		pb   pb.KeyAlgorithm
	}{
		{"AES256GCM", kms.AlgorithmAES256GCM, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"ChaCha20", kms.AlgorithmChaCha20Poly1305, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{"RSA2048", kms.AlgorithmRSA2048, pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"RSA4096", kms.AlgorithmRSA4096, pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{"ECDSAP256", kms.AlgorithmECDSAP256, pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"ECDSAP384", kms.AlgorithmECDSAP384, pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{"ED25519", kms.AlgorithmED25519, pb.KeyAlgorithm_KEY_ALG_ED25519},
		{"default", kms.KeyAlgorithm(99), pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sdkAlgorithmToPb(tc.sdk)
			if got != tc.pb {
				t.Fatalf("expected %v, got %v", tc.pb, got)
			}
		})
	}
}

func TestBoost_PbUsagesToSDK_AllMappings(t *testing.T) {
	usages := []pb.KeyUsage{
		pb.KeyUsage_KEY_USAGE_ENCRYPT,
		pb.KeyUsage_KEY_USAGE_DECRYPT,
		pb.KeyUsage_KEY_USAGE_SIGN,
		pb.KeyUsage_KEY_USAGE_VERIFY,
		pb.KeyUsage_KEY_USAGE_WRAP_KEY,
	}

	result := pbUsagesToSDK(usages)
	if len(result) != 5 {
		t.Fatalf("expected 5 usages, got %d", len(result))
	}
	expected := []kms.KeyUsage{
		kms.KeyUsageEncrypt,
		kms.KeyUsageDecrypt,
		kms.KeyUsageSign,
		kms.KeyUsageVerify,
		kms.KeyUsageWrap,
	}
	for i, e := range expected {
		if result[i] != e {
			t.Fatalf("index %d: expected %v, got %v", i, e, result[i])
		}
	}
}

func TestBoost_PbUsagesToSDK_EmptySlice(t *testing.T) {
	result := pbUsagesToSDK(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(result))
	}
}

func TestBoost_PbHashAlgorithmToSDK_AllMappings(t *testing.T) {
	tests := []struct {
		name string
		pb   pb.HashAlgorithm
		sdk  quicbaas.HashAlgorithm
	}{
		{"SHA256", pb.HashAlgorithm_HASH_ALG_SHA256, quicbaas.HashSHA256},
		{"SHA384", pb.HashAlgorithm_HASH_ALG_SHA384, quicbaas.HashSHA384},
		{"SHA512", pb.HashAlgorithm_HASH_ALG_SHA512, quicbaas.HashSHA512},
		{"default", pb.HashAlgorithm_HASH_ALG_UNSPECIFIED, quicbaas.HashSHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pbHashAlgorithmToSDK(tc.pb)
			if got != tc.sdk {
				t.Fatalf("expected %v, got %v", tc.sdk, got)
			}
		})
	}
}
