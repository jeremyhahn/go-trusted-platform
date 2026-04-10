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

//go:build codec_msgpack

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Mock Health Registry for QUIC Testing
// =============================================================================

type quicMockHealthRegistry struct {
	checkResult health.SystemHealth
}

func (m *quicMockHealthRegistry) Register(checker health.HealthChecker) error {
	return nil
}

func (m *quicMockHealthRegistry) Unregister(name string) error {
	return nil
}

func (m *quicMockHealthRegistry) Check(ctx context.Context) health.SystemHealth {
	return m.checkResult
}

func (m *quicMockHealthRegistry) CheckComponent(ctx context.Context, name string) (health.ComponentHealth, error) {
	return health.ComponentHealth{}, nil
}

func (m *quicMockHealthRegistry) List() []string {
	return []string{}
}

func (m *quicMockHealthRegistry) Count() int {
	return 0
}

func (m *quicMockHealthRegistry) Close() error {
	return nil
}

// Compile-time assertion
var _ health.Registry = (*quicMockHealthRegistry)(nil)

// TestWithQUICDeviceService tests the WithQUICDeviceService option
func TestWithQUICDeviceService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Test with nil service
	handler := NewQUICServiceHandler(logger, WithQUICDeviceService(nil))
	if handler.deviceService != nil {
		t.Error("expected deviceService to be nil")
	}
}

// TestWithQUICDeviceProfileService tests the WithQUICDeviceProfileService option
func TestWithQUICDeviceProfileService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Test with nil service
	handler := NewQUICServiceHandler(logger, WithQUICDeviceProfileService(nil))
	if handler.profileService != nil {
		t.Error("expected profileService to be nil")
	}
}

// TestWithQUICSDNService tests the WithQUICSDNService option
func TestWithQUICSDNService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Test with nil client
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(nil))
	if handler.sdnService != nil {
		t.Error("expected sdnClient to be nil")
	}
}

// TestHandleDevice_NoDeviceService tests handleDevice when device service is not set
func TestHandleDevice_NoDeviceService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger) // No device service

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  0x30, // Arbitrary opcode for device
		Payload: []byte{},
	}

	resp := handler.handleDevice(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusUnavailable {
		t.Errorf("expected status %d, got %d", quic.StatusUnavailable, resp.Status)
	}
}

// TestHandleDeviceOperation tests handleDeviceOperation routes known opcodes
func TestHandleDeviceOperation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	t.Run("unknown opcode returns not implemented", func(t *testing.T) {
		req := &quic.Request{
			Opcode:  0xFF, // Unknown opcode
			Payload: []byte{},
		}
		resp := handler.handleDeviceOperation(ctx, req)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Status != quic.StatusNotImplemented {
			t.Errorf("expected status %d, got %d", quic.StatusNotImplemented, resp.Status)
		}
	})

	t.Run("valid opcode without device service returns error", func(t *testing.T) {
		req := &quic.Request{
			Opcode:  quic.OpDeviceRegister,
			Payload: []byte{},
		}
		// No device service set, so handleDeviceRegister will fail on decode
		resp := handler.handleDeviceOperation(ctx, req)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		// Should return an error status (invalid request due to empty payload decode)
		if resp.Status == quic.StatusOK {
			t.Error("expected non-OK status for empty payload on register")
		}
	})
}

// TestNewQUICServiceHandler_MultipleOptions tests creating handler with multiple options
func TestNewQUICServiceHandler_MultipleOptions(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	handler := NewQUICServiceHandler(logger,
		WithQUICDeviceService(nil),
		WithQUICDeviceProfileService(nil),
		WithQUICSDNService(nil),
	)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

// TestNewQUICServiceHandler_NilLogger tests creating handler with nil logger
func TestNewQUICServiceHandler_NilLogger(t *testing.T) {
	// Should use default logger when nil is passed
	handler := NewQUICServiceHandler(nil)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.logger == nil {
		t.Error("expected logger to be set to default")
	}
}

// =============================================================================
// Health Handler Tests
// =============================================================================

// TestHandleHealthCheck_NoRegistry tests handleHealthCheck when health registry is nil
func TestHandleHealthCheck_NoRegistry(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpHealth,
		Payload: []byte{},
	}

	resp := handler.handleHealthCheck(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleHealthCheck_WithHealthyRegistry tests handleHealthCheck with a healthy registry
func TestHandleHealthCheck_WithHealthyRegistry(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockRegistry := &quicMockHealthRegistry{
		checkResult: health.SystemHealth{
			Status: health.StatusHealthy,
			Components: []health.ComponentHealth{
				{Name: "test-component", Status: health.StatusHealthy},
			},
		},
	}
	handler := NewQUICServiceHandler(logger, WithQUICHealthRegistry(mockRegistry))

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpHealth,
		Payload: []byte{},
	}

	resp := handler.handleHealthCheck(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleHealthCheck_WithUnhealthyRegistry tests handleHealthCheck with an unhealthy registry
func TestHandleHealthCheck_WithUnhealthyRegistry(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockRegistry := &quicMockHealthRegistry{
		checkResult: health.SystemHealth{
			Status: health.StatusUnhealthy,
			Components: []health.ComponentHealth{
				{Name: "test-component", Status: health.StatusUnhealthy},
			},
		},
	}
	handler := NewQUICServiceHandler(logger, WithQUICHealthRegistry(mockRegistry))

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpHealth,
		Payload: []byte{},
	}

	resp := handler.handleHealthCheck(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleHealthCheck_WithMixedComponents tests handleHealthCheck with mixed healthy/unhealthy components
func TestHandleHealthCheck_WithMixedComponents(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockRegistry := &quicMockHealthRegistry{
		checkResult: health.SystemHealth{
			Status: health.StatusDegraded,
			Components: []health.ComponentHealth{
				{Name: "healthy-component", Status: health.StatusHealthy},
				{Name: "unhealthy-component", Status: health.StatusUnhealthy},
			},
		},
	}
	handler := NewQUICServiceHandler(logger, WithQUICHealthRegistry(mockRegistry))

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpHealth,
		Payload: []byte{},
	}

	resp := handler.handleHealthCheck(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleLiveness tests handleLiveness returns alive status
func TestHandleLiveness(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpLiveness,
		Payload: []byte{},
	}

	resp := handler.handleLiveness(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleReadiness_NoServices tests handleReadiness when no services are set
func TestHandleReadiness_NoServices(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpReadiness,
		Payload: []byte{},
	}

	resp := handler.handleReadiness(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleHealth_ViaHandleRequest tests health via HandleRequest router
func TestHandleHealth_ViaHandleRequest(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpHealth,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleLiveness_ViaHandleRequest tests liveness via HandleRequest router
func TestHandleLiveness_ViaHandleRequest(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpLiveness,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleReadiness_ViaHandleRequest tests readiness via HandleRequest router
func TestHandleReadiness_ViaHandleRequest(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpReadiness,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status %d, got %d", quic.StatusOK, resp.Status)
	}
}

// TestHandleCertificate_NilHandler tests handleCertificate when caHandler is nil
func TestHandleCertificate_NilHandler(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpCertIssue, // Certificate category opcode
		Payload: []byte{},
	}

	resp := handler.handleCertificate(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusUnavailable {
		t.Errorf("expected status %d, got %d", quic.StatusUnavailable, resp.Status)
	}
}

// TestHandleCA_NilCAService tests handleCA when caHandler is nil
func TestHandleCA_NilCAService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpCAInfo, // CA info opcode
		Payload: []byte{},
	}

	resp := handler.handleCA(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusUnavailable {
		t.Errorf("expected status %d, got %d", quic.StatusUnavailable, resp.Status)
	}
}

// TestHandleUnknownOpcode tests HandleRequest with an unknown opcode
func TestHandleUnknownOpcode(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	req := &quic.Request{
		Opcode:  0xFE, // Unknown opcode (Container Stop is 0xFE but without service it returns Unavailable)
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// When no container service is configured, container opcodes return Unavailable
	if resp.Status != quic.StatusUnavailable && resp.Status != quic.StatusNotImplemented {
		t.Errorf("expected status Unavailable or NotImplemented, got %d", resp.Status)
	}
}

// TestHandleRequest_NilRequest tests HandleRequest with nil request
func TestHandleRequest_NilRequest(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()
	resp := handler.HandleRequest(ctx, nil)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status %d, got %d", quic.StatusInvalidRequest, resp.Status)
	}
}
