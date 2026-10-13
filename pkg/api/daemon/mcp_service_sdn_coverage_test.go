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
	"log/slog"
	"testing"
)

// =============================================================================
// SDNListBridges Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_returns_error",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			result, err := provider.SDNListBridges(ctx)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}
			if result != nil {
				t.Error("expected nil result for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNListFlows Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_bridge",
			bridgeName:     "br0",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_bridge",
			bridgeName:     "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_special_chars",
			bridgeName:     "bridge-with-dashes",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			result, err := provider.SDNListFlows(ctx, tc.bridgeName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}
			if result != nil {
				t.Error("expected nil result for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNGetPortState Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		portName       string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_params",
			bridgeName:     "br0",
			portName:       "port1",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_bridge",
			bridgeName:     "",
			portName:       "port1",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_port",
			bridgeName:     "br0",
			portName:       "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_both_empty",
			bridgeName:     "",
			portName:       "",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			result, err := provider.SDNGetPortState(ctx, tc.bridgeName, tc.portName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}
			if result != nil {
				t.Error("expected nil result for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNAddFlow Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNAddFlow_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		flow           map[string]interface{}
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_params",
			bridgeName:     "br0",
			flow:           map[string]interface{}{"priority": 100},
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_flow",
			bridgeName:     "br0",
			flow:           map[string]interface{}{},
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_nil_flow",
			bridgeName:     "br0",
			flow:           nil,
			expectedErrSvc: "sdn",
		},
		{
			name:       "nil_sdn_service_with_complex_flow",
			bridgeName: "test-bridge",
			flow: map[string]interface{}{
				"priority":  200,
				"match":     "in_port=1",
				"actions":   "output:2",
				"table_id":  0,
				"idle_time": 300,
			},
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNAddFlow(ctx, tc.bridgeName, tc.flow)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNCreateBridge Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNCreateBridge_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_name",
			bridgeName:     "br0",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_name",
			bridgeName:     "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_long_name",
			bridgeName:     "my-very-long-bridge-name-for-testing",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNCreateBridge(ctx, tc.bridgeName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNDeleteBridge Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNDeleteBridge_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_name",
			bridgeName:     "br0",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_name",
			bridgeName:     "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_special_chars",
			bridgeName:     "bridge_123",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNDeleteBridge(ctx, tc.bridgeName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNAddPort Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNAddPort_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		portName       string
		portType       string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_params",
			bridgeName:     "br0",
			portName:       "eth0",
			portType:       "internal",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_bridge",
			bridgeName:     "",
			portName:       "eth0",
			portType:       "internal",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_port",
			bridgeName:     "br0",
			portName:       "",
			portType:       "internal",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_type",
			bridgeName:     "br0",
			portName:       "eth0",
			portType:       "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_all_empty",
			bridgeName:     "",
			portName:       "",
			portType:       "",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNAddPort(ctx, tc.bridgeName, tc.portName, tc.portType)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNDeletePort Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNDeletePort_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		portName       string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_params",
			bridgeName:     "br0",
			portName:       "eth0",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_bridge",
			bridgeName:     "",
			portName:       "eth0",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_port",
			bridgeName:     "br0",
			portName:       "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_both_empty",
			bridgeName:     "",
			portName:       "",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNDeletePort(ctx, tc.bridgeName, tc.portName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNDeleteFlow Tests - Extended Table-Driven Coverage
// =============================================================================

func TestMCPServiceProvider_SDNDeleteFlow_NilServiceTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		flowID         string
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_with_valid_params",
			bridgeName:     "br0",
			flowID:         "flow-1",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_bridge",
			bridgeName:     "",
			flowID:         "flow-1",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_empty_flow_id",
			bridgeName:     "br0",
			flowID:         "",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_numeric_flow_id",
			bridgeName:     "br0",
			flowID:         "12345",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_sdn_service_with_uuid_flow_id",
			bridgeName:     "test-bridge",
			flowID:         "550e8400-e29b-41d4-a716-446655440000",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			err := provider.SDNDeleteFlow(ctx, tc.bridgeName, tc.flowID)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// Error Message Tests - Comprehensive Coverage
// =============================================================================

func TestMCPServiceProvider_SDN_NilService_ErrorMessages(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: nil,
		Logger:     slog.Default(),
	})

	testCases := []struct {
		name        string
		operation   string
		callFunc    func() error
		expectedMsg string
	}{
		{
			name:      "SDNListBridges_error_message",
			operation: "SDNListBridges",
			callFunc: func() error {
				_, err := provider.SDNListBridges(ctx)
				return err
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNListFlows_error_message",
			operation: "SDNListFlows",
			callFunc: func() error {
				_, err := provider.SDNListFlows(ctx, "br0")
				return err
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNListPolicies_error_message",
			operation: "SDNListPolicies",
			callFunc: func() error {
				_, err := provider.SDNListPolicies(ctx, "", "")
				return err
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNGetPortState_error_message",
			operation: "SDNGetPortState",
			callFunc: func() error {
				_, err := provider.SDNGetPortState(ctx, "br0", "port1")
				return err
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNAddFlow_error_message",
			operation: "SDNAddFlow",
			callFunc: func() error {
				return provider.SDNAddFlow(ctx, "br0", nil)
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNCreateBridge_error_message",
			operation: "SDNCreateBridge",
			callFunc: func() error {
				return provider.SDNCreateBridge(ctx, "br0")
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNDeleteBridge_error_message",
			operation: "SDNDeleteBridge",
			callFunc: func() error {
				return provider.SDNDeleteBridge(ctx, "br0")
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNAddPort_error_message",
			operation: "SDNAddPort",
			callFunc: func() error {
				return provider.SDNAddPort(ctx, "br0", "eth0", "internal")
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNDeletePort_error_message",
			operation: "SDNDeletePort",
			callFunc: func() error {
				return provider.SDNDeletePort(ctx, "br0", "eth0")
			},
			expectedMsg: "service not available: sdn",
		},
		{
			name:      "SDNDeleteFlow_error_message",
			operation: "SDNDeleteFlow",
			callFunc: func() error {
				return provider.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
			expectedMsg: "service not available: sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.callFunc()
			if err == nil {
				t.Fatalf("%s: expected error but got nil", tc.operation)
			}

			errMsg := err.Error()
			if errMsg != tc.expectedMsg {
				t.Errorf("%s: expected error message %q, got %q", tc.operation, tc.expectedMsg, errMsg)
			}
		})
	}
}

// =============================================================================
// Context Cancellation Tests - Comprehensive Coverage
// =============================================================================

func TestMCPServiceProvider_SDN_NilService_WithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: nil,
		Logger:     slog.Default(),
	})

	// The nil service check should happen before context is used,
	// so we should still get ErrServiceNotAvailable
	testCases := []struct {
		name     string
		callFunc func() error
	}{
		{
			name: "SDNListBridges_with_cancelled_context",
			callFunc: func() error {
				_, err := provider.SDNListBridges(ctx)
				return err
			},
		},
		{
			name: "SDNListFlows_with_cancelled_context",
			callFunc: func() error {
				_, err := provider.SDNListFlows(ctx, "br0")
				return err
			},
		},
		{
			name: "SDNGetPortState_with_cancelled_context",
			callFunc: func() error {
				_, err := provider.SDNGetPortState(ctx, "br0", "port1")
				return err
			},
		},
		{
			name: "SDNAddFlow_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNAddFlow(ctx, "br0", nil)
			},
		},
		{
			name: "SDNCreateBridge_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNCreateBridge(ctx, "br0")
			},
		},
		{
			name: "SDNDeleteBridge_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNDeleteBridge(ctx, "br0")
			},
		},
		{
			name: "SDNAddPort_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNAddPort(ctx, "br0", "eth0", "internal")
			},
		},
		{
			name: "SDNDeletePort_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNDeletePort(ctx, "br0", "eth0")
			},
		},
		{
			name: "SDNDeleteFlow_with_cancelled_context",
			callFunc: func() error {
				return provider.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.callFunc()
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			// Should be ErrServiceNotAvailable, not context.Canceled
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}
