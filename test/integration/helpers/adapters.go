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

//go:build integration

package helpers

import (
	"context"
	"testing"
)

// Protocol represents a communication protocol type
type Protocol string

const (
	ProtocolREST Protocol = "REST"
	ProtocolGRPC Protocol = "gRPC"
	ProtocolQUIC Protocol = "QUIC"
	ProtocolMCP  Protocol = "MCP"
	ProtocolUnix Protocol = "Unix"
)

// AllProtocols returns all supported protocols
func AllProtocols() []Protocol {
	return []Protocol{
		ProtocolREST,
		ProtocolGRPC,
		ProtocolQUIC,
		ProtocolMCP,
		ProtocolUnix,
	}
}

// ProtocolAdapter defines the interface for protocol-specific adapters
// Each service should implement this interface for each protocol
type ProtocolAdapter interface {
	// Name returns the protocol name
	Name() string

	// Setup initializes the protocol client
	Setup(t *testing.T, ctx context.Context) error

	// Teardown cleans up resources
	Teardown(t *testing.T) error

	// IsAvailable checks if the protocol is available
	IsAvailable(ctx context.Context) bool
}

// TestRunner runs tests across multiple protocols
type TestRunner struct {
	adapters []ProtocolAdapter
}

// NewTestRunner creates a new multi-protocol test runner
func NewTestRunner(adapters ...ProtocolAdapter) *TestRunner {
	return &TestRunner{adapters: adapters}
}

// RunAll runs a test function across all configured protocols
func (r *TestRunner) RunAll(t *testing.T, ctx context.Context, name string, testFn func(t *testing.T, adapter ProtocolAdapter)) {
	t.Helper()

	for _, adapter := range r.adapters {
		adapter := adapter // capture for closure
		t.Run(name+"/"+adapter.Name(), func(t *testing.T) {
			if !adapter.IsAvailable(ctx) {
				t.Skipf("%s protocol not available", adapter.Name())
				return
			}

			if err := adapter.Setup(t, ctx); err != nil {
				t.Skipf("Failed to setup %s: %v", adapter.Name(), err)
				return
			}
			defer func() {
				if err := adapter.Teardown(t); err != nil {
					t.Logf("Warning: %s teardown failed: %v", adapter.Name(), err)
				}
			}()

			testFn(t, adapter)
		})
	}
}

// RunProtocol runs a test function for a specific protocol
func (r *TestRunner) RunProtocol(t *testing.T, ctx context.Context, protocol Protocol, testFn func(t *testing.T, adapter ProtocolAdapter)) {
	t.Helper()

	for _, adapter := range r.adapters {
		if Protocol(adapter.Name()) != protocol {
			continue
		}

		if !adapter.IsAvailable(ctx) {
			t.Skipf("%s protocol not available", adapter.Name())
			return
		}

		if err := adapter.Setup(t, ctx); err != nil {
			t.Fatalf("Failed to setup %s: %v", adapter.Name(), err)
		}
		defer func() {
			if err := adapter.Teardown(t); err != nil {
				t.Logf("Warning: %s teardown failed: %v", adapter.Name(), err)
			}
		}()

		testFn(t, adapter)
		return
	}

	t.Fatalf("No adapter found for protocol: %s", protocol)
}

// BaseAdapter provides common adapter functionality
type BaseAdapter struct {
	protocol Protocol
	endpoint string
}

// NewBaseAdapter creates a new base adapter
func NewBaseAdapter(protocol Protocol, endpoint string) *BaseAdapter {
	return &BaseAdapter{
		protocol: protocol,
		endpoint: endpoint,
	}
}

// Name returns the protocol name
func (a *BaseAdapter) Name() string {
	return string(a.protocol)
}

// Endpoint returns the configured endpoint
func (a *BaseAdapter) Endpoint() string {
	return a.endpoint
}

// Setup is a no-op base implementation
func (a *BaseAdapter) Setup(t *testing.T, ctx context.Context) error {
	return nil
}

// Teardown is a no-op base implementation
func (a *BaseAdapter) Teardown(t *testing.T) error {
	return nil
}

// IsAvailable checks basic endpoint availability
func (a *BaseAdapter) IsAvailable(ctx context.Context) bool {
	return true
}

// TestContext holds test configuration and state
type TestContext struct {
	T         *testing.T
	Ctx       context.Context
	Endpoints *EndpointConfig
}

// NewTestContext creates a new test context
func NewTestContext(t *testing.T, ctx context.Context) *TestContext {
	return &TestContext{
		T:         t,
		Ctx:       ctx,
		Endpoints: GetEndpointConfig(),
	}
}

// UniqueID generates a unique identifier for test resources
func UniqueID(prefix string) string {
	return GenerateUniqueID(prefix)
}
