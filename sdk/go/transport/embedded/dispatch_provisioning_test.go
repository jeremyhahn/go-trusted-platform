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

package embedded

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// testConfigDeliveryServer overrides GetNonce so a real in-process dispatch
// round-trip can be asserted; every other RPC inherits the generated
// Unimplemented behavior.
type testConfigDeliveryServer struct {
	platformv1.UnimplementedConfigDeliveryServiceServer
}

func (s *testConfigDeliveryServer) GetNonce(ctx context.Context, req *platformv1.GetNonceRequest) (*platformv1.GetNonceResponse, error) {
	return &platformv1.GetNonceResponse{Nonce: "embedded-nonce"}, nil
}

// configDeliveryMethodNames lists every ConfigDeliveryService full method
// the embedded dispatcher must register.
var configDeliveryMethodNames = []string{
	platformv1.ConfigDeliveryService_GetNonce_FullMethodName,
	platformv1.ConfigDeliveryService_FetchConfig_FullMethodName,
	platformv1.ConfigDeliveryService_SignDigest_FullMethodName,
	platformv1.ConfigDeliveryService_PollSession_FullMethodName,
	platformv1.ConfigDeliveryService_FulfillSession_FullMethodName,
	platformv1.ConfigDeliveryService_ListSessions_FullMethodName,
	platformv1.ConfigDeliveryService_GetSession_FullMethodName,
}

// TestBuildHandlerMap_ConfigDeliveryRegistered verifies all seven
// ConfigDeliveryService handlers are registered when the service is present.
func TestBuildHandlerMap_ConfigDeliveryRegistered(t *testing.T) {
	registry := &ServiceRegistry{
		ConfigDelivery: &testConfigDeliveryServer{},
	}
	m := buildHandlerMap(registry)

	for _, method := range configDeliveryMethodNames {
		if _, ok := m[method]; !ok {
			t.Errorf("handler for %s not registered", method)
		}
	}
}

// TestBuildHandlerMap_ConfigDeliveryNil verifies no ConfigDeliveryService
// handlers are registered when the service is absent from the registry.
func TestBuildHandlerMap_ConfigDeliveryNil(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{})

	for _, method := range configDeliveryMethodNames {
		if _, ok := m[method]; ok {
			t.Errorf("handler for %s registered despite nil service", method)
		}
	}
}

// TestDispatch_ConfigDeliveryGetNonce round-trips a GetNonce call through
// the embedded dispatcher.
func TestDispatch_ConfigDeliveryGetNonce(t *testing.T) {
	registry := &ServiceRegistry{
		ConfigDelivery: &testConfigDeliveryServer{},
	}
	m := buildHandlerMap(registry)

	handler, ok := m[platformv1.ConfigDeliveryService_GetNonce_FullMethodName]
	if !ok {
		t.Fatal("expected GetNonce handler to be registered")
	}

	resp, err := handler(context.Background(), &platformv1.GetNonceRequest{})
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}
	nonceResp, ok := resp.(*platformv1.GetNonceResponse)
	if !ok {
		t.Fatalf("expected *GetNonceResponse, got %T", resp)
	}
	if nonceResp.GetNonce() != "embedded-nonce" {
		t.Errorf("nonce = %q, want embedded-nonce", nonceResp.GetNonce())
	}
}

// TestDispatch_ConfigDeliveryUnimplemented verifies the Unimplemented
// fallback errors flow through the dispatcher unchanged (error-path guard
// for every remaining RPC).
func TestDispatch_ConfigDeliveryUnimplemented(t *testing.T) {
	registry := &ServiceRegistry{
		ConfigDelivery: &testConfigDeliveryServer{},
	}
	m := buildHandlerMap(registry)

	handler := m[platformv1.ConfigDeliveryService_FetchConfig_FullMethodName]
	if handler == nil {
		t.Fatal("expected FetchConfig handler to be registered")
	}
	if _, err := handler(context.Background(), &platformv1.FetchConfigRequest{}); err == nil {
		t.Fatal("expected Unimplemented error from stub FetchConfig")
	}
}
