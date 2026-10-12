// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"context"
	"errors"
	"testing"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// TestDeviceBootMCPMapping verifies the two diskless-boot RPCs map to the
// server tools of the same purpose.
func TestDeviceBootMCPMapping(t *testing.T) {
	want := map[string]string{
		platformv1.DeviceService_BootCertificate_FullMethodName: "device_boot_certificate",
		platformv1.DeviceService_BootDelivery_FullMethodName:    "device_boot_delivery",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s = %q, want %q", method, got, tool)
		}
	}
}

// TestDeviceBootMCPRefusesChannelBinding verifies a boot call bound to its
// channel is refused with the typed error before anything is sent: MCP has
// no TLS connection whose exporter a proof could be bound to, so the proof
// callback is never run.
func TestDeviceBootMCPRefusesChannelBinding(t *testing.T) {
	conn := &mcpClientConn{adapter: &Adapter{}}
	called := false
	bind := transport.WithChannelBinding(func(context.Context, []byte) error {
		called = true
		return nil
	})

	for _, method := range []string{
		platformv1.DeviceService_BootCertificate_FullMethodName,
		platformv1.DeviceService_BootDelivery_FullMethodName,
	} {
		err := conn.Invoke(context.Background(), method, &platformv1.BootDeliveryRequest{}, &platformv1.BootDeliveryResponse{}, bind)

		var unavailable *transport.ErrChannelBindingUnavailable
		if !errors.As(err, &unavailable) {
			t.Fatalf("%s: err = %v, want ErrChannelBindingUnavailable", method, err)
		}
		if unavailable.Transport != platform.ProtocolMCP.String() {
			t.Errorf("%s: transport = %q, want %q", method, unavailable.Transport, platform.ProtocolMCP.String())
		}
	}
	if called {
		t.Error("the proof callback ran on a transport with no connection to bind to")
	}
}

// TestDeviceBootMCPUnboundCallsPassThrough verifies only bound calls are
// refused: an ordinary call on a disconnected adapter fails for being
// disconnected, not for channel binding.
func TestDeviceBootMCPUnboundCallsPassThrough(t *testing.T) {
	conn := &mcpClientConn{adapter: &Adapter{}}

	err := conn.Invoke(context.Background(), platformv1.DeviceService_ListDevices_FullMethodName,
		&platformv1.ListDevicesRequest{}, &platformv1.ListDevicesResponse{})

	var unavailable *transport.ErrChannelBindingUnavailable
	if err == nil || errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want a disconnected-adapter error", err)
	}
}
