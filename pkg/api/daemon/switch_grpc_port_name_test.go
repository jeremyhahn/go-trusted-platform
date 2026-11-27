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
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestSwitchGRPCService_RejectsUnsafePortName pins that the servicer QUIC
// and MCP share refuses a port name that is not one interface identifier as
// InvalidArgument before any switch manager is looked up, so CLI separators
// and control characters never reach the switch command path.
func TestSwitchGRPCService_RejectsUnsafePortName(t *testing.T) {
	ctx := context.Background()
	for _, port := range []string{"eth1; show running-config", "eth1\nshow", "eth1|include x"} {
		svc := newFakeSwitchService()
		s := NewSwitchGRPCService(logging.DefaultLogger(), svc)

		ops := map[string]func() error{
			"GetPortStatus": func() error {
				_, err := s.GetPortStatus(ctx, &platformv1.GetSwitchPortStatusRequest{SwitchName: "core-1", PortName: port})
				return err
			},
			"SetPortVLAN": func() error {
				_, err := s.SetPortVLAN(ctx, &platformv1.SetSwitchPortVLANRequest{SwitchName: "core-1", PortName: port, VlanId: 20})
				return err
			},
			"EnablePort": func() error {
				_, err := s.EnablePort(ctx, &platformv1.EnableSwitchPortRequest{SwitchName: "core-1", PortName: port})
				return err
			},
			"DisablePort": func() error {
				_, err := s.DisablePort(ctx, &platformv1.DisableSwitchPortRequest{SwitchName: "core-1", PortName: port})
				return err
			},
		}
		for name, op := range ops {
			err := op()
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "%s(%q): %v", name, port, err)
		}
		assert.Zero(t, svc.lookups(), "port %q: a refused call looked up a switch manager", port)
		calls, _ := svc.managers["core-1"].snapshot()
		assert.Empty(t, calls, "port %q: a refused call reached the switch manager", port)
	}
}
