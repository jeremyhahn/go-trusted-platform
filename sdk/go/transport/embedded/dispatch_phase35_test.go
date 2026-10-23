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
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// statusCeremonyServer answers Status so a full adapter round trip can be
// asserted; every other RPC keeps the generated Unimplemented behaviour,
// whose message names the method that was reached.
type statusCeremonyServer struct {
	platformv1.UnimplementedCeremonyServiceServer
}

func (statusCeremonyServer) Status(context.Context, *platformv1.CeremonyStatusRequest) (*platformv1.CeremonyStatusResponse, error) {
	return &platformv1.CeremonyStatusResponse{CeremonyId: "embedded-ceremony"}, nil
}

// phase35Services pairs each service's generated descriptor with an
// Unimplemented server, registered the way production fills the registry.
func phase35Services() (*ServiceRegistry, []grpc.ServiceDesc, []any) {
	ceremony := statusCeremonyServer{}
	piv := platformv1.UnimplementedPIVServiceServer{}
	fido := platformv1.UnimplementedFIDO2ServiceServer{}
	bmc := platformv1.UnimplementedBMCServiceServer{}
	ntp := platformv1.UnimplementedNTPServiceServer{}
	luks := platformv1.UnimplementedLUKSServiceServer{}
	sw := platformv1.UnimplementedSwitchServiceServer{}
	reg := &ServiceRegistry{Ceremony: ceremony, PIV: piv, FIDO2: fido, BMC: bmc, NTP: ntp, LUKS: luks, Switch: sw}
	descs := []grpc.ServiceDesc{
		platformv1.CeremonyService_ServiceDesc,
		platformv1.PIVService_ServiceDesc,
		platformv1.FIDO2Service_ServiceDesc,
		platformv1.BMCService_ServiceDesc,
		platformv1.NTPService_ServiceDesc,
		platformv1.LUKSService_ServiceDesc,
		platformv1.SwitchService_ServiceDesc,
	}
	return reg, descs, []any{ceremony, piv, fido, bmc, ntp, luks, sw}
}

// requestTypeOf asks the generated gRPC handler which request message the
// method decodes, so the test needs no hand-kept request table.
func requestTypeOf(t *testing.T, md grpc.MethodDesc, srv any) any {
	t.Helper()
	var req any
	dec := func(v any) error {
		req = v
		return nil
	}
	if _, err := md.Handler(srv, context.Background(), dec, nil); err == nil && req == nil {
		t.Fatalf("%s: generated handler decoded no request", md.MethodName)
	}
	return req
}

// TestBuildHandlerMap_Phase35EveryMethodReachesItsServer drives every
// ceremony, PIV, FIDO2, BMC, NTP, LUKS and Switch method in the generated service descriptors
// through the embedded dispatcher and asserts it lands on the server method
// of the same name.
func TestBuildHandlerMap_Phase35EveryMethodReachesItsServer(t *testing.T) {
	reg, descs, servers := phase35Services()
	m := buildHandlerMap(reg)

	for i, desc := range descs {
		for _, md := range desc.Methods {
			full := "/" + desc.ServiceName + "/" + md.MethodName
			t.Run(full, func(t *testing.T) {
				handler, ok := m[full]
				if !ok {
					t.Fatalf("%s is not registered", full)
				}
				_, err := handler(context.Background(), requestTypeOf(t, md, servers[i]))
				if full == platformv1.CeremonyService_Status_FullMethodName {
					if err != nil {
						t.Fatalf("Status: %v", err)
					}
					return
				}
				st, _ := status.FromError(err)
				if st.Code() != codes.Unimplemented || !strings.Contains(st.Message(), "method "+md.MethodName+" ") {
					t.Errorf("%s reached %v, want the server's %s", full, err, md.MethodName)
				}
			})
		}
	}
}

func TestBuildHandlerMap_Phase35NilServicesRegisterNothing(t *testing.T) {
	_, descs, _ := phase35Services()
	m := buildHandlerMap(&ServiceRegistry{})

	for _, desc := range descs {
		for _, md := range desc.Methods {
			if _, ok := m["/"+desc.ServiceName+"/"+md.MethodName]; ok {
				t.Errorf("%s/%s registered without a service", desc.ServiceName, md.MethodName)
			}
		}
	}
}

// TestAdapter_CeremonyStatusRoundTrip invokes through the embedded
// connection, the path the SDK client takes.
func TestAdapter_CeremonyStatusRoundTrip(t *testing.T) {
	reg, _, _ := phase35Services()
	a, err := New(reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reply := &platformv1.CeremonyStatusResponse{}

	if err := a.Connection().Invoke(context.Background(), platformv1.CeremonyService_Status_FullMethodName, &platformv1.CeremonyStatusRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if reply.GetCeremonyId() != "embedded-ceremony" {
		t.Errorf("ceremony id = %q", reply.GetCeremonyId())
	}
}
