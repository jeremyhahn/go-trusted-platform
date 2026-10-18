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

package quic

import (
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestAppServiceMethodsRouteToTheirCategory pins the QUIC wire contract:
// every CacheService, SchedulerService and MessagingService method reaches
// its category opcode with its own sub-opcode and carries its request body.
func TestAppServiceMethodsRouteToTheirCategory(t *testing.T) {
	services := []struct {
		desc     grpc.ServiceDesc
		category byte
	}{
		{platformv1.CacheService_ServiceDesc, quicwire.OpCacheCategory},
		{platformv1.SchedulerService_ServiceDesc, quicwire.OpSchedulerCategory},
		{platformv1.MessagingService_ServiceDesc, quicwire.OpMessagingCategory},
		{platformv1.ObjectStorageService_ServiceDesc, quicwire.OpObjectStorageCategory},
	}
	for _, service := range services {
		if _, isCategory := categoryOpcodes[service.category]; !isCategory {
			t.Fatalf("0x%02x is not registered as a category opcode", service.category)
		}
		seen := make(map[byte]string)
		for _, m := range service.desc.Methods {
			method := "/" + service.desc.ServiceName + "/" + m.MethodName
			t.Run(method, func(t *testing.T) {
				if opcode := grpcMethodToOpcodeMap[method]; opcode != service.category {
					t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, service.category)
				}
				sub, ok := categorySubOpcodeMap[method]
				if !ok {
					t.Fatal("no sub-opcode mapped")
				}
				if other, taken := seen[sub]; taken {
					t.Fatalf("sub-opcode 0x%02x is shared with %s", sub, other)
				}
				seen[sub] = method
				if _, empty := categoryEmptyBodyMethods[method]; empty {
					t.Fatalf("%s carries a request body and must not be marked empty-bodied", method)
				}
			})
		}
	}
}

// TestAppServiceSubOpcodesCoverOnlyServedMethods refuses a wire entry for a
// method the generated services do not declare.
func TestAppServiceSubOpcodesCoverOnlyServedMethods(t *testing.T) {
	declared := make(map[string]bool)
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
		platformv1.ObjectStorageService_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			declared["/"+desc.ServiceName+"/"+m.MethodName] = true
		}
	}
	for method := range appServiceSubOpcodes {
		if !declared[method] {
			t.Errorf("%s is mapped but not declared by any application service", method)
		}
	}
	if len(appServiceSubOpcodes) != len(declared) {
		t.Fatalf("wire table maps %d methods, the services declare %d", len(appServiceSubOpcodes), len(declared))
	}
}

func TestAppServiceCategoryPayloadCarriesTheRequest(t *testing.T) {
	request := &platformv1.GetSchedulerJobRequest{JobId: "42"}
	payload, err := buildCategoryPayload(quicwire.SchedulerSubGetJob, request)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if payload[0] != quicwire.SchedulerSubGetJob {
		t.Fatalf("payload[0] = 0x%02x, want 0x%02x", payload[0], quicwire.SchedulerSubGetJob)
	}

	var decoded platformv1.GetSchedulerJobRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetJobId() != "42" {
		t.Fatalf("decoded = %v, want the original request", &decoded)
	}
}
