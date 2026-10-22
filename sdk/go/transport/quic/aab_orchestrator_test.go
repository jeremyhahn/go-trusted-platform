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

package quic

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// orchestratorMethods pins the wire value of every OrchestratorService RPC,
// so a renumbered sub-opcode fails here before it breaks deployed clients.
var orchestratorMethods = map[string]byte{
	platformv1.OrchestratorService_Health_FullMethodName:       0x01,
	platformv1.OrchestratorService_ListAgents_FullMethodName:   0x02,
	platformv1.OrchestratorService_GetAgent_FullMethodName:     0x03,
	platformv1.OrchestratorService_DisableAgent_FullMethodName: 0x04,
	platformv1.OrchestratorService_EnableAgent_FullMethodName:  0x05,
	platformv1.OrchestratorService_ListSessions_FullMethodName: 0x06,
	platformv1.OrchestratorService_CloseSession_FullMethodName: 0x07,
	platformv1.OrchestratorService_ListJobs_FullMethodName:     0x08,
	platformv1.OrchestratorService_GetJob_FullMethodName:       0x09,
	platformv1.OrchestratorService_CancelJob_FullMethodName:    0x0A,
}

func TestOrchestratorMethodsRouteToTheCategoryOpcode(t *testing.T) {
	if quicwire.OpOrchestratorCategory != 0x66 {
		t.Fatalf("OpOrchestratorCategory = 0x%02x, want 0x66", quicwire.OpOrchestratorCategory)
	}
	if _, isCategory := categoryOpcodes[quicwire.OpOrchestratorCategory]; !isCategory {
		t.Fatal("OpOrchestratorCategory is not registered as a category opcode")
	}
	if len(platformv1.OrchestratorService_ServiceDesc.Methods) != len(orchestratorMethods) {
		t.Fatalf("OrchestratorService has %d methods, the wire table pins %d",
			len(platformv1.OrchestratorService_ServiceDesc.Methods), len(orchestratorMethods))
	}

	for method, wantSub := range orchestratorMethods {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpOrchestratorCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpOrchestratorCategory)
			}
			if sub, ok := categorySubOpcodeMap[method]; !ok || sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x (mapped %t), want 0x%02x", sub, ok, wantSub)
			}
			if _, empty := categoryEmptyBodyMethods[method]; empty {
				t.Fatalf("%s carries a request body and must not be marked empty-bodied", method)
			}
		})
	}
}

func TestOrchestratorCategoryPayloadCarriesTheRequest(t *testing.T) {
	request := &platformv1.ListOrchestratorJobsRequest{
		TenantId: "acme",
		Statuses: []string{"running"},
		Page:     &platformv1.OrchestratorPage{Limit: 20, Offset: 40},
	}
	payload, err := buildCategoryPayload(quicwire.OrchestratorSubListJobs, request)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if payload[0] != quicwire.OrchestratorSubListJobs {
		t.Fatalf("payload[0] = 0x%02x, want 0x%02x", payload[0], quicwire.OrchestratorSubListJobs)
	}

	var decoded platformv1.ListOrchestratorJobsRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetTenantId() != "acme" || decoded.GetPage().GetLimit() != 20 || decoded.GetPage().GetOffset() != 40 {
		t.Fatalf("decoded = %v, want the original request", &decoded)
	}
}

func TestOrchestratorSubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string, len(orchestratorSubOpcodes))
	for method, sub := range orchestratorSubOpcodes {
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
}
