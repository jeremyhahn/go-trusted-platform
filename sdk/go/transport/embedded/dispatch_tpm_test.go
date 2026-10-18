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

// TestBuildHandlerMap_TPMEveryMethodReachesItsServer drives every
// TPMService and IDevIDService method in the generated descriptors through
// the embedded dispatcher, so an RPC added to tpm.proto or idevid.proto
// without its embedded handler fails here instead of answering
// Unimplemented to embedded callers.
func TestBuildHandlerMap_TPMEveryMethodReachesItsServer(t *testing.T) {
	tpm := platformv1.UnimplementedTPMServiceServer{}
	idevid := platformv1.UnimplementedIDevIDServiceServer{}
	m := buildHandlerMap(&ServiceRegistry{TPM: tpm, IDevID: idevid})
	descs := []grpc.ServiceDesc{platformv1.TPMService_ServiceDesc, platformv1.IDevIDService_ServiceDesc}
	servers := []any{tpm, idevid}

	for i, desc := range descs {
		for _, md := range desc.Methods {
			full := "/" + desc.ServiceName + "/" + md.MethodName
			t.Run(full, func(t *testing.T) {
				handler, ok := m[full]
				if !ok {
					t.Fatalf("%s is not registered", full)
				}
				_, err := handler(context.Background(), requestTypeOf(t, md, servers[i]))
				st, _ := status.FromError(err)
				if st.Code() != codes.Unimplemented || !strings.Contains(st.Message(), "method "+md.MethodName+" ") {
					t.Errorf("%s reached %v, want the server's %s", full, err, md.MethodName)
				}
			})
		}
	}
}

// TestBuildHandlerMap_TPMAbsentRegistersNothing: a registry without a TPM
// service leaves the TPM methods unregistered, so the caller gets the
// dispatcher's not-registered error rather than a nil-server panic.
func TestBuildHandlerMap_TPMAbsentRegistersNothing(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{})

	for _, md := range platformv1.TPMService_ServiceDesc.Methods {
		full := "/" + platformv1.TPMService_ServiceDesc.ServiceName + "/" + md.MethodName
		if _, ok := m[full]; ok {
			t.Errorf("%s registered without a TPM service", full)
		}
	}
}
