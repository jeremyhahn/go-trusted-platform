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
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newLUKSServicer builds the LUKSService gRPC servicer over backend, the
// way the daemon builds the one gRPC registers.
func newLUKSServicer(backend LUKSBackend, root RootChecker) *LUKSGRPCService {
	logger := logging.DefaultLogger()
	return NewLUKSGRPCService(logger, NewLUKSService(logger, backend, root))
}

// luksSDKCalls holds one call for every LUKSService method, each naming
// device.
func luksSDKCalls(device string) []sdkCall {
	return []sdkCall{
		{platformv1.LUKSService_Status_FullMethodName,
			&platformv1.LUKSStatusRequest{Device: device}, &platformv1.LUKSStatusResponse{}},
		{platformv1.LUKSService_ListSlots_FullMethodName,
			&platformv1.LUKSListSlotsRequest{Device: device}, &platformv1.LUKSListSlotsResponse{}},
		{platformv1.LUKSService_Info_FullMethodName,
			&platformv1.LUKSInfoRequest{Device: device}, &platformv1.LUKSInfoResponse{}},
		{platformv1.LUKSService_EnrollPassphrase_FullMethodName,
			&platformv1.LUKSEnrollPassphraseRequest{
				Device: device, ExistingPassphrase: luksTestExisting, NewPassphrase: luksTestNew,
			}, &platformv1.LUKSEnrollPassphraseResponse{}},
		{platformv1.LUKSService_EnrollFIDO2_FullMethodName,
			&platformv1.LUKSEnrollFIDO2Request{
				Device: device, ExistingPassphrase: luksTestExisting, CredentialId: "cred-1",
				RequirePin: true, RequireUv: true,
			}, &platformv1.LUKSEnrollFIDO2Response{}},
		{platformv1.LUKSService_EnrollTPM_FullMethodName,
			&platformv1.LUKSEnrollTPMRequest{
				Device: device, ExistingPassphrase: luksTestExisting, Pcrs: []int32{0, 7}, Handle: "0x81000003",
			}, &platformv1.LUKSEnrollTPMResponse{}},
		{platformv1.LUKSService_EnrollRecovery_FullMethodName,
			&platformv1.LUKSEnrollRecoveryRequest{Device: device, ExistingPassphrase: luksTestExisting},
			&platformv1.LUKSEnrollRecoveryResponse{}},
		{platformv1.LUKSService_RemoveKey_FullMethodName,
			&platformv1.LUKSRemoveKeyRequest{Device: device, Slot: 5}, &platformv1.LUKSRemoveKeyResponse{}},
		{platformv1.LUKSService_TestUnlock_FullMethodName,
			&platformv1.LUKSTestUnlockRequest{Device: device, Slot: 6}, &platformv1.LUKSTestUnlockResponse{}},
		{platformv1.LUKSService_ChangePassphrase_FullMethodName,
			&platformv1.LUKSChangePassphraseRequest{
				Device: device, Slot: 7, OldPassphrase: luksTestOld, NewPassphrase: luksTestNew,
			}, &platformv1.LUKSChangePassphraseResponse{}},
	}
}

// connectLUKSEmbedded wires server as an embedded host's LUKS service and
// connects the SDK's embedded adapter to the registry the host builds.
func connectLUKSEmbedded(t *testing.T, server *LUKSGRPCService) grpc.ClientConnInterface {
	t.Helper()
	return connectEmbeddedHost(t, func(d *Daemon) { d.luksService = server })
}

// TestSDKEmbedded_LUKSMethods drives every LUKSService method through the
// SDK's embedded adapter and the registry the daemon's embedded host
// builds. Each reply, and each request the backend records, matches a
// direct gRPC call on the same servicer.
func TestSDKEmbedded_LUKSMethods(t *testing.T) {
	calls := luksSDKCalls("/dev/sda")
	require.Len(t, calls, len(platformv1.LUKSService_ServiceDesc.Methods))

	for _, call := range calls {
		t.Run(path.Base(call.method), func(t *testing.T) {
			direct := &luksWireBackend{}
			want, err := invokeGRPCMethod(&platformv1.LUKSService_ServiceDesc, newLUKSServicer(direct, rootYes()), call.method, call.req)
			require.NoError(t, err)

			via := &luksWireBackend{}
			conn := connectLUKSEmbedded(t, newLUKSServicer(via, rootYes()))
			require.NoError(t, conn.Invoke(context.Background(), call.method, call.req, call.resp))

			require.True(t, proto.Equal(want, call.resp), "embedded reply\n%v\nwant the gRPC reply\n%v", call.resp, want)
			require.NotEqual(t, &luksWireBackend{}, via, "the LUKS backend saw no call")
			require.Equal(t, direct, via)
		})
	}
}

// TestSDKEmbedded_LUKSMethodsRefuse checks every LUKSService method
// refuses through the embedded adapter with the status a direct gRPC call
// gives: a request naming no device, a node with no LUKS backend, and a
// daemon whose registry carries no LUKS service at all.
func TestSDKEmbedded_LUKSMethodsRefuse(t *testing.T) {
	refusals := []struct {
		name    string
		backend func() LUKSBackend
		device  string
		want    codes.Code
	}{
		{"device required", func() LUKSBackend { return &luksWireBackend{} }, "", codes.InvalidArgument},
		{"not configured", func() LUKSBackend { return nil }, "/dev/sda", codes.Unavailable},
	}
	for _, refusal := range refusals {
		for _, call := range luksSDKCalls(refusal.device) {
			t.Run(refusal.name+"/"+path.Base(call.method), func(t *testing.T) {
				_, direct := invokeGRPCMethod(&platformv1.LUKSService_ServiceDesc, newLUKSServicer(refusal.backend(), rootYes()), call.method, call.req)

				conn := connectLUKSEmbedded(t, newLUKSServicer(refusal.backend(), rootYes()))
				via := conn.Invoke(context.Background(), call.method, call.req, call.resp)

				requireSameRefusal(t, refusal.want, direct, via)
			})
		}
	}

	for _, call := range luksSDKCalls("/dev/sda") {
		t.Run("not registered/"+path.Base(call.method), func(t *testing.T) {
			conn := connectLUKSEmbedded(t, nil)
			err := conn.Invoke(context.Background(), call.method, call.req, call.resp)
			require.Equal(t, codes.Unimplemented, status.Code(err), "%v", err)
		})
	}
}
