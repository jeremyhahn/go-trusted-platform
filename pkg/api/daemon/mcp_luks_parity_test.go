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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// luksMissingDevice is the device the parity backend does not have.
const luksMissingDevice = "/dev/missing"

// errFakeLUKSNoDevice is what the parity backend answers for luksMissingDevice.
var errFakeLUKSNoDevice = errors.New("luks: no such device")

// missingDeviceLUKSBackend is fakeLUKSBackend with one device absent, so a
// parity case can drive the backend's not-found path through both transports.
type missingDeviceLUKSBackend struct {
	fakeLUKSBackend
}

func (b *missingDeviceLUKSBackend) Status(ctx context.Context, device string) (*LUKSStatus, error) {
	if device == luksMissingDevice {
		return nil, errFakeLUKSNoDevice
	}
	return b.fakeLUKSBackend.Status(ctx, device)
}

func (b *missingDeviceLUKSBackend) EnrollRecovery(ctx context.Context, req *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error) {
	if req.Device == luksMissingDevice {
		return nil, errFakeLUKSNoDevice
	}
	return b.fakeLUKSBackend.EnrollRecovery(ctx, req)
}

func (b *missingDeviceLUKSBackend) RemoveKey(ctx context.Context, req *LUKSRemoveKeyRequest) error {
	if req.Device == luksMissingDevice {
		return errFakeLUKSNoDevice
	}
	return b.fakeLUKSBackend.RemoveKey(ctx, req)
}

// luksTwins builds the MCP provider and the gRPC service over one
// LUKSService, the way the daemon wires them.
func luksTwins(backend LUKSBackend, isRoot bool) (*MCPServiceProvider, *LUKSGRPCService) {
	svc := NewLUKSService(logging.DefaultLogger(), backend, RootCheckerFunc(func() bool { return isRoot }))
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	provider.SetPhase35Services(Phase35Services{LUKS: svc})
	return provider, NewLUKSGRPCService(logging.DefaultLogger(), svc)
}

// luksParityCall runs one LUKS operation over MCP and over gRPC.
type luksParityCall struct {
	name string
	mcp  func(context.Context, *MCPServiceProvider) (interface{}, error)
	grpc func(context.Context, *LUKSGRPCService) (interface{}, error)
}

func luksStatusCall(device string) luksParityCall {
	return luksParityCall{
		name: "status",
		mcp: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
			return p.LUKSStatus(ctx, device)
		},
		grpc: func(ctx context.Context, g *LUKSGRPCService) (interface{}, error) {
			return g.Status(ctx, &platformv1.LUKSStatusRequest{Device: device})
		},
	}
}

func luksEnrollRecoveryCall(device string) luksParityCall {
	return luksParityCall{
		name: "enroll_recovery",
		mcp: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
			return p.LUKSEnrollRecovery(ctx, map[string]interface{}{"device": device, "existing_passphrase": "e"})
		},
		grpc: func(ctx context.Context, g *LUKSGRPCService) (interface{}, error) {
			return g.EnrollRecovery(ctx, &platformv1.LUKSEnrollRecoveryRequest{Device: device, ExistingPassphrase: "e"})
		},
	}
}

func luksRemoveKeyCall(device string) luksParityCall {
	return luksParityCall{
		name: "remove_key",
		mcp: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
			return p.LUKSRemoveKey(ctx, map[string]interface{}{"device": device, "slot": float64(1)})
		},
		grpc: func(ctx context.Context, g *LUKSGRPCService) (interface{}, error) {
			return g.RemoveKey(ctx, &platformv1.LUKSRemoveKeyRequest{Device: device, Slot: 1})
		},
	}
}

// TestMCPLUKS_ErrorClassMatchesGRPC drives one operation per scope group
// (read, write, delete) through both transports and requires the same
// class: an MCP caller must read what a gRPC caller reads.
func TestMCPLUKS_ErrorClassMatchesGRPC(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		backend LUKSBackend
		isRoot  bool
		call    luksParityCall
		want    codes.Code
	}{
		{"read invalid input", &missingDeviceLUKSBackend{}, true, luksStatusCall(""), codes.InvalidArgument},
		{"read not found", &missingDeviceLUKSBackend{}, true, luksStatusCall(luksMissingDevice), codes.Internal},
		{"read not configured", nil, true, luksStatusCall("/dev/x"), codes.Unavailable},
		{"write invalid input", &missingDeviceLUKSBackend{}, true, luksEnrollRecoveryCall(""), codes.InvalidArgument},
		{"write not found", &missingDeviceLUKSBackend{}, true, luksEnrollRecoveryCall(luksMissingDevice), codes.Internal},
		{"write not root", &missingDeviceLUKSBackend{}, false, luksEnrollRecoveryCall("/dev/x"), codes.PermissionDenied},
		{"delete invalid input", &missingDeviceLUKSBackend{}, true, luksRemoveKeyCall(""), codes.InvalidArgument},
		{"delete not found", &missingDeviceLUKSBackend{}, true, luksRemoveKeyCall(luksMissingDevice), codes.Internal},
		{"delete not root", &missingDeviceLUKSBackend{}, false, luksRemoveKeyCall("/dev/x"), codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, grpcSvc := luksTwins(tt.backend, tt.isRoot)
			_, mcpErr := tt.call.mcp(ctx, provider)
			_, grpcErr := tt.call.grpc(ctx, grpcSvc)
			if got := status.Code(grpcErr); got != tt.want {
				t.Fatalf("%s over gRPC: code %s, want %s", tt.call.name, got, tt.want)
			}
			if got := status.Code(mcpErr); got != tt.want {
				t.Errorf("%s over MCP: code %s, want %s (gRPC answers %s)", tt.call.name, got, tt.want, tt.want)
			}
		})
	}
}

// TestMCPLUKS_ErrorKeepsSentinel keeps the service sentinel reachable
// through the class the MCP provider adds.
func TestMCPLUKS_ErrorKeepsSentinel(t *testing.T) {
	provider, _ := luksTwins(&missingDeviceLUKSBackend{}, true)
	_, err := provider.LUKSStatus(context.Background(), "")
	if !errors.Is(err, ErrLUKSDeviceRequired) {
		t.Errorf("err = %v, want ErrLUKSDeviceRequired", err)
	}
	if err.Error() != ErrLUKSDeviceRequired.Error() {
		t.Errorf("message = %q, want the service's %q", err.Error(), ErrLUKSDeviceRequired.Error())
	}
}

// TestMCPLUKS_ReadAnswersMatchGRPC compares the read tools' answers.
func TestMCPLUKS_ReadAnswersMatchGRPC(t *testing.T) {
	ctx := context.Background()
	provider, grpcSvc := luksTwins(&missingDeviceLUKSBackend{}, true)

	mcpStatus, err := provider.LUKSStatus(ctx, "/dev/x")
	if err != nil {
		t.Fatalf("MCP status: %v", err)
	}
	grpcStatus, err := grpcSvc.Status(ctx, &platformv1.LUKSStatusRequest{Device: "/dev/x"})
	if err != nil {
		t.Fatalf("gRPC status: %v", err)
	}
	st := mcpStatus.(*LUKSStatus)
	if st.Device != grpcStatus.GetDevice() || st.IsLUKS != grpcStatus.GetIsLuks() || st.Version != grpcStatus.GetVersion() {
		t.Errorf("status: MCP %+v, gRPC %+v", st, grpcStatus)
	}

	mcpSlots, err := provider.LUKSListSlots(ctx, "/dev/x")
	if err != nil {
		t.Fatalf("MCP list_slots: %v", err)
	}
	grpcSlots, err := grpcSvc.ListSlots(ctx, &platformv1.LUKSListSlotsRequest{Device: "/dev/x"})
	if err != nil {
		t.Fatalf("gRPC list_slots: %v", err)
	}
	slots := mcpSlots.(*LUKSListSlotsResult)
	if len(slots.Slots) != len(grpcSlots.GetSlots()) || slots.Slots[0].Slot != grpcSlots.GetSlots()[0].GetSlot() {
		t.Errorf("list_slots: MCP %+v, gRPC %+v", slots, grpcSlots)
	}

	mcpInfo, err := provider.LUKSInfo(ctx, "/dev/x")
	if err != nil {
		t.Fatalf("MCP info: %v", err)
	}
	grpcInfo, err := grpcSvc.Info(ctx, &platformv1.LUKSInfoRequest{Device: "/dev/x"})
	if err != nil {
		t.Fatalf("gRPC info: %v", err)
	}
	info := mcpInfo.(*LUKSInfo)
	if info.Cipher != grpcInfo.GetCipher() || info.Version != grpcInfo.GetVersion() {
		t.Errorf("info: MCP %+v, gRPC %+v", info, grpcInfo)
	}
}

// TestMCPLUKS_WriteAnswersMatchGRPC compares the write and delete tools'
// answers. The recovery key is the one secret a tool returns, at creation,
// as gRPC does.
func TestMCPLUKS_WriteAnswersMatchGRPC(t *testing.T) {
	ctx := context.Background()
	provider, grpcSvc := luksTwins(&missingDeviceLUKSBackend{}, true)
	enrollArgs := map[string]interface{}{"device": "/dev/x", "existing_passphrase": "e"}

	pp, err := provider.LUKSEnrollPassphrase(ctx, map[string]interface{}{"device": "/dev/x", "existing_passphrase": "e", "new_passphrase": "n"})
	if err != nil {
		t.Fatalf("MCP enroll_passphrase: %v", err)
	}
	grpcPP, err := grpcSvc.EnrollPassphrase(ctx, &platformv1.LUKSEnrollPassphraseRequest{Device: "/dev/x", ExistingPassphrase: "e", NewPassphrase: "n"})
	if err != nil {
		t.Fatalf("gRPC enroll_passphrase: %v", err)
	}
	if got := pp.(*LUKSEnrollPassphraseResult).Slot; got != grpcPP.GetSlot() {
		t.Errorf("enroll_passphrase slot: MCP %d, gRPC %d", got, grpcPP.GetSlot())
	}

	fido, err := provider.LUKSEnrollFIDO2(ctx, map[string]interface{}{"device": "/dev/x", "existing_passphrase": "e", "credential_id": "c"})
	if err != nil {
		t.Fatalf("MCP enroll_fido2: %v", err)
	}
	grpcFido, err := grpcSvc.EnrollFIDO2(ctx, &platformv1.LUKSEnrollFIDO2Request{Device: "/dev/x", ExistingPassphrase: "e", CredentialId: "c"})
	if err != nil {
		t.Fatalf("gRPC enroll_fido2: %v", err)
	}
	if got := fido.(*LUKSEnrollFIDO2Result); got.Slot != grpcFido.GetSlot() || got.TokenID != grpcFido.GetTokenId() {
		t.Errorf("enroll_fido2: MCP %+v, gRPC %+v", got, grpcFido)
	}

	tpm, err := provider.LUKSEnrollTPM(ctx, enrollArgs)
	if err != nil {
		t.Fatalf("MCP enroll_tpm: %v", err)
	}
	grpcTPM, err := grpcSvc.EnrollTPM(ctx, &platformv1.LUKSEnrollTPMRequest{Device: "/dev/x", ExistingPassphrase: "e"})
	if err != nil {
		t.Fatalf("gRPC enroll_tpm: %v", err)
	}
	if got := tpm.(*LUKSEnrollTPMResult); got.Slot != grpcTPM.GetSlot() || got.TokenID != grpcTPM.GetTokenId() {
		t.Errorf("enroll_tpm: MCP %+v, gRPC %+v", got, grpcTPM)
	}

	recovery, err := provider.LUKSEnrollRecovery(ctx, enrollArgs)
	if err != nil {
		t.Fatalf("MCP enroll_recovery: %v", err)
	}
	grpcRecovery, err := grpcSvc.EnrollRecovery(ctx, &platformv1.LUKSEnrollRecoveryRequest{Device: "/dev/x", ExistingPassphrase: "e"})
	if err != nil {
		t.Fatalf("gRPC enroll_recovery: %v", err)
	}
	if got := recovery.(*LUKSEnrollRecoveryResult); got.Slot != grpcRecovery.GetSlot() || got.RecoveryKey != grpcRecovery.GetRecoveryKey() {
		t.Errorf("enroll_recovery: MCP slot %d, gRPC slot %d; keys equal: %v",
			got.Slot, grpcRecovery.GetSlot(), got.RecoveryKey == grpcRecovery.GetRecoveryKey())
	}

	changed, err := provider.LUKSChangePassphrase(ctx, map[string]interface{}{"device": "/dev/x", "slot": float64(1), "old_passphrase": "o", "new_passphrase": "n"})
	if err != nil {
		t.Fatalf("MCP change_passphrase: %v", err)
	}
	grpcChanged, err := grpcSvc.ChangePassphrase(ctx, &platformv1.LUKSChangePassphraseRequest{Device: "/dev/x", Slot: 1, OldPassphrase: "o", NewPassphrase: "n"})
	if err != nil {
		t.Fatalf("gRPC change_passphrase: %v", err)
	}
	if got := changed.(map[string]interface{})["changed"]; got != grpcChanged.GetChanged() {
		t.Errorf("change_passphrase: MCP %v, gRPC %v", got, grpcChanged.GetChanged())
	}

	removed, err := provider.LUKSRemoveKey(ctx, map[string]interface{}{"device": "/dev/x", "slot": float64(1)})
	if err != nil {
		t.Fatalf("MCP remove_key: %v", err)
	}
	grpcRemoved, err := grpcSvc.RemoveKey(ctx, &platformv1.LUKSRemoveKeyRequest{Device: "/dev/x", Slot: 1})
	if err != nil {
		t.Fatalf("gRPC remove_key: %v", err)
	}
	if got := removed.(map[string]interface{})["removed"]; got != grpcRemoved.GetRemoved() {
		t.Errorf("remove_key: MCP %v, gRPC %v", got, grpcRemoved.GetRemoved())
	}
}

// TestMCPLUKSTestUnlock_RefusesWithoutBackend is the regression for the
// faked success: on a wired backend the tool answered {"unlocked": true}
// for any existing keyslot without trying a key. It now refuses with a
// typed error and never reaches the backend.
func TestMCPLUKSTestUnlock_RefusesWithoutBackend(t *testing.T) {
	backend := &recordingLUKSBackend{inner: &fakeLUKSBackend{}}
	provider, _ := luksTwins(backend, true)

	result, err := provider.LUKSTestUnlock(context.Background(), map[string]interface{}{"device": "/dev/x", "slot": float64(1)})
	if !errors.Is(err, ErrLUKSTestUnlockUnverified) {
		t.Fatalf("err = %v, want ErrLUKSTestUnlockUnverified (result %v)", err, result)
	}
	if result != nil {
		t.Errorf("result = %v, want none", result)
	}
	if got := status.Code(err); got != codes.Unimplemented {
		t.Errorf("code = %s, want Unimplemented", got)
	}
	if backend.unlockHit != 0 {
		t.Errorf("backend TestUnlock called %d times, want 0", backend.unlockHit)
	}
}

// TestErrLUKSOperation_ClassOfUnknownCause answers Internal for a cause no
// LUKS sentinel names, as luksErrorToGRPC does for gRPC.
func TestErrLUKSOperation_ClassOfUnknownCause(t *testing.T) {
	err := ErrLUKSOperation{Cause: errFakeLUKSNoDevice}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("code = %s, want Internal", got)
	}
	if !errors.Is(err, errFakeLUKSNoDevice) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
	if err.Error() != errFakeLUKSNoDevice.Error() {
		t.Errorf("message = %q, want %q", err.Error(), errFakeLUKSNoDevice.Error())
	}
}
