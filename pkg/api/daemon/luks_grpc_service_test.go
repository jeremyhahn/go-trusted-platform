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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newLUKSGRPC(backend LUKSBackend, isRoot bool) *LUKSGRPCService {
	rc := RootCheckerFunc(func() bool { return isRoot })
	return NewLUKSGRPCService(logging.DefaultLogger(), NewLUKSService(logging.DefaultLogger(), backend, rc))
}

func TestLUKSGRPC_Unavailable(t *testing.T) {
	svc := newLUKSGRPC(nil, true)
	_, err := svc.Status(context.Background(), &platformv1.LUKSStatusRequest{Device: "/d"})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Errorf("code = %v", st.Code())
	}
}

func TestLUKSGRPC_PermissionDenied(t *testing.T) {
	svc := newLUKSGRPC(&fakeLUKSBackend{}, false)
	_, err := svc.EnrollPassphrase(context.Background(), &platformv1.LUKSEnrollPassphraseRequest{
		Device:             "/d",
		ExistingPassphrase: "e",
		NewPassphrase:      "n",
	})
	if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v", st.Code())
	}
}

func TestLUKSGRPC_InvalidArgument(t *testing.T) {
	svc := newLUKSGRPC(&fakeLUKSBackend{}, true)
	_, err := svc.Status(context.Background(), &platformv1.LUKSStatusRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v", st.Code())
	}
}

func TestLUKSGRPC_Success(t *testing.T) {
	svc := newLUKSGRPC(&fakeLUKSBackend{}, true)
	ctx := context.Background()

	if s, err := svc.Status(ctx, &platformv1.LUKSStatusRequest{Device: "/d"}); err != nil || !s.GetIsLuks() {
		t.Errorf("Status: %v %+v", err, s)
	}
	if s, err := svc.ListSlots(ctx, &platformv1.LUKSListSlotsRequest{Device: "/d"}); err != nil || len(s.GetSlots()) == 0 {
		t.Errorf("ListSlots: %v %+v", err, s)
	}
	if _, err := svc.Info(ctx, &platformv1.LUKSInfoRequest{Device: "/d"}); err != nil {
		t.Errorf("Info: %v", err)
	}
	if r, err := svc.EnrollPassphrase(ctx, &platformv1.LUKSEnrollPassphraseRequest{Device: "/d", ExistingPassphrase: "e", NewPassphrase: "n"}); err != nil || r.GetSlot() != 1 {
		t.Errorf("EnrollPassphrase: %v %+v", err, r)
	}
	if r, err := svc.EnrollFIDO2(ctx, &platformv1.LUKSEnrollFIDO2Request{Device: "/d", ExistingPassphrase: "e", CredentialId: "c"}); err != nil || r.GetSlot() != 2 {
		t.Errorf("EnrollFIDO2: %v %+v", err, r)
	}
	if r, err := svc.EnrollTPM(ctx, &platformv1.LUKSEnrollTPMRequest{Device: "/d", ExistingPassphrase: "e"}); err != nil || r.GetSlot() != 3 {
		t.Errorf("EnrollTPM: %v %+v", err, r)
	}
	if r, err := svc.EnrollRecovery(ctx, &platformv1.LUKSEnrollRecoveryRequest{Device: "/d", ExistingPassphrase: "e"}); err != nil || r.GetSlot() != 4 {
		t.Errorf("EnrollRecovery: %v %+v", err, r)
	}
	if r, err := svc.RemoveKey(ctx, &platformv1.LUKSRemoveKeyRequest{Device: "/d", Slot: 1}); err != nil || !r.GetRemoved() {
		t.Errorf("RemoveKey: %v %+v", err, r)
	}
	if r, err := svc.TestUnlock(ctx, &platformv1.LUKSTestUnlockRequest{Device: "/d", Slot: 1}); err != nil || !r.GetUnlocked() {
		t.Errorf("TestUnlock: %v %+v", err, r)
	}
	if r, err := svc.ChangePassphrase(ctx, &platformv1.LUKSChangePassphraseRequest{Device: "/d", Slot: 1, OldPassphrase: "o", NewPassphrase: "n"}); err != nil || !r.GetChanged() {
		t.Errorf("ChangePassphrase: %v %+v", err, r)
	}
}
