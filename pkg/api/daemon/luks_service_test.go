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
)

type fakeLUKSBackend struct{}

func (f *fakeLUKSBackend) Status(_ context.Context, device string) (*LUKSStatus, error) {
	return &LUKSStatus{Device: device, IsLUKS: true, Version: 2}, nil
}

func (f *fakeLUKSBackend) ListSlots(_ context.Context, device string) (*LUKSListSlotsResult, error) {
	return &LUKSListSlotsResult{Device: device, Slots: []LUKSKeyslot{{Slot: 0, Type: LUKSKeyTypePassphrase}}}, nil
}

func (f *fakeLUKSBackend) Info(_ context.Context, device string) (*LUKSInfo, error) {
	return &LUKSInfo{Device: device, Version: 2, Cipher: "aes-xts-plain64"}, nil
}

func (f *fakeLUKSBackend) EnrollPassphrase(_ context.Context, _ *LUKSEnrollPassphraseRequest) (*LUKSEnrollPassphraseResult, error) {
	return &LUKSEnrollPassphraseResult{Slot: 1}, nil
}

func (f *fakeLUKSBackend) EnrollFIDO2(_ context.Context, _ *LUKSEnrollFIDO2Request) (*LUKSEnrollFIDO2Result, error) {
	return &LUKSEnrollFIDO2Result{Slot: 2, TokenID: "tok"}, nil
}

func (f *fakeLUKSBackend) EnrollTPM(_ context.Context, _ *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error) {
	return &LUKSEnrollTPMResult{Slot: 3, TokenID: "tpm-tok"}, nil
}

func (f *fakeLUKSBackend) EnrollRecovery(_ context.Context, _ *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error) {
	return &LUKSEnrollRecoveryResult{Slot: 4, RecoveryKey: "r-key"}, nil
}

func (f *fakeLUKSBackend) RemoveKey(_ context.Context, _ *LUKSRemoveKeyRequest) error {
	return nil
}

func (f *fakeLUKSBackend) TestUnlock(_ context.Context, _ *LUKSTestUnlockRequest) (bool, error) {
	return true, nil
}

func (f *fakeLUKSBackend) ChangePassphrase(_ context.Context, _ *LUKSChangePassphraseRequest) error {
	return nil
}

func rootYes() RootChecker  { return RootCheckerFunc(func() bool { return true }) }
func rootFalse() RootChecker { return RootCheckerFunc(func() bool { return false }) }

func TestLUKSService_NotConfigured(t *testing.T) {
	svc := NewLUKSService(logging.DefaultLogger(), nil, rootYes())
	ctx := context.Background()
	if _, err := svc.Status(ctx, "/dev/sda"); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("Status: want ErrLUKSNotConfigured, got %v", err)
	}
	req := &LUKSEnrollPassphraseRequest{Device: "/dev/sda", ExistingPassphrase: "e", NewPassphrase: "n"}
	if _, err := svc.EnrollPassphrase(ctx, req); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("EnrollPassphrase: want ErrLUKSNotConfigured, got %v", err)
	}
}

func TestLUKSService_RootRequired(t *testing.T) {
	svc := NewLUKSService(logging.DefaultLogger(), &fakeLUKSBackend{}, rootFalse())
	ctx := context.Background()
	cases := []func() error{
		func() error {
			_, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{Device: "/d", ExistingPassphrase: "e", NewPassphrase: "n"})
			return err
		},
		func() error {
			_, err := svc.EnrollFIDO2(ctx, &LUKSEnrollFIDO2Request{Device: "/d", ExistingPassphrase: "e", CredentialID: "c"})
			return err
		},
		func() error {
			_, err := svc.EnrollTPM(ctx, &LUKSEnrollTPMRequest{Device: "/d", ExistingPassphrase: "e"})
			return err
		},
		func() error {
			_, err := svc.EnrollRecovery(ctx, &LUKSEnrollRecoveryRequest{Device: "/d", ExistingPassphrase: "e"})
			return err
		},
		func() error { return svc.RemoveKey(ctx, &LUKSRemoveKeyRequest{Device: "/d", Slot: 1}) },
		func() error {
			return svc.ChangePassphrase(ctx, &LUKSChangePassphraseRequest{Device: "/d", Slot: 1, OldPassphrase: "o", NewPassphrase: "n"})
		},
	}
	for i, run := range cases {
		if err := run(); !errors.Is(err, ErrLUKSRootRequired) {
			t.Errorf("case %d: want ErrLUKSRootRequired, got %v", i, err)
		}
	}
}

func TestLUKSService_Validation(t *testing.T) {
	svc := NewLUKSService(logging.DefaultLogger(), &fakeLUKSBackend{}, rootYes())
	ctx := context.Background()
	if _, err := svc.Status(ctx, ""); !errors.Is(err, ErrLUKSDeviceRequired) {
		t.Errorf("Status: want ErrLUKSDeviceRequired, got %v", err)
	}
	if _, err := svc.ListSlots(ctx, ""); !errors.Is(err, ErrLUKSDeviceRequired) {
		t.Errorf("ListSlots: want ErrLUKSDeviceRequired, got %v", err)
	}
	if _, err := svc.Info(ctx, ""); !errors.Is(err, ErrLUKSDeviceRequired) {
		t.Errorf("Info: want ErrLUKSDeviceRequired, got %v", err)
	}
	if _, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{}); !errors.Is(err, ErrLUKSDeviceRequired) {
		t.Errorf("EnrollPassphrase no device: got %v", err)
	}
	if _, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{Device: "/d"}); !errors.Is(err, ErrLUKSNewPassphraseRequired) {
		t.Errorf("EnrollPassphrase no new pp: got %v", err)
	}
	if _, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{Device: "/d", NewPassphrase: "n"}); !errors.Is(err, ErrLUKSPassphraseRequired) {
		t.Errorf("EnrollPassphrase no existing pp: got %v", err)
	}
	if _, err := svc.EnrollFIDO2(ctx, &LUKSEnrollFIDO2Request{Device: "/d"}); !errors.Is(err, ErrLUKSCredentialIDRequired) {
		t.Errorf("EnrollFIDO2 no credid: got %v", err)
	}
}

func TestLUKSService_BackendSuccess(t *testing.T) {
	svc := NewLUKSService(logging.DefaultLogger(), &fakeLUKSBackend{}, rootYes())
	ctx := context.Background()

	if s, err := svc.Status(ctx, "/dev/sda"); err != nil || !s.IsLUKS {
		t.Errorf("Status: %v %+v", err, s)
	}
	if s, err := svc.ListSlots(ctx, "/dev/sda"); err != nil || len(s.Slots) == 0 {
		t.Errorf("ListSlots: %v %+v", err, s)
	}
	if i, err := svc.Info(ctx, "/dev/sda"); err != nil || i.Cipher == "" {
		t.Errorf("Info: %v %+v", err, i)
	}
	if r, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{Device: "/d", ExistingPassphrase: "e", NewPassphrase: "n"}); err != nil || r.Slot != 1 {
		t.Errorf("EnrollPassphrase: %v %+v", err, r)
	}
	if r, err := svc.EnrollFIDO2(ctx, &LUKSEnrollFIDO2Request{Device: "/d", ExistingPassphrase: "e", CredentialID: "c"}); err != nil || r.Slot != 2 {
		t.Errorf("EnrollFIDO2: %v %+v", err, r)
	}
	if r, err := svc.EnrollTPM(ctx, &LUKSEnrollTPMRequest{Device: "/d", ExistingPassphrase: "e"}); err != nil || r.Slot != 3 {
		t.Errorf("EnrollTPM: %v %+v", err, r)
	}
	if r, err := svc.EnrollRecovery(ctx, &LUKSEnrollRecoveryRequest{Device: "/d", ExistingPassphrase: "e"}); err != nil || r.Slot != 4 {
		t.Errorf("EnrollRecovery: %v %+v", err, r)
	}
	if err := svc.RemoveKey(ctx, &LUKSRemoveKeyRequest{Device: "/d", Slot: 1}); err != nil {
		t.Errorf("RemoveKey: %v", err)
	}
	if ok, err := svc.TestUnlock(ctx, &LUKSTestUnlockRequest{Device: "/d", Slot: 1}); err != nil || !ok {
		t.Errorf("TestUnlock: %v %v", err, ok)
	}
	if err := svc.ChangePassphrase(ctx, &LUKSChangePassphraseRequest{Device: "/d", Slot: 1, OldPassphrase: "o", NewPassphrase: "n"}); err != nil {
		t.Errorf("ChangePassphrase: %v", err)
	}
}

func TestLUKSService_DefaultRootChecker(t *testing.T) {
	// When root is nil, the constructor installs a conservative default
	// that always reports non-root.
	svc := NewLUKSService(logging.DefaultLogger(), &fakeLUKSBackend{}, nil)
	ctx := context.Background()
	_, err := svc.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{Device: "/d", ExistingPassphrase: "e", NewPassphrase: "n"})
	if !errors.Is(err, ErrLUKSRootRequired) {
		t.Errorf("want ErrLUKSRootRequired, got %v", err)
	}
}
