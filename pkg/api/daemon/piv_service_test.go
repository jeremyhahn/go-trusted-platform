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

type fakePIVBackend struct {
	devices []PIVDevice
	slots   []PIVSlot
}

func (f *fakePIVBackend) ListDevices(_ context.Context) ([]PIVDevice, error) {
	return f.devices, nil
}

func (f *fakePIVBackend) ListSlots(_ context.Context, _ string) ([]PIVSlot, error) {
	return f.slots, nil
}

func (f *fakePIVBackend) SlotInfo(_ context.Context, _, slot string) (*PIVSlotInfo, error) {
	return &PIVSlotInfo{Slot: PIVSlot{ID: slot, Algorithm: PIVAlgorithmRSA, HasKey: true}}, nil
}

func (f *fakePIVBackend) Generate(_ context.Context, req *PIVGenerateRequest) (*PIVGenerateResult, error) {
	return &PIVGenerateResult{PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n" + req.Slot + "\n-----END PUBLIC KEY-----\n"}, nil
}

func (f *fakePIVBackend) Import(_ context.Context, _ *PIVImportRequest) error {
	return nil
}

func (f *fakePIVBackend) Sign(_ context.Context, req *PIVSignRequest) ([]byte, error) {
	out := make([]byte, len(req.Payload))
	copy(out, req.Payload)
	return out, nil
}

func (f *fakePIVBackend) Attest(_ context.Context, _ string) (*PIVAttestResult, error) {
	return &PIVAttestResult{AttestationCertPEM: "CERT", AttestationChainPEM: "CHAIN"}, nil
}

func (f *fakePIVBackend) Reset(_ context.Context, _ string) error {
	return nil
}

func TestPIVService_NotConfigured(t *testing.T) {
	svc := NewPIVService(logging.DefaultLogger(), nil)
	ctx := context.Background()

	if _, err := svc.ListDevices(ctx); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("ListDevices: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := svc.ListSlots(ctx, "dev1"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("ListSlots: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := svc.SlotInfo(ctx, "dev1", "9a"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("SlotInfo: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := svc.Generate(ctx, &PIVGenerateRequest{Slot: "9a", Algorithm: PIVAlgorithmRSA}); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("Generate: want ErrPIVNotConfigured, got %v", err)
	}
	if err := svc.Import(ctx, &PIVImportRequest{Slot: "9a", PrivateKeyPEM: "pem"}); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("Import: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := svc.Sign(ctx, &PIVSignRequest{Slot: "9a", Payload: []byte{1}}); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("Sign: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := svc.Attest(ctx, "9a"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("Attest: want ErrPIVNotConfigured, got %v", err)
	}
	if err := svc.Reset(ctx, "dev1"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("Reset: want ErrPIVNotConfigured, got %v", err)
	}
}

func TestPIVService_Validation(t *testing.T) {
	svc := NewPIVService(logging.DefaultLogger(), &fakePIVBackend{})
	ctx := context.Background()

	if _, err := svc.ListSlots(ctx, ""); !errors.Is(err, ErrPIVDeviceRequired) {
		t.Errorf("ListSlots: want ErrPIVDeviceRequired, got %v", err)
	}
	if _, err := svc.SlotInfo(ctx, "", ""); !errors.Is(err, ErrPIVSlotRequired) {
		t.Errorf("SlotInfo: want ErrPIVSlotRequired, got %v", err)
	}
	if _, err := svc.Generate(ctx, &PIVGenerateRequest{}); !errors.Is(err, ErrPIVSlotRequired) {
		t.Errorf("Generate: want ErrPIVSlotRequired, got %v", err)
	}
	if err := svc.Import(ctx, &PIVImportRequest{Slot: "9a"}); !errors.Is(err, ErrPIVPrivateKeyRequired) {
		t.Errorf("Import missing key: want ErrPIVPrivateKeyRequired, got %v", err)
	}
	if err := svc.Import(ctx, &PIVImportRequest{}); !errors.Is(err, ErrPIVSlotRequired) {
		t.Errorf("Import missing slot: want ErrPIVSlotRequired, got %v", err)
	}
	if _, err := svc.Sign(ctx, &PIVSignRequest{Slot: "9a"}); !errors.Is(err, ErrPIVPayloadRequired) {
		t.Errorf("Sign missing payload: want ErrPIVPayloadRequired, got %v", err)
	}
	if _, err := svc.Attest(ctx, ""); !errors.Is(err, ErrPIVSlotRequired) {
		t.Errorf("Attest: want ErrPIVSlotRequired, got %v", err)
	}
	if err := svc.Reset(ctx, ""); !errors.Is(err, ErrPIVDeviceRequired) {
		t.Errorf("Reset: want ErrPIVDeviceRequired, got %v", err)
	}
}

func TestPIVService_BackendSuccess(t *testing.T) {
	backend := &fakePIVBackend{
		devices: []PIVDevice{{ID: "dev1", Name: "YubiKey"}},
		slots:   []PIVSlot{{ID: "9a", Name: "auth"}},
	}
	svc := NewPIVService(logging.DefaultLogger(), backend)
	ctx := context.Background()

	d, err := svc.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(d) != 1 || d[0].ID != "dev1" {
		t.Errorf("unexpected devices: %+v", d)
	}
	s, err := svc.ListSlots(ctx, "dev1")
	if err != nil {
		t.Fatalf("ListSlots: %v", err)
	}
	if len(s) != 1 || s[0].ID != "9a" {
		t.Errorf("unexpected slots: %+v", s)
	}
	if _, err := svc.SlotInfo(ctx, "", "9a"); err != nil {
		t.Errorf("SlotInfo: %v", err)
	}
	if _, err := svc.Generate(ctx, &PIVGenerateRequest{Slot: "9a", Algorithm: PIVAlgorithmRSA, PIN: "123456"}); err != nil {
		t.Errorf("Generate: %v", err)
	}
	if err := svc.Import(ctx, &PIVImportRequest{Slot: "9a", PrivateKeyPEM: "pem"}); err != nil {
		t.Errorf("Import: %v", err)
	}
	sig, err := svc.Sign(ctx, &PIVSignRequest{Slot: "9a", Payload: []byte("hello"), PIN: "123456"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != "hello" {
		t.Errorf("Sign: unexpected %q", sig)
	}
	if _, err := svc.Attest(ctx, "9a"); err != nil {
		t.Errorf("Attest: %v", err)
	}
	if err := svc.Reset(ctx, "dev1"); err != nil {
		t.Errorf("Reset: %v", err)
	}
}
