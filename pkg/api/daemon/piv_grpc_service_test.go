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

func newPIVGRPC(backend PIVBackend) *PIVGRPCService {
	return NewPIVGRPCService(logging.DefaultLogger(), NewPIVService(logging.DefaultLogger(), backend))
}

func TestPIVGRPC_Unavailable(t *testing.T) {
	svc := newPIVGRPC(nil)
	_, err := svc.ListDevices(context.Background(), &platformv1.PIVListDevicesRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Errorf("code = %v", st.Code())
	}
}

func TestPIVGRPC_InvalidArgument(t *testing.T) {
	svc := newPIVGRPC(&fakePIVBackend{})
	_, err := svc.ListSlots(context.Background(), &platformv1.PIVListSlotsRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v", st.Code())
	}
}

func TestPIVGRPC_Success(t *testing.T) {
	backend := &fakePIVBackend{
		devices: []PIVDevice{{ID: "dev1"}},
		slots:   []PIVSlot{{ID: "9a", Algorithm: PIVAlgorithmRSA, HasKey: true}},
	}
	svc := newPIVGRPC(backend)
	ctx := context.Background()

	dev, err := svc.ListDevices(ctx, &platformv1.PIVListDevicesRequest{})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(dev.GetDevices()) != 1 || dev.GetDevices()[0].GetId() != "dev1" {
		t.Errorf("unexpected: %+v", dev)
	}

	slots, err := svc.ListSlots(ctx, &platformv1.PIVListSlotsRequest{Device: "dev1"})
	if err != nil {
		t.Fatalf("ListSlots: %v", err)
	}
	if len(slots.GetSlots()) != 1 {
		t.Errorf("slots: %+v", slots)
	}
	if slots.GetSlots()[0].GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA {
		t.Errorf("algo: %v", slots.GetSlots()[0].GetAlgorithm())
	}

	gen, err := svc.Generate(ctx, &platformv1.PIVGenerateRequest{
		Slot:      "9a",
		Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA,
		Pin:       "111111",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.GetPublicKeyPem() == "" {
		t.Error("empty public key")
	}

	imp, err := svc.Import(ctx, &platformv1.PIVImportRequest{Slot: "9a", PrivateKeyPem: "pem"})
	if err != nil || !imp.GetImported() {
		t.Errorf("Import: %v %+v", err, imp)
	}

	sig, err := svc.Sign(ctx, &platformv1.PIVSignRequest{Slot: "9a", Payload: []byte("data")})
	if err != nil || string(sig.GetSignature()) != "data" {
		t.Errorf("Sign: %v %+v", err, sig)
	}

	at, err := svc.Attest(ctx, &platformv1.PIVAttestRequest{Slot: "9a"})
	if err != nil || at.GetAttestationCertPem() != "CERT" {
		t.Errorf("Attest: %v %+v", err, at)
	}

	rs, err := svc.Reset(ctx, &platformv1.PIVResetRequest{Device: "dev1"})
	if err != nil || !rs.GetReset_() {
		t.Errorf("Reset: %v %+v", err, rs)
	}
}
