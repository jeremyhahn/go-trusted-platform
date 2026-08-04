//go:build gcpcompute

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

package gcp

import (
	"bytes"
	"context"
	"errors"
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func TestAttestVM_Happy(t *testing.T) {
	identity := ekIdentity(t)
	inst := runningInstance("node-01")
	client := &fakeGCE{
		getInstance: func(context.Context, string) (*computepb.Instance, error) {
			return inst, nil
		},
		shieldedIdentity: func(context.Context, string) (*computepb.ShieldedInstanceIdentity, error) {
			return identity, nil
		},
	}
	o := newTestOrchestrator(t, client)

	report, err := o.AttestVM(context.Background(), "node-01", nil, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if len(report.AKPublicKey) == 0 {
		t.Error("expected EK public key in report")
	}
	if len(report.Nonce) == 0 {
		t.Error("expected generated nonce")
	}
	if report.VMID != "node-01" || report.VMName != "node-01" {
		t.Errorf("report identity = %+v", report)
	}
}

func TestAttestVM_EchoesNonce(t *testing.T) {
	identity := ekIdentity(t)
	inst := runningInstance("node-01")
	client := &fakeGCE{
		getInstance:      func(context.Context, string) (*computepb.Instance, error) { return inst, nil },
		shieldedIdentity: func(context.Context, string) (*computepb.ShieldedInstanceIdentity, error) { return identity, nil },
	}
	o := newTestOrchestrator(t, client)
	nonce := []byte("caller-supplied-nonce")
	report, err := o.AttestVM(context.Background(), "node-01", nonce, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if !bytes.Equal(report.Nonce, nonce) {
		t.Errorf("nonce = %x, want %x", report.Nonce, nonce)
	}
}

func TestAttestVM_NotRunning(t *testing.T) {
	inst := runningInstance("node-01")
	inst.Status = ptr(statusTerminated)
	client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
		return inst, nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.AttestVM(context.Background(), "node-01", nil, nil)
	if !errors.Is(err, compute.ErrVTPMNotAvailable) {
		t.Fatalf("err = %v, want ErrVTPMNotAvailable", err)
	}
}

func TestAttestVM_BadEK(t *testing.T) {
	inst := runningInstance("node-01")
	client := &fakeGCE{
		getInstance: func(context.Context, string) (*computepb.Instance, error) { return inst, nil },
		shieldedIdentity: func(context.Context, string) (*computepb.ShieldedInstanceIdentity, error) {
			return &computepb.ShieldedInstanceIdentity{
				EncryptionKey: &computepb.ShieldedInstanceIdentityEntry{EkPub: ptr("!!!not-pem!!!")},
			}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	_, err := o.AttestVM(context.Background(), "node-01", nil, nil)
	if !errors.Is(err, ErrEndorsementKey) {
		t.Fatalf("err = %v, want ErrEndorsementKey", err)
	}
}

func TestAttestVM_EmptyEK(t *testing.T) {
	inst := runningInstance("node-01")
	client := &fakeGCE{
		getInstance: func(context.Context, string) (*computepb.Instance, error) { return inst, nil },
		shieldedIdentity: func(context.Context, string) (*computepb.ShieldedInstanceIdentity, error) {
			return &computepb.ShieldedInstanceIdentity{}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	_, err := o.AttestVM(context.Background(), "node-01", nil, nil)
	if !errors.Is(err, ErrEndorsementKey) {
		t.Fatalf("err = %v, want ErrEndorsementKey", err)
	}
}

func TestAttestVM_EmptyInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	_, err := o.AttestVM(context.Background(), "", nil, nil)
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestVerifyVMAttestation_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	_, err := o.VerifyVMAttestation(context.Background(), "node-01", &compute.VMAttestationEvidence{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}
