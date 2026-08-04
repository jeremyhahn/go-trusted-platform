//go:build azurecompute

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

package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// Azure Trusted Launch attestation is guest-driven (Microsoft Azure
// Attestation): the control plane exposes no vTPM EK / quote API, so both
// attester methods honestly reject with a typed error. These tests pin that
// contract so a future change that silently fabricates a report is caught.

func TestAttestVM_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.AttestVM(context.Background(), "node-01", nil, nil)
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}

func TestAttestVM_EmptyInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.AttestVM(context.Background(), "", nil, nil)
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestVerifyVMAttestation_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.VerifyVMAttestation(context.Background(), "node-01", &compute.VMAttestationEvidence{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}
