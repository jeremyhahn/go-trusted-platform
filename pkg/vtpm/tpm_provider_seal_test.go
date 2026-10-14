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

package vtpm

import (
	"context"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// sealRecordingTPM supports the two calls TPMOperations.Seal makes and
// records the options the seal reached the TPM with.
type sealRecordingTPM struct {
	xkmssdk.TrustedPlatformModule
	sealCalls int
	gotOpts   *xkmssdk.SealOptions
}

func (t *sealRecordingTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{CN: "ssrk"}, nil
}

func (t *sealRecordingTPM) Seal(_ context.Context, _ []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	t.sealCalls++
	t.gotOpts = opts
	return &xkmssdk.SealedData{KeyID: opts.KeyAttributes.CN}, nil
}

// A PCR selection without a policy digest would be sealed as a
// password-only object, so the seal must never reach the TPM.
func TestTPMOperations_Seal_RefusesPCRBoundSeal(t *testing.T) {
	tpm := &sealRecordingTPM{}
	ops := &TPMOperations{tpm: tpm}

	_, err := ops.Seal(context.Background(), []byte("secret"), []int{7}, "auth")

	if !errors.As(err, &common.ErrPCRBoundSealUnavailable{}) {
		t.Fatalf("Seal error = %v, want ErrPCRBoundSealUnavailable", err)
	}
	if tpm.sealCalls != 0 {
		t.Errorf("the TPM sealed %d object(s) for a refused PCR-bound request", tpm.sealCalls)
	}
}

func TestTPMOperations_Seal_PasswordOnlySealReachesTPM(t *testing.T) {
	tpm := &sealRecordingTPM{}
	ops := &TPMOperations{tpm: tpm}

	sealed, err := ops.Seal(context.Background(), []byte("secret"), nil, "auth")

	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed.KeyID != "vtpm-sealed-data" {
		t.Errorf("KeyID = %q, want vtpm-sealed-data", sealed.KeyID)
	}
	attrs := tpm.gotOpts.KeyAttributes
	if attrs.Password == nil || string(attrs.Password.Bytes()) != "auth" {
		t.Error("the auth value must become the object's password")
	}
	if attrs.Parent == nil || attrs.Parent.CN != "ssrk" {
		t.Error("the sealed object must be parented on the SSRK")
	}
	if len(attrs.TPMAttributes.PCRSelection.PCRSelections) != 0 {
		t.Error("a password-only seal must not carry a PCR selection")
	}
}

// The refusal must survive the service's ErrTPMSealFailed wrapping so
// every transport can map it.
func TestService_Seal_RefusesPCRBoundSeal(t *testing.T) {
	service, err := NewService(createTestConfig(t), nil, &mockCA{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	tpm := &sealRecordingTPM{}
	service.instances["pcr-bound"] = &runningInstance{tpmOps: &TPMOperations{tpm: tpm}}

	_, err = service.Seal(context.Background(), "pcr-bound", []byte("secret"), &SealOptions{PCRs: []int{0, 7}, AuthValue: "auth"})

	if !errors.As(err, &common.ErrPCRBoundSealUnavailable{}) {
		t.Fatalf("Seal error = %v, want ErrPCRBoundSealUnavailable", err)
	}
	var sealFailed ErrTPMSealFailed
	if !errors.As(err, &sealFailed) || sealFailed.BundleID != "pcr-bound" {
		t.Errorf("Seal error = %v, want ErrTPMSealFailed for bundle pcr-bound", err)
	}
	if tpm.sealCalls != 0 {
		t.Errorf("the TPM sealed %d object(s) for a refused PCR-bound request", tpm.sealCalls)
	}
}
