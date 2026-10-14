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

package backends

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	luks "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/luks"
)

// These tests cover the thin platform wiring around the canonical go-xkms
// TPM LUKS sealer (reached through the QuicBaaS SDK). The sealer's own
// behaviour — token encoding, PCR policy digests, and the simulator-backed
// seal/unseal round-trips — is tested upstream in go-xkms/pkg/luks.

func TestNewLUKSTPMHandler_NilTPM(t *testing.T) {
	_, err := NewLUKSTPMHandler(nil, LUKSTPMSealerConfig{})
	if !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestNewLUKSTPMHandler_InvalidPCRBank(t *testing.T) {
	_, err := NewLUKSTPMHandler(&fakeLUKSTPM{}, LUKSTPMSealerConfig{
		Parent:  luks.SealParentSSRK,
		PCRBank: "md5",
	})
	if !errors.Is(err, luks.ErrInvalidPCRBank) {
		t.Fatalf("expected ErrInvalidPCRBank, got %v", err)
	}
}

func TestLUKSTPMHandler_PlatformSeal(t *testing.T) {
	tpm := &fakeLUKSTPM{}
	h, err := NewLUKSTPMHandler(tpm, LUKSTPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	var handler LUKSTPMHandler = h

	res, err := handler.SealPassphrase(context.Background(), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	defer res.Passphrase.Destroy()

	if res.Token == nil || res.Token.Type != LUKSXKMSTPMTokenType {
		t.Fatalf("expected a %q token, got %+v", LUKSXKMSTPMTokenType, res.Token)
	}
	if res.Passphrase.Size() != 32 {
		t.Fatalf("expected a 32-byte passphrase, got %d", res.Passphrase.Size())
	}
	if tpm.sealOpts == nil || tpm.sealOpts.KeyAttributes == nil ||
		tpm.sealOpts.KeyAttributes.Parent != tpm.platformSRK() {
		t.Fatalf("expected the seal to be parented to the Platform SRK, got %+v", tpm.sealOpts)
	}
}

func TestLUKSTPMHandler_PlatformSeal_RefusesPCRs(t *testing.T) {
	h, err := NewLUKSTPMHandler(&fakeLUKSTPM{}, LUKSTPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, err = h.SealPassphrase(context.Background(), []int32{7}); !errors.Is(err, ErrLUKSTPMPCRSelectionNotSupported) {
		t.Fatalf("expected ErrLUKSTPMPCRSelectionNotSupported, got %v", err)
	}
}

func TestLUKSTPMHandler_SealFailure_Surfaces(t *testing.T) {
	tpmErr := errors.New("tpm busy")
	h, err := NewLUKSTPMHandler(&fakeLUKSTPM{sealErr: tpmErr}, LUKSTPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	_, err = h.SealPassphrase(context.Background(), nil)
	if !errors.Is(err, ErrLUKSTPMSealFailed) || !errors.Is(err, tpmErr) {
		t.Fatalf("expected ErrLUKSTPMSealFailed wrapping the TPM error, got %v", err)
	}
}

func TestLUKSTPMHandler_Unseal_NilToken(t *testing.T) {
	h, err := NewLUKSTPMHandler(&fakeLUKSTPM{}, LUKSTPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, err = h.UnsealPassphrase(context.Background(), nil); !errors.Is(err, ErrLUKSTPMInvalidToken) {
		t.Fatalf("expected ErrLUKSTPMInvalidToken, got %v", err)
	}
}

// fakeLUKSTPM is an in-process LUKSTPM: Seal records its options and returns
// fixed blobs (or sealErr), so the wiring is exercised without a TPM.
type fakeLUKSTPM struct {
	sealErr  error
	sealOpts *xkmssdk.SealOptions
	srk      *xkmssdk.KeyAttributes
}

func (f *fakeLUKSTPM) platformSRK() *xkmssdk.KeyAttributes {
	if f.srk == nil {
		f.srk = &xkmssdk.KeyAttributes{CN: "platform-srk"}
	}
	return f.srk
}

func (f *fakeLUKSTPM) Seal(_ context.Context, _ []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	f.sealOpts = opts
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return &xkmssdk.SealedData{TPMPublic: []byte("public"), TPMPrivate: []byte("private")}, nil
}

func (f *fakeLUKSTPM) Unseal(context.Context, *xkmssdk.SealedData, *xkmssdk.UnsealOptions) ([]byte, error) {
	return nil, errors.New("fakeLUKSTPM: unseal not exercised")
}

func (f *fakeLUKSTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return f.platformSRK(), nil
}

func (f *fakeLUKSTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{CN: "ssrk"}, nil
}

func (f *fakeLUKSTPM) Transport() transport.TPM { return nil }
