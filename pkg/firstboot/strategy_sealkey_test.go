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

package firstboot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// configuredSealRuleTPM is a sealRuleTPM that also answers a TPM config,
// which sealKeyToTPM reads to write pcr-banks after sealing.
type configuredSealRuleTPM struct {
	*sealRuleTPM
}

func (f configuredSealRuleTPM) Config() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		SSRK:        &xkmssdk.SRKConfig{Handle: 0x81000001},
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000002, PlatformPolicy: true},
	}
}

// TestSealKeyToTPM_SealsUnderPlatformPolicy: the production firstboot LUKS
// seal carries the platform policy on its object, so go-xkms v0.49's seal
// protection rule accepts it and the blobs reach the EFI partition.
func TestSealKeyToTPM_SealsUnderPlatformPolicy(t *testing.T) {
	tpm := &sealRuleTPM{}
	config := DefaultConfig()
	config.PCRSelection = []uint{7, 11}
	executor := &Executor{tpm: configuredSealRuleTPM{tpm}, logger: logging.DefaultLogger(), config: config}
	strategy := NewFirstbootSealStrategy(executor, nil, logging.DefaultLogger())
	efi := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(efi, strategySealPub)), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := strategy.sealKeyToTPM(context.Background(), []byte("luks-key"), efi); err != nil {
		t.Fatalf("sealKeyToTPM: %v", err)
	}
	if len(tpm.sealed) != 1 || tpm.sealed[0] != "luks-root" {
		t.Fatalf("sealed objects = %v, want [luks-root]", tpm.sealed)
	}
	for _, name := range []string{strategySealPub, strategySealPriv, strategyPCRBanks} {
		if _, err := os.Stat(filepath.Join(efi, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}

// TestSealKeyToTPM_NoTPM: without a TPM nothing is sealed.
func TestSealKeyToTPM_NoTPM(t *testing.T) {
	executor := &Executor{logger: logging.DefaultLogger(), config: DefaultConfig()}
	strategy := NewFirstbootSealStrategy(executor, nil, logging.DefaultLogger())

	if err := strategy.sealKeyToTPM(context.Background(), []byte("luks-key"), t.TempDir()); err != ErrTPMNotAvailable {
		t.Fatalf("sealKeyToTPM error = %v, want ErrTPMNotAvailable", err)
	}
}
