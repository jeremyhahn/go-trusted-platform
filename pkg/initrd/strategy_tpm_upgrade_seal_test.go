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

// strategy_tpm_upgrade_seal_test.go pins the initrd TPM-Upgrade writer under
// the go-xkms v0.49 seal rule: a sealed object needs a policy or a password
// (go-xkms tpm2 requireSealProtection, ErrSealUnprotected). The upgrade seal
// carries neither, so the TPM refuses it before any blob reaches the EFI
// partition; the PCR-bound seal names the platform policy and still seals.

package initrd

import (
	"context"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// errSealUnprotected stands in for go-xkms tpm2.ErrSealUnprotected, which the
// quicbaas SDK does not re-export.
var errSealUnprotected = errors.New("tpm: a sealed object needs a policy or a password")

// sealRuleTPM applies the go-xkms v0.49 seal protection rule to every Seal
// call and records the CN of each object it sealed.
type sealRuleTPM struct {
	xkmssdk.TrustedPlatformModule
	sealed []string
}

func (f *sealRuleTPM) Config() *xkmssdk.TPMConfig { return nil }

func (f *sealRuleTPM) KeyAttributes(xkmssdk.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{CN: "srk"}, nil
}

func (f *sealRuleTPM) Seal(_ context.Context, _ []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	attrs := opts.KeyAttributes
	protected := attrs.TPMPolicy != "" ||
		attrs.Password != nil ||
		opts.Password != nil ||
		len(opts.AuthPolicy) > 0 ||
		(attrs.TPMAttributes != nil && len(attrs.TPMAttributes.Template.AuthPolicy.Buffer) > 0)
	if !protected {
		return nil, errSealUnprotected
	}
	f.sealed = append(f.sealed, attrs.CN)
	return &xkmssdk.SealedData{TPMPublic: []byte("public"), TPMPrivate: []byte("private")}, nil
}

// TestTPMUpgradeSealUpgradeKey_RefusedWithoutPolicyOrPassword asserts the
// upgrade seal is refused by the v0.49 TPM, so CreateUpgradeSeal returns
// before writing seal-upgrade.pub/priv.
func TestTPMUpgradeSealUpgradeKey_RefusedWithoutPolicyOrPassword(t *testing.T) {
	tpm := &sealRuleTPM{}
	platform := createTestPlatform()
	platform.TPM = tpm
	strategy := NewTPMUpgradeStrategy(platform, logging.DefaultLogger())

	sealed, err := strategy.sealUpgradeKey([]byte("luks-key"))
	if !errors.Is(err, errSealUnprotected) {
		t.Fatalf("sealUpgradeKey error = %v, want the seal protection refusal", err)
	}
	if sealed != nil {
		t.Fatal("a refused upgrade seal must return no sealed data")
	}
	if len(tpm.sealed) != 0 {
		t.Fatalf("sealed objects = %v, want none", tpm.sealed)
	}
}

// TestTPMNoPCRInstall_RefusedWithoutPolicyOrPassword pins the TPM-NoPCR
// install seal, which nothing reaches in production (no caller of
// Manager.Install or StrategyChain.ExecuteInstall): its object carries
// neither a policy nor a password, so go-xkms v0.49 refuses it.
func TestTPMNoPCRInstall_RefusedWithoutPolicyOrPassword(t *testing.T) {
	tpm := &sealRuleTPM{}
	platform := createTestPlatform()
	platform.TPM = tpm
	strategy := NewTPMNoPCRStrategy(platform, logging.DefaultLogger())

	err := strategy.Install(context.Background(), &luks.VolumeConfig{DevicePath: "/dev/test"}, nil)
	if !errors.Is(err, errSealUnprotected) {
		t.Fatalf("Install error = %v, want the seal protection refusal", err)
	}
	if len(tpm.sealed) != 0 {
		t.Fatalf("sealed objects = %v, want none", tpm.sealed)
	}
}

// TestSealedObjectAttrs_SealsUnderPlatformPolicy is the control: the
// PCR-bound object attributes name the platform policy, so the same TPM
// seals them.
func TestSealedObjectAttrs_SealsUnderPlatformPolicy(t *testing.T) {
	tpm := &sealRuleTPM{}
	attrs := sealedObjectAttrs("luks-root", &xkmssdk.KeyAttributes{CN: "srk"})

	_, err := tpm.Seal(context.Background(), []byte("luks-key"), &xkmssdk.SealOptions{KeyAttributes: attrs})
	if err != nil {
		t.Fatalf("Seal of the PCR-bound object: %v", err)
	}
	if len(tpm.sealed) != 1 || tpm.sealed[0] != attrs.CN {
		t.Fatalf("sealed objects = %v, want [%s]", tpm.sealed, attrs.CN)
	}
}
