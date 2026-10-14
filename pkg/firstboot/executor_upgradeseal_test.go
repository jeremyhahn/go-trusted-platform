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

// executor_upgradeseal_test.go pins the TPM-Upgrade write half under the
// go-xkms v0.49 seal rule: a sealed object needs a policy or a password
// (go-xkms tpm2 requireSealProtection, ErrSealUnprotected). The upgrade seal
// carries neither, so the TPM refuses it and nothing is written; the
// PCR-bound seal names the platform policy and still seals.

package firstboot

import (
	"context"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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
	return &xkmssdk.KeyAttributes{CN: "ssrk"}, nil
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

func newSealRuleExecutor(tpm *sealRuleTPM) *Executor {
	return &Executor{tpm: tpm, logger: logging.DefaultLogger(), config: DefaultConfig()}
}

// TestCreateSealedObjects_RefusedWithoutPolicyOrPassword asserts the upgrade
// seal writer is refused by the v0.49 TPM and returns no blobs to write.
func TestCreateSealedObjects_RefusedWithoutPolicyOrPassword(t *testing.T) {
	tpm := &sealRuleTPM{}
	executor := newSealRuleExecutor(tpm)

	pub, priv, err := executor.createSealedObjects(context.Background(), []byte("luks-key"))
	if !errors.Is(err, errSealUnprotected) {
		t.Fatalf("createSealedObjects error = %v, want the seal protection refusal", err)
	}
	if pub != nil || priv != nil {
		t.Fatal("a refused upgrade seal must return no blobs")
	}
	if len(tpm.sealed) != 0 {
		t.Fatalf("sealed objects = %v, want none", tpm.sealed)
	}
}

// TestCreatePCRSealedObjects_SealsUnderPlatformPolicy is the control: the
// PCR-bound writer names the platform policy, so the same TPM seals it.
func TestCreatePCRSealedObjects_SealsUnderPlatformPolicy(t *testing.T) {
	tpm := &sealRuleTPM{}
	executor := newSealRuleExecutor(tpm)

	pub, priv, err := executor.createPCRSealedObjects(context.Background(), []byte("luks-key"), []uint{7, 11})
	if err != nil {
		t.Fatalf("createPCRSealedObjects: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatal("PCR seal returned empty blobs")
	}
	if len(tpm.sealed) != 1 || tpm.sealed[0] != "luks-root-pcr" {
		t.Fatalf("sealed objects = %v, want [luks-root-pcr]", tpm.sealed)
	}
}
