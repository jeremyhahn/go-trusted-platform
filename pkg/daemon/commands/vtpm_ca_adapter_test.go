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

package commands

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// fakeEKCA embeds the full CACertificateAuthority interface so only
// IssueEKCertificate needs a real implementation; any other method call would
// panic on the nil embedded interface, catching accidental extra usage.
type fakeEKCA struct {
	quicbaasca.CACertificateAuthority

	gotReq    *quicbaasca.CACertificateRequest
	gotPub    crypto.PublicKey
	returnCrt *x509.Certificate
	returnErr error
}

func (f *fakeEKCA) IssueEKCertificate(
	_ context.Context,
	req *quicbaasca.CACertificateRequest,
	pub crypto.PublicKey,
) (*x509.Certificate, error) {
	f.gotReq = req
	f.gotPub = pub
	return f.returnCrt, f.returnErr
}

func TestNewVTPMCAAdapter_NilCAYieldsNilInterface(t *testing.T) {
	if adapter := newVTPMCAAdapter(nil); adapter != nil {
		t.Fatalf("expected nil interface for nil CA, got %#v", adapter)
	}
}

func TestVTPMCAAdapter_IssueEKCertificate_Success(t *testing.T) {
	want := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "node-01"},
	}
	fake := &fakeEKCA{returnCrt: want}

	adapter := newVTPMCAAdapter(fake)
	if adapter == nil {
		t.Fatal("expected non-nil adapter for non-nil CA")
	}

	pub := crypto.PublicKey([]byte("ek-public-key"))
	got, err := adapter.IssueEKCertificate(context.Background(), pub, "node-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected returned certificate to be passed through, got %#v", got)
	}
	if fake.gotReq == nil || fake.gotReq.Subject.CommonName != "node-01" {
		t.Fatalf("expected subject common name node-01, got %#v", fake.gotReq)
	}
	if _, ok := fake.gotPub.([]byte); !ok {
		t.Fatalf("expected EK public key to be forwarded, got %#v", fake.gotPub)
	}
}

func TestVTPMCAAdapter_IssueEKCertificate_CAError(t *testing.T) {
	sentinel := errors.New("ca refused issuance")
	fake := &fakeEKCA{returnErr: sentinel}

	adapter := newVTPMCAAdapter(fake)
	if _, err := adapter.IssueEKCertificate(context.Background(), nil, "node-01"); !errors.Is(err, sentinel) {
		t.Fatalf("expected CA error to propagate, got %v", err)
	}
}

func TestVTPMCAAdapter_IssueEKCertificate_NilCAGuard(t *testing.T) {
	adapter := &vtpmCAAdapter{ca: nil}
	_, err := adapter.IssueEKCertificate(context.Background(), nil, "node-01")
	var nilErr ErrNilVTPMCA
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected ErrNilVTPMCA, got %v", err)
	}
}
