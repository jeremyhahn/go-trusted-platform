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

package webservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// trustCallerAnchors is exercised through the same package-private seam
// requestOptionalClientCert is, with a registry stub that carries only the
// method under test; the rest of RestHandlerRegistry is irrelevant here.
type anchorsRegistry struct {
	v1.RestHandlerRegistry
	rep *restattestation.Reporting
}

func (r *anchorsRegistry) AttestationReporting() *restattestation.Reporting { return r.rep }

type fixedPolicy struct {
	anchors []*x509.Certificate
}

func (p fixedPolicy) Evaluate(_ context.Context, _ *calleradmission.Peer) calleradmission.Decision {
	return calleradmission.Decision{}
}
func (p fixedPolicy) Describe() calleradmission.Description { return calleradmission.Description{} }
func (p fixedPolicy) Anchors() []*x509.Certificate          { return p.anchors }

func TestTrustCallerAnchors_AddsPolicyAnchorsToClientCAs(t *testing.T) {
	anchor := &x509.Certificate{Raw: []byte{1, 2, 3}, RawSubject: []byte("anchor"), Subject: pkix.Name{CommonName: "root-ca.cp.example.io"}}
	own := &x509.Certificate{Raw: []byte{4, 5, 6}, RawSubject: []byte("own"), Subject: pkix.Name{CommonName: "ca01.compute.example.io"}}
	ownPool := x509.NewCertPool()
	ownPool.AddCert(own)

	server := &WebServerV1{restServiceRegistry: &anchorsRegistry{rep: &restattestation.Reporting{Policy: fixedPolicy{anchors: []*x509.Certificate{anchor}}}}}
	cfg := server.trustCallerAnchors(&tls.Config{ClientCAs: ownPool, ClientAuth: tls.NoClientCert})

	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if !poolHas(cfg.ClientCAs, anchor) || !poolHas(cfg.ClientCAs, own) {
		t.Fatalf("ClientCAs must hold the node's own CA and the caller anchors")
	}
	if poolHas(ownPool, anchor) {
		t.Fatalf("the CA's own pool must not be mutated")
	}
}

func TestTrustCallerAnchors_NoPolicyOrNoAnchorsLeavesConfigAlone(t *testing.T) {
	ownPool := x509.NewCertPool()
	base := &tls.Config{ClientCAs: ownPool}

	server := &WebServerV1{restServiceRegistry: &anchorsRegistry{}}
	if got := server.trustCallerAnchors(base); got != base || got.ClientCAs != ownPool {
		t.Fatalf("nil reporting must be a no-op")
	}
	server = &WebServerV1{restServiceRegistry: &anchorsRegistry{rep: &restattestation.Reporting{Policy: fixedPolicy{}}}}
	if got := server.trustCallerAnchors(base); got.ClientCAs != ownPool {
		t.Fatalf("a policy with no anchors must be a no-op")
	}
	server = &WebServerV1{}
	if got := server.trustCallerAnchors(nil); got != nil {
		t.Fatalf("nil config must stay nil")
	}
}

func TestTrustCallerAnchors_CreatesAPoolWhenTheCAGaveNone(t *testing.T) {
	anchor := &x509.Certificate{Raw: []byte{9}, RawSubject: []byte("a"), Subject: pkix.Name{CommonName: "root"}}
	server := &WebServerV1{restServiceRegistry: &anchorsRegistry{rep: &restattestation.Reporting{Policy: fixedPolicy{anchors: []*x509.Certificate{anchor}}}}}
	cfg := server.trustCallerAnchors(&tls.Config{})
	if cfg.ClientCAs == nil || !poolHas(cfg.ClientCAs, anchor) {
		t.Fatalf("a pool must be created for the anchors")
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("certificates must be requested once there is something to verify them against")
	}
}

func poolHas(pool *x509.CertPool, cert *x509.Certificate) bool {
	for _, subject := range pool.Subjects() { //nolint:staticcheck // enumeration is the point of this test
		if string(subject) == string(cert.RawSubject) {
			return true
		}
	}
	return false
}
