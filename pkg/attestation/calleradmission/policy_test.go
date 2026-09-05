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

package calleradmission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA is a throwaway issuing authority for one test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool []*x509.Certificate
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pool: []*x509.Certificate{cert}}
}

// issue signs a client-auth leaf carrying cn and dnsNames. clientAuth=false
// issues a server-only certificate.
func (ca *testCA) issue(t *testing.T, cn string, dnsNames []string, clientAuth bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if clientAuth {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

type recordingAuditor struct {
	decisions []Decision
	err       error
}

func (a *recordingAuditor) RecordAdmission(_ context.Context, d Decision) error {
	a.decisions = append(a.decisions, d)
	return a.err
}

type stubAttested struct {
	byName map[string]PeerAttestation
}

func (s *stubAttested) PeerAttestation(names []string) (PeerAttestation, bool) {
	for _, n := range names {
		if a, ok := s.byName[n]; ok {
			return a, true
		}
	}
	return PeerAttestation{}, false
}

func peerOf(cert *x509.Certificate) *Peer {
	return &Peer{Leaf: cert, RemoteAddr: "192.0.2.10:4242"}
}

func TestNew_RejectsUnknownStrategy(t *testing.T) {
	_, err := New(Config{Strategy: "everyone"})
	require.Error(t, err)
	var unknown ErrUnknownStrategy
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "everyone", unknown.Strategy)
	assert.Contains(t, unknown.Error(), "everyone")
}

func TestNew_CompilesEveryStrategy(t *testing.T) {
	for _, s := range []Strategy{StrategyReportingServers, StrategyAnyAttested, StrategyAllowlist} {
		p, err := New(Config{Strategy: s})
		require.NoError(t, err, string(s))
		assert.Equal(t, s, p.Strategy())
		assert.Empty(t, p.Anchors())
	}
}

func TestPeerFromTLS(t *testing.T) {
	_, ok := PeerFromTLS(nil, "a")
	assert.False(t, ok)
	_, ok = PeerFromTLS(&tls.ConnectionState{}, "a")
	assert.False(t, ok)
	_, ok = PeerFromTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}}, "a")
	assert.False(t, ok)

	ca := newTestCA(t, "root")
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	peer, ok := PeerFromTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca.cert}}, "192.0.2.1:1")
	require.True(t, ok)
	assert.Same(t, leaf, peer.Leaf)
	assert.Len(t, peer.Intermediates, 1)
	assert.Equal(t, "192.0.2.1:1", peer.RemoteAddr)
}

func TestNames_SANsFirstCNOnlyWithoutSANs(t *testing.T) {
	assert.Nil(t, Names(nil))
	ca := newTestCA(t, "root")
	withSANs := ca.issue(t, " CP.Example.Internal ", []string{"cp.example.io", "CP.example.internal", ""}, true)
	assert.Equal(t, []string{"cp.example.internal", "cp.example.io"}, Names(withSANs))

	// A CN that disagrees with the SANs is not an identity.
	disagreeing := ca.issue(t, "other.example.internal", []string{"cp.example.io"}, true)
	assert.Equal(t, []string{"cp.example.io"}, Names(disagreeing))

	cnOnly := ca.issue(t, " Legacy.Example.Internal ", nil, true)
	assert.Equal(t, []string{"legacy.example.internal"}, Names(cnOnly))
}

func TestEvaluate_CNDoesNotMatchWhenSANsArePresent(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          ca.pool,
	})
	require.NoError(t, err)
	// CN names the reporting server; the SAN does not. SANs decide.
	leaf := ca.issue(t, "cp.example.internal", []string{"www.example.io"}, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonNotListed, d.Reason)
	assert.Equal(t, "www.example.io", d.Identity)
}

func TestEvaluate_ReportingServersAdmitsConfiguredIdentity(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	audit := &recordingAuditor{}
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"CP.example.internal"},
		Anchors:          ca.pool,
		Auditor:          audit,
	})
	require.NoError(t, err)

	leaf := ca.issue(t, "cp.example.io", []string{"cp.example.internal"}, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.True(t, d.Admitted)
	assert.Equal(t, ReasonAdmitted, d.Reason)
	assert.Equal(t, "cp.example.internal", d.Identity, "the identity is the first SAN, not the CN")
	assert.Equal(t, StrategyReportingServers, d.Strategy)
	assert.Equal(t, "192.0.2.10:4242", d.RemoteAddr)
	assert.False(t, d.At.IsZero())
	require.Len(t, audit.decisions, 1)
	assert.True(t, audit.decisions[0].Admitted)
}

func TestEvaluate_RefusesUnlistedIdentityEvenWithValidChain(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	audit := &recordingAuditor{}
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          ca.pool,
		Auditor:          audit,
	})
	require.NoError(t, err)

	leaf := ca.issue(t, "rogue.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonNotListed, d.Reason)
	assert.False(t, d.Reason.SecurityRelevant())
	require.Len(t, audit.decisions, 1)
	assert.Equal(t, ReasonNotListed, audit.decisions[0].Reason)
}

func TestEvaluate_RefusesCertificateFromAnotherIssuer(t *testing.T) {
	platform := newTestCA(t, "platform-root")
	other := newTestCA(t, "some-other-root")
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          platform.pool,
	})
	require.NoError(t, err)

	// Right name, wrong issuer: the name must never rescue the chain.
	leaf := other.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonUntrustedIssuer, d.Reason)
	assert.Contains(t, d.Detail, "does not chain")
}

func TestEvaluate_RefusesServerOnlyCertificate(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          ca.pool,
	})
	require.NoError(t, err)

	leaf := ca.issue(t, "cp.example.internal", nil, false)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonUntrustedIssuer, d.Reason)
}

func TestEvaluate_RefusesEverythingWithoutAnchors(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
	})
	require.NoError(t, err)
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonNoAnchors, d.Reason)
	assert.True(t, p.Describe().AdmitsNobody)
}

func TestEvaluate_RefusesNilPeerAndNamelessCertificate(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{Strategy: StrategyReportingServers, ReportingServers: []string{"x"}, Anchors: ca.pool})
	require.NoError(t, err)

	d := p.Evaluate(context.Background(), nil)
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonNoIdentity, d.Reason)

	d = p.Evaluate(context.Background(), &Peer{})
	assert.Equal(t, ReasonNoIdentity, d.Reason)

	nameless := ca.issue(t, "", nil, true)
	d = p.Evaluate(context.Background(), peerOf(nameless))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonNoIdentity, d.Reason)
	assert.Empty(t, d.Identity)
}

func TestEvaluate_AllowlistEmptyRefusesEveryone(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{Strategy: StrategyAllowlist, Anchors: ca.pool})
	require.NoError(t, err)
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonListEmpty, d.Reason)
	desc := p.Describe()
	assert.True(t, desc.AdmitsNobody)
	assert.True(t, desc.ListValid)
	assert.Empty(t, desc.Identities)
	assert.Equal(t, "configured", desc.IdentitiesSource)
}

func TestEvaluate_AllowlistUnparseableRefusesEveryone(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:  StrategyAllowlist,
		Allowlist: []string{"cp.example.internal", "not a host name", "-bad.example", "ok.example", "a..b"},
		Anchors:   ca.pool,
	})
	require.NoError(t, err)

	// A listed, perfectly-chained host is still refused: the list as a whole
	// is untrustworthy once any entry is unparseable.
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonListInvalid, d.Reason)
	assert.Contains(t, d.Detail, "not a host name")

	desc := p.Describe()
	assert.False(t, desc.ListValid)
	assert.True(t, desc.AdmitsNobody)
	assert.ElementsMatch(t, []string{"not a host name", "-bad.example", "a..b"}, desc.InvalidEntries)
	assert.Equal(t, []string{"cp.example.internal", "ok.example"}, desc.Identities)
}

func TestEvaluate_AllowlistAdmitsListedHostAndAcceptsIPLiterals(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:  StrategyAllowlist,
		Allowlist: []string{" Reporting-01.Example.Internal ", "192.0.2.5", "2001:db8::1"},
		Anchors:   ca.pool,
	})
	require.NoError(t, err)
	leaf := ca.issue(t, "reporting-01.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.True(t, d.Admitted)
	assert.Equal(t, ReasonAdmitted, d.Reason)
	assert.Equal(t, []string{"192.0.2.5", "2001:db8::1", "reporting-01.example.internal"}, p.Describe().Identities)
}

func TestEvaluate_AnyAttestedWithoutEvidenceSourceRefusesEveryone(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{Strategy: StrategyAnyAttested, Anchors: ca.pool})
	require.NoError(t, err)
	leaf := ca.issue(t, "node-07.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonGateUnavailable, d.Reason)
	assert.Contains(t, d.Detail, "go-qrdb#278")
	desc := p.Describe()
	assert.True(t, desc.AdmitsNobody)
	assert.False(t, desc.AttestedPeersAvailable)
	assert.Nil(t, desc.Identities)
	assert.True(t, desc.ListValid)
}

func TestEvaluate_AnyAttestedDistinguishesFreshFailedStaleAndUnknown(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	src := &stubAttested{byName: map[string]PeerAttestation{
		"fresh.example.internal":  {Verified: true, Fresh: true},
		"failed.example.internal": {Verified: false, Fresh: true},
		"stale.example.internal":  {Verified: true, Fresh: false},
	}}
	p, err := New(Config{Strategy: StrategyAnyAttested, Anchors: ca.pool, AttestedPeers: src})
	require.NoError(t, err)

	cases := []struct {
		cn       string
		admitted bool
		reason   Reason
		security bool
	}{
		{"fresh.example.internal", true, ReasonAdmitted, false},
		{"failed.example.internal", false, ReasonNotAttested, true},
		{"stale.example.internal", false, ReasonStale, true},
		{"unknown.example.internal", false, ReasonNotAttested, true},
	}
	for _, tc := range cases {
		t.Run(tc.cn, func(t *testing.T) {
			leaf := ca.issue(t, tc.cn, nil, true)
			d := p.Evaluate(context.Background(), peerOf(leaf))
			assert.Equal(t, tc.admitted, d.Admitted)
			assert.Equal(t, tc.reason, d.Reason)
			assert.Equal(t, tc.security, d.Reason.SecurityRelevant())
		})
	}
	desc := p.Describe()
	assert.False(t, desc.AdmitsNobody)
	assert.True(t, desc.AttestedPeersAvailable)
}

func TestEvaluate_AuditFailureDoesNotChangeTheDecision(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	audit := &recordingAuditor{err: errors.New("disk full")}
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          ca.pool,
		Auditor:          audit,
	})
	require.NoError(t, err)
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.True(t, d.Admitted)
	require.Len(t, audit.decisions, 1)
}

func TestEvaluate_ExpiredCertificateIsRefusedByTheClock(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:         StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          ca.pool,
		Now:              func() time.Time { return time.Now().Add(48 * time.Hour) },
	})
	require.NoError(t, err)
	leaf := ca.issue(t, "cp.example.internal", nil, true)
	d := p.Evaluate(context.Background(), peerOf(leaf))
	assert.False(t, d.Admitted)
	assert.Equal(t, ReasonUntrustedIssuer, d.Reason)
}

func TestDescribe_ReportsSourcesAndAnchors(t *testing.T) {
	ca := newTestCA(t, "platform-root")
	p, err := New(Config{
		Strategy:               StrategyReportingServers,
		ReportingServers:       []string{"cp.example.internal"},
		ReportingServersSource: "derived:acme.client.directory",
		Anchors:                ca.pool,
		AnchorSource:           "idevid-issuer",
	})
	require.NoError(t, err)
	desc := p.Describe()
	assert.Equal(t, StrategyReportingServers, desc.Strategy)
	assert.Equal(t, []string{"cp.example.internal"}, desc.Identities)
	assert.Equal(t, "derived:acme.client.directory", desc.IdentitiesSource)
	assert.True(t, desc.AnchorsConfigured)
	assert.Equal(t, "idevid-issuer", desc.AnchorSource)
	assert.False(t, desc.AdmitsNobody)
	assert.Equal(t, ca.pool, p.Anchors())
	nilOnly, err := New(Config{Strategy: StrategyAllowlist, Allowlist: []string{"a"}, Anchors: []*x509.Certificate{nil}})
	require.NoError(t, err)
	assert.Empty(t, nilOnly.Anchors())
	assert.True(t, nilOnly.Describe().AdmitsNobody)
}

func TestValidHostIdentity(t *testing.T) {
	assert.True(t, validHostIdentity("cp.example.internal"))
	assert.True(t, validHostIdentity("node-01"))
	assert.True(t, validHostIdentity("10.0.0.1"))
	assert.False(t, validHostIdentity(""))
	assert.False(t, validHostIdentity("-leading.example"))
	assert.False(t, validHostIdentity("trailing-.example"))
	assert.False(t, validHostIdentity("under_score.example"))
	assert.False(t, validHostIdentity("*.example.internal"))
	assert.False(t, validHostIdentity("a..b"))
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	assert.False(t, validHostIdentity(long+".example"))
}

func TestErrChainVerification_Unwraps(t *testing.T) {
	cause := errors.New("boom")
	err := ErrChainVerification{Cause: cause}
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "boom")
}
