// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// tcgVerifiedTPMRestricted is tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3),
// taken from the SDK re-export so the fixture stamps exactly the arc the
// verifier looks for. go-xkms pins the literal against the TCG registry.
var tcgVerifiedTPMRestricted = quicbaasca.TCGVerifiedTPMRestrictedPolicy

// attestTestCA is a two-tier test CA (root -> intermediate) that issues
// attestation-key certificates with or without the Restricted policy.
type attestTestCA struct {
	root            *x509.Certificate
	rootKey         *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
	now             time.Time
}

func newAttestTestCA(t *testing.T) *attestTestCA {
	t.Helper()
	// The clock is the real time at fixture construction, not a wall-clock
	// constant: paths such as DeviceQuoteVerifierForReporting and the
	// collector build their verifier with the production clock, so a fixed
	// date here expires the certificates the moment the calendar passes it
	// (#506). Every certificate window below is relative to this instant.
	now := time.Now().UTC().Truncate(time.Second)
	ca := &attestTestCA{now: now}

	ca.rootKey = newECKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ca.root = selfSign(t, rootTmpl, ca.rootKey)

	ca.intermediateKey = newECKey(t)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, intTmpl, ca.root, &ca.intermediateKey.PublicKey, ca.rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	ca.intermediate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return ca
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	return key
}

func selfSign(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

// issueAK issues an attestation-key certificate for pub from the
// intermediate. restricted controls whether tcg-cap-verifiedTPMRestricted
// is stamped.
func (ca *attestTestCA) issueAK(t *testing.T, pub *rsa.PublicKey, restricted bool) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "iak"},
		NotBefore:    ca.now.Add(-time.Hour),
		NotAfter:     ca.now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if restricted {
		tmpl.Policies = []x509.OID{tcgVerifiedTPMRestricted}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.intermediate, pub, ca.intermediateKey)
	if err != nil {
		t.Fatalf("issue AK: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeAKTrust is an AKTrustAnchor backed by a test CA. rootErr simulates a CA
// whose root cannot be read.
type fakeAKTrust struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
	rootErr      error
}

func (f *fakeAKTrust) TrustedRoot() (*x509.Certificate, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	return f.root, nil
}

func (f *fakeAKTrust) TrustedIntermediate() (*x509.Certificate, error) {
	if f.intermediate == nil {
		return nil, errors.New("no intermediate")
	}
	return f.intermediate, nil
}

// captureSink records every verdict it receives.
type captureSink struct {
	mu       sync.Mutex
	verdicts []verdict.DeviceVerdict
	err      error
}

func (c *captureSink) RecordDeviceVerdict(_ context.Context, v verdict.DeviceVerdict) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verdicts = append(c.verdicts, v)
	return c.err
}

func (c *captureSink) last(t *testing.T) verdict.DeviceVerdict {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.verdicts) == 0 {
		t.Fatal("no verdict recorded")
	}
	return c.verdicts[len(c.verdicts)-1]
}

// quoteFixture is an enrolled device with a Restricted attestation
// certificate, a matching profile with no baseline yet, a trust anchor and a
// verdict sink — everything a device quote verification touches.
type quoteFixture struct {
	ca       *attestTestCA
	key      *rsa.PrivateKey
	devices  *spMockDeviceService
	profiles *mockProfileService
	trust    *fakeAKTrust
	sink     *captureSink
	device   *deviceentities.Device
	profile  *deviceentities.DeviceProfile
	now      time.Time
}

func newQuoteFixture(t *testing.T) *quoteFixture {
	t.Helper()
	ca := newAttestTestCA(t)
	key, _ := newAttestTestKey(t)

	f := &quoteFixture{
		ca:       ca,
		key:      key,
		devices:  newSPMockDeviceService(),
		profiles: newMockProfileService(),
		trust:    &fakeAKTrust{root: ca.root, intermediate: ca.intermediate},
		sink:     &captureSink{},
		now:      ca.now,
	}
	f.device = &deviceentities.Device{
		TenantID:   "tenant-a",
		Model:      "test-model",
		Serial:     "SN-1",
		Hostname:   "node-1.example.test",
		AttestCert: ca.issueAK(t, &key.PublicKey, true),
	}
	// Create, not Save: the fixture has no ID to supply, which is what
	// creation means, and Save requires one (#525). The mock used to
	// mint one inside Save, which is exactly how the broken create path
	// stayed invisible to these tests.
	if err := f.devices.Create(context.Background(), f.device); err != nil {
		t.Fatalf("create device: %v", err)
	}
	f.profile = &deviceentities.DeviceProfile{
		ID:         1,
		Name:       "test-profile",
		Model:      "test-model",
		MatchRules: &deviceentities.ProfileMatchRules{Model: "test-model"},
	}
	f.profiles.profiles[f.profile.ID] = f.profile
	return f
}

// verifier builds a DeviceQuoteVerifier over the fixture, pinned to the CA's
// clock so certificate validity is deterministic.
func (f *quoteFixture) verifier(t *testing.T) *DeviceQuoteVerifier {
	t.Helper()
	v := NewDeviceQuoteVerifier(f.devices, f.profiles, f.trust, f.sink, nil)
	v.now = func() time.Time { return f.now }
	return v
}

// deviceOptions configure DeviceGRPCService and the QUIC handler with the
// fixture's dependencies.
func (f *quoteFixture) deviceOptions() []DeviceGRPCOption {
	return []DeviceGRPCOption{WithDeviceAKTrust(f.trust), WithDeviceVerdictSink(f.sink)}
}

// grpcService returns a DeviceGRPCService whose verifier uses the fixture
// clock.
func (f *quoteFixture) grpcService(t *testing.T) *DeviceGRPCService {
	t.Helper()
	s := NewDeviceGRPCService(f.devices, f.profiles, nil, f.deviceOptions()...)
	s.verifier.now = func() time.Time { return f.now }
	return s
}

// evidence signs a quote over pcrs with the fixture key and packages it as
// DeviceQuoteEvidence, reporting exactly the values that were quoted.
func (f *quoteFixture) evidence(t *testing.T, nonce []byte, pcrs map[int][]byte) []byte {
	t.Helper()
	return signedEvidence(t, f.key, nonce, pcrs, pcrs)
}

// signedEvidence builds evidence where the quote covers quoted but the
// device reports reported, so a test can make the two disagree.
func signedEvidence(t *testing.T, key *rsa.PrivateKey, nonce []byte, quoted, reported map[int][]byte) []byte {
	t.Helper()
	quote := buildAttestTestQuote(t, nonce, quoted)
	raw, err := json.Marshal(DeviceQuoteEvidence{
		Quote:     quote,
		Signature: signAttestQuote(t, key, quote),
		Nonce:     nonce,
		PCRs:      reported,
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return raw
}

// goldenPCRs is a fixed PCR set shared by the tests.
func goldenPCRs() map[int][]byte {
	return map[int][]byte{
		0: fillPCR(0x11),
		7: fillPCR(0x77),
	}
}

func fillPCR(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
