// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// Boot-time behaviour of initBMCCertManagement.
//
// Wiring this into platformd's boot path turned "issue the initial certificate"
// into "issue a certificate on every restart". On a BMC that is not free:
// each pass generates a fresh keypair, replaces the device identity, restarts
// the BMC web interface, invalidates the stored TOFU pin and republishes DANE
// records — for a certificate that was healthy.

// bmcCertDeployer serves a chosen certificate as the BMC's current one and
// records how many times a replacement was pushed.
type bmcCertDeployer struct {
	current  *x509.Certificate
	getErr   error
	replaced int
}

func (d *bmcCertDeployer) GetWebCertificate(context.Context) (*x509.Certificate, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}
	return d.current, nil
}

func (d *bmcCertDeployer) ReplaceWebCertificate(
	_ context.Context, _ []byte, _ *memguard.MemoryEnclave) error {
	d.replaced++
	return nil
}

func (d *bmcCertDeployer) Close() error { return nil }

// certFor mints a self-signed certificate carrying cn as both subject CN and
// DNS SAN, valid for the given duration.
func certFor(t *testing.T, cn string, validFor time.Duration) *x509.Certificate {
	t.Helper()
	return certWithSANs(t, cn, []string{cn}, validFor)
}

// certWithSANs mints a certificate whose subject CN and DNS SAN set are
// controlled independently, so the matcher can be tested against a certificate
// that carries the right CN but the wrong (or an incomplete) SAN set.
func certWithSANs(t *testing.T, cn string, dnsNames []string, validFor time.Duration) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// caSignedCertFor mints a certificate SIGNED BY a test CA, and returns the pool
// that trusts it. certFor stays self-signed on purpose: it is what an attacker
// or a factory image can produce, and it must NOT be accepted.
func caSignedCertFor(t *testing.T, cn string, dnsNames []string, validFor time.Duration) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "bmc-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor + time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return leaf, pool
}

func TestBMCCertMatchesConfiguredIdentity(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")

	signed, roots := caSignedCertFor(t, "bmc01.internal", []string{"bmc01.internal"}, time.Hour)
	if !bmcCertMatchesConfiguredIdentity(signed, cfg, "ops@x.com", roots) {
		t.Error("a CA-signed certificate carrying the configured identity was not " +
			"recognised; boot would reissue and redeploy it on every restart")
	}

	// The provenance hole: a SELF-SIGNED certificate with exactly the right CN
	// and SANs. Anyone can mint this, and a factory image or a substituted
	// certificate looks identical by name. Accepting it means boot skips
	// provisioning and DueOverride reports not-due forever, leaving the BMC on
	// an unauthenticated certificate indefinitely.
	forged := certWithSANs(t, "bmc01.internal", []string{"bmc01.internal"}, time.Hour)
	if bmcCertMatchesConfiguredIdentity(forged, cfg, "ops@x.com", roots) {
		t.Error("a self-signed certificate with the expected CN and SANs was " +
			"accepted as platform-issued; names prove nothing without a chain")
	}

	// A certificate signed by some OTHER authority, correct names and all.
	other, _ := caSignedCertFor(t, "bmc01.internal", []string{"bmc01.internal"}, time.Hour)
	if bmcCertMatchesConfiguredIdentity(other, cfg, "ops@x.com", roots) {
		t.Error("a certificate from an unrelated CA was accepted; it does not " +
			"chain to any root this platform trusts")
	}

	// The factory case: long-lived, self-signed, different name.
	factory := certFor(t, "ATEN-FACTORY-DEFAULT", 10*365*24*time.Hour)
	if bmcCertMatchesConfiguredIdentity(factory, cfg, "ops@x.com", roots) {
		t.Error("a factory certificate was accepted as the configured identity; " +
			"the BMC would never be provisioned because its cert does not expire soon")
	}

	// No roots means provenance cannot be established. Treated as not ours: the
	// cost is one reissue, whereas trusting an unverifiable certificate is
	// silent and permanent.
	if bmcCertMatchesConfiguredIdentity(signed, cfg, "ops@x.com", nil) {
		t.Error("a certificate was accepted with no trust roots supplied")
	}
	if bmcCertMatchesConfiguredIdentity(nil, cfg, "ops@x.com", roots) {
		t.Error("nil certificate must not match")
	}
}

func TestBMCNeedsInitialProvisioning(t *testing.T) {
	opts := baseInitOpts()

	ours, roots := caSignedCertFor(t, "bmc01.internal", []string{"bmc01.internal"}, 90*24*time.Hour)

	cases := map[string]struct {
		dep  *bmcCertDeployer
		want bool
	}{
		"already carries the configured cert": {
			dep:  &bmcCertDeployer{current: ours},
			want: false,
		},
		"self-signed impostor with the right names": {
			dep:  &bmcCertDeployer{current: certFor(t, "bmc01.internal", 90*24*time.Hour)},
			want: true,
		},
		"still on the factory cert": {
			dep:  &bmcCertDeployer{current: certFor(t, "FACTORY", 10*365*24*time.Hour)},
			want: true,
		},
		"unreachable": {
			dep:  &bmcCertDeployer{getErr: errors.New("connection refused")},
			want: true,
		},
		"returns no certificate": {
			dep:  &bmcCertDeployer{},
			want: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			target := buildBMCCertTarget("dev-1", opts.BMCConfig,
				issueBMCCertificateOptions{Deployer: tc.dep, TrustRoots: roots})
			_, got := bmcNeedsInitialProvisioning(context.Background(), target, "dev-1")
			if got != tc.want {
				t.Errorf("needs provisioning = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildBMCCertTarget_ReadsCurrentWithoutIssuing(t *testing.T) {
	// The target must be constructible for an already-provisioned BMC without
	// issuing anything — that is what lets boot register a target and leave
	// renewal to the sweep.
	dep := &bmcCertDeployer{current: certFor(t, "bmc01.internal", 90*24*time.Hour)}
	target := buildBMCCertTarget("dev-1", minimalCertConfig("bmc01.internal"),
		issueBMCCertificateOptions{Deployer: dep})

	if target.Name != "bmc.dev-1" {
		t.Errorf("Name = %q", target.Name)
	}
	if target.Kind != CertKindBMC {
		t.Errorf("Kind = %q", target.Kind)
	}
	got, err := target.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.Subject.CommonName != "bmc01.internal" {
		t.Errorf("Current CN = %q", got.Subject.CommonName)
	}
	if dep.replaced != 0 {
		t.Errorf("building a target deployed %d certificates; construction must not "+
			"touch the device", dep.replaced)
	}
}

// TestInitBMCCert_RestartDoesNotRotateAHealthyCertificate is the regression the
// hosted review blocked on: with the boot wiring in place, initBMCCertManagement
// ran issuance unconditionally, so every platformd restart replaced a perfectly
// good BMC certificate.
func TestInitBMCCert_RestartDoesNotRotateAHealthyCertificate(t *testing.T) {
	opts := baseInitOpts()
	localCA := &fakeLocalCA{}
	opts.LocalCAIssuer = localCA
	opts.ACMEIssuer = nil
	sched := newFakeScheduler()
	opts.Scheduler = sched
	reg := NewCertTargetRegistry()
	opts.Registry = reg
	// The BMC already carries the configured identity, properly CA-signed and
	// well clear of expiry.
	ours, roots := caSignedCertFor(t, "bmc01.internal", []string{"bmc01.internal"}, 90*24*time.Hour)
	opts.TrustRoots = roots
	opts.DeployerOverride = &bmcCertDeployer{current: ours}

	for boot := 1; boot <= 3; boot++ {
		if err := initBMCCertManagement(context.Background(), opts); err != nil {
			t.Fatalf("boot %d: %v", boot, err)
		}
	}

	if localCA.callCnt != 0 {
		t.Errorf("issued %d certificates across 3 restarts, want 0. A healthy BMC "+
			"certificate was rotated on restart: that regenerates the device key, "+
			"restarts the BMC web interface, invalidates the TOFU pin and "+
			"republishes DANE records for nothing.", localCA.callCnt)
	}
	if _, ok := reg.Get("bmc.bmc01.internal"); !ok {
		t.Error("no BMC target registered, so the sweep could never renew it")
	}
	if len(sched.jobs) != 1 {
		t.Errorf("scheduled %d jobs across 3 restarts, want 1 (idempotent)", len(sched.jobs))
	}
}

// The complement: an unprovisioned BMC must still get its first certificate.
func TestInitBMCCert_FactoryCertificateIsReplacedOnce(t *testing.T) {
	opts := baseInitOpts()
	localCA := &fakeLocalCA{}
	opts.LocalCAIssuer = localCA
	opts.ACMEIssuer = nil
	opts.Registry = NewCertTargetRegistry()
	opts.Scheduler = newFakeScheduler()
	opts.DeployerOverride = &bmcCertDeployer{
		current: certFor(t, "ATEN-FACTORY-DEFAULT", 10*365*24*time.Hour),
	}

	if err := initBMCCertManagement(context.Background(), opts); err != nil {
		t.Fatalf("initBMCCertManagement: %v", err)
	}
	if localCA.callCnt != 1 {
		t.Errorf("issued %d certificates, want 1 — a BMC still on its factory "+
			"certificate must be provisioned at boot; its cert does not expire for "+
			"years, so the renewal sweep alone would never do it", localCA.callCnt)
	}
}

// --- identity matching must require the WHOLE configured identity ---

func TestBMCCertMatchesConfiguredIdentity_RequiresEveryConfiguredName(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	cfg.Certificate.SANS = &quicbaasca.CASubjectAlternativeNames{
		DNS: []string{"bmc01.internal", "bmc01.mgmt.internal"},
	}

	full, roots := caSignedCertFor(t, "bmc01.internal",
		[]string{"bmc01.internal", "bmc01.mgmt.internal"}, time.Hour)
	if !bmcCertMatchesConfiguredIdentity(full, cfg, "ops@x.com", roots) {
		t.Error("a certificate covering every configured name was rejected; " +
			"boot would redeploy a correct certificate on each restart")
	}

	// Only a subset present, and properly CA-signed so the chain is not what
	// rejects it. Leaving this in place strands the remaining name undeployed
	// while boot reports the BMC as provisioned.
	subset, subsetRoots := caSignedCertFor(t, "bmc01.internal",
		[]string{"bmc01.internal"}, time.Hour)
	if bmcCertMatchesConfiguredIdentity(subset, cfg, "ops@x.com", subsetRoots) {
		t.Error("a certificate covering only SOME of the configured names was " +
			"accepted as fully provisioned; the missing identity would never " +
			"be deployed")
	}
}

func TestBMCCertMatchesConfiguredIdentity_CommonNameAloneIsNotEnough(t *testing.T) {
	// CN matches, but the SAN extension does not cover it. Modern TLS ignores
	// CN entirely, so this certificate does not actually serve the configured
	// name — accepting it on CN equality alone would leave a BMC that fails
	// every client handshake looking correctly provisioned.
	cfg := minimalCertConfig("bmc01.internal")
	mismatched, roots := caSignedCertFor(t, "bmc01.internal",
		[]string{"someone-else.internal"}, time.Hour)

	if bmcCertMatchesConfiguredIdentity(mismatched, cfg, "ops@x.com", roots) {
		t.Error("a certificate whose SANs contradict its CommonName was accepted; " +
			"CN equality must not be sufficient on its own")
	}
}

// --- a failed boot must actually be recovered by a later sweep ---

func TestBMCTarget_FactoryCertificateIsDueDespiteLongExpiry(t *testing.T) {
	// The claim "boot failure is non-fatal, the sweep retries" is only true if
	// the sweep considers this target due. A factory certificate is valid for
	// years, so the expiry test alone skips it every day forever.
	cfg := minimalCertConfig("bmc01.internal")
	ours, roots := caSignedCertFor(t, "bmc01.internal", []string{"bmc01.internal"}, 90*24*time.Hour)
	dep := &bmcCertDeployer{current: certFor(t, "ATEN-FACTORY-DEFAULT", 10*365*24*time.Hour)}
	target := buildBMCCertTarget("dev-1", cfg,
		issueBMCCertificateOptions{Deployer: dep, TrustRoots: roots})

	if target.DueOverride == nil {
		t.Fatal("BMC targets need a DueOverride or an unprovisioned BMC is never " +
			"provisioned by the sweep")
	}
	cert, err := target.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	due, reason := target.DueOverride(context.Background(), cert, nil)
	if !due {
		t.Error("a factory certificate was not reported due, so the sweep would " +
			"skip it every day and the BMC would stay unprovisioned indefinitely")
	}
	if reason == "" {
		t.Error("no reason given; the sweep log would not explain the reissue")
	}

	// The complement: our own healthy certificate must NOT be due.
	dep.current = ours
	cert, err = target.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if due, _ := target.DueOverride(context.Background(), cert, nil); due {
		t.Error("a healthy, correctly-issued certificate was reported due; the " +
			"sweep would rotate the BMC identity daily")
	}
}

// TestBMCFailedBootProvisioningIsRecoveredByTheSweep runs the actual sweep, which
// is what the review asked for: registration alone proves nothing.
func TestBMCFailedBootProvisioningIsRecoveredByTheSweep(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	localCA := &fakeLocalCA{}
	// The BMC is still on its factory certificate: boot provisioning failed.
	dep := &bmcCertDeployer{current: certFor(t, "ATEN-FACTORY-DEFAULT", 10*365*24*time.Hour)}
	target := buildBMCCertTarget("dev-1", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: localCA,
		Deployer:      dep,
	})

	reg := NewCertTargetRegistry()
	if err := reg.Register(target); err != nil {
		t.Fatalf("register: %v", err)
	}

	results, _ := runCertRenewalSweep(context.Background(), reg,
		DefaultCertRenewalThreshold, time.Now(), nil)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Action != "renewed" {
		t.Errorf("sweep action = %q, want \"renewed\". A BMC left unprovisioned by "+
			"a failed boot must be recovered by the scheduled sweep; otherwise the "+
			"non-fatal boot path silently strands it forever. error=%q",
			results[0].Action, results[0].Error)
	}
	if localCA.callCnt != 1 {
		t.Errorf("issuance ran %d times, want 1", localCA.callCnt)
	}
}

// --- RequireACME: no silent issuer substitution on the production path ---

func TestIssueBMCCertificateCore_RequireACMERefusesLocalCASubstitution(t *testing.T) {
	// A validated BMC cert config always declares ACME dns-01, so reaching the
	// local-CA branch means the certificate would be signed by an authority the
	// operator never selected. That is a trust decision, not a degradation.
	cfg := minimalCertConfig("bmc01.internal")
	localCA := &fakeLocalCA{}

	_, err := issueBMCCertificateCore(context.Background(), "dev-9", cfg,
		issueBMCCertificateOptions{
			// ACME declared in cfg, no issuer wired, and ACME is required.
			LocalCAIssuer: localCA,
			Deployer:      &bmcCertDeployer{},
			RequireACME:   true,
		})

	var want ErrBMCACMEIssuerUnavailable
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrBMCACMEIssuerUnavailable", err)
	}
	if localCA.callCnt != 0 {
		t.Errorf("the local CA issued %d certificates despite ACME being required; "+
			"the BMC would present a certificate signed by an authority the "+
			"configuration did not select", localCA.callCnt)
	}
}

func TestIssueBMCCertificateCore_RequireACMEOffKeepsTheFallback(t *testing.T) {
	// The flag is opt-in: callers that accept the long-standing fallback are
	// unaffected, which is why turning it on was safe to scope to the boot path.
	cfg := minimalCertConfig("bmc01.internal")
	localCA := &fakeLocalCA{}

	if _, err := issueBMCCertificateCore(context.Background(), "dev-9", cfg,
		issueBMCCertificateOptions{
			LocalCAIssuer: localCA,
			Deployer:      &bmcCertDeployer{},
		}); err != nil {
		t.Fatalf("err = %v, want the fallback to still work when ACME is not required", err)
	}
	if localCA.callCnt != 1 {
		t.Errorf("localCA.callCnt = %d, want 1", localCA.callCnt)
	}
}

func TestInitBMCCert_RefusedIssuanceStillLeavesRenewalWired(t *testing.T) {
	// With RequireACME set and no ACME issuer, issuance is refused. That refusal
	// must cost exactly one target: the renewal handler and job are registered
	// before issuance is attempted, so the rest of the node keeps renewing.
	localCA := &fakeLocalCA{}

	opts := baseInitOpts()
	opts.ACMEIssuer = nil
	opts.LocalCAIssuer = localCA
	opts.RequireACME = true
	opts.Registry = NewCertTargetRegistry()
	sched := newFakeScheduler()
	opts.Scheduler = sched
	opts.DeployerOverride = &bmcCertDeployer{
		current: certFor(t, "ATEN-FACTORY-DEFAULT", 10*365*24*time.Hour),
	}

	if err := initBMCCertManagement(context.Background(), opts); err != nil {
		t.Fatalf("a refused issuance must not fail the whole wiring: %v", err)
	}
	if localCA.callCnt != 0 {
		t.Errorf("local CA issued %d certificates with RequireACME set", localCA.callCnt)
	}
	if len(sched.jobs) == 0 {
		t.Error("the renewal job must still be registered: one target refusing to " +
			"issue cannot disable renewal for the whole node")
	}
}

// --- convergence: the sweep must be able to fix what it finds broken ---

func TestBMCTarget_UnreadableCertificateIsDue(t *testing.T) {
	// A BMC serving nothing readable is the one that most needs issuing — a
	// device still on a factory image, or one whose deploy failed at boot.
	// Before this, Current's error short-circuited the sweep to "failed" and
	// DueOverride was never consulted, so such a BMC re-read and re-failed every
	// day for the life of the process without ever converging.
	cfg := minimalCertConfig("bmc01.internal")
	target := buildBMCCertTarget("dev-1", cfg, issueBMCCertificateOptions{
		Deployer: &bmcCertDeployer{getErr: errors.New("connection refused")},
	})

	due, reason := target.DueOverride(context.Background(), nil, errors.New("connection refused"))
	if !due {
		t.Error("an unreadable BMC was not reported due, so the sweep can never " +
			"provision it")
	}
	if !strings.Contains(reason, "connection refused") {
		t.Errorf("reason %q does not carry the read failure, so the audit trail "+
			"cannot explain the reissue", reason)
	}
}

func TestRunSweep_UnreadableTargetWithDueOverrideIsReissued(t *testing.T) {
	// End-to-end through the real sweep: an unreadable endpoint whose target
	// claims it is due must be reissued, not merely recorded failed.
	localCA := &fakeLocalCA{}
	dep := &bmcCertDeployer{getErr: errors.New("connection refused")}
	target := buildBMCCertTarget("dev-1", minimalCertConfig("bmc01.internal"),
		issueBMCCertificateOptions{LocalCAIssuer: localCA, Deployer: dep})

	reg := NewCertTargetRegistry()
	if err := reg.Register(target); err != nil {
		t.Fatalf("register: %v", err)
	}

	results, _ := runCertRenewalSweep(context.Background(), reg,
		DefaultCertRenewalThreshold, time.Now(), nil)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Action != "renewed" {
		t.Errorf("action = %q (error %q), want \"renewed\". A BMC serving nothing "+
			"readable must be provisioned by the sweep; recording it failed leaves "+
			"it stuck forever.", results[0].Action, results[0].Error)
	}
	if results[0].DueReason == "" {
		t.Error("the result carries no due_reason, so an operator reading the job " +
			"history sees a reissue with no stated cause")
	}
	if localCA.callCnt != 1 {
		t.Errorf("issuance ran %d times, want 1", localCA.callCnt)
	}
}

func TestRunSweep_UnreadableTargetWithoutDueOverrideStillFails(t *testing.T) {
	// Webservice targets have no DueOverride. An unreachable one must NOT be
	// reissued: the service simply is not listening, and reissuing would churn
	// certificates without fixing anything.
	reissued := 0
	reg := NewCertTargetRegistry()
	err := reg.Register(&CertTarget{
		Name: "webservice.api",
		Kind: CertKindWebservice,
		Current: func(context.Context) (*x509.Certificate, error) {
			return nil, errors.New("connection refused")
		},
		Reissue: func(context.Context) error { reissued++; return nil },
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	results, _ := runCertRenewalSweep(context.Background(), reg,
		DefaultCertRenewalThreshold, time.Now(), nil)

	if results[0].Action != "failed" {
		t.Errorf("action = %q, want \"failed\"", results[0].Action)
	}
	if reissued != 0 {
		t.Errorf("reissued %d times; a target with no due rule must not be "+
			"reissued merely because it could not be read", reissued)
	}
}

func TestBMCTarget_ACMEIssuerResolvedLazily(t *testing.T) {
	// The target's Reissue closure captures its options by value. If the ACME
	// issuer is captured while still nil — which is what an ordinary restart
	// produces, since InitWebServer skips the issuance that initializes it —
	// then every future sweep re-uses that nil and the BMC never converges.
	var issuer ACMEIssuer
	opts := issueBMCCertificateOptions{
		ACMEIssuerFunc: func() ACMEIssuer { return issuer },
		LocalCAIssuer:  &fakeLocalCA{},
		Deployer:       &bmcCertDeployer{},
		RequireACME:    true,
	}

	if got := opts.resolveACMEIssuer(); got != nil {
		t.Fatalf("precondition: expected no issuer yet, got %#v", got)
	}

	// The client comes up later in boot.
	issuer = &fakeACME{}
	if got := opts.resolveACMEIssuer(); got == nil {
		t.Error("an ACME client initialized after the target was built was not " +
			"picked up; the BMC target would stay permanently unable to converge")
	}
}

// --- the sweep must survive one bad target, and stop when cancelled ---

func TestRunSweep_PanickingTargetDoesNotAbortTheSweep(t *testing.T) {
	// Current and Reissue call into deployers, ACME clients and BMC transports.
	// A panic in one of them must not stop the others: a single misbehaving
	// device would otherwise silently halt certificate renewal for the whole
	// node — the same failure already designed out of the boot path.
	reg := NewCertTargetRegistry()
	healthyReissued := 0

	if err := reg.Register(&CertTarget{
		Name: "bmc.exploding",
		Kind: CertKindBMC,
		Current: func(context.Context) (*x509.Certificate, error) {
			panic("deployer blew up")
		},
		Reissue: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(&CertTarget{
		Name: "webservice.healthy",
		Kind: CertKindWebservice,
		Current: func(context.Context) (*x509.Certificate, error) {
			return certFor(t, "api.internal", time.Hour), nil // due: expires within threshold
		},
		Reissue: func(context.Context) error { healthyReissued++; return nil },
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	results, _ := runCertRenewalSweep(context.Background(), reg,
		DefaultCertRenewalThreshold, time.Now(), nil)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 — the panicking target aborted the sweep", len(results))
	}
	byName := map[string]renewalResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	if got := byName["bmc.exploding"].Action; got != "failed" {
		t.Errorf("panicking target action = %q, want \"failed\"", got)
	}
	if !strings.Contains(byName["bmc.exploding"].Error, "panic") {
		t.Errorf("the panic was swallowed rather than recorded: %q",
			byName["bmc.exploding"].Error)
	}
	if healthyReissued != 1 {
		t.Errorf("the healthy target was reissued %d times, want 1; one bad device "+
			"stopped renewal for the rest of the node", healthyReissued)
	}
}

func TestRunSweep_CancelledContextStopsInsteadOfFailingEveryTarget(t *testing.T) {
	// The job carries a timeout and the daemon can shut down mid-sweep. Marking
	// every remaining target "failed" would make a cancellation read as a
	// fleet-wide certificate outage in the audit trail.
	reg := NewCertTargetRegistry()
	for _, name := range []string{"a", "b", "c"} {
		if err := reg.Register(&CertTarget{
			Name: "webservice." + name,
			Kind: CertKindWebservice,
			Current: func(context.Context) (*x509.Certificate, error) {
				return certFor(t, "api.internal", 90*24*time.Hour), nil
			},
			Reissue: func(context.Context) error { return nil },
		}); err != nil {
			t.Fatalf("register: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, _ := runCertRenewalSweep(ctx, reg, DefaultCertRenewalThreshold, time.Now(), nil)

	if len(results) != 0 {
		t.Errorf("got %d results from a cancelled sweep, want 0. Recording targets "+
			"as failed on cancellation reports a certificate outage that is not "+
			"happening.", len(results))
	}
}

// --- an incomplete sweep must never report success ---

// staticTarget is a target whose Current is fixed and whose evaluation can
// cancel a context, so a sweep can be interrupted at a chosen point.
func staticTarget(t *testing.T, name string, notAfter time.Duration, onEval func()) *CertTarget {
	t.Helper()
	return &CertTarget{
		Name: "webservice." + name,
		Kind: CertKindWebservice,
		Current: func(context.Context) (*x509.Certificate, error) {
			if onEval != nil {
				onEval()
			}
			return certFor(t, "api.internal", notAfter), nil
		},
		Reissue: func(context.Context) error { return nil },
	}
}

func TestCertRenewalHandler_CancelledBeforeTheFirstTargetIsNotSuccess(t *testing.T) {
	// The nastiest shape: zero results, which previously looked identical to
	// "no cert targets" and reported Success: true. The job would then record a
	// clean tick over certificates nothing had even looked at.
	reg := NewCertTargetRegistry()
	if err := reg.Register(staticTarget(t, "a", 90*24*time.Hour, nil)); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handler := buildCertRenewalHandler(reg, DefaultCertRenewalThreshold, time.Now, nil)
	res, err := handler(ctx, nil)

	if err == nil {
		t.Error("the handler returned no error for a sweep that evaluated nothing; " +
			"the scheduler cannot apply its retry semantics to work it is not told " +
			"was skipped")
	}
	if res != nil && res.Success {
		t.Error("a sweep that evaluated no targets reported Success: true. Every " +
			"certificate on the node is unchecked and the job history says the " +
			"renewal tick was clean.")
	}
	var want ErrCertRenewalSweepIncomplete
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrCertRenewalSweepIncomplete", err)
	}
	if want.Total == 0 {
		t.Error("the error does not say how many targets were skipped")
	}
}

func TestCertRenewalHandler_CancelledBetweenTargetsIsNotSuccess(t *testing.T) {
	// The subtler shape: the first target is evaluated successfully and the
	// deadline expires before the second. A partial slice of healthy results
	// must not read as a healthy sweep.
	reg := NewCertTargetRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel while evaluating the first target, so the loop stops before the second.
	if err := reg.Register(staticTarget(t, "a", 90*24*time.Hour, cancel)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(staticTarget(t, "b", 90*24*time.Hour, nil)); err != nil {
		t.Fatalf("register: %v", err)
	}

	handler := buildCertRenewalHandler(reg, DefaultCertRenewalThreshold, time.Now, nil)
	res, err := handler(ctx, nil)

	if err == nil {
		t.Error("a truncated sweep returned no error, so the second certificate " +
			"was never checked and nothing records that")
	}
	if res != nil && res.Success {
		t.Error("a truncated sweep reported Success: true; the unevaluated target's " +
			"certificate is in an unknown state")
	}
	var want ErrCertRenewalSweepIncomplete
	if errors.As(err, &want) && want.Evaluated >= want.Total {
		t.Errorf("the error claims %d of %d evaluated, which is not a truncation",
			want.Evaluated, want.Total)
	}
}

func TestCertRenewalHandler_CompleteSweepStillReportsSuccess(t *testing.T) {
	// The complement: normal operation must not start failing because of the above.
	reg := NewCertTargetRegistry()
	if err := reg.Register(staticTarget(t, "a", 90*24*time.Hour, nil)); err != nil {
		t.Fatalf("register: %v", err)
	}

	handler := buildCertRenewalHandler(reg, DefaultCertRenewalThreshold, time.Now, nil)
	res, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("a complete sweep must not error: %v", err)
	}
	if !res.Success {
		t.Errorf("a complete sweep over a healthy target reported Success: false (%q)",
			res.Message)
	}
}

func TestResolveACMEIssuer_ContractAndPrecedence(t *testing.T) {
	live := &fakeACME{}

	// The resolver wins when it has an issuer.
	opts := issueBMCCertificateOptions{ACMEIssuerFunc: func() ACMEIssuer { return live }}
	if got := opts.resolveACMEIssuer(); got != ACMEIssuer(live) {
		t.Error("the lazy resolver was not preferred, so a client initialized after " +
			"the target was built would never be used")
	}

	// No resolver: the eagerly captured issuer is used.
	opts = issueBMCCertificateOptions{ACMEIssuer: live}
	if got := opts.resolveACMEIssuer(); got != ACMEIssuer(live) {
		t.Error("the eager issuer was ignored when no resolver was supplied")
	}

	// Resolver present but empty, no eager issuer: absent.
	opts = issueBMCCertificateOptions{ACMEIssuerFunc: func() ACMEIssuer { return nil }}
	if got := opts.resolveACMEIssuer(); got != nil {
		t.Errorf("expected no issuer, got %#v", got)
	}

	// Resolver returns nothing but an eager issuer exists: fall back to it
	// rather than losing an issuer the caller explicitly supplied.
	opts = issueBMCCertificateOptions{
		ACMEIssuer:     live,
		ACMEIssuerFunc: func() ACMEIssuer { return nil },
	}
	if got := opts.resolveACMEIssuer(); got != ACMEIssuer(live) {
		t.Error("an explicitly supplied issuer was discarded because the resolver " +
			"returned nothing")
	}
}

// --- dns-01 without a DNS updater must be an error, never a panic ---

func TestBuildBMCACMERequest_RequiresADNSUpdater(t *testing.T) {
	// Production passes app.DNSService, which is nil whenever DNS is disabled or
	// failed to initialize. The challenge callbacks run deep inside the ACME
	// client, so a nil dereference there panics on whichever goroutine drove
	// issuance — during boot that is platformd's own, outside the sweep's panic
	// isolation, in the code path that promises warn-and-continue.
	cfg := minimalCertConfig("bmc01.internal")

	_, err := buildBMCACMERequest(context.Background(), cfg, []byte("csr"), nil, 60, nil)

	var want ErrMissingDNSUpdater
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrMissingDNSUpdater. Without it the dns-01 "+
			"challenge callback nil-dereferences and takes platformd down.", err)
	}
}

func TestIssueBMCCertificateCore_NoDNSUpdaterFailsRetryably(t *testing.T) {
	// Both the boot path and the renewal path reach issuance through this
	// function, so covering it covers both.
	cfg := minimalCertConfig("bmc01.internal")
	localCA := &fakeLocalCA{}

	_, err := issueBMCCertificateCore(context.Background(), "dev-1", cfg,
		issueBMCCertificateOptions{
			ACMEIssuer:    &fakeACME{}, // ACME available...
			DNSUpdater:    nil,         // ...but nothing can answer dns-01
			LocalCAIssuer: localCA,
			Deployer:      &bmcCertDeployer{},
		})

	if err == nil {
		t.Fatal("issuance without a DNS updater reported success")
	}
	var want ErrMissingDNSUpdater
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrMissingDNSUpdater wrapped", err)
	}
	if localCA.callCnt != 0 {
		t.Errorf("the local CA issued %d certificates as a side effect of a failed "+
			"ACME attempt; a missing DNS updater must not become an issuer "+
			"substitution", localCA.callCnt)
	}
}

func TestBMCRenewalWithoutDNSUpdaterIsRecordedFailedNotPanicked(t *testing.T) {
	// Through the real sweep: the target must be recorded failed and the sweep
	// must survive, rather than the process dying inside the ACME client.
	cfg := minimalCertConfig("bmc01.internal")
	target := buildBMCCertTarget("dev-1", cfg, issueBMCCertificateOptions{
		ACMEIssuer:    &fakeACME{},
		DNSUpdater:    nil,
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      &bmcCertDeployer{getErr: errors.New("connection refused")},
	})

	reg := NewCertTargetRegistry()
	if err := reg.Register(target); err != nil {
		t.Fatalf("register: %v", err)
	}

	results, sweepErr := runCertRenewalSweep(context.Background(), reg,
		DefaultCertRenewalThreshold, time.Now(), nil)
	if sweepErr != nil {
		t.Fatalf("sweep reported incomplete: %v", sweepErr)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Action != "failed" {
		t.Errorf("action = %q, want \"failed\"", results[0].Action)
	}
	if !strings.Contains(results[0].Error, "DNS updater") {
		t.Errorf("the recorded error does not name the missing DNS updater, so an "+
			"operator cannot tell why renewal is stuck: %q", results[0].Error)
	}
}

// --- a stored renewal job that no longer matches configuration must say so ---

func TestRegisterCertRenewal_ReportsStoredJobDrift(t *testing.T) {
	// "Idempotent" here means the job is not recreated. It does NOT mean the
	// stored job is reconciled: schedule, timeout and retry count keep whatever
	// they were created with. An operator who edits the schedule and restarts
	// must not be left believing the new one is in force.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	sched := newFakeScheduler()
	reg := NewCertTargetRegistry()
	ctx := context.Background()

	// First boot creates the job.
	if err := RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: sched, Registry: reg, NodeID: "node-A",
		Schedule: "0 2 * * *", Logger: logger,
	}); err != nil {
		t.Fatalf("first boot: %v", err)
	}

	// Second boot asks for a different schedule.
	buf.Reset()
	if err := RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: sched, Registry: reg, NodeID: "node-A",
		Schedule: "0 5 * * *", Logger: logger,
	}); err != nil {
		t.Fatalf("second boot: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "0 5 * * *") || !strings.Contains(out, "0 2 * * *") {
		t.Errorf("the schedule drift was not reported with both values, so an "+
			"operator cannot see that their edit did not take effect.\nlogged: %q", out)
	}
	if len(sched.jobs) != 1 {
		t.Errorf("scheduled %d jobs, want 1 — the job must not be duplicated", len(sched.jobs))
	}
}

func TestRegisterCertRenewal_NoDriftIsQuiet(t *testing.T) {
	// The complement: an unchanged configuration must not warn on every boot, or
	// the warning becomes noise and stops being read.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	sched := newFakeScheduler()
	reg := NewCertTargetRegistry()
	ctx := context.Background()
	opts := CertRenewalRegistration{
		Scheduler: sched, Registry: reg, NodeID: "node-A",
		Schedule: "0 2 * * *", Logger: logger,
	}

	if err := RegisterCertRenewal(ctx, opts); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	buf.Reset()
	if err := RegisterCertRenewal(ctx, opts); err != nil {
		t.Fatalf("second boot: %v", err)
	}

	if strings.Contains(buf.String(), "does not match") {
		t.Errorf("an unchanged configuration warned about drift: %q", buf.String())
	}
}
