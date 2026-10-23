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

package app

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// --- fakes for hook tests ---

// hookRecorder captures hook call order and arguments.
type hookRecorder struct {
	mu      sync.Mutex
	calls   []string // ordered call names: "issued", "deployed"
	retErrs map[string]error
}

func newHookRecorder() *hookRecorder {
	return &hookRecorder{retErrs: make(map[string]error)}
}

func (r *hookRecorder) onIssued(_ context.Context, _ *x509.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "issued")
	return r.retErrs["issued"]
}

func (r *hookRecorder) onDeployed(_ context.Context, _, _ *x509.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "deployed")
	return r.retErrs["deployed"]
}

func (r *hookRecorder) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// orderTrackingDeployer records how many times ReplaceWebCertificate
// was called so ordering tests can snapshot the count.
type orderTrackingDeployer struct {
	mu    sync.Mutex
	calls int
}

func (d *orderTrackingDeployer) ReplaceWebCertificate(_ context.Context, _ []byte, _ *memguard.MemoryEnclave) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return nil
}

func (d *orderTrackingDeployer) GetWebCertificate(_ context.Context) (*x509.Certificate, error) {
	return testIssuedCertificate(), nil
}

func (d *orderTrackingDeployer) Close() error { return nil }

func (d *orderTrackingDeployer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// --- issueBMCCertificateCore hook tests ---

// TestIssueBMCCertificateCore_HooksCalledInOrder verifies that
// OnCertIssued fires BEFORE the deploy step and OnCertDeployed fires
// AFTER the deploy step by snapshotting the deployer call count at each
// hook invocation.
func TestIssueBMCCertificateCore_HooksCalledInOrder(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &orderTrackingDeployer{}
	rec := newHookRecorder()

	var issuedDeployCount int32   // deployer calls when OnCertIssued fires
	var deployedDeployCount int32 // deployer calls when OnCertDeployed fires

	_, err := issueBMCCertificateCore(context.Background(), "dev-hook-order", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertIssued: func(_ context.Context, _ *x509.Certificate) error {
			atomic.StoreInt32(&issuedDeployCount, int32(dep.callCount()))
			return rec.onIssued(context.Background(), nil)
		},
		OnCertDeployed: func(_ context.Context, leaf, ca *x509.Certificate) error {
			atomic.StoreInt32(&deployedDeployCount, int32(dep.callCount()))
			return rec.onDeployed(context.Background(), leaf, ca)
		},
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore: %v", err)
	}

	// OnCertIssued must fire when deploy count is still 0.
	if got := atomic.LoadInt32(&issuedDeployCount); got != 0 {
		t.Errorf("OnCertIssued saw deploy count=%d, want 0 (should fire before deploy)", got)
	}
	// OnCertDeployed must fire after deploy count reaches 1.
	if got := atomic.LoadInt32(&deployedDeployCount); got != 1 {
		t.Errorf("OnCertDeployed saw deploy count=%d, want 1 (should fire after deploy)", got)
	}
	if rec.callCount() != 2 {
		t.Errorf("total hook calls = %d, want 2", rec.callCount())
	}
}

// TestIssueBMCCertificateCore_NilHooksAreNoOp verifies that nil hooks
// do not affect the happy path and the certificate is deployed normally.
func TestIssueBMCCertificateCore_NilHooksAreNoOp(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}
	_, err := issueBMCCertificateCore(context.Background(), "dev-nil-hooks", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		// OnCertIssued and OnCertDeployed intentionally nil.
	})
	if err != nil {
		t.Fatalf("nil hooks should not affect issuance: %v", err)
	}
	if dep.replaceCalls != 1 {
		t.Errorf("deploy calls = %d, want 1", dep.replaceCalls)
	}
}

// TestIssueBMCCertificateCore_IssuedHookErrorIsNonFatal verifies that
// an error from OnCertIssued does NOT abort the deploy — the certificate
// is still deployed and the function returns nil.
func TestIssueBMCCertificateCore_IssuedHookErrorIsNonFatal(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}

	_, err := issueBMCCertificateCore(context.Background(), "dev-issued-err", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertIssued: func(_ context.Context, _ *x509.Certificate) error {
			return errors.New("dane pre-publish failed")
		},
	})
	if err != nil {
		t.Fatalf("OnCertIssued error must be non-fatal, got: %v", err)
	}
	if dep.replaceCalls != 1 {
		t.Errorf("deploy must still run despite hook error, calls=%d", dep.replaceCalls)
	}
}

// TestIssueBMCCertificateCore_DeployedHookErrorIsNonFatal verifies that
// an error from OnCertDeployed does NOT cause issueBMCCertificateCore to
// return an error — the deploy succeeded and the CertTarget is returned.
func TestIssueBMCCertificateCore_DeployedHookErrorIsNonFatal(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}

	target, err := issueBMCCertificateCore(context.Background(), "dev-deployed-err", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertDeployed: func(_ context.Context, _, _ *x509.Certificate) error {
			return errors.New("tlsa re-publish failed")
		},
	})
	if err != nil {
		t.Fatalf("OnCertDeployed error must be non-fatal, got: %v", err)
	}
	if target == nil {
		t.Fatal("CertTarget must be returned despite hook error")
	}
	if dep.replaceCalls != 1 {
		t.Errorf("deploy must still run, calls=%d", dep.replaceCalls)
	}
}

// TestIssueBMCCertificateCore_DeployedHookReceivesLeaf verifies that
// OnCertDeployed receives a non-nil leaf certificate. The CA cert may
// be nil (ACME path or local CA with empty CACertificatePEM) — that is
// acceptable — but the leaf must always be set.
func TestIssueBMCCertificateCore_DeployedHookReceivesLeaf(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}
	var seenLeaf *x509.Certificate

	_, err := issueBMCCertificateCore(context.Background(), "dev-deployed-leaf", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertDeployed: func(_ context.Context, leaf, _ *x509.Certificate) error {
			seenLeaf = leaf
			return nil
		},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if seenLeaf == nil {
		t.Fatal("OnCertDeployed received nil leaf")
	}
}

// TestIssueBMCCertificateCore_DeployedHookNilCATolerance verifies that
// the hook is called with nil ca when the issued certificate's
// CACertificatePEM is empty (default for fakeLocalCA) without causing a
// panic or error.
func TestIssueBMCCertificateCore_DeployedHookNilCATolerance(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}
	var seenCA *x509.Certificate
	called := false

	// fakeLocalCA returns IssuedCertificate with CACertificatePEM == nil,
	// so caCert will be nil inside issueBMCCertificateCore.
	_, err := issueBMCCertificateCore(context.Background(), "dev-nil-ca", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertDeployed: func(_ context.Context, _ *x509.Certificate, ca *x509.Certificate) error {
			called = true
			seenCA = ca
			return nil
		},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !called {
		t.Fatal("OnCertDeployed was not called")
	}
	// CACertificatePEM is empty, so the hook must be handed a nil CA.
	if seenCA != nil {
		t.Errorf("OnCertDeployed ca = %v, want nil when CACertificatePEM is empty", seenCA.Subject)
	}
}

// TestIssueBMCCertificateCore_HooksPassedThroughReissue verifies that
// the Reissue closure returned by issueBMCCertificateCore preserves the
// hook wiring so renewal triggers both hooks on each invocation.
func TestIssueBMCCertificateCore_HooksPassedThroughReissue(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}
	var issuedCalls, deployedCalls int32

	target, err := issueBMCCertificateCore(context.Background(), "dev-reissue-hooks", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertIssued: func(_ context.Context, _ *x509.Certificate) error {
			atomic.AddInt32(&issuedCalls, 1)
			return nil
		},
		OnCertDeployed: func(_ context.Context, _, _ *x509.Certificate) error {
			atomic.AddInt32(&deployedCalls, 1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("initial issue: %v", err)
	}
	if err := target.Reissue(context.Background()); err != nil {
		t.Fatalf("Reissue: %v", err)
	}

	// Each of the two issuance runs (initial + reissue) should trigger
	// both hooks once, for a total of 2 calls each.
	if got := atomic.LoadInt32(&issuedCalls); got != 2 {
		t.Errorf("issuedCalls = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&deployedCalls); got != 2 {
		t.Errorf("deployedCalls = %d, want 2", got)
	}
}

// --- buildBMCRenewalHooks wiring tests ---

// fakeDanePublisher is a test double for the daneRenewalPublisher
// interface.
type fakeDanePublisher struct {
	mu              sync.Mutex
	prePublishCalls int
	publishCalls    int
	prePublishErr   error
	publishErr      error
	lastCA          *x509.Certificate
	lastHostname    string
}

func (f *fakeDanePublisher) PrePublishRollover(_ context.Context, newCert *x509.Certificate, hostname string, _ uint16, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prePublishCalls++
	f.lastHostname = hostname
	return f.prePublishErr
}

func (f *fakeDanePublisher) PublishForCertificate(_ context.Context, leafCert, caCert *x509.Certificate, hostname string, _ uint16, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishCalls++
	f.lastCA = caCert
	f.lastHostname = hostname
	return f.publishErr
}

// TestBuildBMCRenewalHooks_OnIssuedCallsPrePublish verifies that the
// OnCertIssued hook calls DANEPublisher.PrePublishRollover when DANE is
// configured and a DNS name is available.
func TestBuildBMCRenewalHooks_OnIssuedCallsPrePublish(t *testing.T) {
	leaf := testIssuedCertificate()
	dane := &fakeDanePublisher{}
	dnsName := "node-01-bmc.internal"

	onIssued, _ := buildRenewalHooksForTest(dane, dnsName, "1.2.3.4", nil)
	if err := onIssued(context.Background(), leaf); err != nil {
		t.Fatalf("onIssued: %v", err)
	}
	if dane.prePublishCalls != 1 {
		t.Errorf("prePublishCalls = %d, want 1", dane.prePublishCalls)
	}
	if dane.lastHostname != dnsName {
		t.Errorf("hostname = %q, want %q", dane.lastHostname, dnsName)
	}
}

// TestBuildBMCRenewalHooks_OnIssuedNoDNSSkipsPrePublish verifies that
// the OnCertIssued hook is a no-op when there is no enrolled DNS name.
func TestBuildBMCRenewalHooks_OnIssuedNoDNSSkipsPrePublish(t *testing.T) {
	leaf := testIssuedCertificate()
	dane := &fakeDanePublisher{}

	onIssued, _ := buildRenewalHooksForTest(dane, "", "1.2.3.4", nil)
	if err := onIssued(context.Background(), leaf); err != nil {
		t.Fatalf("onIssued with empty dnsName: %v", err)
	}
	if dane.prePublishCalls != 0 {
		t.Errorf("prePublishCalls = %d, want 0 when DNS name is absent", dane.prePublishCalls)
	}
}

// TestBuildBMCRenewalHooks_OnDeployedUpdatesPinAndPublishes verifies
// that the OnCertDeployed hook updates the TOFU pin before re-publishing
// the full TLSA record set.
func TestBuildBMCRenewalHooks_OnDeployedUpdatesPinAndPublishes(t *testing.T) {
	leaf := testIssuedCertificate()
	ca := testIssuedCertificate()
	dane := &fakeDanePublisher{}

	var pinMu sync.Mutex
	pinUpdates := []string{}
	pinUpdater := func(_ context.Context, host string, _ int, _, _ string) error {
		pinMu.Lock()
		defer pinMu.Unlock()
		pinUpdates = append(pinUpdates, host)
		return nil
	}

	dnsName := "node-01-bmc.internal"
	_, onDeployed := buildRenewalHooksForTest(dane, dnsName, "1.2.3.4", pinUpdater)
	if err := onDeployed(context.Background(), leaf, ca); err != nil {
		t.Fatalf("onDeployed: %v", err)
	}

	pinMu.Lock()
	defer pinMu.Unlock()
	if len(pinUpdates) != 1 || pinUpdates[0] != "1.2.3.4" {
		t.Errorf("pinUpdates = %v, want [1.2.3.4]", pinUpdates)
	}
	if dane.publishCalls != 1 {
		t.Errorf("publishCalls = %d, want 1", dane.publishCalls)
	}
	if dane.lastCA != ca {
		t.Error("publishCalls received wrong CA cert pointer")
	}
}

// TestBuildBMCRenewalHooks_NoDNSNameSkipsDANEButUpdatePin verifies that
// when the device has no enrolled DNS name, DANE calls are skipped but
// the TOFU pin is still updated.
func TestBuildBMCRenewalHooks_NoDNSNameSkipsDANEButUpdatePin(t *testing.T) {
	leaf := testIssuedCertificate()
	dane := &fakeDanePublisher{}

	var pinCalled bool
	pinUpdater := func(_ context.Context, _ string, _ int, _, _ string) error {
		pinCalled = true
		return nil
	}

	// Empty dnsName simulates a device with no enrolled DNS name.
	_, onDeployed := buildRenewalHooksForTest(dane, "", "1.2.3.4", pinUpdater)
	if err := onDeployed(context.Background(), leaf, nil); err != nil {
		t.Fatalf("onDeployed: %v", err)
	}

	if !pinCalled {
		t.Error("TOFU pin must be updated even when DNS name is absent")
	}
	if dane.publishCalls != 0 {
		t.Errorf("DANE publish must be skipped when DNS name absent, got %d calls", dane.publishCalls)
	}
}

// TestBuildBMCRenewalHooks_NilCATolerance verifies that the
// OnCertDeployed hook tolerates a nil ca (ACME path) — it must not
// panic, must still update the pin, and must still attempt TLSA
// publication (passing nil ca through).
func TestBuildBMCRenewalHooks_NilCATolerance(t *testing.T) {
	leaf := testIssuedCertificate()
	dane := &fakeDanePublisher{}

	var pinCalled bool
	pinUpdater := func(_ context.Context, _ string, _ int, _, _ string) error {
		pinCalled = true
		return nil
	}

	_, onDeployed := buildRenewalHooksForTest(dane, "node-01-bmc.internal", "1.2.3.4", pinUpdater)
	if err := onDeployed(context.Background(), leaf, nil); err != nil {
		t.Fatalf("onDeployed with nil ca: %v", err)
	}
	if !pinCalled {
		t.Error("pin update must run even with nil ca")
	}
	if dane.publishCalls != 1 {
		t.Errorf("publishCalls = %d, want 1", dane.publishCalls)
	}
	if dane.lastCA != nil {
		t.Error("nil ca must be forwarded to PublishForCertificate")
	}
}

// TestBuildBMCRenewalHooks_PinErrorIsReturnedFromHook verifies that a
// pin update failure is returned from the deployed hook. The non-fatal
// semantics (renewal still succeeds) are covered by
// TestIssueBMCCertificateCore_DeployedHookErrorIsNonFatal.
func TestBuildBMCRenewalHooks_PinErrorIsReturnedFromHook(t *testing.T) {
	leaf := testIssuedCertificate()
	pinErr := errors.New("pin store unavailable")
	pinUpdater := func(_ context.Context, _ string, _ int, _, _ string) error {
		return pinErr
	}

	_, onDeployed := buildRenewalHooksForTest(nil, "node-01-bmc.internal", "1.2.3.4", pinUpdater)
	err := onDeployed(context.Background(), leaf, nil)
	if !errors.Is(err, pinErr) {
		t.Errorf("err = %v, want pin error", err)
	}
}

// buildRenewalHooksForTest constructs OnCertIssued and OnCertDeployed
// closures for unit tests, mirroring the shape of buildBMCRenewalHooks
// without requiring a live App instance. This function exercises the
// same logic paths as the production hook builder.
func buildRenewalHooksForTest(
	dp daneRenewalPublisher,
	dnsName string,
	bmcHost string,
	pinUpdater func(context.Context, string, int, string, string) error,
) (
	onIssued func(context.Context, *x509.Certificate) error,
	onDeployed func(context.Context, *x509.Certificate, *x509.Certificate) error,
) {
	const internalZone = "internal."

	onIssued = func(ctx context.Context, leaf *x509.Certificate) error {
		if dp == nil || dnsName == "" {
			return nil
		}
		return dp.PrePublishRollover(ctx, leaf, dnsName, 443, internalZone)
	}

	onDeployed = func(ctx context.Context, leaf, ca *x509.Certificate) error {
		if bmcHost != "" && pinUpdater != nil {
			spki := certSPKISHA256(leaf)
			fp := certDERSHA256(leaf)
			if err := pinUpdater(ctx, bmcHost, 443, spki, fp); err != nil {
				return err
			}
		}
		if dp == nil || dnsName == "" {
			return nil
		}
		return dp.PublishForCertificate(ctx, leaf, ca, dnsName, 443, internalZone)
	}

	return onIssued, onDeployed
}

// TestInitBMCCert_HooksPropagateThroughOptions verifies that
// OnCertIssued and OnCertDeployed set in issueBMCCertificateOptions are
// both called during a normal issuance cycle. The test drives
// issueBMCCertificateCore directly with a fakeDeployer to bypass the
// AutoCertManager dial.
func TestInitBMCCert_HooksPropagateThroughOptions(t *testing.T) {
	dep := &fakeDeployer{}
	cfg := minimalCertConfig("bmc01.internal")

	var issuedCalled, deployedCalled bool

	_, err := issueBMCCertificateCore(context.Background(), "bmc01.internal", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		OnCertIssued: func(_ context.Context, _ *x509.Certificate) error {
			issuedCalled = true
			return nil
		},
		OnCertDeployed: func(_ context.Context, _, _ *x509.Certificate) error {
			deployedCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore: %v", err)
	}
	if !issuedCalled {
		t.Error("OnCertIssued was not called")
	}
	if !deployedCalled {
		t.Error("OnCertDeployed was not called")
	}
}

// TestEnrolledDNSNameForHost_MatchesCorrectDevice verifies that on a
// control plane holding several enrolled devices, the renewal hooks
// resolve the DNS name of the device whose BMCEnrollment.Host matches
// the platform's BMC address — never another device's name.
func TestEnrolledDNSNameForHost_MatchesCorrectDevice(t *testing.T) {
	devices := []*entities.Device{
		{ID: 1, BMCEnrollment: &entities.BMCEnrollment{Host: "10.4.6.102", DNSName: "node-01-bmc.internal."}},
		{ID: 2, BMCEnrollment: &entities.BMCEnrollment{Host: "10.4.6.103", DNSName: "node-02-bmc.internal."}},
		{ID: 3, BMCEnrollment: nil},
	}
	if got := enrolledDNSNameForHost(devices, "10.4.6.103"); got != "node-02-bmc.internal" {
		t.Errorf("enrolledDNSNameForHost = %q, want %q", got, "node-02-bmc.internal")
	}
}

// TestEnrolledDNSNameForHost_NoMatch verifies that an unmatched host, a
// matched enrollment without a DNS name, nil devices, and an empty host
// all yield an empty string.
func TestEnrolledDNSNameForHost_NoMatch(t *testing.T) {
	devices := []*entities.Device{
		nil,
		{ID: 1, BMCEnrollment: &entities.BMCEnrollment{Host: "10.4.6.102", DNSName: "node-01-bmc.internal."}},
		{ID: 2, BMCEnrollment: &entities.BMCEnrollment{Host: "10.4.6.104"}},
	}
	if got := enrolledDNSNameForHost(devices, "10.0.0.1"); got != "" {
		t.Errorf("unmatched host: got %q, want empty", got)
	}
	if got := enrolledDNSNameForHost(devices, "10.4.6.104"); got != "" {
		t.Errorf("enrollment without DNS name: got %q, want empty", got)
	}
	if got := enrolledDNSNameForHost(nil, "10.4.6.102"); got != "" {
		t.Errorf("nil devices: got %q, want empty", got)
	}
}
