package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// sweepScheduler captures the handler RegisterCertRenewal registers so a
// test can run the renewal sweep on demand.
type sweepScheduler struct {
	handler quicbaas.JobHandler
}

func (s *sweepScheduler) RegisterHandler(_ string, handler quicbaas.JobHandler) error {
	s.handler = handler
	return nil
}

func (s *sweepScheduler) ScheduleJob(context.Context, *quicbaas.Job) error { return nil }

func (s *sweepScheduler) ListJobs(context.Context, *quicbaas.JobQuery) ([]*quicbaas.Job, error) {
	return nil, nil
}

// renewalFixture is a daemon whose TLS identity was provisioned by
// applyDaemonTLSIdentity, a loopback TLS listener presenting it, and the
// platform renewal sweep registered on an injected clock (#284).
type renewalFixture struct {
	ca    *fakeKeystoreCA
	app   *app.App
	cfg   *daemon.Config
	sweep quicbaas.JobHandler
	log   *bytes.Buffer
	addr  string
	clock time.Time
}

func newRenewalFixture(t *testing.T) *renewalFixture {
	t.Helper()
	return newRenewalFixtureOn(t, tlsTransportConfig(), func(cfg *daemon.Config) *tls.Config {
		return &tls.Config{
			GetCertificate: cfg.TLSIdentity.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
	})
}

// newRenewalFixtureOn provisions the identity into cfg, registers the renewal
// sweep, and serves handshakes on the tls.Config listenerTLS takes from cfg
// once the identity is applied.
func newRenewalFixtureOn(t *testing.T, cfg *daemon.Config, listenerTLS func(*daemon.Config) *tls.Config) *renewalFixture {
	t.Helper()
	f := &renewalFixture{ca: newFakeKeystoreCA(t), cfg: cfg, log: &bytes.Buffer{}, clock: time.Now()}
	f.app = &app.App{CA: f.ca, PlatformDir: t.TempDir()}
	if err := applyDaemonTLSIdentity(context.Background(), logging.NewLogger(slog.LevelDebug, f.log), f.app, f.cfg, true); err != nil {
		t.Fatalf("applyDaemonTLSIdentity: %v", err)
	}

	sched := &sweepScheduler{}
	err := app.RegisterCertRenewal(context.Background(), app.CertRenewalRegistration{
		Scheduler: sched,
		Registry:  f.app.CertTargets,
		NodeID:    "node-1",
		Logger:    slog.New(slog.NewTextHandler(f.log, nil)),
		Now:       func() time.Time { return f.clock },
	})
	if err != nil {
		t.Fatalf("RegisterCertRenewal: %v", err)
	}
	f.sweep = sched.handler

	listener, err := tls.Listen("tcp", "127.0.0.1:0", listenerTLS(f.cfg))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan struct{})
	go serveHandshakes(t, listener, served)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		<-served
	})
	f.addr = listener.Addr().String()
	return f
}

// serveHandshakes completes the server side of each handshake, one
// connection at a time, until the listener is closed; then it closes done.
func serveHandshakes(t *testing.T, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Logf("server close after handshake: %v", err)
		}
	}
}

// presentedSerial dials the listener and returns the serial of the leaf it
// presented on that handshake.
func (f *renewalFixture) presentedSerial(t *testing.T) *big.Int {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", f.addr, &tls.Config{
		RootCAs:    f.ca.root.pool(),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	serial := conn.ConnectionState().PeerCertificates[0].SerialNumber
	if err := conn.Close(); err != nil {
		t.Logf("client close after handshake: %v", err)
	}
	return serial
}

func (f *renewalFixture) runSweep(t *testing.T) *quicbaas.JobResult {
	t.Helper()
	result, err := f.sweep(context.Background(), &quicbaas.Job{Name: "sweep"})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	return result
}

func (f *renewalFixture) servedLeaf() *x509.Certificate {
	return f.cfg.TLSIdentity.Current().Leaf
}

func TestDaemonIdentityRenewal_InsideWindowRenewsAndNextHandshakePresentsIt(t *testing.T) {
	f := newRenewalFixture(t)
	before := f.presentedSerial(t)

	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	result := f.runSweep(t)
	if !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("sweep result = %+v, want one renewal", result)
	}

	after := f.presentedSerial(t)
	if after.Cmp(before) == 0 {
		t.Fatalf("the next handshake still presented serial %s", before)
	}
	if after.Cmp(f.servedLeaf().SerialNumber) != 0 {
		t.Errorf("presented serial %s, want the newly issued %s", after, f.servedLeaf().SerialNumber)
	}
	if f.ca.signerOf(f.servedLeaf()) == nil {
		t.Error("the renewed identity has no keystore-held key")
	}
}

// TestDaemonIdentityRenewal_QUICListenerPresentsTheRenewedIdentity proves the
// QUIC listener serves the daemon identity and its renewal (#36). serve hands
// QUIC a boot-time self-signed tls.Config (quic.DefaultServerConfigWithTLS);
// unless applyDaemonTLSIdentity points it at the renewable identity, QUIC
// presents that boot certificate for the life of the process. The listener
// here is built from the same tls.Config the QUIC server is given.
func TestDaemonIdentityRenewal_QUICListenerPresentsTheRenewedIdentity(t *testing.T) {
	cfg := tlsTransportConfig()
	cfg.EnableQUIC = true
	quicConfig, err := quic.DefaultServerConfigWithTLS()
	if err != nil {
		t.Fatalf("DefaultServerConfigWithTLS: %v", err)
	}
	cfg.QUICConfig = quicConfig
	f := newRenewalFixtureOn(t, cfg, func(cfg *daemon.Config) *tls.Config {
		return cfg.QUICConfig.TLSConfig.Clone()
	})

	before := f.presentedSerial(t)
	if before.Cmp(f.servedLeaf().SerialNumber) != 0 {
		t.Fatalf("QUIC presented serial %s, want the daemon identity %s", before, f.servedLeaf().SerialNumber)
	}

	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	result := f.runSweep(t)
	if !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("sweep result = %+v, want one renewal", result)
	}

	after := f.presentedSerial(t)
	if after.Cmp(before) == 0 {
		t.Fatalf("the next QUIC handshake still presented serial %s", before)
	}
	if after.Cmp(f.servedLeaf().SerialNumber) != 0 {
		t.Errorf("QUIC presented serial %s, want the newly issued %s", after, f.servedLeaf().SerialNumber)
	}
}

// oldIdentity is the served identity a renewal test starts from.
type oldIdentity struct {
	cn     string
	serial *big.Int
	signer *keystoreSigner
}

func (f *renewalFixture) oldIdentity() oldIdentity {
	leaf := f.servedLeaf()
	return oldIdentity{cn: leaf.Subject.CommonName, serial: leaf.SerialNumber, signer: f.ca.signerOf(leaf)}
}

// assertOldIdentityServing fails unless the next handshake still presents
// the old certificate and its slot is untouched: key held, not revoked.
func (f *renewalFixture) assertOldIdentityServing(t *testing.T, old oldIdentity) {
	t.Helper()
	if got := f.presentedSerial(t); got.Cmp(old.serial) != 0 {
		t.Fatalf("a failed renewal replaced the served certificate: %s -> %s", old.serial, got)
	}
	if f.ca.keys[old.cn] != old.signer {
		t.Error("a failed renewal touched the serving key")
	}
	if f.ca.certs[old.cn] == nil || f.ca.isRevoked(old.serial) {
		t.Error("a failed renewal revoked or deleted the serving certificate")
	}
}

func TestDaemonIdentityRenewal_IssueFailureKeepsTheOldKeyServing(t *testing.T) {
	f := newRenewalFixture(t)
	old := f.oldIdentity()
	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	f.ca.issueErr = errFake{op: "issue"}

	if result := f.runSweep(t); result.Success {
		t.Fatalf("sweep result = %+v, want a reported failure", result)
	}
	f.assertOldIdentityServing(t, old)
}

func TestDaemonIdentityRenewal_LoadFailureKeepsTheOldKeyServingAndIsRetried(t *testing.T) {
	f := newRenewalFixture(t)
	old := f.oldIdentity()
	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	f.ca.loadErr = errFake{op: "load"}

	if result := f.runSweep(t); result.Success {
		t.Fatalf("sweep result = %+v, want a reported failure", result)
	}
	f.assertOldIdentityServing(t, old)

	// The identity issued before the load failed is not served; the retry
	// retires it and issues again.
	f.ca.loadErr = nil
	if result := f.runSweep(t); !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("retry sweep result = %+v, want one renewal", result)
	}
	if got := f.presentedSerial(t); got.Cmp(old.serial) == 0 {
		t.Error("the retried renewal is not presented on the next handshake")
	}
}

func TestDaemonIdentityRenewal_OldKeyIsDeletedOnlyAfterTheSwap(t *testing.T) {
	f := newRenewalFixture(t)
	old := f.oldIdentity()
	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	servingWhenDeleted := ""
	f.ca.onDeleteKey = func(cn string) {
		if cn == old.cn {
			servingWhenDeleted = f.servedLeaf().Subject.CommonName
		}
	}

	if result := f.runSweep(t); !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("sweep result = %+v, want one renewal", result)
	}
	if servingWhenDeleted == "" {
		t.Fatal("the old key was not deleted after the renewal")
	}
	if servingWhenDeleted == old.cn {
		t.Fatal("the old key was deleted while it was still serving")
	}
	if !f.ca.isRevoked(old.serial) || f.ca.certs[old.cn] != nil {
		t.Error("the replaced certificate must be revoked and deleted")
	}
	if got := f.presentedSerial(t); got.Cmp(old.serial) == 0 {
		t.Error("the renewed identity is not presented on the next handshake")
	}
}

func TestDaemonIdentityRenewal_RetireFailureKeepsServingAndIsRetriedNextSweep(t *testing.T) {
	f := newRenewalFixture(t)
	old := f.oldIdentity()
	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)
	f.ca.deleteKeyErr = errFake{op: "delete key"}

	if result := f.runSweep(t); !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("sweep result = %+v, want one renewal: a failed retirement is not a failed renewal", result)
	}
	renewed := f.presentedSerial(t)
	if renewed.Cmp(old.serial) == 0 {
		t.Fatal("the renewed identity is not presented on the next handshake")
	}
	if !strings.Contains(f.log.String(), "could not be retired") {
		t.Errorf("the failed retirement was not logged: %s", f.log.String())
	}
	if f.ca.keys[old.cn] != old.signer {
		t.Fatal("the old key must stay until a retirement succeeds")
	}

	f.ca.deleteKeyErr = nil
	f.clock = time.Now()
	if result := f.runSweep(t); !result.Success || strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("retry sweep result = %+v, want nothing renewed", result)
	}
	if f.ca.keys[old.cn] != nil || f.ca.certs[old.cn] != nil {
		t.Error("the next sweep must retire the replaced slot")
	}
	if got := f.presentedSerial(t); got.Cmp(renewed) != 0 {
		t.Errorf("retiring the old slot changed the served certificate: %s -> %s", renewed, got)
	}
}

func TestDaemonIdentityRenewal_FailureKeepsCurrentAndIsRetried(t *testing.T) {
	f := newRenewalFixture(t)
	before := f.presentedSerial(t)
	f.clock = f.servedLeaf().NotAfter.Add(-25 * 24 * time.Hour)

	f.ca.unavailable = true
	result := f.runSweep(t)
	if result.Success {
		t.Fatalf("sweep result = %+v, want a reported failure", result)
	}
	if !strings.Contains(f.log.String(), "cert-renewal: reissue failed") ||
		!strings.Contains(f.log.String(), daemonIdentityCertTargetName) {
		t.Errorf("failure not logged for %s: %s", daemonIdentityCertTargetName, f.log.String())
	}
	if got := f.presentedSerial(t); got.Cmp(before) != 0 {
		t.Fatalf("a failed renewal replaced the served certificate: %s -> %s", before, got)
	}

	target, ok := f.app.CertTargets.Get(daemonIdentityCertTargetName)
	if !ok {
		t.Fatal("daemon identity target not registered")
	}
	var keystoreErr ErrTLSIdentityKeystore
	if err := target.Reissue(context.Background()); !errors.As(err, &keystoreErr) || keystoreErr.Op != "issue" {
		t.Fatalf("Reissue error = %v, want ErrTLSIdentityKeystore{Op: issue}", err)
	}

	f.ca.unavailable = false
	if result := f.runSweep(t); !result.Success || !strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("retry sweep result = %+v, want one renewal", result)
	}
	if got := f.presentedSerial(t); got.Cmp(before) == 0 {
		t.Error("the retried renewal is not presented on the next handshake")
	}
}

func TestDaemonIdentityRenewal_OutsideWindowLeftAlone(t *testing.T) {
	f := newRenewalFixture(t)
	before := f.presentedSerial(t)
	issued := f.ca.issueCalls

	result := f.runSweep(t)
	if !result.Success || strings.Contains(result.Message, "1 renewed") {
		t.Fatalf("sweep result = %+v, want nothing renewed", result)
	}
	if f.ca.issueCalls != issued {
		t.Errorf("issueCalls = %d, want %d: a certificate outside the window was reissued", f.ca.issueCalls, issued)
	}
	if got := f.presentedSerial(t); got.Cmp(before) != 0 {
		t.Errorf("served certificate changed outside the window: %s -> %s", before, got)
	}
}

func TestDaemonIdentityCertTarget_CurrentWithoutIdentityFails(t *testing.T) {
	var serving *daemon.ServingCertificate
	target := daemonIdentityCertTarget(newTestLogger(), newFakeKeystoreCA(t), serving, nil, nil)
	_, err := target.Current(context.Background())
	var want ErrTLSIdentityNotProvisioned
	if !errors.As(err, &want) {
		t.Fatalf("Current error = %v, want ErrTLSIdentityNotProvisioned", err)
	}
}
