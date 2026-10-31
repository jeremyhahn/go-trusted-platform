// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// testGateway builds a plain enabled gateway node for reporter tests.
func testGateway(t *testing.T) *gateway.Gateway {
	t.Helper()
	gw, err := BuildGateway(context.Background(), &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: true, ID: "gw-report"},
	}, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	return gw
}

func TestBuildReporterAbsentOrDisabled(t *testing.T) {
	gw := testGateway(t)
	rep, err := BuildReporter(context.Background(), &ServeConfig{}, gw, testLogger())
	if err != nil || rep != nil {
		t.Fatalf("absent section: reporter=%v err=%v, want nil/nil", rep, err)
	}
	cfg := &ServeConfig{ControlPlane: &controlplane.Config{Enabled: false}}
	rep, err = BuildReporter(context.Background(), cfg, gw, testLogger())
	if err != nil || rep != nil {
		t.Fatalf("disabled section: reporter=%v err=%v, want nil/nil", rep, err)
	}
}

func TestBuildReporterInvalidSection(t *testing.T) {
	gw := testGateway(t)
	cfg := &ServeConfig{ControlPlane: &controlplane.Config{Enabled: true}}
	var sectionErr *ErrConfigSection
	if _, err := BuildReporter(context.Background(), cfg, gw, testLogger()); !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection", err)
	}
}

func TestBuildReporterWithMTLSIdentity(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
			// BuildReporter refuses a gateway-id the control plane
			// would not recognise, so an enabled section must name the
			// identity its own certificate carries.
			GatewayID: tlsFixtureCN,
		},
	}
	rep, err := BuildReporter(context.Background(), cfg, gw, testLogger())
	if err != nil {
		t.Fatalf("BuildReporter: %v", err)
	}
	if rep == nil {
		t.Fatal("reporter must be constructed for an enabled section")
	}
}

func TestBuildReporterBadKeypair(t *testing.T) {
	gw := testGateway(t)
	_, _, caFile := writeTLSFixtures(t)
	badCert := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: badCert,
			KeyFile:  badCert,
			CAFile:   caFile,
		},
	}
	var certErr *proxysvc.ErrCertificateLoadFailed
	if _, err := BuildReporter(context.Background(), cfg, gw, testLogger()); !errors.As(err, &certErr) {
		t.Fatalf("err = %v, want *ErrCertificateLoadFailed", err)
	}
}

func TestBuildReporterBadCAFile(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, _ := writeTLSFixtures(t)

	missing := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   filepath.Join(t.TempDir(), "missing-ca.pem"),
		},
	}
	var caErr *ErrCAFileLoadFailed
	if _, err := BuildReporter(context.Background(), missing, gw, testLogger()); !errors.As(err, &caErr) {
		t.Fatalf("missing ca-file err = %v, want *ErrCAFileLoadFailed", err)
	}

	garbageFile := filepath.Join(t.TempDir(), "garbage-ca.pem")
	if err := os.WriteFile(garbageFile, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	garbage := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   garbageFile,
		},
	}
	if _, err := BuildReporter(context.Background(), garbage, gw, testLogger()); !errors.As(err, &caErr) {
		t.Fatalf("garbage ca-file err = %v, want *ErrCAFileLoadFailed", err)
	}
}

func TestBuildReporterWithoutClientIdentityFailsClosed(t *testing.T) {
	// The telemetry identity claim is the mTLS client certificate; an
	// enabled section without one must be refused, not silently sent
	// unauthenticated.
	gw := testGateway(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled: true,
			BaseURL: "https://cp.example.com:8443",
		},
	}
	var sectionErr *ErrConfigSection
	if _, err := BuildReporter(context.Background(), cfg, gw, testLogger()); !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection (missing cert-file)", err)
	}
}

func TestBuildReporterNilConfigAndNilLogger(t *testing.T) {
	gw := testGateway(t)
	if _, err := BuildReporter(context.Background(), nil, gw, testLogger()); !errors.Is(err, ErrConfigLoadFailed) {
		t.Fatalf("nil cfg err = %v, want ErrConfigLoadFailed", err)
	}

	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:   true,
			BaseURL:   "https://cp.example.com:8443",
			CertFile:  certFile,
			KeyFile:   keyFile,
			CAFile:    caFile,
			GatewayID: tlsFixtureCN,
		},
	}
	rep, err := BuildReporter(context.Background(), cfg, gw, nil)
	if err != nil || rep == nil {
		t.Fatalf("nil logger must default, got rep=%v err=%v", rep, err)
	}
}

func TestVPNLeaseControl_TheVPNChildRecordsItsLeasesWithTheControlPlane(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, caFile := writeTLSFixtures(t)
	dataDir := t.TempDir()
	cfg := &ServeConfig{
		DataDir: dataDir,
		ControlPlane: &controlplane.Config{
			Enabled:   true,
			BaseURL:   "https://cp.example.com:8443",
			CertFile:  certFile,
			KeyFile:   keyFile,
			CAFile:    caFile,
			GatewayID: tlsFixtureCN,
		},
	}
	control, journal, err := vpnLeaseControl(context.Background(), cfg, gw, testLogger())
	if err != nil {
		t.Fatalf("vpnLeaseControl: %v", err)
	}
	if _, ok := control.(*controlplane.Reporter); !ok {
		t.Fatalf("control = %T, want the control-plane reporter", control)
	}
	if want := vpnRevocationJournal(dataDir); !reflect.DeepEqual(journal, want) {
		t.Fatalf("journal = %+v, want the journal under the data directory %+v", journal, want)
	}
}

func TestVPNLeaseControl_NoControlPlaneKeepsTheLeasesInMemory(t *testing.T) {
	gw := testGateway(t)
	cfg := &ServeConfig{DataDir: t.TempDir(), ControlPlane: &controlplane.Config{Enabled: false}}
	control, journal, err := vpnLeaseControl(context.Background(), cfg, gw, testLogger())
	if err != nil || control != nil || journal != nil {
		t.Fatalf("disabled section: control=%v journal=%v err=%v, want nil/nil/nil", control, journal, err)
	}
}

func TestVPNLeaseControl_AnInvalidControlPlaneSectionIsRefused(t *testing.T) {
	gw := testGateway(t)
	cfg := &ServeConfig{ControlPlane: &controlplane.Config{Enabled: true}}
	var sectionErr *ErrConfigSection
	control, journal, err := vpnLeaseControl(context.Background(), cfg, gw, testLogger())
	if !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection", err)
	}
	if control != nil || journal != nil {
		t.Fatalf("a refused section yields no record: control=%v journal=%v", control, journal)
	}
}

func TestSnapshotCollectorCollect(t *testing.T) {
	gw := testGateway(t)
	collector := &snapshotCollector{gw: gw}
	snap, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap == nil || snap.GatewayID != "gw-report" {
		t.Fatalf("snapshot = %+v, want gateway_id gw-report", snap)
	}
}

// tlsFixtureCN is the Subject Common Name carried by the certificate
// writeTLSFixtures writes. TestTLSFixtureCommonName pins it, so the
// constant cannot drift away from the fixture it describes.
const tlsFixtureCN = "localhost"

func TestTLSFixtureCommonName(t *testing.T) {
	certFile, keyFile, _ := writeTLSFixtures(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	cn, err := clientCertCommonName(&cert)
	if err != nil {
		t.Fatalf("clientCertCommonName: %v", err)
	}
	if cn != tlsFixtureCN {
		t.Fatalf("fixture CN = %q, want %q — update tlsFixtureCN", cn, tlsFixtureCN)
	}
}

// TestBuildReporterRejectsGatewayIDCertMismatch is the gatewayd half of
// the control plane's certificate binding. A gateway-id the certificate
// does not name can only ever produce 403s on every push, so assembly
// refuses it once instead of warning on a ticker forever.
func TestBuildReporterRejectsGatewayIDCertMismatch(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:   true,
			BaseURL:   "https://cp.example.com:8443",
			CertFile:  certFile,
			KeyFile:   keyFile,
			CAFile:    caFile,
			GatewayID: "somebody-elses-gateway",
		},
	}
	var mismatch *ErrGatewayIDCertMismatch
	rep, err := BuildReporter(context.Background(), cfg, gw, testLogger())
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *ErrGatewayIDCertMismatch", err)
	}
	if rep != nil {
		t.Fatal("a mismatched identity must not yield a running reporter")
	}
	if mismatch.CertCN != tlsFixtureCN || mismatch.GatewayID != "somebody-elses-gateway" {
		t.Fatalf("error names CertCN=%q GatewayID=%q; want %q / %q",
			mismatch.CertCN, mismatch.GatewayID, tlsFixtureCN, "somebody-elses-gateway")
	}
}

// TestBuildReporterRejectsNodeIDCertMismatch covers the defaulted path:
// when control-plane gateway-id is omitted the gateway node ID is used,
// and that must be bound to the certificate on the same terms rather
// than slipping through unchecked.
func TestBuildReporterRejectsNodeIDCertMismatch(t *testing.T) {
	gw := testGateway(t) // node ID "gw-report"
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
	}
	var mismatch *ErrGatewayIDCertMismatch
	if _, err := BuildReporter(context.Background(), cfg, gw, testLogger()); !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *ErrGatewayIDCertMismatch", err)
	}
	if mismatch.GatewayID != "gw-report" {
		t.Fatalf("GatewayID = %q, want the defaulted node ID gw-report", mismatch.GatewayID)
	}
}

// TestClientCertCommonNameEmptyKeypair covers the error path of the CN
// reader: a keypair with no certificate has no identity to report and
// must say so rather than returning an empty CN that would read as
// "no client certificate configured" and skip the binding check.
func TestClientCertCommonNameEmptyKeypair(t *testing.T) {
	if _, err := clientCertCommonName(&tls.Certificate{}); !errors.Is(err, ErrClientCertEmpty) {
		t.Fatalf("err = %v, want ErrClientCertEmpty", err)
	}
}

// TestClientCertCommonNameParsesDER covers the Leaf-less fallback: a
// tls.Certificate assembled without a parsed Leaf must still yield the
// CN from its DER rather than silently reporting none.
func TestClientCertCommonNameParsesDER(t *testing.T) {
	certFile, keyFile, _ := writeTLSFixtures(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	cert.Leaf = nil
	cn, err := clientCertCommonName(&cert)
	if err != nil {
		t.Fatalf("clientCertCommonName: %v", err)
	}
	if cn != tlsFixtureCN {
		t.Fatalf("CN = %q, want %q", cn, tlsFixtureCN)
	}
}

// TestClientCertCommonNameIsVerbatim pins the client half of the same
// rule. Trimming here would hide a padded CN from the gateway-id
// comparison while the control plane refuses that very certificate,
// converting a clear startup error into a permanent 403 on every tick.
func TestClientCertCommonNameIsVerbatim(t *testing.T) {
	cert := tls.Certificate{Leaf: &x509.Certificate{
		Subject: pkix.Name{CommonName: " gw-padded "},
	}}
	cn, err := clientCertCommonName(&cert)
	if err != nil {
		t.Fatalf("clientCertCommonName: %v", err)
	}
	if cn != " gw-padded " {
		t.Fatalf("CN = %q, want the verbatim %q", cn, " gw-padded ")
	}
}

// TestBuildReporterRejectsPaddedGatewayID pins the rule that closes the
// case a bare CN comparison waves through: when the certificate CN and
// the configured gateway-id are IDENTICALLY padded they match each
// other, yet the control plane refuses a padded Common Name outright, so
// the reporter would 401 on every push forever with both halves
// agreeing. The refusal is on the identity itself and runs before the
// certificate is loaded, so the CN never enters the decision — which is
// what makes that case unreachable, and why this test does not need a
// padded-CN fixture to cover it.
func TestBuildReporterRejectsPaddedGatewayID(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, caFile := writeTLSFixtures(t)
	padded := " " + tlsFixtureCN + " "
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:   true,
			BaseURL:   "https://cp.example.com:8443",
			CertFile:  certFile,
			KeyFile:   keyFile,
			CAFile:    caFile,
			GatewayID: padded,
		},
	}
	var notReportable *ErrGatewayIDNotReportable
	rep, err := BuildReporter(context.Background(), cfg, gw, testLogger())
	if !errors.As(err, &notReportable) {
		t.Fatalf("err = %v, want *ErrGatewayIDNotReportable", err)
	}
	if rep != nil {
		t.Fatal("an unreportable identity must not yield a running reporter")
	}
	if notReportable.GatewayID != padded {
		t.Fatalf("GatewayID = %q, want %q", notReportable.GatewayID, padded)
	}
}

// TestBuildReporterRejectsWhitespaceOnlyGatewayID covers the degenerate
// form of the same rule.
func TestBuildReporterRejectsWhitespaceOnlyGatewayID(t *testing.T) {
	gw := testGateway(t)
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:   true,
			BaseURL:   "https://cp.example.com:8443",
			CertFile:  certFile,
			KeyFile:   keyFile,
			CAFile:    caFile,
			GatewayID: "   ",
		},
	}
	var notReportable *ErrGatewayIDNotReportable
	if _, err := BuildReporter(context.Background(), cfg, gw, testLogger()); !errors.As(err, &notReportable) {
		t.Fatalf("err = %v, want *ErrGatewayIDNotReportable", err)
	}
}

// TestBuildReporterUnsetGatewayIDReportsCertMismatch pins what happens
// when neither the control-plane section nor the gateway node names an
// ID: BuildGateway defaults the node ID to "gatewayd", so the resolved
// identity is that default rather than empty, and the CN comparison
// reports it against the CN the certificate actually carries — which
// tells an operator exactly what to set gateway-id to. It is
// deliberately NOT ErrGatewayIDNotReportable: the default is a
// well-formed identity, just not this certificate's.
func TestBuildReporterUnsetGatewayIDReportsCertMismatch(t *testing.T) {
	gw, err := BuildGateway(context.Background(), &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: true, ID: ""},
	}, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := &ServeConfig{
		ControlPlane: &controlplane.Config{
			Enabled:  true,
			BaseURL:  "https://cp.example.com:8443",
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
	}
	var mismatch *ErrGatewayIDCertMismatch
	var notReportable *ErrGatewayIDNotReportable
	rep, err := BuildReporter(context.Background(), cfg, gw, testLogger())
	if errors.As(err, &notReportable) {
		t.Fatalf("err = %v; an empty ID is not refused for its shape", err)
	}
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *ErrGatewayIDCertMismatch", err)
	}
	if rep != nil {
		t.Fatal("an empty identity must not yield a running reporter")
	}
	if mismatch.GatewayID != gw.GetConfig().ID || mismatch.CertCN != tlsFixtureCN {
		t.Fatalf("error names GatewayID=%q CertCN=%q; want %q / %q",
			mismatch.GatewayID, mismatch.CertCN, gw.GetConfig().ID, tlsFixtureCN)
	}
	if gw.GetConfig().ID == "" {
		t.Fatal("BuildGateway no longer defaults an unset node ID; the empty-ID path this test describes has changed")
	}
}

// stubFetcher satisfies controlplane.DesiredConfigFetcher for the builder.
type stubFetcher struct{}

func (stubFetcher) FetchDesiredConfig(context.Context) (*gwstate.DesiredConfig, error) {
	return &gwstate.DesiredConfig{}, nil
}

func TestBuildReconciler(t *testing.T) {
	gw := testGateway(t)
	if _, err := BuildReconciler(nil, stubFetcher{}, gw, testLogger()); err == nil {
		t.Fatal("nil config must be refused")
	}
	if _, err := BuildReconciler(&ServeConfig{}, stubFetcher{}, gw, testLogger()); err == nil {
		t.Fatal("absent control-plane section must be refused")
	}
	cfg := &ServeConfig{ControlPlane: &controlplane.Config{Enabled: true, ReconcileInterval: 90 * time.Second}}
	r, err := BuildReconciler(cfg, stubFetcher{}, gw, nil)
	if err != nil || r == nil {
		t.Fatalf("BuildReconciler: r=%v err=%v", r, err)
	}
	var sectionErr *ErrConfigSection
	if _, err := BuildReconciler(cfg, nil, gw, testLogger()); !errors.As(err, &sectionErr) {
		t.Fatalf("nil fetcher: err = %v, want *ErrConfigSection", err)
	}
}
