package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	dane "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/dane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

const (
	rolloverFailureHost = "leaf.example.com"
	rolloverFailureZone = "example.com."
	rolloverFailureName = "_443._tcp.leaf.example.com."
)

// rolloverZoneRecords returns the TLSA records the zone holds at the
// rollover test name.
func rolloverZoneRecords(t *testing.T, svc *testDNSService) []*entities.TLSARecord {
	t.Helper()
	var records []*entities.TLSARecord
	for _, record := range svc.zones[rolloverFailureZone].RecordSet.TLSARecords {
		if record.Name == rolloverFailureName {
			records = append(records, record)
		}
	}
	return records
}

// expectedRolloverData is the hex DANE-EE data the publisher derives for cert
// under the rollover test configuration.
func expectedRolloverData(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	data, err := dane.ComputeTLSAData(cert, dane.SelectorSPKI, dane.MatchingSHA256)
	if err != nil {
		t.Fatalf("ComputeTLSAData: %v", err)
	}
	return hex.EncodeToString(data)
}

// assertOnlyRecord fails unless the zone holds exactly one TLSA record at the
// test name, a DANE-EE record carrying data.
func assertOnlyRecord(t *testing.T, svc *testDNSService, data string) {
	t.Helper()
	records := rolloverZoneRecords(t, svc)
	if len(records) != 1 {
		t.Fatalf("zone holds %d TLSA records at %s, want 1", len(records), rolloverFailureName)
	}
	if records[0].Data != data {
		t.Errorf("TLSA data = %q, want %q", records[0].Data, data)
	}
	if records[0].Usage != dane.UsageDANEEE {
		t.Errorf("TLSA usage = %d, want DANE-EE", records[0].Usage)
	}
}

func waitRollover(t *testing.T, mgr *RolloverManager) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	err := mgr.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Wait did not return before the deadline")
	}
	return err
}

// Completing a key-rotation rollover retires the old record and keeps the
// pre-published one (RFC 7671 §8.1): the zone must never end the rollover
// without a record for the certificate it now serves.
func TestRollover_KeyRotation_CompleteKeepsPrePublishedRecord(t *testing.T) {
	mgr, svc, reloader, newCert, newTLSCert := rolloverTestSetup(t, false, 0)
	mgr.config.DefaultTTL = 0

	err := mgr.BeginRollover(context.Background(), newCert, newTLSCert,
		rolloverFailureHost, 443, rolloverFailureZone)
	if err != nil {
		t.Fatalf("BeginRollover: %v", err)
	}
	if err := waitRollover(t, mgr); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if reloader.Current() != newTLSCert {
		t.Error("new certificate was not activated")
	}
	assertOnlyRecord(t, svc, expectedRolloverData(t, newCert))
	if mgr.Phase() != RolloverIdle {
		t.Errorf("phase = %d, want RolloverIdle", mgr.Phase())
	}
}

// When the new certificate cannot be loaded, the server keeps the old one, so
// the rollover is withdrawn: the old record stays, the pre-published record is
// removed, and Wait reports the failure.
func TestRollover_KeyRotation_ReloadFailureWithdrawsRollover(t *testing.T) {
	mgr, svc, reloader, newCert, _ := rolloverTestSetup(t, false, 0)
	mgr.config.DefaultTTL = 0
	initial := reloader.Current()

	err := mgr.BeginRollover(context.Background(), newCert, nil,
		rolloverFailureHost, 443, rolloverFailureZone)
	if err != nil {
		t.Fatalf("BeginRollover: %v", err)
	}

	err = waitRollover(t, mgr)
	var reloadErr ErrCertReloadFailed
	if !errors.As(err, &reloadErr) {
		t.Fatalf("Wait error = %v, want ErrCertReloadFailed", err)
	}
	if errors.As(reloadErr.Cause, &ErrCertReloadFailed{}) {
		t.Errorf("reload error is wrapped twice: %v", err)
	}

	if reloader.Current() != initial {
		t.Error("old certificate was replaced despite the reload failure")
	}
	assertOnlyRecord(t, svc, "olddata")
	if mgr.Phase() != RolloverIdle {
		t.Errorf("phase = %d, want RolloverIdle", mgr.Phase())
	}
}

// A withdrawn rollover leaves the manager ready for the next attempt.
func TestRollover_KeyRotation_RetryAfterReloadFailure(t *testing.T) {
	mgr, svc, reloader, newCert, newTLSCert := rolloverTestSetup(t, false, 0)
	mgr.config.DefaultTTL = 0
	ctx := context.Background()

	if err := mgr.BeginRollover(ctx, newCert, nil, rolloverFailureHost, 443, rolloverFailureZone); err != nil {
		t.Fatalf("first BeginRollover: %v", err)
	}
	if err := waitRollover(t, mgr); err == nil {
		t.Fatal("first rollover: Wait returned nil, want the reload failure")
	}

	if err := mgr.BeginRollover(ctx, newCert, newTLSCert, rolloverFailureHost, 443, rolloverFailureZone); err != nil {
		t.Fatalf("second BeginRollover: %v", err)
	}
	if err := waitRollover(t, mgr); err != nil {
		t.Fatalf("second rollover: Wait: %v", err)
	}
	if reloader.Current() != newTLSCert {
		t.Error("new certificate was not activated on retry")
	}
	assertOnlyRecord(t, svc, expectedRolloverData(t, newCert))
}

// With key reuse, a reload failure aborts before DNS is touched, and Wait
// returns the failure instead of blocking until its context expires.
func TestRollover_KeyReuse_ReloadFailureLeavesZoneUntouched(t *testing.T) {
	mgr, svc, reloader, newCert, _ := rolloverTestSetup(t, true, 0)
	initial := reloader.Current()

	err := mgr.BeginRollover(context.Background(), newCert, nil,
		rolloverFailureHost, 443, rolloverFailureZone)
	var reloadErr ErrCertReloadFailed
	if !errors.As(err, &reloadErr) {
		t.Fatalf("BeginRollover error = %v, want ErrCertReloadFailed", err)
	}

	if reloader.Current() != initial {
		t.Error("old certificate was replaced despite the reload failure")
	}
	assertOnlyRecord(t, svc, "olddata")
	if svc.saveSignCalls != 0 {
		t.Errorf("SaveAndSign called %d times, want 0", svc.saveSignCalls)
	}
	if waitErr := waitRollover(t, mgr); !errors.As(waitErr, &reloadErr) {
		t.Errorf("Wait error = %v, want ErrCertReloadFailed", waitErr)
	}
	if mgr.Phase() != RolloverIdle {
		t.Errorf("phase = %d, want RolloverIdle", mgr.Phase())
	}
}

// A key-reuse rollover replaces the old record with exactly one record for the
// new certificate.
func TestRollover_KeyReuse_ReplacesRecord(t *testing.T) {
	mgr, svc, _, newCert, newTLSCert := rolloverTestSetup(t, true, 0)

	err := mgr.BeginRollover(context.Background(), newCert, newTLSCert,
		rolloverFailureHost, 443, rolloverFailureZone)
	if err != nil {
		t.Fatalf("BeginRollover: %v", err)
	}
	assertOnlyRecord(t, svc, expectedRolloverData(t, newCert))
	if err := waitRollover(t, mgr); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

// The new record is published before the old one is removed, so a publish
// failure leaves the old record in place rather than an empty name.
func TestRollover_KeyReuse_PublishFailureKeepsOldRecord(t *testing.T) {
	mgr, svc, _, newCert, newTLSCert := rolloverTestSetup(t, true, 0)
	svc.addErr = errors.New("zone store unavailable")

	err := mgr.BeginRollover(context.Background(), newCert, newTLSCert,
		rolloverFailureHost, 443, rolloverFailureZone)
	var publishErr ErrDANEPublishFailed
	if !errors.As(err, &publishErr) {
		t.Fatalf("BeginRollover error = %v, want ErrDANEPublishFailed", err)
	}
	if publishErr.Zone != rolloverFailureZone {
		t.Errorf("error zone = %q, want %q", publishErr.Zone, rolloverFailureZone)
	}
	assertOnlyRecord(t, svc, "olddata")
	if waitErr := waitRollover(t, mgr); !errors.As(waitErr, &publishErr) {
		t.Errorf("Wait error = %v, want ErrDANEPublishFailed", waitErr)
	}
}

// The rollover record helpers refuse a nil certificate before touching the
// zone, and report a zone they cannot load as a publish failure.
func TestDANEPublisher_RolloverRecordRemovalErrors(t *testing.T) {
	removals := map[string]func(*DANEPublisher, *x509.Certificate) error{
		"retire": func(p *DANEPublisher, cert *x509.Certificate) error {
			return p.retireForHostname(context.Background(), cert, rolloverFailureHost, 443, rolloverFailureZone)
		},
		"withdraw": func(p *DANEPublisher, cert *x509.Certificate) error {
			return p.withdrawRollover(context.Background(), cert, rolloverFailureHost, 443, rolloverFailureZone)
		},
	}

	for name, remove := range removals {
		t.Run(name+"/nil certificate", func(t *testing.T) {
			_, svc, _, _, _ := rolloverTestSetup(t, false, 0)
			publisher := NewDANEPublisher(svc, rolloverTestConfig(false, 0), daneTestLogger())

			err := remove(publisher, nil)
			var computeErr ErrTLSAComputeFailed
			if !errors.As(err, &computeErr) {
				t.Fatalf("error = %v, want ErrTLSAComputeFailed", err)
			}
			if computeErr.CN != rolloverFailureHost {
				t.Errorf("error CN = %q, want %q", computeErr.CN, rolloverFailureHost)
			}
			assertOnlyRecord(t, svc, "olddata")
		})

		t.Run(name+"/zone unavailable", func(t *testing.T) {
			_, svc, _, newCert, _ := rolloverTestSetup(t, false, 0)
			publisher := NewDANEPublisher(svc, rolloverTestConfig(false, 0), daneTestLogger())
			svc.zoneErr = errors.New("zone store unavailable")

			err := remove(publisher, newCert)
			var publishErr ErrDANEPublishFailed
			if !errors.As(err, &publishErr) {
				t.Fatalf("error = %v, want ErrDANEPublishFailed", err)
			}
			if publishErr.Zone != rolloverFailureZone {
				t.Errorf("error zone = %q, want %q", publishErr.Zone, rolloverFailureZone)
			}
			if svc.saveSignCalls != 0 {
				t.Errorf("SaveAndSign called %d times, want 0", svc.saveSignCalls)
			}
		})
	}
}
