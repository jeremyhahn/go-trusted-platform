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

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	dane "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/dane"
	dnsconfig "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// rolloverTestConfig creates a DANEConfig suitable for rollover tests.
func rolloverTestConfig(keyReuse bool, rolloverTTL uint32) *dnsconfig.DANEConfig {
	return &dnsconfig.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        dane.UsageDANETA,
		DefaultSelector:     dane.SelectorSPKI,
		DefaultMatchingType: dane.MatchingSHA256,
		PublishDANEEE:       true,
		KeyReuse:            keyReuse,
		RolloverTTL:         rolloverTTL,
	}
}

// rolloverTestTLSCert generates a tls.Certificate for rollover tests.
func rolloverTestTLSCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &tls.Certificate{
		PrivateKey: key,
	}
}

// rolloverTestSetup creates the standard test fixtures for rollover tests.
func rolloverTestSetup(t *testing.T, keyReuse bool, rolloverTTLSeconds uint32) (
	*RolloverManager, *testDNSService, *CertReloader, *x509.Certificate, *tls.Certificate,
) {
	t.Helper()

	logger := daneTestLogger()
	config := rolloverTestConfig(keyReuse, rolloverTTLSeconds)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANEEE, Data: "olddata"},
			},
		},
	}

	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	publisher := NewDANEPublisher(svc, config, logger)
	mgr := NewRolloverManager(publisher, reloader, config, logger)

	newCert := testCert(t, "leaf.example.com", false)
	newTLSCert := rolloverTestTLSCert(t)

	_ = newTLSCert
	return mgr, svc, reloader, newCert, rolloverTestTLSCert(t)
}

func TestBeginRollover_KeyReuse_ImmediateActivation(t *testing.T) {
	mgr, _, reloader, newCert, newTLSCert := rolloverTestSetup(t, true, 0)

	initialCert := reloader.Current()

	ctx := context.Background()
	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Certificate should have been reloaded immediately.
	currentCert := reloader.Current()
	if currentCert == initialCert {
		t.Error("expected certificate to be reloaded, but it was not changed")
	}
	if currentCert != newTLSCert {
		t.Error("expected current certificate to be the new TLS certificate")
	}

	// Phase should be back to idle.
	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected phase RolloverIdle, got %d", mgr.Phase())
	}

	// Wait should return immediately since rollover is already complete.
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	t.Cleanup(cancel)
	if err := mgr.Wait(waitCtx); err != nil {
		t.Errorf("Wait returned error: %v", err)
	}
}

func TestBeginRollover_KeyReuse_CertReloadVerifiesNewCert(t *testing.T) {
	mgr, _, reloader, newCert, newTLSCert := rolloverTestSetup(t, true, 0)

	ctx := context.Background()
	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the reloader holds exactly the new TLS cert.
	if reloader.Current() != newTLSCert {
		t.Error("reloader does not hold the expected new TLS certificate")
	}
}

func TestBeginRollover_KeyRotation_TransitionsToPrePublish(t *testing.T) {
	mgr, svc, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Phase should be PrePublish.
	if mgr.Phase() != RolloverPrePublish {
		t.Errorf("expected phase RolloverPrePublish, got %d", mgr.Phase())
	}

	// A new TLSA record should have been pre-published.
	if len(svc.addedRecords) < 1 {
		t.Fatal("expected at least 1 TLSA record to be pre-published")
	}

	// Cancel to clean up the goroutine.
	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(waitCancel)
	mgr.Wait(waitCtx)
}

func TestBeginRollover_KeyRotation_PrePublishRecordHasCorrectUsage(t *testing.T) {
	mgr, svc, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(svc.addedRecords) == 0 {
		t.Fatal("expected pre-published TLSA record")
	}
	if svc.addedRecords[0].Usage != dane.UsageDANEEE {
		t.Errorf("expected DANE-EE usage, got %d", svc.addedRecords[0].Usage)
	}

	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(waitCancel)
	mgr.Wait(waitCtx)
}

func TestBeginRollover_AlreadyInProgress(t *testing.T) {
	mgr, _, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// First rollover should succeed.
	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("first rollover failed: %v", err)
	}

	// Second rollover should return ErrRolloverInProgress.
	err = mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for second rollover, got nil")
	}

	var rolloverErr ErrRolloverInProgress
	if !errors.As(err, &rolloverErr) {
		t.Errorf("expected ErrRolloverInProgress, got %T: %v", err, err)
	}
	if rolloverErr.Hostname != "leaf.example.com" {
		t.Errorf("expected hostname leaf.example.com, got %s", rolloverErr.Hostname)
	}

	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(waitCancel)
	mgr.Wait(waitCtx)
}

func TestBeginRollover_AlreadyInProgress_DifferentHostname(t *testing.T) {
	mgr, _, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("first rollover failed: %v", err)
	}

	// Even with a different hostname, the manager-level lock prevents concurrent rollovers.
	err = mgr.BeginRollover(ctx, newCert, newTLSCert, "other.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for concurrent rollover, got nil")
	}

	var rolloverErr ErrRolloverInProgress
	if !errors.As(err, &rolloverErr) {
		t.Errorf("expected ErrRolloverInProgress, got %T: %v", err, err)
	}

	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(waitCancel)
	mgr.Wait(waitCtx)
}

func TestRollover_FullCycle(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	// Use a very small DefaultTTL so 2x gives a ~20ms delay.
	config.DefaultTTL = 0 // 2 * 0 = 0 seconds, effectively immediate.
	config.RolloverTTL = 0

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANEEE, Data: "olddata"},
			},
		},
	}

	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	publisher := NewDANEPublisher(svc, config, logger)
	mgr := NewRolloverManager(publisher, reloader, config, logger)

	newCert := testCert(t, "leaf.example.com", false)
	newTLSCert := rolloverTestTLSCert(t)

	ctx := context.Background()
	err = mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	// Wait for the rollover to complete with a reasonable timeout.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(cancel)

	if err := mgr.Wait(waitCtx); err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}

	// Phase should be back to idle.
	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected phase RolloverIdle after completion, got %d", mgr.Phase())
	}

	// Certificate should have been reloaded.
	if reloader.Current() != newTLSCert {
		t.Error("expected certificate to be reloaded to the new TLS certificate")
	}
}

func TestRollover_FullCycle_SaveAndSignCalled(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	config.DefaultTTL = 0
	config.RolloverTTL = 0

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANEEE, Data: "olddata"},
			},
		},
	}

	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	publisher := NewDANEPublisher(svc, config, logger)
	mgr := NewRolloverManager(publisher, reloader, config, logger)

	newCert := testCert(t, "leaf.example.com", false)
	newTLSCert := rolloverTestTLSCert(t)

	ctx := context.Background()
	err = mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(cancel)
	mgr.Wait(waitCtx)

	// SaveAndSign should have been called at least twice: once for pre-publish, once for cleanup.
	if svc.saveSignCalls < 2 {
		t.Errorf("expected at least 2 SaveAndSign calls, got %d", svc.saveSignCalls)
	}
}

func TestRollover_ContextCancelled(t *testing.T) {
	mgr, _, reloader, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	initialCert := reloader.Current()

	ctx, cancel := context.WithCancel(context.Background())

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	// Cancel immediately to abort the rollover.
	cancel()

	// Wait should observe the cancellation.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(waitCancel)

	// Wait on the doneChan which should close after cancellation.
	mgr.Wait(waitCtx)

	// Phase should return to idle after cancellation.
	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected phase RolloverIdle after cancellation, got %d", mgr.Phase())
	}

	// Certificate should NOT have been reloaded since we cancelled before activation.
	if reloader.Current() != initialCert {
		t.Error("certificate should not have been reloaded after cancellation")
	}
}

func TestRollover_ContextCancelled_WaitReturnsNil(t *testing.T) {
	mgr, _, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	cancel()

	// Wait with a fresh context should succeed since doneChan closes on cancel.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(waitCancel)

	err = mgr.Wait(waitCtx)
	if err != nil {
		t.Errorf("expected nil error from Wait after cancel, got: %v", err)
	}
}

func TestRollover_Wait_BlocksUntilComplete(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	config.DefaultTTL = 0
	config.RolloverTTL = 0

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANEEE, Data: "olddata"},
			},
		},
	}

	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	publisher := NewDANEPublisher(svc, config, logger)
	mgr := NewRolloverManager(publisher, reloader, config, logger)

	newCert := testCert(t, "leaf.example.com", false)
	newTLSCert := rolloverTestTLSCert(t)

	ctx := context.Background()
	err = mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	doneCh := make(chan error, 1)
	go func() {
		waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		doneCh <- mgr.Wait(waitCtx)
	}()

	select {
	case waitErr := <-doneCh:
		if waitErr != nil {
			t.Fatalf("Wait returned error: %v", waitErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return within timeout")
	}

	// Verify rollover completed.
	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected phase RolloverIdle, got %d", mgr.Phase())
	}
}

func TestRollover_Wait_ContextTimeout(t *testing.T) {
	mgr, _, _, newCert, newTLSCert := rolloverTestSetup(t, false, 300)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := mgr.BeginRollover(ctx, newCert, newTLSCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("BeginRollover failed: %v", err)
	}

	// Wait with a very short timeout should return context.DeadlineExceeded.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	t.Cleanup(waitCancel)

	err = mgr.Wait(waitCtx)
	if err == nil {
		t.Fatal("expected timeout error from Wait, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	cancel()
}

func TestPhase_ReturnsCurrentPhase(t *testing.T) {
	mgr, _, _, _, _ := rolloverTestSetup(t, false, 300)

	// Initially idle.
	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected RolloverIdle initially, got %d", mgr.Phase())
	}

	// Manually set phase to verify atomic reads.
	mgr.phase.Store(uint32(RolloverPrePublish))
	if mgr.Phase() != RolloverPrePublish {
		t.Errorf("expected RolloverPrePublish, got %d", mgr.Phase())
	}

	mgr.phase.Store(uint32(RolloverActivated))
	if mgr.Phase() != RolloverActivated {
		t.Errorf("expected RolloverActivated, got %d", mgr.Phase())
	}

	mgr.phase.Store(uint32(RolloverComplete))
	if mgr.Phase() != RolloverComplete {
		t.Errorf("expected RolloverComplete, got %d", mgr.Phase())
	}
}

func TestPhase_ReturnsIdleForNewManager(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, config, logger)
	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	mgr := NewRolloverManager(publisher, reloader, config, logger)

	if mgr.Phase() != RolloverIdle {
		t.Errorf("expected RolloverIdle for new manager, got %d", mgr.Phase())
	}
}

func TestRolloverDelay_CustomTTL(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 7200)
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, config, logger)
	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	mgr := NewRolloverManager(publisher, reloader, config, logger)

	expected := 7200 * time.Second
	if mgr.rolloverDelay() != expected {
		t.Errorf("expected rollover delay %v, got %v", expected, mgr.rolloverDelay())
	}
}

func TestRolloverDelay_CustomTTL_NonStandard(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 900)
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, config, logger)
	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	mgr := NewRolloverManager(publisher, reloader, config, logger)

	expected := 900 * time.Second
	if mgr.rolloverDelay() != expected {
		t.Errorf("expected rollover delay %v, got %v", expected, mgr.rolloverDelay())
	}
}

func TestRolloverDelay_DefaultTTL(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	config.DefaultTTL = 1800
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, config, logger)
	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	mgr := NewRolloverManager(publisher, reloader, config, logger)

	expected := 3600 * time.Second // 2 * 1800
	if mgr.rolloverDelay() != expected {
		t.Errorf("expected rollover delay %v (2x DefaultTTL), got %v", expected, mgr.rolloverDelay())
	}
}

func TestRolloverDelay_DefaultTTL_StandardValue(t *testing.T) {
	logger := daneTestLogger()
	config := rolloverTestConfig(false, 0)
	config.DefaultTTL = 3600
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, config, logger)
	initialTLSCert := rolloverTestTLSCert(t)
	reloader, err := NewCertReloader(initialTLSCert)
	if err != nil {
		t.Fatalf("failed to create CertReloader: %v", err)
	}

	mgr := NewRolloverManager(publisher, reloader, config, logger)

	expected := 7200 * time.Second // 2 * 3600
	if mgr.rolloverDelay() != expected {
		t.Errorf("expected rollover delay %v (2x DefaultTTL), got %v", expected, mgr.rolloverDelay())
	}
}
