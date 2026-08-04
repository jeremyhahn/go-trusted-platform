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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ---------------------------------------------------------------------------
// runDANEUnpublishStep – internalZone == "" with non-nil daneUnpublish
// (86.7% → 100%)
//
// The existing bmc_restore_test.go exercises:
//   - daneUnpublish == nil (HappyPath / PinDelete tests: empty zone, nil fn)
//   - daneUnpublish != nil, internalZone != "", dnsName == "" (SkipsWithoutDNSName)
//   - daneUnpublish != nil, internalZone != "", dnsName != "", error (DANE_NonFatal)
//   - daneUnpublish != nil, internalZone != "", dnsName != "", success (UsesEnrolledDNSName)
//
// The only remaining uncovered branch is:
//   daneUnpublish != nil, internalZone == ""
// which records a "skipped" step and returns nil.
// ---------------------------------------------------------------------------

// TestW1bRunDANEUnpublishStep_NonNilFuncEmptyZone verifies that the step is
// recorded as skipped (OK=true, "no internal DNS zone") and returns nil when
// daneUnpublish is non-nil but internalZone is empty.
func TestW1bRunDANEUnpublishStep_NonNilFuncEmptyZone(t *testing.T) {
	result := &BMCRestoreResult{}
	called := false
	core := &restoreCore{
		daneUnpublish: func(_ context.Context, _ string, _ uint16, _ string) error {
			called = true
			return errors.New("should not be reached")
		},
	}

	err := runDANEUnpublishStep(context.Background(), result, core, "bmc.internal.", "" /* empty zone */)
	if err != nil {
		t.Fatalf("runDANEUnpublishStep with empty zone: unexpected error: %v", err)
	}
	if called {
		t.Error("daneUnpublish must not be called when internalZone is empty")
	}

	step := findRestoreStep(t, result, "dane-unpublish", true)
	if step.Detail == "" {
		t.Error("expected non-empty detail in dane-unpublish step")
	}
}

// TestW1bRunDANEUnpublishStep_NilFuncReturnNil is a companion confirming the
// already-covered nil-fn path is still a no-op (regression guard).
func TestW1bRunDANEUnpublishStep_NilFuncReturnNil(t *testing.T) {
	result := &BMCRestoreResult{}
	core := &restoreCore{daneUnpublish: nil}

	err := runDANEUnpublishStep(context.Background(), result, core, "bmc.internal.", "internal.")
	if err != nil {
		t.Fatalf("unexpected error with nil daneUnpublish: %v", err)
	}
	findRestoreStep(t, result, "dane-unpublish", true)
}

// ---------------------------------------------------------------------------
// RestoreBMC – early-exit paths (0% → ~15%)
//
// The full RestoreBMC ceremony requires a live BMC and is integration-only.
// The nil-config and nil-trust-resolver guards are the only unit-testable
// paths: they return errors before any network connection is attempted,
// mirroring the analogous EnrollBMC guards already tested in
// bmc_enroll_cov2_test.go.
// ---------------------------------------------------------------------------

// TestW1bRestoreBMC_NilConfig verifies that a nil bmcCfg is rejected with
// bmc.ErrNilConfig before any other work is done.
func TestW1bRestoreBMC_NilConfig(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	_, err := app.RestoreBMC(context.Background(), 1, nil)
	if err == nil {
		t.Fatal("expected error for nil bmcCfg")
	}
	var nilCfg bmc.ErrNilConfig
	if !errors.As(err, &nilCfg) {
		t.Errorf("err = %T(%v), want bmc.ErrNilConfig", err, err)
	}
}

// TestW1bRestoreBMC_NoTrustResolver verifies ErrBMCEnrollNoTrustResolver is
// returned when the App has no trust configuration (resolver is nil).
func TestW1bRestoreBMC_NoTrustResolver(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()} // no TrustConfig → nil resolver
	cfg := &bmc.Config{
		Address:  "1.2.3.4",
		Port:     623,
		Protocol: bmc.ProtocolIPMI,
	}
	_, err := app.RestoreBMC(context.Background(), 1, cfg)
	if err == nil {
		t.Fatal("expected error when trust resolver is unavailable")
	}
	var noResolver ErrBMCEnrollNoTrustResolver
	if !errors.As(err, &noResolver) {
		t.Errorf("err = %T(%v), want ErrBMCEnrollNoTrustResolver", err, err)
	}
}
