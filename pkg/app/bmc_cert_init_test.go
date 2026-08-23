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
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// baseInitOpts builds a working bmcCertInitOptions using
// in-process fakes (ACME, CA, DNS, scheduler). Callers mutate a
// single field to drive the specific test scenario.
func baseInitOpts() bmcCertInitOptions {
	return bmcCertInitOptions{
		BMCConfig:     minimalCertConfig("bmc01.internal"),
		NodeID:        "node-A",
		ACMEIssuer:    &fakeACME{},
		LocalCAIssuer: &fakeLocalCA{},
		DNSUpdater:    &fakeDNS{},
		Hostmaster:    "ops@x.com",
		Scheduler:     newFakeScheduler(),
		Registry:      NewCertTargetRegistry(),
	}
}

// --- disabled path ---

func TestInitBMCCert_DisabledNilBMCConfig(t *testing.T) {
	opts := baseInitOpts()
	opts.BMCConfig = nil
	if err := initBMCCertManagement(context.Background(), opts); err != nil {
		t.Errorf("disabled config should no-op, got %v", err)
	}
	// Nothing registered, no job created.
	if opts.Registry.Len() != 0 {
		t.Error("registry should be empty when disabled")
	}
	if sched := opts.Scheduler.(*fakeScheduler); len(sched.jobs) != 0 {
		t.Error("no jobs should be created when BMC cert disabled")
	}
}

func TestInitBMCCert_DisabledNilCertificate(t *testing.T) {
	opts := baseInitOpts()
	opts.BMCConfig = &bmc.Config{
		Address: "x", Port: 623, Protocol: bmc.ProtocolIPMI,
	}
	if err := initBMCCertManagement(context.Background(), opts); err != nil {
		t.Errorf("cert-unset config should no-op, got %v", err)
	}
}

// --- validation ---

func TestInitBMCCert_MissingNodeID(t *testing.T) {
	opts := baseInitOpts()
	opts.NodeID = ""
	err := initBMCCertManagement(context.Background(), opts)
	if !errors.Is(err, ErrInitBMCCertMissingNodeID) {
		t.Errorf("err = %v, want ErrInitBMCCertMissingNodeID", err)
	}
}

func TestInitBMCCert_MissingRegistry(t *testing.T) {
	opts := baseInitOpts()
	opts.Registry = nil
	err := initBMCCertManagement(context.Background(), opts)
	if !errors.Is(err, ErrInitBMCCertMissingRegistry) {
		t.Errorf("err = %v, want ErrInitBMCCertMissingRegistry", err)
	}
}

func TestInitBMCCert_MissingScheduler(t *testing.T) {
	opts := baseInitOpts()
	opts.Scheduler = nil
	err := initBMCCertManagement(context.Background(), opts)
	if !errors.Is(err, ErrInitBMCCertMissingScheduler) {
		t.Errorf("err = %v, want ErrInitBMCCertMissingScheduler", err)
	}
}

func TestInitBMCCert_MissingLocalCAIssuer(t *testing.T) {
	opts := baseInitOpts()
	opts.LocalCAIssuer = nil
	err := initBMCCertManagement(context.Background(), opts)
	if !errors.Is(err, ErrMissingLocalCAIssuer) {
		t.Errorf("err = %v, want ErrMissingLocalCAIssuer", err)
	}
}

// --- happy paths ---

func TestInitBMCCert_UnreachableBMCStillLeavesRenewalWired(t *testing.T) {
	// Forces local-CA issuance (no ACMEIssuer) and drives end-to-end until the
	// deploy step, which fails because AutoCertManager cannot reach the (closed)
	// BMC address.
	//
	// This asserted a returned error until the boot wiring landed. It must not:
	// a BMC is a remote device that can be down or mid-reboot when platformd
	// starts, and initBMCCertManagement is the function that also registers the
	// renewal handler and job. Propagating the deploy failure meant one
	// unreachable BMC disabled certificate renewal for every OTHER target on the
	// node -- every webservice certificate would quietly stop being renewed
	// because a BMC did not answer a dial.
	opts := baseInitOpts()
	opts.ACMEIssuer = nil
	// Point the BMC at a closed local port so the dial fails
	// immediately (connection refused) instead of timing out.
	opts.BMCConfig.Address = "127.0.0.1"
	opts.BMCConfig.Port = 1
	localCA := &fakeLocalCA{}
	opts.LocalCAIssuer = localCA
	sched := newFakeScheduler()
	opts.Scheduler = sched
	reg := NewCertTargetRegistry()
	opts.Registry = reg

	if err := initBMCCertManagement(context.Background(), opts); err != nil {
		t.Fatalf("an unreachable BMC must degrade, not fail the whole cert-management "+
			"wiring: %v", err)
	}
	if localCA.callCnt != 1 {
		t.Errorf("localCA.callCnt = %d, want 1 — provisioning must still be attempted "+
			"for a BMC that is not carrying our certificate", localCA.callCnt)
	}
	if _, ok := reg.Get("bmc.bmc01.internal"); !ok {
		t.Error("the BMC target was not registered, so the sweep can never retry it")
	}
	if len(sched.jobs) == 0 {
		t.Error("no renewal job was scheduled. This is the regression that matters: " +
			"one unreachable BMC would leave the whole node with no certificate " +
			"renewal at all.")
	}
}

// TestInitBMCCert_FullyWiredWithDeployerOverride exercises the happy
// path end-to-end by temporarily wiring a Deployer through a test
// hook. Since InitBMCCertManagement's public options don't carry a
// Deployer (the live AutoCertManager is the production path), this
// test uses issueBMCCertificateCore directly with the same plumbing
// to validate the full sequence InitBMCCertManagement orchestrates.
func TestInitBMCCert_FullyWiredWithDeployerOverride(t *testing.T) {
	deployer := &fakeDeployer{}
	cfg := minimalCertConfig("bmc01.internal")

	// Run the same sequence InitBMCCertManagement runs, injecting
	// a fake deployer that InitBMCCertManagement cannot inject in
	// production (where the real AutoCertManager wires itself).
	target, err := issueBMCCertificateCore(context.Background(), "bmc01.internal", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      deployer,
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore: %v", err)
	}

	reg := NewCertTargetRegistry()
	if err := reg.Replace(target); err != nil {
		t.Fatalf("register target: %v", err)
	}

	sched := newFakeScheduler()
	if err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched, Registry: reg, NodeID: "node-A",
	}); err != nil {
		t.Fatalf("RegisterCertRenewal: %v", err)
	}

	// Verify the expected wiring: one target + one renewal job.
	if reg.Len() != 1 {
		t.Errorf("registry Len = %d, want 1", reg.Len())
	}
	if len(sched.jobs) != 1 {
		t.Fatalf("sched jobs = %d, want 1", len(sched.jobs))
	}
	job := sched.jobs[0]
	if job.NodeAffinity != "node-A" {
		t.Errorf("job.NodeAffinity = %q", job.NodeAffinity)
	}
	if job.Handler != CertRenewalHandlerName {
		t.Errorf("job.Handler = %q", job.Handler)
	}
	if deployer.replaceCalls != 1 {
		t.Errorf("deployer.replaceCalls = %d", deployer.replaceCalls)
	}
}

// --- deriveBMCDeviceID ---

func TestDeriveBMCDeviceID_PrefersCommonName(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	got := deriveBMCDeviceID(cfg, "node-A")
	if got != "bmc01.internal" {
		t.Errorf("deriveBMCDeviceID = %q, want bmc01.internal", got)
	}
}

func TestDeriveBMCDeviceID_FallsBackToAddress(t *testing.T) {
	cfg := &bmc.Config{
		Address:     "192.168.1.100",
		Port:        623,
		Certificate: &common.Identity{}, // no CN
	}
	got := deriveBMCDeviceID(cfg, "node-A")
	if got != "192-168-1-100-623" {
		t.Errorf("deriveBMCDeviceID = %q", got)
	}
}

func TestDeriveBMCDeviceID_FallsBackToNodeID(t *testing.T) {
	cfg := &bmc.Config{} // no address, no cert
	got := deriveBMCDeviceID(cfg, "node-A")
	if got != "node-A" {
		t.Errorf("deriveBMCDeviceID = %q, want node-A", got)
	}
}

func TestDeriveBMCDeviceID_NilConfig(t *testing.T) {
	got := deriveBMCDeviceID(nil, "node-A")
	if got != "node-A" {
		t.Errorf("nil config fallback = %q", got)
	}
}

// --- errors ---

func TestInitBMCCertErrors_Messages(t *testing.T) {
	cases := []error{
		ErrInitBMCCertMissingNodeID,
		ErrInitBMCCertMissingRegistry,
		ErrInitBMCCertMissingScheduler,
		ErrInitBMCCertIssue{DeviceID: "d", Cause: errors.New("c")},
		ErrInitBMCCertRegister{DeviceID: "d", Cause: errors.New("c")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
	inner := errors.New("inner")
	if !errors.Is(ErrInitBMCCertIssue{Cause: inner}, inner) {
		t.Error("ErrInitBMCCertIssue does not unwrap")
	}
	if !errors.Is(ErrInitBMCCertRegister{Cause: inner}, inner) {
		t.Error("ErrInitBMCCertRegister does not unwrap")
	}
}
