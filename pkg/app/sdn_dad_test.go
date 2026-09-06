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
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
)

var (
	testLocalMAC     = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	testResponderMAC = net.HardwareAddr{0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x14}
)

// newDADTestApp builds the minimal App the duplicate-address guard needs.
func newDADTestApp(t *testing.T) *App {
	t.Helper()
	return &App{
		Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
	}
}

// stubProbe installs an in-memory duplicate-address probe for the duration of
// one test. No test in this package ever opens a socket or touches a segment.
func stubProbe(t *testing.T, probe func(context.Context, string, net.IP) error) {
	t.Helper()
	original := bridgeAddressProbe
	bridgeAddressProbe = probe
	t.Cleanup(func() { bridgeAddressProbe = original })
}

func conflictFor(iface string, ip net.IP) error {
	return &arp.ConflictError{
		Interface:             iface,
		Address:               ip,
		LocalHardwareAddr:     testLocalMAC,
		ResponderHardwareAddr: testResponderMAC,
	}
}

func TestGuardBridgeAddressFreeAddress(t *testing.T) {
	app := newDADTestApp(t)
	var probed struct {
		iface string
		ip    net.IP
	}
	stubProbe(t, func(_ context.Context, iface string, ip net.IP) error {
		probed.iface, probed.ip = iface, ip
		return nil
	})

	if err := app.guardBridgeAddress(context.Background(), "trusted0", "198.18.0.2/24"); err != nil {
		t.Fatalf("expected a free address to be permitted, got %v", err)
	}
	if probed.iface != "trusted0" {
		t.Errorf("expected the bridge to be probed, probed %q", probed.iface)
	}
	if !probed.ip.Equal(net.IPv4(172, 16, 200, 2)) {
		t.Errorf("expected the host address to be probed, probed %s", probed.ip)
	}
	if got := app.BridgeAddressConflicts(); len(got) != 0 {
		t.Errorf("expected no recorded conflict, got %d", len(got))
	}
}

func TestGuardBridgeAddressConflictIsRefused(t *testing.T) {
	app := newDADTestApp(t)
	stubProbe(t, func(_ context.Context, iface string, ip net.IP) error {
		return conflictFor(iface, ip)
	})

	err := app.guardBridgeAddress(context.Background(), "trusted0", "198.18.0.1/24")

	var refusal ErrBridgeAddressConflict
	if !errors.As(err, &refusal) {
		t.Fatalf("expected an ErrBridgeAddressConflict, got %v", err)
	}
	if !strings.Contains(err.Error(), testResponderMAC.String()) {
		t.Errorf("expected the refusal to name the responder MAC, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "198.18.0.1/24") {
		t.Errorf("expected the refusal to name the address, got %q", err.Error())
	}

	conflicts := app.BridgeAddressConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("expected one recorded conflict, got %d", len(conflicts))
	}
	recorded := conflicts[0]
	if recorded.Bridge != "trusted0" || recorded.Address != "198.18.0.1/24" {
		t.Errorf("unexpected record %+v", recorded)
	}
	if recorded.LocalHardwareAddr != testLocalMAC.String() {
		t.Errorf("expected local MAC %s, got %s", testLocalMAC, recorded.LocalHardwareAddr)
	}
	if recorded.ResponderHardwareAddr != testResponderMAC.String() {
		t.Errorf("expected responder MAC %s, got %s", testResponderMAC, recorded.ResponderHardwareAddr)
	}
	if recorded.DetectedAt.IsZero() {
		t.Error("expected the conflict to be timestamped")
	}
	if !errors.Is(err, refusal.Cause) {
		t.Error("expected the refusal to unwrap to the probe conflict")
	}
}

// TestGuardBridgeAddressProbeUnavailable proves an unusable probe never
// withholds an address: a node that cannot open a raw socket must still come
// up addressed, because the failure said nothing about the segment. It also
// proves the node does not then look healthy — the unguarded assignment is
// recorded, not merely logged.
func TestGuardBridgeAddressProbeUnavailable(t *testing.T) {
	for name, probeErr := range map[string]error{
		"no privilege":         &arp.SentinelCauseError{Sentinel: arp.ErrInterfaceUnavailable, Cause: errors.New("operation not permitted")},
		"unsupported platform": arp.ErrProbeUnsupported,
		"send failed":          arp.ErrProbeSend,
	} {
		t.Run(name, func(t *testing.T) {
			app := newDADTestApp(t)
			stubProbe(t, func(context.Context, string, net.IP) error { return probeErr })

			if err := app.guardBridgeAddress(context.Background(), "trusted0", "198.18.0.2/24"); err != nil {
				t.Fatalf("expected an unusable probe to permit the address, got %v", err)
			}
			if got := app.BridgeAddressConflicts(); len(got) != 0 {
				t.Errorf("expected no conflict recorded for a failed probe, got %d", len(got))
			}

			failures := app.BridgeAddressProbeFailures()
			if len(failures) != 1 {
				t.Fatalf("expected the unguarded assignment to be recorded, got %d", len(failures))
			}
			recorded := failures[0]
			if recorded.Bridge != "trusted0" || recorded.Address != "198.18.0.2/24" {
				t.Errorf("unexpected record %+v", recorded)
			}
			if !strings.Contains(recorded.Cause, probeErr.Error()) {
				t.Errorf("expected the cause to name the probe failure, got %q", recorded.Cause)
			}
			if recorded.DetectedAt.IsZero() {
				t.Error("expected the failed probe to be timestamped")
			}
		})
	}
}

// TestGuardBridgeAddressFreeAddressRecordsNothing proves a probe that ran and
// found the address free leaves both records empty, so a healthy node reports
// healthy.
func TestGuardBridgeAddressFreeAddressRecordsNothing(t *testing.T) {
	app := newDADTestApp(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	if err := app.guardBridgeAddress(context.Background(), "trusted0", "198.18.0.2/24"); err != nil {
		t.Fatalf("expected a free address to be permitted, got %v", err)
	}
	if got := app.BridgeAddressProbeFailures(); len(got) != 0 {
		t.Fatalf("expected no probe failure recorded for a successful probe, got %v", got)
	}
}

// TestGuardBridgeAddressConflictRecordsNoProbeFailure proves a measured
// conflict is not also counted as a missing probe: the probe ran.
func TestGuardBridgeAddressConflictRecordsNoProbeFailure(t *testing.T) {
	app := newDADTestApp(t)
	stubProbe(t, func(_ context.Context, iface string, ip net.IP) error {
		return conflictFor(iface, ip)
	})

	_ = app.guardBridgeAddress(context.Background(), "trusted0", "198.18.0.1/24")

	if got := app.BridgeAddressProbeFailures(); len(got) != 0 {
		t.Fatalf("expected a conflict not to be recorded as a missing probe, got %v", got)
	}
}

func TestGuardBridgeAddressUnparsableAddress(t *testing.T) {
	app := newDADTestApp(t)
	called := false
	stubProbe(t, func(context.Context, string, net.IP) error {
		called = true
		return nil
	})

	if err := app.guardBridgeAddress(context.Background(), "trusted0", "not-an-address"); err != nil {
		t.Fatalf("expected an unparsable address to be left to the assignment path, got %v", err)
	}
	if called {
		t.Error("expected no probe for an unparsable address")
	}
}

// TestBridgeAddressConflictsIsASnapshot proves callers cannot mutate the
// node's recorded state through the accessor.
func TestBridgeAddressConflictsIsASnapshot(t *testing.T) {
	app := newDADTestApp(t)
	app.recordBridgeAddressConflict(BridgeAddressConflict{Bridge: "trusted0", Address: "198.18.0.1/24"})

	snapshot := app.BridgeAddressConflicts()
	snapshot[0].Bridge = "mutated"

	if got := app.BridgeAddressConflicts(); got[0].Bridge != "trusted0" {
		t.Fatalf("expected the record to be immutable through the accessor, got %q", got[0].Bridge)
	}
}

// TestBridgeAddressConflictsNilApp proves a health checker holding a typed-nil
// App reports "no conflicts" instead of panicking on the health endpoint.
func TestBridgeAddressConflictsNilApp(t *testing.T) {
	var nilApp *App
	if got := nilApp.BridgeAddressConflicts(); got != nil {
		t.Fatalf("expected no conflicts from a nil App, got %v", got)
	}
	if got := nilApp.BridgeAddressProbeFailures(); got != nil {
		t.Fatalf("expected no probe failures from a nil App, got %v", got)
	}
}

// TestBridgeAddressProbeFailuresIsASnapshot proves callers cannot mutate the
// node's recorded state through the accessor.
func TestBridgeAddressProbeFailuresIsASnapshot(t *testing.T) {
	app := newDADTestApp(t)
	app.recordBridgeAddressProbeUnavailable(BridgeAddressProbeUnavailable{
		Bridge: "trusted0", Address: "198.18.0.2/24", Cause: "operation not permitted",
	})

	snapshot := app.BridgeAddressProbeFailures()
	snapshot[0].Bridge = "mutated"

	if got := app.BridgeAddressProbeFailures(); got[0].Bridge != "trusted0" {
		t.Fatalf("expected the record to be immutable through the accessor, got %q", got[0].Bridge)
	}
}

// TestRecordBridgeAddressConflictIsConcurrencySafe runs under -race: the
// guard records from bring-up while health checks read the same slice.
func TestRecordBridgeAddressConflictIsConcurrencySafe(t *testing.T) {
	app := newDADTestApp(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			app.recordBridgeAddressConflict(BridgeAddressConflict{Bridge: "trusted0"})
			app.recordBridgeAddressProbeUnavailable(BridgeAddressProbeUnavailable{Bridge: "public0"})
		}()
		go func() {
			defer wg.Done()
			_ = app.BridgeAddressConflicts()
			_ = app.BridgeAddressProbeFailures()
		}()
	}
	wg.Wait()

	if got := app.BridgeAddressConflicts(); len(got) != 16 {
		t.Fatalf("expected 16 recorded conflicts, got %d", len(got))
	}
	if got := app.BridgeAddressProbeFailures(); len(got) != 16 {
		t.Fatalf("expected 16 recorded probe failures, got %d", len(got))
	}
}

// stubBridgeNetlink replaces the two netlink calls initBridgeIPs makes so the
// bring-up sequence runs entirely in memory.
func stubBridgeNetlink(t *testing.T) *[]string {
	t.Helper()
	assigned := make([]string, 0, 1)
	originalUp, originalAssign := setBridgeUpFn, assignBridgeAddrFn
	setBridgeUpFn = func(context.Context, string) error { return nil }
	assignBridgeAddrFn = func(_ context.Context, name, addr string) error {
		assigned = append(assigned, name+" "+addr)
		return nil
	}
	t.Cleanup(func() {
		setBridgeUpFn, assignBridgeAddrFn = originalUp, originalAssign
	})
	return &assigned
}

func bridgeIPNetworkConfig() *installer.NetworkConfig {
	return &installer.NetworkConfig{
		Bridges: []installer.BridgeConfig{{
			Name:      "trusted0",
			Type:      installer.BridgeTypeOVS,
			AutoStart: true,
		}},
		Subnets: []installer.SubnetConfig{{
			Scope:   installer.SubnetScopeInternal,
			CIDR:    "198.18.0.0/24",
			Gateway: "198.18.0.1",
		}},
	}
}

// TestInitBridgeIPsAssignsWhenAddressIsFree is the control for the mutation
// check below: with no conflict the address reaches the interface.
func TestInitBridgeIPsAssignsWhenAddressIsFree(t *testing.T) {
	app := newDADTestApp(t)
	app.NetworkConfig = bridgeIPNetworkConfig()
	assigned := stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	if err := app.initBridgeIPs(context.Background()); err != nil {
		t.Fatalf("initBridgeIPs: %v", err)
	}
	if len(*assigned) != 1 || (*assigned)[0] != "trusted0 198.18.0.1/24" {
		t.Fatalf("expected the address to be assigned, got %v", *assigned)
	}
}

// TestInitBridgeIPsRecordsAnUnguardedAssignment proves the second half of the
// guard's contract end to end: when the probe cannot run the address still
// reaches the interface, and the node records that it went on unguarded so
// health does not report a node that quietly lost its guard as healthy.
func TestInitBridgeIPsRecordsAnUnguardedAssignment(t *testing.T) {
	app := newDADTestApp(t)
	app.NetworkConfig = bridgeIPNetworkConfig()
	assigned := stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error {
		return &arp.SentinelCauseError{
			Sentinel: arp.ErrInterfaceUnavailable,
			Cause:    errors.New("operation not permitted"),
		}
	})

	if err := app.initBridgeIPs(context.Background()); err != nil {
		t.Fatalf("initBridgeIPs: %v", err)
	}
	if len(*assigned) != 1 || (*assigned)[0] != "trusted0 198.18.0.1/24" {
		t.Fatalf("expected the address to be assigned despite the failed probe, got %v", *assigned)
	}
	failures := app.BridgeAddressProbeFailures()
	if len(failures) != 1 {
		t.Fatalf("expected the unguarded assignment to be recorded, got %d", len(failures))
	}
	if failures[0].Address != "198.18.0.1/24" || failures[0].Bridge != "trusted0" {
		t.Errorf("unexpected record %+v", failures[0])
	}
	if !strings.Contains(failures[0].Cause, "operation not permitted") {
		t.Errorf("expected the cause to be preserved, got %q", failures[0].Cause)
	}
}

// TestInitBridgeIPsRefusesConflictingAddress is the guard's central claim: a
// measured conflict means the address never reaches the interface, the node
// records the conflict, and bring-up still returns cleanly so the daemon
// keeps starting.
func TestInitBridgeIPsRefusesConflictingAddress(t *testing.T) {
	app := newDADTestApp(t)
	app.NetworkConfig = bridgeIPNetworkConfig()
	assigned := stubBridgeNetlink(t)
	stubProbe(t, func(_ context.Context, iface string, ip net.IP) error {
		return conflictFor(iface, ip)
	})

	if err := app.initBridgeIPs(context.Background()); err != nil {
		t.Fatalf("expected bring-up to continue past a refused address, got %v", err)
	}
	if len(*assigned) != 0 {
		t.Fatalf("expected no address assignment after a conflict, got %v", *assigned)
	}
	conflicts := app.BridgeAddressConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("expected the conflict to be recorded for health reporting, got %d", len(conflicts))
	}
	if conflicts[0].Address != "198.18.0.1/24" {
		t.Errorf("expected the refused address to be recorded, got %q", conflicts[0].Address)
	}
}
