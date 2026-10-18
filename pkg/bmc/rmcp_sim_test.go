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

// rmcp_sim_test.go contains end-to-end tests exercising the pkg/bmc
// IPMI client against the test/integration/bmc/rmcpsim reusable
// simulator over real UDP. It lives in the external `bmc_test` package
// (rather than `package bmc`) to break the import cycle between
// pkg/bmc and the simulator -- the simulator imports pkg/bmc for the
// wire constants/helpers exported via rmcp_sim_support.go, so tests
// using the simulator cannot live in `package bmc` itself. Internal
// handshake state needed by these tests is surfaced through the
// TestRMCPSession shim in export_test.go.

package bmc_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/bmc/rmcpsim"
)

// startSim constructs + starts an rmcpsim.Simulator bound to an
// ephemeral loopback port and registers Stop as a t.Cleanup.
// simPassword is at least 14 bytes because the RMCP+ session refuses a shorter
// credential under FIPS activation: IPMI derives its HMAC keys straight from
// the password, and FIPS 140-3 requires 112 bits of keying material (#209).
// These tests exercise the real handshake, so they need a credential that is
// valid in both modes.
const simPassword = "simulator_password"

func startSim(t *testing.T, username, password string) *rmcpsim.Simulator {
	t.Helper()
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: username,
		Password: password,
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("rmcpsim.New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("sim.Start: %v", err)
	}
	t.Cleanup(sim.Stop)
	return sim
}

// --- Simulator-based Tests ---

func TestRMCPSession_FullHandshake(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	session := bmc.NewTestRMCPSession(config, slog.Default())
	err := session.Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	// Verify keys were derived.
	if session.SIK() == nil {
		t.Error("SIK is nil after Open")
	}
	if session.K1() == nil {
		t.Error("K1 is nil after Open")
	}
	if session.K2() == nil {
		t.Error("K2 is nil after Open")
	}
	if session.BMCSessionID() == 0 {
		t.Error("BMC session ID is zero after Open")
	}
}

func TestRMCPSession_CloseSendsCloseSession(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	session := bmc.NewTestRMCPSession(config, slog.Default())
	if err := session.Open(context.Background()); err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if got := sim.OpenSessions(); got != 1 {
		t.Fatalf("OpenSessions() after Open = %d, want 1", got)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if got := sim.OpenSessions(); got != 0 {
		t.Errorf("OpenSessions() after Close = %d, want 0: Close Session never reached the BMC", got)
	}
}

func TestRMCPSession_SendAfterCloseIsRefused(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	session := bmc.NewTestRMCPSession(config, slog.Default())
	if err := session.Open(context.Background()); err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Errorf("second Close() error: %v, want nil", err)
	}
	if _, err := session.Send(bmc.NetFnApp, bmc.CmdCloseSession, nil); !errors.As(err, &bmc.ErrSessionClosed{}) {
		t.Errorf("Send() after Close error = %v, want ErrSessionClosed", err)
	}
}

func TestRMCPSession_FullHandshake_BadPassword(t *testing.T) {
	sim := startSim(t, "admin", "correct_password")

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: "wrong_password",
		Protocol: bmc.ProtocolIPMI,
	}

	session := bmc.NewTestRMCPSession(config, slog.Default())
	err := session.Open(context.Background())
	if err == nil {
		session.Close()
		t.Fatal("expected error for wrong password")
	}
	// Should fail at RAKP Message 2 verification.
	var rakpErr bmc.ErrRAKPAuthFailed
	if !errors.As(err, &rakpErr) {
		// Could also be ErrConnectionFailed wrapping ErrRAKPAuthFailed.
		var connErr bmc.ErrConnectionFailed
		if errors.As(err, &connErr) {
			if !errors.As(connErr.Cause, &rakpErr) {
				t.Errorf("expected ErrRAKPAuthFailed inside ErrConnectionFailed, got %T: %v", connErr.Cause, connErr.Cause)
			}
		} else {
			t.Errorf("expected ErrRAKPAuthFailed, got %T: %v", err, err)
		}
	}
}

func TestIPMIClient_ChassisStatus_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	state, err := client.PowerStatus(context.Background())
	if err != nil {
		t.Fatalf("PowerStatus: %v", err)
	}
	if state != bmc.PowerStateOn {
		t.Errorf("PowerStatus = %q, want %q", state, bmc.PowerStateOn)
	}
}

// TestIPMIClient_ConcurrentCommands_Simulator drives one shared client —
// the shape Service.clientFor hands out — with many concurrent commands
// over a real RMCP+ session. The session has no request correlation
// (rqSeq is fixed), so without exchangeMu two Sends would read each
// other's datagrams and fail with command-mismatch errors or misattributed
// data; every command must succeed with the right answer.
func TestIPMIClient_ConcurrentCommands_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}
	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	const callers, rounds = 16, 25
	var wg sync.WaitGroup
	errs := make(chan error, callers*rounds*2)
	for i := 0; i < callers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				state, err := client.PowerStatus(context.Background())
				if err != nil {
					errs <- err
					return
				}
				if state != bmc.PowerStateOn {
					errs <- errors.New("PowerStatus returned " + string(state) + ", want on")
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				if _, err := client.GetBootDevice(context.Background()); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	n := 0
	for err := range errs {
		if n < 5 {
			t.Errorf("concurrent command over one session: %v", err)
		}
		n++
	}
	if n > 5 {
		t.Errorf("... and %d more", n-5)
	}
}

func TestIPMIClient_PowerOn_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.PowerOn(context.Background()); err != nil {
		t.Fatalf("PowerOn: %v", err)
	}
}

func TestIPMIClient_PowerOff_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.PowerOff(context.Background()); err != nil {
		t.Fatalf("PowerOff: %v", err)
	}
}

func TestIPMIClient_PowerReset_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.PowerReset(context.Background()); err != nil {
		t.Fatalf("PowerReset: %v", err)
	}
}

func TestIPMIClient_PowerCycle_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.PowerCycle(context.Background()); err != nil {
		t.Fatalf("PowerCycle: %v", err)
	}
}

func TestIPMIClient_GetSystemInfo_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	info, err := client.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil SystemInfo")
	}
	if info.FirmwareVersion != "2.69" {
		t.Errorf("FirmwareVersion = %q, want %q", info.FirmwareVersion, "2.69")
	}
	if info.PowerState != bmc.PowerStateOn {
		t.Errorf("PowerState = %q, want %q", info.PowerState, bmc.PowerStateOn)
	}
}

func TestIPMIClient_SetBootDevice_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.SetBootDevice(context.Background(), bmc.BootDevicePXE, false); err != nil {
		t.Fatalf("SetBootDevice: %v", err)
	}
}

func TestIPMIClient_GetBootDevice_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	device, err := client.GetBootDevice(context.Background())
	if err != nil {
		t.Fatalf("GetBootDevice: %v", err)
	}
	if device != bmc.BootDevicePXE {
		t.Errorf("GetBootDevice = %q, want %q", device, bmc.BootDevicePXE)
	}
}

func TestIPMIClient_ConnectionFailure(t *testing.T) {
	// Use an address that will timeout/fail.
	config := &bmc.Config{
		Address:  "192.0.2.1", // TEST-NET-1: guaranteed unroutable
		Port:     623,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// PowerStatus should fail because it tries to establish the session.
	_, err = client.PowerStatus(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable BMC")
	}
	var connErr bmc.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
	}
}

func TestIPMIClient_SetBootDevice_Persistent_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Test with persistent=true.
	if err := client.SetBootDevice(context.Background(), bmc.BootDeviceDisk, true); err != nil {
		t.Fatalf("SetBootDevice(persistent=true): %v", err)
	}
}

// ListUsers walks every slot the BMC reports and returns the populated ones;
// the simulator's admin account is among them.
func TestIPMIUserManager_ListUsers_Simulator(t *testing.T) {
	sim := startSim(t, "admin", simPassword)

	config := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}
	mgr, err := bmc.NewUserManager(context.Background(), config, slog.Default())
	if err != nil {
		t.Fatalf("NewUserManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	users, err := mgr.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.Username == "admin" {
			return
		}
	}
	t.Fatalf("ListUsers = %+v, want the admin account", users)
}
