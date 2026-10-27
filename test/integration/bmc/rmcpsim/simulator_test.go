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

package rmcpsim_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/bmc/rmcpsim"
)

// TestNew_EmptyAddress ensures New rejects a zero-value Addr and
// returns ErrInvalidAddress.
// The credentials of every test that completes an RMCP+ handshake are at
// least 14 bytes: under FIPS activation pkg/bmc refuses a shorter IPMI
// password as an HMAC key (FIPS 140-3, SP 800-131A's 112-bit floor), and
// these tests exercise the simulator, not that policy, so they run unchanged
// in the FIPS and non-FIPS builds. The refusal itself is tested in
// pkg/bmc/rmcp_fips_keys_test.go.
const (
	simPassword    = "rmcpsim-password"
	simOldPassword = "rmcpsim-old-password"
	simNewPassword = "rmcpsim-new-password"
)

func TestNew_EmptyAddress(t *testing.T) {
	_, err := rmcpsim.New(rmcpsim.Options{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("expected error for empty address")
	}
	var invalid rmcpsim.ErrInvalidAddress
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidAddress, got %T: %v", err, err)
	}
}

// TestNew_DefaultLogger confirms a nil Logger resolves to slog.Default
// rather than causing a panic at runtime.
func TestNew_DefaultLogger(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "u",
		Password: "p",
		Logger:   nil,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()
	if sim.LocalAddr() == nil {
		t.Fatal("LocalAddr is nil after Start")
	}
}

// TestStart_InvalidAddress verifies Start surfaces bind errors via
// ErrListen when the addr is syntactically valid but unbindable.
func TestStart_InvalidAddress(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "300.300.300.300:1",
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = sim.Start()
	if err == nil {
		sim.Stop()
		t.Fatal("expected Start to fail for bogus address")
	}
	// Either resolution or listen can fail -- both are acceptable.
	var invalid rmcpsim.ErrInvalidAddress
	var listenErr rmcpsim.ErrListen
	if !errors.As(err, &invalid) && !errors.As(err, &listenErr) {
		t.Fatalf("expected ErrInvalidAddress or ErrListen, got %T: %v", err, err)
	}
}

// TestStart_Idempotent verifies Start returns ErrAlreadyStarted on
// the second call, and Stop is safe to call multiple times.
func TestStart_Idempotent(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err = sim.Start()
	if err == nil {
		sim.Stop()
		t.Fatal("expected second Start to fail")
	}
	var already rmcpsim.ErrAlreadyStarted
	if !errors.As(err, &already) {
		t.Fatalf("expected ErrAlreadyStarted, got %T: %v", err, err)
	}
	sim.Stop()
	sim.Stop() // second Stop must be a no-op
}

// TestCredentials_SetAndGet verifies SetCredentials atomically updates
// accepted credentials and Credentials reads them back.
func TestCredentials_SetAndGet(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "orig_user",
		Password: "orig_pw",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, p := sim.Credentials()
	if u != "orig_user" || p != "orig_pw" {
		t.Fatalf("Credentials = (%q,%q), want (orig_user,orig_pw)", u, p)
	}
	sim.SetCredentials("new_user", "new_pw")
	u, p = sim.Credentials()
	if u != "new_user" || p != "new_pw" {
		t.Fatalf("Credentials after Set = (%q,%q), want (new_user,new_pw)", u, p)
	}
}

// TestSimulator_HandshakeAndPowerStatus exercises the happy path end
// to end: handshake completes and an IPMI Chassis Status command
// returns PowerStateOn.
func TestSimulator_HandshakeAndPowerStatus(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	cfg := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}

	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	state, err := client.PowerStatus(context.Background())
	if err != nil {
		t.Fatalf("PowerStatus: %v", err)
	}
	if state != bmc.PowerStateOn {
		t.Fatalf("PowerStatus = %q, want %q", state, bmc.PowerStateOn)
	}
}

// TestSimulator_CredentialRotation verifies SetCredentials takes
// effect for handshakes opened after the rotation -- simulating an
// IPMI Set User Password command mutation.
func TestSimulator_CredentialRotation(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simOldPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// Rotate credentials before any client connects.
	sim.SetCredentials("admin", simNewPassword)

	// Client using NEW password must succeed.
	cfg := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simNewPassword,
		Protocol: bmc.ProtocolIPMI,
	}
	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	if _, err := client.PowerStatus(context.Background()); err != nil {
		t.Fatalf("PowerStatus with rotated creds: %v", err)
	}
}

// TestErrors_FormattingAndUnwrap exercises the error types' Error()
// and Unwrap() paths so they participate in coverage.
func TestErrors_FormattingAndUnwrap(t *testing.T) {
	cause := errors.New("boom")

	invalid := rmcpsim.ErrInvalidAddress{Addr: "bad", Cause: cause}
	if invalid.Error() == "" {
		t.Error("ErrInvalidAddress.Error empty")
	}
	if !errors.Is(invalid, cause) {
		t.Error("ErrInvalidAddress does not unwrap to cause")
	}

	invalidNoCause := rmcpsim.ErrInvalidAddress{Addr: "bad"}
	if invalidNoCause.Error() == "" {
		t.Error("ErrInvalidAddress (no cause) .Error empty")
	}
	if invalidNoCause.Unwrap() != nil {
		t.Error("ErrInvalidAddress (no cause) should unwrap to nil")
	}

	listen := rmcpsim.ErrListen{Addr: ":1", Cause: cause}
	if listen.Error() == "" {
		t.Error("ErrListen.Error empty")
	}
	if !errors.Is(listen, cause) {
		t.Error("ErrListen does not unwrap to cause")
	}

	already := rmcpsim.ErrAlreadyStarted{}
	if already.Error() == "" {
		t.Error("ErrAlreadyStarted.Error empty")
	}
}

// sendRawAndExpectSilence sends a raw UDP packet to the simulator and
// confirms the simulator does NOT reply within a short window. Used
// to exercise the error-path branches in handlePacket / handleIPMI
// where the simulator drops bad packets instead of responding.
func sendRawAndExpectSilence(t *testing.T, sim *rmcpsim.Simulator, packet []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, sim.LocalAddr())
	if err != nil {
		t.Fatalf("dial sim: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Very short deadline -- if the simulator was going to respond,
	// it would have done so well before this.
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Fatalf("expected no response, got %d bytes", n)
	}
}

// TestHandlePacket_BadRMCPHeader ensures packets whose RMCP header
// fields don't match the IPMI class are silently dropped.
func TestHandlePacket_BadRMCPHeader(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// 16-byte buffer with wrong RMCP version byte -- should be dropped.
	badVersion := make([]byte, 20)
	badVersion[0] = 0x00 // not rmcpVersion
	badVersion[3] = 0x07
	sendRawAndExpectSilence(t, sim, badVersion)

	// Correct version, wrong class -- also dropped.
	badClass := make([]byte, 20)
	badClass[0] = 0x06
	badClass[3] = 0x00 // not rmcpClassIPMI
	sendRawAndExpectSilence(t, sim, badClass)
}

// TestHandlePacket_UnknownPayloadType ensures packets with a payload
// type byte the simulator doesn't implement are dropped rather than
// crashing the serve loop.
func TestHandlePacket_UnknownPayloadType(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	pkt := make([]byte, 20)
	pkt[0] = 0x06 // rmcpVersion
	pkt[3] = 0x07 // rmcpClassIPMI
	pkt[5] = 0x20 // unknown payload type (not IPMI/0x00, not RAKP/0x10..0x15)
	sendRawAndExpectSilence(t, sim, pkt)
}

// TestHandlePacket_ShortPacket ensures packets below the 16-byte
// minimum are dropped by the read loop prior to routing.
func TestHandlePacket_ShortPacket(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	sendRawAndExpectSilence(t, sim, []byte{0x01, 0x02, 0x03})
}

// TestHandlePacket_MalformedOpenSession sends a payload-type =
// OpenSessionReq with a payload that fails ExtractUnauthPayload.
func TestHandlePacket_MalformedOpenSession(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// Correct headers but truncated body -- extract should fail.
	pkt := make([]byte, 20)
	pkt[0] = 0x06
	pkt[3] = 0x07
	pkt[5] = bmc.PayloadTypeOpenSessionReq
	sendRawAndExpectSilence(t, sim, pkt)
}

// TestHandleIPMI_ShortAfterHandshake drives a real handshake, then
// sends an IPMI-typed packet with a truncated payload-length to hit
// the len(packet)<16 / payloadEnd > len(packet) early-return in
// handleIPMI.
func TestHandleIPMI_MalformedPayloadLength(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// 20 bytes with payload-length claim larger than the packet.
	pkt := make([]byte, 20)
	pkt[0] = 0x06
	pkt[3] = 0x07
	pkt[5] = bmc.PayloadTypeIPMI
	// payload length bytes at [14:16] -- declare 1000, which exceeds
	// the actual payload area (4 bytes).
	pkt[14] = 0xE8
	pkt[15] = 0x03
	sendRawAndExpectSilence(t, sim, pkt)
}

// TestSimulator_AllIPMIHandlers drives every IPMI command the
// simulator dispatches for, so the per-command handler lambdas in
// ipmiHandlers are covered.
func TestSimulator_AllIPMIHandlers(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	cfg := &bmc.Config{
		Address:  sim.LocalAddr().IP.String(),
		Port:     sim.LocalAddr().Port,
		Username: "admin",
		Password: simPassword,
		Protocol: bmc.ProtocolIPMI,
	}
	factory := bmc.NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// GetSystemInfo exercises Get Device ID + Chassis Status.
	if _, err := client.GetSystemInfo(ctx); err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	// Power operations -> Chassis Control.
	if err := client.PowerOn(ctx); err != nil {
		t.Fatalf("PowerOn: %v", err)
	}
	if err := client.PowerOff(ctx); err != nil {
		t.Fatalf("PowerOff: %v", err)
	}
	// Boot options set + get.
	if err := client.SetBootDevice(ctx, bmc.BootDevicePXE, false); err != nil {
		t.Fatalf("SetBootDevice: %v", err)
	}
	if dev, err := client.GetBootDevice(ctx); err != nil {
		t.Fatalf("GetBootDevice: %v", err)
	} else if dev != bmc.BootDevicePXE {
		t.Fatalf("GetBootDevice = %q, want PXE", dev)
	}
	// Close triggers cmdCloseSession via Close.
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestHandleIPMI_UnknownSession verifies that IPMI-typed packets whose
// RMCP+ session ID does not match any active session are silently
// dropped. This exercises the "session not found" early-return in
// handleIPMI without requiring a full RAKP handshake.
func TestHandleIPMI_UnknownSession(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// Build an IPMI-typed packet with a non-zero session ID that has
	// never been established (no prior Open Session exchange).
	// packet[6:10] = BMC session ID = 0xDEADBEEF -- unknown.
	pkt := make([]byte, 24)
	pkt[0] = 0x06 // RMCP version
	pkt[3] = 0x07 // RMCP class IPMI
	pkt[5] = bmc.PayloadTypeIPMI
	pkt[6] = 0xEF // session ID byte 0 (little-endian 0xDEADBEEF)
	pkt[7] = 0xBE
	pkt[8] = 0xAD
	pkt[9] = 0xDE
	// Declare an 8-byte payload so payload[:8] is accessible.
	pkt[14] = 0x08
	pkt[15] = 0x00
	// Arbitrary IPMI command bytes inside the payload.
	pkt[16] = 0x20
	pkt[17] = (0x0A << 2) // netfn=Storage
	pkt[18] = bmc.IPMIChecksum(pkt[16:18])
	pkt[19] = 0x81
	pkt[20] = 0x00
	pkt[21] = 0x43 // cmd: Get SEL Entry
	pkt[22] = 0x00
	pkt[23] = bmc.IPMIChecksum(pkt[19:23])
	sendRawAndExpectSilence(t, sim, pkt)
}

// TestHandleIPMI_ShortPayload exercises the len(payload)<7 early
// return in handleIPMI -- a well-formed RMCP+ header but an IPMI
// payload too short to contain the (rsAddr..cmd) prefix.
func TestHandleIPMI_ShortPayload(t *testing.T) {
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "admin",
		Password: simPassword,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sim.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sim.Stop()

	// 20 bytes total = 16-byte header + 4-byte payload (<7).
	pkt := make([]byte, 20)
	pkt[0] = 0x06
	pkt[3] = 0x07
	pkt[5] = bmc.PayloadTypeIPMI
	pkt[14] = 0x04
	pkt[15] = 0x00
	sendRawAndExpectSilence(t, sim, pkt)
}

// TestStart_PortAlreadyBound exercises the ErrListen branch by
// starting a simulator on a port, then attempting to start a second
// simulator on the same address.
func TestStart_PortAlreadyBound(t *testing.T) {
	first, err := rmcpsim.New(rmcpsim.Options{
		Addr:     "127.0.0.1:0",
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	if err := first.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer first.Stop()

	addr := first.LocalAddr().String()
	second, err := rmcpsim.New(rmcpsim.Options{
		Addr:     addr,
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	err = second.Start()
	if err == nil {
		second.Stop()
		t.Fatal("expected Start to fail on already-bound address")
	}
	var listenErr rmcpsim.ErrListen
	if !errors.As(err, &listenErr) {
		t.Fatalf("expected ErrListen, got %T: %v", err, err)
	}
}
