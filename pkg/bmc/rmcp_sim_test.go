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

package bmc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
)

// bmcSimulator is a minimal IPMI 2.0 RMCP+ BMC simulator for testing.
// It handles the RAKP handshake and responds to basic IPMI commands.
type bmcSimulator struct {
	conn     *net.UDPConn
	addr     *net.UDPAddr
	password string
	username string
	guid     [16]byte
	running  atomic.Bool
	done     chan struct{}

	// Session state learned during handshake
	clientSessionID uint32
	bmcSessionID    uint32
	clientRand      [16]byte
	authAlgo        uint8
	sik             []byte
	k1              []byte
	k2              []byte
}

// hashFunc returns the hash constructor for the negotiated auth algorithm.
func (s *bmcSimulator) hashFunc() func() hash.Hash {
	if s.authAlgo == authAlgoHMACSHA256 {
		return sha256.New
	}
	return sha1.New
}

// newBMCSimulator creates and starts a minimal RMCP+ BMC simulator.
func newBMCSimulator(t *testing.T, username, password string) *bmcSimulator {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}

	sim := &bmcSimulator{
		conn:         conn,
		addr:         conn.LocalAddr().(*net.UDPAddr),
		password:     password,
		username:     username,
		bmcSessionID: 0xAABBCCDD,
		done:         make(chan struct{}),
	}
	for i := range sim.guid {
		sim.guid[i] = byte(i + 0xA0)
	}

	sim.running.Store(true)
	go sim.serve(t)
	return sim
}

// localAddr returns the simulator's listening address.
func (s *bmcSimulator) localAddr() *net.UDPAddr {
	return s.addr
}

// stop shuts down the simulator.
func (s *bmcSimulator) stop() {
	if s.running.Swap(false) {
		s.conn.Close()
		<-s.done
	}
}

// serve handles incoming RMCP+ packets.
func (s *bmcSimulator) serve(t *testing.T) {
	t.Helper()
	defer close(s.done)

	buf := make([]byte, 2048)
	for s.running.Load() {
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.running.Load() {
				t.Logf("sim: read error: %v", err)
			}
			return
		}
		if n < 16 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		resp := s.handlePacket(t, packet)
		if resp != nil {
			if _, err := s.conn.WriteToUDP(resp, remoteAddr); err != nil {
				t.Logf("sim: write error: %v", err)
			}
		}
	}
}

// handlePacket routes a packet to the appropriate handler based on payload type.
func (s *bmcSimulator) handlePacket(t *testing.T, packet []byte) []byte {
	t.Helper()

	if packet[0] != rmcpVersion || packet[3] != rmcpClassIPMI {
		return nil
	}

	payloadType := packet[5] & 0x3F
	isEncrypted := packet[5]&0x80 != 0
	isAuthenticated := packet[5]&0x40 != 0

	switch payloadType {
	case payloadTypeOpenSessionReq:
		return s.handleOpenSession(t, packet)
	case payloadTypeRAKP1:
		return s.handleRAKP1(t, packet)
	case payloadTypeRAKP3:
		return s.handleRAKP3(t, packet)
	case payloadTypeIPMI:
		return s.handleIPMI(t, packet, isEncrypted, isAuthenticated)
	default:
		t.Logf("sim: unknown payload type 0x%02x", payloadType)
		return nil
	}
}

// handleOpenSession handles Open Session Request and returns Open Session Response.
func (s *bmcSimulator) handleOpenSession(t *testing.T, packet []byte) []byte {
	t.Helper()
	payload, err := extractUnauthPayload(packet, payloadTypeOpenSessionReq)
	if err != nil {
		t.Logf("sim: extract open session: %v", err)
		return nil
	}

	s.clientSessionID = binary.LittleEndian.Uint32(payload[4:8])
	s.authAlgo = payload[12]
	authAlgo := s.authAlgo
	integAlgo := payload[20]
	cryptoAlgo := payload[28]

	// Build response.
	resp := make([]byte, 36)
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status: no errors
	resp[2] = payload[1] // Max privilege
	resp[3] = 0x00
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	binary.LittleEndian.PutUint32(resp[8:12], s.bmcSessionID)

	// Auth algorithm payload
	resp[12] = 0x00 // type
	resp[13] = 0x00
	resp[14] = 0x00
	resp[15] = 0x08
	resp[16] = authAlgo

	// Integrity algorithm payload
	resp[20] = 0x01
	resp[21] = 0x00
	resp[22] = 0x00
	resp[23] = 0x08
	resp[24] = integAlgo

	// Confidentiality algorithm payload
	resp[28] = 0x02
	resp[29] = 0x00
	resp[30] = 0x00
	resp[31] = 0x08
	resp[32] = cryptoAlgo

	return buildRMCPPlusUnauthPacket(payloadTypeOpenSessionResp, 0, 0, resp)
}

// handleRAKP1 handles RAKP Message 1 and returns RAKP Message 2.
func (s *bmcSimulator) handleRAKP1(t *testing.T, packet []byte) []byte {
	t.Helper()
	payload, err := extractUnauthPayload(packet, payloadTypeRAKP1)
	if err != nil {
		t.Logf("sim: extract RAKP1: %v", err)
		return nil
	}

	copy(s.clientRand[:], payload[8:24])
	privilege := payload[24]
	userLen := payload[27]
	username := string(payload[28 : 28+userLen])
	_ = username

	// Generate BMC random number.
	var bmcRand [16]byte
	if _, err := rand.Read(bmcRand[:]); err != nil {
		t.Logf("sim: rand: %v", err)
		return nil
	}

	// Build HMAC data for auth code.
	// HMAC(password, clientSID || bmcSID || clientRand || bmcRand || bmcGUID || role || userLen || username)
	hmacData := make([]byte, 0, 58+int(userLen))
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.clientSessionID)
	hmacData = append(hmacData, sidBuf...)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	hmacData = append(hmacData, sidBuf...)
	hmacData = append(hmacData, s.clientRand[:]...)
	hmacData = append(hmacData, bmcRand[:]...)
	hmacData = append(hmacData, s.guid[:]...)
	hmacData = append(hmacData, privilege)
	hmacData = append(hmacData, userLen)
	hmacData = append(hmacData, payload[28:28+userLen]...)

	mac := hmac.New(s.hashFunc(), []byte(s.password))
	mac.Write(hmacData)
	authCode := mac.Sum(nil)

	// Derive SIK for RAKP4.
	sikData := make([]byte, 0, 34+int(userLen))
	sikData = append(sikData, s.clientRand[:]...)
	sikData = append(sikData, bmcRand[:]...)
	sikData = append(sikData, privilege)
	sikData = append(sikData, userLen)
	sikData = append(sikData, payload[28:28+userLen]...)

	mac = hmac.New(s.hashFunc(), []byte(s.password))
	mac.Write(sikData)
	s.sik = mac.Sum(nil)

	// Derive K1.
	k1Input := make([]byte, 20)
	for i := range k1Input {
		k1Input[i] = 0x01
	}
	mac = hmac.New(s.hashFunc(), s.sik)
	mac.Write(k1Input)
	s.k1 = mac.Sum(nil)

	// Derive K2.
	k2Input := make([]byte, 20)
	for i := range k2Input {
		k2Input[i] = 0x02
	}
	mac = hmac.New(s.hashFunc(), s.sik)
	mac.Write(k2Input)
	s.k2 = mac.Sum(nil)

	// Build RAKP Message 2 response.
	resp := make([]byte, 40+len(authCode))
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status
	// resp[2:4] reserved
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	copy(resp[8:24], bmcRand[:])
	copy(resp[24:40], s.guid[:])
	copy(resp[40:], authCode)

	return buildRMCPPlusUnauthPacket(payloadTypeRAKP2, 0, 0, resp)
}

// handleRAKP3 handles RAKP Message 3 and returns RAKP Message 4.
func (s *bmcSimulator) handleRAKP3(t *testing.T, packet []byte) []byte {
	t.Helper()
	payload, err := extractUnauthPayload(packet, payloadTypeRAKP3)
	if err != nil {
		t.Logf("sim: extract RAKP3: %v", err)
		return nil
	}

	statusCode := payload[1]
	if statusCode != 0x00 {
		t.Logf("sim: RAKP3 status: 0x%02x", statusCode)
		return nil
	}

	// Build integrity check value for RAKP4.
	// HMAC(SIK, clientRand || bmcSID || bmcGUID)
	icvData := make([]byte, 0, 36)
	icvData = append(icvData, s.clientRand[:]...)
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	icvData = append(icvData, sidBuf...)
	icvData = append(icvData, s.guid[:]...)

	mac := hmac.New(s.hashFunc(), s.sik)
	mac.Write(icvData)
	icv := mac.Sum(nil)

	resp := make([]byte, 8+len(icv))
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status
	// resp[2:4] reserved
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	copy(resp[8:], icv)

	return buildRMCPPlusUnauthPacket(payloadTypeRAKP4, 0, 0, resp)
}

// handleIPMI handles an authenticated IPMI command payload.
func (s *bmcSimulator) handleIPMI(t *testing.T, packet []byte, isEncrypted, isAuthenticated bool) []byte {
	t.Helper()

	if len(packet) < 16 {
		return nil
	}

	payloadLen := binary.LittleEndian.Uint16(packet[14:16])
	payloadStart := 16
	payloadEnd := payloadStart + int(payloadLen)
	if payloadEnd > len(packet) {
		return nil
	}

	payload := packet[payloadStart:payloadEnd]

	if isEncrypted && s.k2 != nil {
		// Create a temporary session for decryption.
		tmpSession := &rmcpSession{
			cryptoAlgo: cryptoAlgoAESCBC128,
			k2:         s.k2,
		}
		decrypted, err := tmpSession.decryptPayload(payload)
		if err != nil {
			t.Logf("sim: decrypt: %v", err)
			return nil
		}
		payload = decrypted
	}

	if len(payload) < 7 {
		return nil
	}

	netfn := payload[1] >> 2
	cmd := payload[5]

	// Build IPMI response.
	var respData []byte
	switch {
	case netfn == netFnApp && cmd == cmdSetSessionPrivilege:
		respData = []byte{privilegeAdministrator}
	case netfn == netFnApp && cmd == cmdCloseSession:
		respData = nil
	case netfn == netFnChassis && cmd == cmdChassisStatus:
		respData = []byte{0x61, 0x10, 0x40} // Power on, last event power up, misc
	case netfn == netFnChassis && cmd == cmdChassisControl:
		respData = nil
	case netfn == netFnChassis && cmd == cmdSetSystemBootOptions:
		respData = nil
	case netfn == netFnChassis && cmd == cmdGetSystemBootOptions:
		// Return boot flags with PXE selected.
		respData = []byte{0x01, 0x05, 0x80, bootDevicePXEBits, 0x00, 0x00}
	case netfn == netFnApp && cmd == cmdGetDeviceID:
		// Device ID response: 12+ bytes.
		respData = make([]byte, 12)
		respData[0] = 0x20 // Device ID
		respData[1] = 0x01 // Device revision
		respData[2] = 0x02 // Firmware major (2)
		respData[3] = 0x45 // Firmware minor (0x45 = BCD 45)
		respData[4] = 0x02 // IPMI version 2.0
		respData[5] = 0x00 // Additional device support
		respData[6] = 0x57 // Manufacturer ID byte 0 (Supermicro = 0x003757 -> 14167)
		respData[7] = 0x37 // Manufacturer ID byte 1
		respData[8] = 0x00 // Manufacturer ID byte 2
		respData[9] = 0x00 // Product ID byte 0
		respData[10] = 0x00 // Product ID byte 1
		respData[11] = 0x00 // Aux firmware rev
	default:
		t.Logf("sim: unhandled cmd 0x%02x netfn 0x%02x", cmd, netfn)
		return nil
	}

	// Build IPMI response message.
	respNetfn := (netfn + 1) // Response netfn = request + 1
	ipmiResp := make([]byte, 8+len(respData))
	ipmiResp[0] = 0x81                          // rqAddr
	ipmiResp[1] = respNetfn << 2                // netfn/lun
	ipmiResp[2] = ipmiChecksum(ipmiResp[0:2])
	ipmiResp[3] = 0x20                          // rsAddr
	ipmiResp[4] = 0x00                          // rsSeq
	ipmiResp[5] = cmd
	ipmiResp[6] = 0x00                          // Completion code: success
	if len(respData) > 0 {
		copy(ipmiResp[7:], respData)
	}
	ipmiResp[len(ipmiResp)-1] = ipmiChecksum(ipmiResp[3 : len(ipmiResp)-1])

	// Wrap response in RMCP+ session envelope.
	// Use the negotiated integrity algorithm — SHA256-128 for SHA256 auth, SHA1-96 otherwise.
	integAlgo := integrityAlgoHMACSHA1_96
	if s.authAlgo == authAlgoHMACSHA256 {
		integAlgo = integrityAlgoHMACSHA256_128
	}
	tmpSession := &rmcpSession{
		cryptoAlgo:    cryptoAlgoAESCBC128,
		integrityAlgo: uint8(integAlgo),
		bmcSessionID:  s.clientSessionID, // Response uses client's session ID
		k1:            s.k1,
		k2:            s.k2,
		logger:        slog.Default(),
	}
	if s.k2 == nil {
		// Keys not yet derived (shouldn't happen for IPMI commands)
		tmpSession.cryptoAlgo = cryptoAlgoNone
		tmpSession.integrityAlgo = integrityAlgoNone
	}

	wrapped, err := tmpSession.wrapPayload(ipmiResp)
	if err != nil {
		t.Logf("sim: wrap: %v", err)
		return nil
	}
	return wrapped
}

// --- Simulator-based Tests ---

func TestRMCPSession_FullHandshake(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	session := newRMCPSession(config, slog.Default())
	err := session.Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	// Verify keys were derived.
	if session.sik == nil {
		t.Error("SIK is nil after Open")
	}
	if session.k1 == nil {
		t.Error("K1 is nil after Open")
	}
	if session.k2 == nil {
		t.Error("K2 is nil after Open")
	}
	if session.bmcSessionID == 0 {
		t.Error("BMC session ID is zero after Open")
	}
}

func TestRMCPSession_FullHandshake_BadPassword(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "correct_password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "wrong_password",
		Protocol: ProtocolIPMI,
	}

	session := newRMCPSession(config, slog.Default())
	err := session.Open(context.Background())
	if err == nil {
		session.Close()
		t.Fatal("expected error for wrong password")
	}
	// Should fail at RAKP Message 2 verification.
	var rakpErr ErrRAKPAuthFailed
	if !errors.As(err, &rakpErr) {
		// Could also be ErrConnectionFailed wrapping ErrRAKPAuthFailed.
		var connErr ErrConnectionFailed
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
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	state, err := client.PowerStatus(context.Background())
	if err != nil {
		t.Fatalf("PowerStatus: %v", err)
	}
	if state != PowerStateOn {
		t.Errorf("PowerStatus = %q, want %q", state, PowerStateOn)
	}
}

func TestIPMIClient_PowerOn_Simulator(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	if info.PowerState != PowerStateOn {
		t.Errorf("PowerState = %q, want %q", info.PowerState, PowerStateOn)
	}
}

func TestIPMIClient_SetBootDevice_Simulator(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.SetBootDevice(context.Background(), BootDevicePXE, false); err != nil {
		t.Fatalf("SetBootDevice: %v", err)
	}
}

func TestIPMIClient_GetBootDevice_Simulator(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	device, err := client.GetBootDevice(context.Background())
	if err != nil {
		t.Fatalf("GetBootDevice: %v", err)
	}
	if device != BootDevicePXE {
		t.Errorf("GetBootDevice = %q, want %q", device, BootDevicePXE)
	}
}

func TestIPMIClient_ConnectionFailure(t *testing.T) {
	// Use an address that will timeout/fail.
	config := &Config{
		Address:  "192.0.2.1", // TEST-NET-1: guaranteed unroutable
		Port:     623,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
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
	var connErr ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
	}
}

func TestIPMIClient_SetBootDevice_Persistent_Simulator(t *testing.T) {
	sim := newBMCSimulator(t, "admin", "password")
	t.Cleanup(sim.stop)

	config := &Config{
		Address:  sim.localAddr().IP.String(),
		Port:     sim.localAddr().Port,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}

	factory := NewIPMIClientFactory(slog.Default())
	client, err := factory.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Test with persistent=true.
	if err := client.SetBootDevice(context.Background(), BootDeviceDisk, true); err != nil {
		t.Fatalf("SetBootDevice(persistent=true): %v", err)
	}
}
