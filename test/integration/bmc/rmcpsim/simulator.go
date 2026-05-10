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

// Package rmcpsim implements a minimal IPMI 2.0 RMCP+ BMC simulator.
//
// The simulator handles the RAKP handshake (HMAC-SHA1 / HMAC-SHA256),
// AES-CBC-128 confidentiality, and responds to a small set of IPMI
// commands sufficient to exercise power control, boot option, device
// ID, and session management flows. It is used both by pkg/bmc unit
// tests and by the devcontainer vBMC image to provide a real UDP IPMI
// surface for integration tests.
//
// The simulator is NOT a fully conformant BMC -- it supports only the
// handful of commands the platform's IPMI client exercises. It is
// sufficient for functional testing; production code paths that
// require features not implemented here (SOL, SEL, FRU, sensor data,
// etc.) must target real hardware or extend the simulator.
//
// Thread safety:
//
//   - Credentials (username/password) are protected by an RWMutex and
//     safe to update at runtime via SetCredentials. This supports
//     simulating IPMI Set User Password against a live listener.
//   - Start/Stop are idempotent and may be called concurrently.
//
// Typical use:
//
//	sim, err := rmcpsim.New(rmcpsim.Options{
//	    Addr:     ":6230",
//	    Username: "ADMIN",
//	    Password: "ADMIN",
//	    Logger:   slog.Default(),
//	})
//	if err != nil { ... }
//	if err := sim.Start(); err != nil { ... }
//	defer sim.Stop()
package rmcpsim

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// Options controls simulator construction.
type Options struct {
	// Addr is the UDP listen address (e.g. ":6230" or "127.0.0.1:0").
	// Required.
	Addr string

	// Username is the BMC account name the simulator accepts.
	// Required.
	Username string

	// Password is the BMC account password the simulator accepts.
	// Required.
	Password string

	// Logger is used for diagnostic output. Defaults to slog.Default()
	// when nil.
	Logger *slog.Logger
}

// ErrInvalidAddress indicates the listen address was empty or could
// not be parsed as a UDP address.
type ErrInvalidAddress struct {
	Addr  string
	Cause error
}

func (e ErrInvalidAddress) Error() string {
	if e.Cause == nil {
		return "rmcpsim: invalid address: " + e.Addr
	}
	return "rmcpsim: invalid address " + e.Addr + ": " + e.Cause.Error()
}

func (e ErrInvalidAddress) Unwrap() error { return e.Cause }

// ErrListen indicates the UDP socket could not be bound.
type ErrListen struct {
	Addr  string
	Cause error
}

func (e ErrListen) Error() string {
	return "rmcpsim: listen " + e.Addr + ": " + e.Cause.Error()
}

func (e ErrListen) Unwrap() error { return e.Cause }

// ErrAlreadyStarted indicates Start was called on a running simulator.
type ErrAlreadyStarted struct{}

func (ErrAlreadyStarted) Error() string { return "rmcpsim: simulator already started" }

// Simulator is a minimal IPMI 2.0 RMCP+ BMC simulator bound to a UDP
// address. Zero value is not usable; construct via New.
type Simulator struct {
	logger *slog.Logger
	addr   string

	credMu   sync.RWMutex
	username string
	password string

	guid         [16]byte
	bmcSessionID uint32

	// running guards Start/Stop idempotency.
	running atomic.Bool
	conn    *net.UDPConn
	listen  *net.UDPAddr
	done    chan struct{}

	// Session state captured during the RAKP handshake. The simulator
	// tracks a single session -- sufficient for unit + integration
	// tests but not for multi-client scenarios.
	sessMu          sync.Mutex
	clientSessionID uint32
	clientRand      [16]byte
	authAlgo        uint8
	sik             []byte
	k1              []byte
	k2              []byte

	// handlers is the instance-level IPMI command dispatch map. It
	// holds handlers that require per-simulator state (e.g. user
	// management). Checked before the package-level staticHandlers.
	handlers map[ipmiKey]ipmiHandler

	// users is the in-memory IPMI user table. Slot 0 is reserved;
	// valid user IDs are 1-15.
	userMu sync.RWMutex
	users  [userTableSize]userEntry
}

// New constructs a Simulator with the given options. The UDP socket
// is not bound until Start is called.
func New(opts Options) (*Simulator, error) {
	if opts.Addr == "" {
		return nil, ErrInvalidAddress{Addr: opts.Addr}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sim := &Simulator{
		logger:       logger,
		addr:         opts.Addr,
		username:     opts.Username,
		password:     opts.Password,
		bmcSessionID: 0xAABBCCDD,
		handlers:     make(map[ipmiKey]ipmiHandler),
	}
	for i := range sim.guid {
		sim.guid[i] = byte(i + 0xA0)
	}

	sim.initUserTable()
	sim.registerUserHandlers()

	return sim, nil
}

// SetCredentials atomically replaces the username/password the
// simulator accepts. Safe to call concurrently with Start/Stop and
// in-flight RAKP handshakes -- new handshakes after this call will
// validate against the new credentials.
func (s *Simulator) SetCredentials(username, password string) {
	s.credMu.Lock()
	s.username = username
	s.password = password
	s.credMu.Unlock()
}

// Credentials returns the currently accepted username/password.
func (s *Simulator) Credentials() (username, password string) {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return s.username, s.password
}

// LocalAddr returns the simulator's bound UDP address. Returns nil if
// the simulator has not been started.
func (s *Simulator) LocalAddr() *net.UDPAddr {
	return s.listen
}

// Start binds the UDP socket and launches the packet-handling
// goroutine. Returns ErrAlreadyStarted if already running.
func (s *Simulator) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return ErrAlreadyStarted{}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.running.Store(false)
		return ErrInvalidAddress{Addr: s.addr, Cause: err}
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.running.Store(false)
		return ErrListen{Addr: s.addr, Cause: err}
	}

	s.conn = conn
	s.listen = conn.LocalAddr().(*net.UDPAddr)
	s.done = make(chan struct{})
	go s.serve()
	return nil
}

// Stop shuts down the listener and blocks until the serve goroutine
// has exited. Safe to call multiple times.
func (s *Simulator) Stop() {
	if !s.running.CompareAndSwap(true, false) {
		return
	}
	// Closing the conn unblocks ReadFromUDP in serve.
	_ = s.conn.Close()
	<-s.done
}

// password snapshots the password under the credential lock.
func (s *Simulator) passwordSnapshot() string {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return s.password
}

// hashFunc returns the hash constructor for the negotiated auth
// algorithm. Must be called with the session state already populated
// (i.e. after Open Session / RAKP1).
func (s *Simulator) hashFunc() func() hash.Hash {
	if s.authAlgo == bmc.AuthAlgoHMACSHA256 {
		return sha256.New
	}
	return sha1.New
}

// serve is the main UDP read loop.
func (s *Simulator) serve() {
	defer close(s.done)

	buf := make([]byte, 2048)
	for s.running.Load() {
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.running.Load() {
				s.logger.Debug("rmcpsim: read error", "err", err)
			}
			return
		}
		if n < 16 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		resp := s.handlePacket(packet)
		if resp != nil {
			if _, err := s.conn.WriteToUDP(resp, remoteAddr); err != nil {
				s.logger.Debug("rmcpsim: write error", "err", err)
			}
		}
	}
}

// handlePacket routes a packet to the appropriate handler based on
// payload type.
func (s *Simulator) handlePacket(packet []byte) []byte {
	if packet[0] != bmc.RMCPVersion || packet[3] != bmc.RMCPClassIPMI {
		return nil
	}

	payloadType := packet[5] & 0x3F
	isEncrypted := packet[5]&0x80 != 0
	isAuthenticated := packet[5]&0x40 != 0

	switch payloadType {
	case bmc.PayloadTypeOpenSessionReq:
		return s.handleOpenSession(packet)
	case bmc.PayloadTypeRAKP1:
		return s.handleRAKP1(packet)
	case bmc.PayloadTypeRAKP3:
		return s.handleRAKP3(packet)
	case bmc.PayloadTypeIPMI:
		return s.handleIPMI(packet, isEncrypted, isAuthenticated)
	default:
		s.logger.Debug("rmcpsim: unknown payload type", "type", payloadType)
		return nil
	}
}

// handleOpenSession handles Open Session Request and returns Open
// Session Response.
func (s *Simulator) handleOpenSession(packet []byte) []byte {
	payload, err := bmc.ExtractUnauthPayload(packet, bmc.PayloadTypeOpenSessionReq)
	if err != nil {
		s.logger.Debug("rmcpsim: extract open session", "err", err)
		return nil
	}
	// Open Session Request body layout requires fields through
	// offset 32 (confidentiality-algo tuple ending at payload[32]).
	// Anything shorter is malformed -- drop silently rather than
	// index-panic the serve goroutine.
	if len(payload) < 32 {
		s.logger.Debug("rmcpsim: open session payload too short", "len", len(payload))
		return nil
	}

	s.sessMu.Lock()
	s.clientSessionID = binary.LittleEndian.Uint32(payload[4:8])
	s.authAlgo = payload[12]
	authAlgo := s.authAlgo
	s.sessMu.Unlock()

	integAlgo := payload[20]
	cryptoAlgo := payload[28]

	resp := make([]byte, 36)
	resp[0] = 0x00       // Tag
	resp[1] = 0x00       // Status: no errors
	resp[2] = payload[1] // Max privilege
	resp[3] = 0x00
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	binary.LittleEndian.PutUint32(resp[8:12], s.bmcSessionID)

	// Auth algorithm payload.
	resp[12] = 0x00
	resp[13] = 0x00
	resp[14] = 0x00
	resp[15] = 0x08
	resp[16] = authAlgo

	// Integrity algorithm payload.
	resp[20] = 0x01
	resp[21] = 0x00
	resp[22] = 0x00
	resp[23] = 0x08
	resp[24] = integAlgo

	// Confidentiality algorithm payload.
	resp[28] = 0x02
	resp[29] = 0x00
	resp[30] = 0x00
	resp[31] = 0x08
	resp[32] = cryptoAlgo

	return bmc.BuildRMCPPlusUnauthPacket(bmc.PayloadTypeOpenSessionResp, 0, 0, resp)
}

// handleRAKP1 handles RAKP Message 1 and returns RAKP Message 2.
func (s *Simulator) handleRAKP1(packet []byte) []byte {
	payload, err := bmc.ExtractUnauthPayload(packet, bmc.PayloadTypeRAKP1)
	if err != nil {
		s.logger.Debug("rmcpsim: extract RAKP1", "err", err)
		return nil
	}
	// RAKP1 body layout: 8 bytes header + 16 bytes clientRand +
	// privilege(1) + reserved(2) + userLen(1) + username(userLen).
	// Require at least 28 bytes before reading userLen.
	if len(payload) < 28 {
		s.logger.Debug("rmcpsim: RAKP1 payload too short", "len", len(payload))
		return nil
	}
	userLen := payload[27]
	if len(payload) < 28+int(userLen) {
		s.logger.Debug("rmcpsim: RAKP1 truncated username", "len", len(payload), "userLen", userLen)
		return nil
	}

	s.sessMu.Lock()
	copy(s.clientRand[:], payload[8:24])
	s.sessMu.Unlock()

	privilege := payload[24]
	// Username is present at payload[28:28+userLen] -- the simulator
	// accepts whichever name the client supplies; credentials are
	// enforced via HMAC verification on the client side (password).

	var bmcRand [16]byte
	if _, err := rand.Read(bmcRand[:]); err != nil {
		s.logger.Debug("rmcpsim: rand", "err", err)
		return nil
	}

	password := s.passwordSnapshot()

	// HMAC(password, clientSID || bmcSID || clientRand || bmcRand || bmcGUID || role || userLen || username).
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

	mac := hmac.New(s.hashFunc(), []byte(password))
	mac.Write(hmacData)
	authCode := mac.Sum(nil)

	// Derive SIK for RAKP4.
	sikData := make([]byte, 0, 34+int(userLen))
	sikData = append(sikData, s.clientRand[:]...)
	sikData = append(sikData, bmcRand[:]...)
	sikData = append(sikData, privilege)
	sikData = append(sikData, userLen)
	sikData = append(sikData, payload[28:28+userLen]...)

	mac = hmac.New(s.hashFunc(), []byte(password))
	mac.Write(sikData)
	sik := mac.Sum(nil)

	// Derive K1.
	k1Input := make([]byte, 20)
	for i := range k1Input {
		k1Input[i] = 0x01
	}
	mac = hmac.New(s.hashFunc(), sik)
	mac.Write(k1Input)
	k1 := mac.Sum(nil)

	// Derive K2.
	k2Input := make([]byte, 20)
	for i := range k2Input {
		k2Input[i] = 0x02
	}
	mac = hmac.New(s.hashFunc(), sik)
	mac.Write(k2Input)
	k2 := mac.Sum(nil)

	s.sessMu.Lock()
	s.sik = sik
	s.k1 = k1
	s.k2 = k2
	s.sessMu.Unlock()

	resp := make([]byte, 40+len(authCode))
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	copy(resp[8:24], bmcRand[:])
	copy(resp[24:40], s.guid[:])
	copy(resp[40:], authCode)

	return bmc.BuildRMCPPlusUnauthPacket(bmc.PayloadTypeRAKP2, 0, 0, resp)
}

// handleRAKP3 handles RAKP Message 3 and returns RAKP Message 4.
func (s *Simulator) handleRAKP3(packet []byte) []byte {
	payload, err := bmc.ExtractUnauthPayload(packet, bmc.PayloadTypeRAKP3)
	if err != nil {
		s.logger.Debug("rmcpsim: extract RAKP3", "err", err)
		return nil
	}
	// RAKP3 body needs at least tag + status before we peek.
	if len(payload) < 2 {
		s.logger.Debug("rmcpsim: RAKP3 payload too short", "len", len(payload))
		return nil
	}

	statusCode := payload[1]
	if statusCode != 0x00 {
		s.logger.Debug("rmcpsim: RAKP3 bad status", "status", statusCode)
		return nil
	}

	// HMAC(SIK, clientRand || bmcSID || bmcGUID).
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
	binary.LittleEndian.PutUint32(resp[4:8], s.clientSessionID)
	copy(resp[8:], icv)

	return bmc.BuildRMCPPlusUnauthPacket(bmc.PayloadTypeRAKP4, 0, 0, resp)
}

// handleIPMI handles an authenticated IPMI command payload.
func (s *Simulator) handleIPMI(packet []byte, isEncrypted, isAuthenticated bool) []byte {
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

	s.sessMu.Lock()
	k1 := s.k1
	k2 := s.k2
	authAlgo := s.authAlgo
	clientSessionID := s.clientSessionID
	s.sessMu.Unlock()

	if isEncrypted && k2 != nil {
		decrypted, err := bmc.DecryptSessionPayload(bmc.CryptoAlgoAESCBC128, k2, payload)
		if err != nil {
			s.logger.Debug("rmcpsim: decrypt", "err", err)
			return nil
		}
		payload = decrypted
	}

	if len(payload) < 7 {
		return nil
	}

	netfn := payload[1] >> 2
	cmd := payload[5]

	respData, completionCode, ok := s.dispatchIPMI(netfn, cmd, payload)
	if !ok {
		s.logger.Debug("rmcpsim: unhandled IPMI command", "netfn", netfn, "cmd", cmd)
		return nil
	}

	// Build IPMI response message.
	respNetfn := netfn + 1
	ipmiResp := make([]byte, 8+len(respData))
	ipmiResp[0] = 0x81 // rqAddr
	ipmiResp[1] = respNetfn << 2
	ipmiResp[2] = bmc.IPMIChecksum(ipmiResp[0:2])
	ipmiResp[3] = 0x20 // rsAddr
	ipmiResp[4] = 0x00 // rsSeq
	ipmiResp[5] = cmd
	ipmiResp[6] = completionCode
	if len(respData) > 0 {
		copy(ipmiResp[7:], respData)
	}
	ipmiResp[len(ipmiResp)-1] = bmc.IPMIChecksum(ipmiResp[3 : len(ipmiResp)-1])

	// Wrap response in RMCP+ session envelope. Use the negotiated
	// integrity algorithm -- SHA256-128 for SHA256 auth, SHA1-96
	// otherwise.
	integAlgo := uint8(bmc.IntegrityAlgoHMACSHA1_96)
	if authAlgo == bmc.AuthAlgoHMACSHA256 {
		integAlgo = uint8(bmc.IntegrityAlgoHMACSHA256_128)
	}
	cryptoAlgo := uint8(bmc.CryptoAlgoAESCBC128)
	if k2 == nil {
		cryptoAlgo = uint8(bmc.CryptoAlgoNone)
		integAlgo = uint8(bmc.IntegrityAlgoNone)
	}

	wrapped, err := bmc.WrapSessionPayload(cryptoAlgo, integAlgo, clientSessionID, k1, k2, ipmiResp, s.logger)
	if err != nil {
		s.logger.Debug("rmcpsim: wrap", "err", err)
		return nil
	}
	return wrapped
}

// ipmiHandler processes an IPMI command and returns response data bytes
// and a completion code. The ipmiPayload parameter is the full IPMI
// message frame starting from rqAddr.
type ipmiHandler func(ipmiPayload []byte) ([]byte, byte)

// ipmiKey uniquely identifies a dispatch target.
type ipmiKey struct {
	netfn byte
	cmd   byte
}

// staticHandlers maps (netfn, cmd) to stateless handlers that do not
// require per-simulator state. Instance-level handlers in
// Simulator.handlers take precedence.
var staticHandlers = map[ipmiKey]ipmiHandler{
	{bmc.NetFnApp, bmc.CmdSetSessionPrivilege}: func(_ []byte) ([]byte, byte) {
		return []byte{bmc.RMCPPrivilegeAdministrator}, ccSuccess
	},
	{bmc.NetFnApp, bmc.CmdCloseSession}: func(_ []byte) ([]byte, byte) {
		return nil, ccSuccess
	},
	{bmc.NetFnChassis, bmc.CmdChassisStatus}: func(_ []byte) ([]byte, byte) {
		// Power on, last event = power up, misc.
		return []byte{0x61, 0x10, 0x40}, ccSuccess
	},
	{bmc.NetFnChassis, bmc.CmdChassisControl}: func(_ []byte) ([]byte, byte) {
		return nil, ccSuccess
	},
	{bmc.NetFnChassis, bmc.CmdSetSystemBootOptions}: func(_ []byte) ([]byte, byte) {
		return nil, ccSuccess
	},
	{bmc.NetFnChassis, bmc.CmdGetSystemBootOptions}: func(_ []byte) ([]byte, byte) {
		// Boot flags with PXE selected.
		return []byte{0x01, 0x05, 0x80, bmc.BootDevicePXEBits, 0x00, 0x00}, ccSuccess
	},
	{bmc.NetFnApp, bmc.CmdGetDeviceID}: func(_ []byte) ([]byte, byte) {
		// Device ID response: 12 bytes, Supermicro manufacturer ID.
		resp := make([]byte, 12)
		resp[0] = 0x20  // Device ID
		resp[1] = 0x01  // Device revision
		resp[2] = 0x02  // Firmware major (2)
		resp[3] = 0x45  // Firmware minor (0x45 = BCD 45)
		resp[4] = 0x02  // IPMI version 2.0
		resp[5] = 0x00  // Additional device support
		resp[6] = 0x57  // Manufacturer ID byte 0 (Supermicro = 0x003757)
		resp[7] = 0x37  // Manufacturer ID byte 1
		resp[8] = 0x00  // Manufacturer ID byte 2
		resp[9] = 0x00  // Product ID byte 0
		resp[10] = 0x00 // Product ID byte 1
		resp[11] = 0x00 // Aux firmware rev
		return resp, ccSuccess
	},
}

// dispatchIPMI looks up the handler for (netfn, cmd) in the instance
// handlers first, then falls back to the package-level static handlers.
// Returns response data, completion code, and whether a handler was found.
func (s *Simulator) dispatchIPMI(netfn, cmd byte, ipmiPayload []byte) ([]byte, byte, bool) {
	key := ipmiKey{netfn: netfn, cmd: cmd}

	// Instance handlers take precedence (user management, etc.).
	if h, ok := s.handlers[key]; ok {
		data, cc := h(ipmiPayload)
		return data, cc, true
	}

	// Fall back to stateless package-level handlers.
	if h, ok := staticHandlers[key]; ok {
		data, cc := h(ipmiPayload)
		return data, cc, true
	}

	return nil, 0, false
}
