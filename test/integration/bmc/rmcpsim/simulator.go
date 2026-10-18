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
// The simulator answers the IPMI 1.5 session-less Get Channel
// Authentication Capabilities request a console sends first, handles the
// RAKP handshake (HMAC-SHA1 / HMAC-SHA256), AES-CBC-128 confidentiality,
// and responds to a small set of IPMI
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
//   - Multiple concurrent sessions are supported. Each Open Session
//     request creates an independent session with a unique BMC session
//     ID so that concurrent or sequential sessions do not interfere
//     with each other's RAKP key material.
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

// authTypeNone is the IPMI 1.5 session header's auth type for an
// unauthenticated, session-less message (IPMI v2.0 §13.6).
const authTypeNone = 0x00

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

// session holds per-session RAKP handshake state for a single IPMI
// 2.0 RMCP+ session. Fields are populated progressively as the
// Open Session → RAKP1 → RAKP3 handshake proceeds. authAlgo is
// written once during Open Session and is thereafter read-only; all
// other mutable fields are protected by Simulator.sessMu.
type session struct {
	bmcSessionID    uint32
	clientSessionID uint32
	clientRand      [16]byte
	authAlgo        uint8
	sik             []byte
	k1              []byte
	k2              []byte
}

// Simulator is a minimal IPMI 2.0 RMCP+ BMC simulator bound to a UDP
// address. Zero value is not usable; construct via New.
type Simulator struct {
	logger *slog.Logger
	addr   string

	credMu   sync.RWMutex
	username string
	password string

	guid [16]byte

	// sessionCounter generates unique, non-zero BMC session IDs.
	// Incremented atomically; first session gets ID 1.
	sessionCounter atomic.Uint32

	// running guards Start/Stop idempotency.
	running atomic.Bool
	conn    *net.UDPConn
	listen  *net.UDPAddr
	done    chan struct{}

	// sessMu guards sessions.
	sessMu   sync.Mutex
	sessions map[uint32]*session

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
		logger:   logger,
		addr:     opts.Addr,
		username: opts.Username,
		password: opts.Password,
		sessions: make(map[uint32]*session),
		handlers: make(map[ipmiKey]ipmiHandler),
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

// passwordSnapshot snapshots the password under the credential lock.
func (s *Simulator) passwordSnapshot() string {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return s.password
}

// hashFuncFor returns the hash constructor for the session's negotiated
// auth algorithm. authAlgo is written once during Open Session and is
// thereafter read-only, so this may be called without holding sessMu.
func hashFuncFor(sess *session) func() hash.Hash {
	if sess.authAlgo == bmc.AuthAlgoHMACSHA256 {
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
	if packet[4] != bmc.AuthTypeRMCPPlus {
		return s.handleSessionless(packet)
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

// handleSessionless answers the IPMI 1.5 session-less Get Channel
// Authentication Capabilities request (IPMI v2.0 §22.13) a console sends
// before it opens an RMCP+ session. A BMC answers it, so a console does not
// wait out its read timeout on every session open. Any other packet outside
// the RMCP+ format is dropped.
func (s *Simulator) handleSessionless(packet []byte) []byte {
	// IPMI 1.5 session header (IPMI v2.0 §13.6): auth type, sequence (4),
	// session ID (4), message length; only the unauthenticated form carries
	// no auth code.
	if packet[4] != authTypeNone {
		return nil
	}
	msgLen := int(packet[13])
	if msgLen < 7 || len(packet) < 14+msgLen {
		return nil
	}
	msg := packet[14 : 14+msgLen]
	if msg[2] != bmc.IPMIChecksum(msg[0:2]) || msg[msgLen-1] != bmc.IPMIChecksum(msg[3:msgLen-1]) {
		return nil
	}
	netfn := msg[1] >> 2
	cmd := msg[5]
	if netfn != bmc.NetFnApp || cmd != bmc.CmdGetAuthCapabilities {
		s.logger.Debug("rmcpsim: unhandled session-less command", "netfn", netfn, "cmd", cmd)
		return nil
	}

	respData := []byte{
		0x01,             // channel number
		0x80,             // IPMI v2.0 extended capabilities available
		0x04,             // non-null usernames enabled
		0x02,             // channel supports IPMI v2.0 connections
		0x00, 0x00, 0x00, // OEM ID
		0x00, // OEM auxiliary data
	}
	ipmiResp := make([]byte, 8+len(respData))
	ipmiResp[0] = msg[3] // rqAddr
	ipmiResp[1] = (netfn + 1) << 2
	ipmiResp[2] = bmc.IPMIChecksum(ipmiResp[0:2])
	ipmiResp[3] = msg[0] // rsAddr
	ipmiResp[4] = msg[4] // rqSeq
	ipmiResp[5] = cmd
	ipmiResp[6] = 0x00 // completion code
	copy(ipmiResp[7:], respData)
	ipmiResp[len(ipmiResp)-1] = bmc.IPMIChecksum(ipmiResp[3 : len(ipmiResp)-1])

	resp := make([]byte, 0, 14+len(ipmiResp))
	resp = append(resp, packet[0:4]...)         // RMCP header
	resp = append(resp, authTypeNone)           // auth type
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // sequence
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // session ID
	resp = append(resp, byte(len(ipmiResp)))
	return append(resp, ipmiResp...)
}

// handleOpenSession handles Open Session Request and returns Open
// Session Response. Each call creates a new session entry with a
// unique BMC session ID so that concurrent sessions do not share
// crypto state.
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

	clientSessionID := binary.LittleEndian.Uint32(payload[4:8])
	authAlgo := payload[12]
	integAlgo := payload[20]
	cryptoAlgo := payload[28]

	// Assign a unique, non-zero BMC session ID for this session.
	bmcSessionID := s.sessionCounter.Add(1)

	sess := &session{
		bmcSessionID:    bmcSessionID,
		clientSessionID: clientSessionID,
		authAlgo:        authAlgo,
	}

	s.sessMu.Lock()
	s.sessions[bmcSessionID] = sess
	s.sessMu.Unlock()

	resp := make([]byte, 36)
	resp[0] = 0x00       // Tag
	resp[1] = 0x00       // Status: no errors
	resp[2] = payload[1] // Max privilege
	resp[3] = 0x00
	binary.LittleEndian.PutUint32(resp[4:8], clientSessionID)
	binary.LittleEndian.PutUint32(resp[8:12], bmcSessionID)

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
// The RAKP1 payload carries the BMC session ID (payload[4:8]) so the
// simulator can look up the correct session and store its key material.
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

	bmcSessionID := binary.LittleEndian.Uint32(payload[4:8])

	s.sessMu.Lock()
	sess, ok := s.sessions[bmcSessionID]
	if !ok {
		s.sessMu.Unlock()
		s.logger.Debug("rmcpsim: RAKP1 unknown session", "bmcSessionID", bmcSessionID)
		return nil
	}
	copy(sess.clientRand[:], payload[8:24])
	// Snapshot immutable fields needed outside the lock.
	clientSessionID := sess.clientSessionID
	clientRand := sess.clientRand
	s.sessMu.Unlock()

	privilege := payload[24]

	var bmcRand [16]byte
	if _, err := rand.Read(bmcRand[:]); err != nil {
		s.logger.Debug("rmcpsim: rand", "err", err)
		return nil
	}

	password := s.passwordSnapshot()

	// authAlgo is set once in handleOpenSession and never modified;
	// safe to read without the lock.
	hf := hashFuncFor(sess)

	// HMAC(password, clientSID || bmcSID || clientRand || bmcRand || bmcGUID || role || userLen || username).
	hmacData := make([]byte, 0, 58+int(userLen))
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, clientSessionID)
	hmacData = append(hmacData, sidBuf...)
	binary.LittleEndian.PutUint32(sidBuf, bmcSessionID)
	hmacData = append(hmacData, sidBuf...)
	hmacData = append(hmacData, clientRand[:]...)
	hmacData = append(hmacData, bmcRand[:]...)
	hmacData = append(hmacData, s.guid[:]...)
	hmacData = append(hmacData, privilege)
	hmacData = append(hmacData, userLen)
	hmacData = append(hmacData, payload[28:28+userLen]...)

	mac := hmac.New(hf, []byte(password))
	mac.Write(hmacData)
	authCode := mac.Sum(nil)

	// Derive SIK for RAKP4.
	sikData := make([]byte, 0, 34+int(userLen))
	sikData = append(sikData, clientRand[:]...)
	sikData = append(sikData, bmcRand[:]...)
	sikData = append(sikData, privilege)
	sikData = append(sikData, userLen)
	sikData = append(sikData, payload[28:28+userLen]...)

	mac = hmac.New(hf, []byte(password))
	mac.Write(sikData)
	sik := mac.Sum(nil)

	// Derive K1.
	k1Input := make([]byte, 20)
	for i := range k1Input {
		k1Input[i] = 0x01
	}
	mac = hmac.New(hf, sik)
	mac.Write(k1Input)
	k1 := mac.Sum(nil)

	// Derive K2.
	k2Input := make([]byte, 20)
	for i := range k2Input {
		k2Input[i] = 0x02
	}
	mac = hmac.New(hf, sik)
	mac.Write(k2Input)
	k2 := mac.Sum(nil)

	s.sessMu.Lock()
	sess.sik = sik
	sess.k1 = k1
	sess.k2 = k2
	s.sessMu.Unlock()

	resp := make([]byte, 40+len(authCode))
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status
	binary.LittleEndian.PutUint32(resp[4:8], clientSessionID)
	copy(resp[8:24], bmcRand[:])
	copy(resp[24:40], s.guid[:])
	copy(resp[40:], authCode)

	return bmc.BuildRMCPPlusUnauthPacket(bmc.PayloadTypeRAKP2, 0, 0, resp)
}

// handleRAKP3 handles RAKP Message 3 and returns RAKP Message 4.
// The RAKP3 payload carries the BMC session ID (payload[4:8]) so the
// simulator can look up the correct session to compute the RAKP4 ICV.
func (s *Simulator) handleRAKP3(packet []byte) []byte {
	payload, err := bmc.ExtractUnauthPayload(packet, bmc.PayloadTypeRAKP3)
	if err != nil {
		s.logger.Debug("rmcpsim: extract RAKP3", "err", err)
		return nil
	}
	// RAKP3 body needs at least 8 bytes: tag(1) + status(1) + reserved(2) + bmcSID(4).
	if len(payload) < 8 {
		s.logger.Debug("rmcpsim: RAKP3 payload too short", "len", len(payload))
		return nil
	}

	statusCode := payload[1]
	if statusCode != 0x00 {
		s.logger.Debug("rmcpsim: RAKP3 bad status", "status", statusCode)
		return nil
	}

	bmcSessionID := binary.LittleEndian.Uint32(payload[4:8])

	s.sessMu.Lock()
	sess, ok := s.sessions[bmcSessionID]
	if !ok {
		s.sessMu.Unlock()
		s.logger.Debug("rmcpsim: RAKP3 unknown session", "bmcSessionID", bmcSessionID)
		return nil
	}
	// Snapshot mutable fields under the lock.
	clientSessionID := sess.clientSessionID
	clientRand := sess.clientRand
	sik := sess.sik
	s.sessMu.Unlock()

	// HMAC(SIK, clientRand || bmcSID || bmcGUID).
	icvData := make([]byte, 0, 36)
	icvData = append(icvData, clientRand[:]...)
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, bmcSessionID)
	icvData = append(icvData, sidBuf...)
	icvData = append(icvData, s.guid[:]...)

	// authAlgo is set once in handleOpenSession; safe to read without lock.
	mac := hmac.New(hashFuncFor(sess), sik)
	mac.Write(icvData)
	icv := mac.Sum(nil)

	resp := make([]byte, 8+len(icv))
	resp[0] = 0x00 // Tag
	resp[1] = 0x00 // Status
	binary.LittleEndian.PutUint32(resp[4:8], clientSessionID)
	copy(resp[8:], icv)

	return bmc.BuildRMCPPlusUnauthPacket(bmc.PayloadTypeRAKP4, 0, 0, resp)
}

// handleIPMI handles an authenticated IPMI command payload.
//
// Session lookup uses the BMC session ID embedded in the RMCP+ session
// header at packet[6:10]. Packets with an unrecognized session ID are
// dropped silently (returns nil). Recognized sessions with unhandled
// commands receive a 0xC1 "invalid/illegal command" completion code
// response so the client gets a fast error rather than a 5-second
// UDP timeout.
func (s *Simulator) handleIPMI(packet []byte, isEncrypted, isAuthenticated bool) []byte {
	if len(packet) < 16 {
		return nil
	}

	// RMCP+ session header: RMCP(4) + authType(1) + payloadType(1) +
	// sessionID(4) + seqNum(4) + payloadLen(2) = 16 bytes.
	// The session ID the client sends is the BMC session ID from Open
	// Session Response (the "managed system session ID" per IPMI spec
	// Table 13-8).
	bmcSessionID := binary.LittleEndian.Uint32(packet[6:10])

	s.sessMu.Lock()
	sess, ok := s.sessions[bmcSessionID]
	if !ok {
		s.sessMu.Unlock()
		if bmcSessionID != 0 {
			s.logger.Debug("rmcpsim: IPMI unknown session", "bmcSessionID", bmcSessionID)
		}
		return nil
	}
	k1 := sess.k1
	k2 := sess.k2
	authAlgo := sess.authAlgo
	clientSessionID := sess.clientSessionID
	s.sessMu.Unlock()

	payloadLen := binary.LittleEndian.Uint16(packet[14:16])
	payloadStart := 16
	payloadEnd := payloadStart + int(payloadLen)
	if payloadEnd > len(packet) {
		return nil
	}

	payload := packet[payloadStart:payloadEnd]

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

	respData, completionCode, handled := s.dispatchIPMI(netfn, cmd, payload)
	if !handled {
		s.logger.Debug("rmcpsim: unhandled IPMI command", "netfn", netfn, "cmd", cmd)
		// Return "invalid/illegal command" so the client gets a fast
		// ErrCompletionCode instead of a 5-second UDP timeout.
		completionCode = 0xC1
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

	// Remove session state on successful Close Session to keep the map tidy.
	if netfn == bmc.NetFnApp && cmd == bmc.CmdCloseSession && completionCode == ccSuccess {
		s.sessMu.Lock()
		delete(s.sessions, bmcSessionID)
		s.sessMu.Unlock()
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
	// Get SDR Repository Info: return 6-byte response with record count = 0.
	// ipmi.go readSDRRepository() short-circuits when recordCount == 0
	// (returns nil, nil immediately without issuing Reserve/Get SDR commands).
	// GetSensors therefore returns an empty slice cleanly — the test
	// tolerates 0 sensors so this makes GetSensors PASS.
	{bmc.NetFnStorage, bmc.CmdGetSDRRepositoryInfo}: func(_ []byte) ([]byte, byte) {
		// Per IPMI Table 33-3 SDR Repository Info Response:
		// byte[0] = SDR version (0x51 = 1.5), byte[1:3] = record count LE,
		// byte[3:5] = free space LE (0xFFFF = unspecified), byte[5] = timestamp.
		return []byte{0x51, 0x00, 0x00, 0xFF, 0xFF, 0x00}, ccSuccess
	},
	// Get FRU Inventory Area Info: return "command not supported".
	// readFRU receives ErrCompletionCode{0xD5} and returns an error.
	// GetSystemInfo treats readFRU failure as non-fatal (debug log + continue).
	// This gives a fast failure instead of the 5-second default IPMI timeout.
	{bmc.NetFnStorage, bmc.CmdGetFRUInventoryArea}: func(_ []byte) ([]byte, byte) {
		return nil, 0xD5 // Command not supported in present state
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
