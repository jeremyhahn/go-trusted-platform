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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// RMCP header constants per IPMI 2.0 spec section 13.1.
const (
	rmcpVersion  = 0x06
	rmcpReserved = 0x00
	rmcpSeqNum   = 0xFF // No RMCP ACK
	rmcpClassIPMI = 0x07
)

// IPMI 2.0 authentication type and payload type constants.
const (
	authTypeRMCPPlus = 0x06

	// Payload types per Table 13-16.
	payloadTypeIPMI             = 0x00
	payloadTypeSOL              = 0x01
	payloadTypeOpenSessionReq   = 0x10
	payloadTypeOpenSessionResp  = 0x11
	payloadTypeRAKP1            = 0x12
	payloadTypeRAKP2            = 0x13
	payloadTypeRAKP3            = 0x14
	payloadTypeRAKP4            = 0x15
)

// Authentication algorithm numbers per Table 13-17.
const (
	authAlgoNone         = 0x00
	authAlgoHMACSHA1     = 0x01
	authAlgoHMACMD5      = 0x02
	authAlgoHMACSHA256   = 0x03
)

// Integrity algorithm numbers per Table 13-18.
const (
	integrityAlgoNone           = 0x00
	integrityAlgoHMACSHA1_96    = 0x01
	integrityAlgoHMACMD5_128    = 0x02
	integrityAlgoHMACSHA256_128 = 0x04
)

// Confidentiality algorithm numbers per Table 13-19.
const (
	cryptoAlgoNone      = 0x00
	cryptoAlgoAESCBC128 = 0x01
)

// IPMI privilege levels.
const (
	privilegeCallback      = 0x01
	privilegeUser          = 0x02
	privilegeOperator      = 0x03
	privilegeAdministrator = 0x04
)

// IPMI network function codes.
const (
	netFnChassis      = 0x00
	netFnBridge       = 0x02
	netFnSensorEvent  = 0x04
	netFnApp          = 0x06
	netFnFirmware     = 0x08
	netFnStorage      = 0x0A
	netFnTransport    = 0x0C
)

// IPMI command codes.
const (
	cmdGetDeviceID          = 0x01
	cmdGetAuthCapabilities  = 0x38
	cmdSetSessionPrivilege  = 0x3B
	cmdCloseSession         = 0x3C
	cmdChassisStatus        = 0x01
	cmdChassisControl       = 0x02
	cmdGetSystemBootOptions = 0x09
	cmdSetSystemBootOptions = 0x08
	cmdGetSDRRepositoryInfo = 0x20
	cmdReserveSDRRepository = 0x22
	cmdGetSDR               = 0x23
	cmdGetSensorReading     = 0x2D
	cmdGetFRUInventoryArea  = 0x10
	cmdReadFRUData          = 0x11
)

// Chassis control codes per IPMI spec.
const (
	chassisControlPowerDown   = 0x00
	chassisControlPowerUp     = 0x01
	chassisControlPowerCycle  = 0x02
	chassisControlHardReset   = 0x03
	chassisControlDiagInterrupt = 0x04
	chassisControlSoftShutdown  = 0x05
)

// Boot device selector bits per IPMI spec Table 28-14.
const (
	bootDeviceNoneBits    = 0x00
	bootDevicePXEBits     = 0x04
	bootDeviceDiskBits    = 0x08
	bootDeviceCDROMBits   = 0x14
)

// Default UDP timeout for IPMI operations.
const defaultIPMITimeout = 5 * time.Second

// Maximum UDP receive buffer size.
const maxUDPRecvSize = 1024

// rmcpSession manages an IPMI 2.0 RMCP+ authenticated session with a BMC.
// The session handles the full RAKP handshake, key derivation, and
// encrypted/authenticated IPMI message exchange.
type rmcpSession struct {
	conn   net.Conn
	addr   string
	username string
	password string
	kg       []byte // KG encryption key (if configured on BMC); nil = use password as KG
	timeout  time.Duration

	// Session state
	clientSessionID uint32
	bmcSessionID    uint32
	clientSeqNum    atomic.Uint32
	bmcSeqNum       uint32

	// RAKP state
	clientRand [16]byte
	bmcRand    [16]byte
	bmcGUID    [16]byte
	sik        []byte // Session Integrity Key
	k1         []byte // Integrity key
	k2         []byte // Confidentiality key

	// Selected algorithms
	authAlgo      uint8
	integrityAlgo uint8
	cryptoAlgo    uint8

	// Requested privilege level
	privilege uint8

	closed atomic.Bool
	logger *slog.Logger
}

// newRMCPSession creates a new RMCP+ session for the given BMC configuration.
func newRMCPSession(config *Config, logger *slog.Logger) *rmcpSession {
	var kg []byte
	if config.EncryptionKey != "" {
		decoded, err := hex.DecodeString(config.EncryptionKey)
		if err == nil && len(decoded) > 0 {
			kg = decoded
		}
	}
	return &rmcpSession{
		addr:          config.Endpoint(),
		username:      config.Username,
		password:      config.Password,
		kg:            kg,
		timeout:       defaultIPMITimeout,
		authAlgo:      authAlgoHMACSHA256,
		integrityAlgo: integrityAlgoHMACSHA256_128,
		cryptoAlgo:    cryptoAlgoAESCBC128,
		privilege:     privilegeAdministrator,
		logger:        logger,
	}
}

// Open establishes an RMCP+ session with the BMC by performing the
// full RAKP (Remote Authenticated Key Exchange Protocol) handshake.
func (s *rmcpSession) Open(ctx context.Context) error {
	if s.closed.Load() {
		return ErrSessionClosed{}
	}

	conn, err := net.DialTimeout("udp", s.addr, s.timeout)
	if err != nil {
		return ErrConnectionFailed{Address: s.addr, Cause: err}
	}
	s.conn = conn

	// Pre-session: Get Channel Authentication Capabilities (IPMI 1.5 unauthenticated).
	// Required by some BMCs (Dell iDRAC) before accepting Open Session Request.
	if err := s.getChannelAuthCapabilities(); err != nil {
		s.logger.Debug("bmc: get auth capabilities failed (non-fatal)", "error", err)
		// Non-fatal — some BMCs don't require this step.
	}

	// Generate client session ID and random number.
	var sidBuf [4]byte
	if _, err := rand.Read(sidBuf[:]); err != nil {
		return ErrConnectionFailed{Address: s.addr, Cause: err}
	}
	s.clientSessionID = binary.LittleEndian.Uint32(sidBuf[:])

	if _, err := rand.Read(s.clientRand[:]); err != nil {
		return ErrConnectionFailed{Address: s.addr, Cause: err}
	}

	// Step 1-2: Open Session Request/Response.
	// Try cipher suite combinations in priority order. If the BMC rejects
	// (status 0x11), fall back to the next combination. This handles BMCs
	// that only support specific cipher suites (e.g., Supermicro = SHA1-only,
	// Dell iDRAC = SHA256-preferred).
	type cipherSuite struct {
		auth      uint8
		integrity uint8
		name      string
	}
	cipherSuites := []cipherSuite{
		{authAlgoHMACSHA256, integrityAlgoHMACSHA256_128, "SHA256"},
		{authAlgoHMACSHA1, integrityAlgoHMACSHA1_96, "SHA1"},
	}
	privilegeLevels := []uint8{privilegeAdministrator, privilegeOperator, privilegeUser}

	var openErr error
	opened := false
	for _, cs := range cipherSuites {
		if opened {
			break
		}
		for _, priv := range privilegeLevels {
			s.authAlgo = cs.auth
			s.integrityAlgo = cs.integrity
			s.privilege = priv

			// Re-generate session ID for each retry
			if _, err := rand.Read(sidBuf[:]); err != nil {
				s.conn.Close()
				return ErrConnectionFailed{Address: s.addr, Cause: err}
			}
			s.clientSessionID = binary.LittleEndian.Uint32(sidBuf[:])

			openErr = s.openSession(ctx)
			if openErr == nil {
				s.logger.Debug("bmc: open session succeeded",
					"cipher", cs.name, "privilege", priv)
				opened = true
				break
			}

			var rakpErr ErrRAKPAuthFailed
			if errors.As(openErr, &rakpErr) && rakpErr.Code == 0x11 {
				s.logger.Debug("bmc: open session rejected, trying next",
					"cipher", cs.name, "privilege", priv, "status", rakpErr.Code)
				continue
			}
			// Non-0x11 error — stop trying
			s.conn.Close()
			return openErr
		}
	}
	if !opened {
		s.conn.Close()
		return openErr
	}

	// Step 3-4: RAKP Message 1/2
	if err := s.rakpExchange12(ctx); err != nil {
		s.conn.Close()
		return err
	}
	s.logger.Debug("bmc: RAKP 1/2 complete")

	// Derive session keys from the RAKP exchange.
	if err := s.deriveKeys(); err != nil {
		s.conn.Close()
		return err
	}
	s.logger.Debug("bmc: keys derived",
		"sik_len", len(s.sik), "k1_len", len(s.k1), "k2_len", len(s.k2),
		"auth_algo", s.authAlgo, "integrity_algo", s.integrityAlgo,
		"sik_hex", fmt.Sprintf("%x", s.sik),
		"k1_hex", fmt.Sprintf("%x", s.k1),
		"k2_hex", fmt.Sprintf("%x", s.k2),
		"kg_used", len(s.kg) > 0)

	// Step 5-6: RAKP Message 3/4
	if err := s.rakpExchange34(ctx); err != nil {
		s.conn.Close()
		return err
	}
	s.logger.Debug("bmc: RAKP 3/4 complete, session established")

	// Set session privilege level.
	if err := s.setPrivilegeLevel(ctx); err != nil {
		s.conn.Close()
		return err
	}
	s.logger.Debug("bmc: privilege level set")

	return nil
}

// Close sends a Close Session command and releases the UDP connection.
func (s *rmcpSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.conn == nil {
		return nil
	}
	// Best-effort close session command. Ignore errors since we're closing.
	closeData := make([]byte, 4)
	binary.LittleEndian.PutUint32(closeData, s.bmcSessionID)
	_, _ = s.Send(netFnApp, cmdCloseSession, closeData)
	return s.conn.Close()
}

// Send sends an IPMI command over the encrypted RMCP+ session and returns
// the response data (excluding the completion code, which is checked).
func (s *rmcpSession) Send(netfn, cmd byte, data []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, ErrSessionClosed{}
	}

	// Build IPMI message body (inside the session wrapper).
	// rsAddr=0x20 (BMC), netFn/rsLUN, checksum, rqAddr=0x81, rqSeq/rqLUN, cmd, data, checksum
	ipmiMsg := buildIPMIMessage(netfn, cmd, data)

	// Wrap in RMCP+ session envelope.
	packet, err := s.wrapPayload(ipmiMsg)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("bmc: send", "netfn", fmt.Sprintf("0x%02x", netfn), "cmd", fmt.Sprintf("0x%02x", cmd),
		"packet_len", len(packet), "hex", fmt.Sprintf("%x", packet))

	// Send and receive.
	resp, err := s.sendRecv(packet)
	if err != nil {
		return nil, err
	}

	// Unwrap response.
	return s.unwrapResponse(resp, cmd, netfn)
}

// getChannelAuthCapabilities sends an IPMI 1.5 unauthenticated Get Channel
// Authentication Capabilities command. Some BMCs (Dell iDRAC) require this
// before accepting an RMCP+ Open Session Request.
func (s *rmcpSession) getChannelAuthCapabilities() error {
	// Build IPMI 1.5 unauthenticated packet.
	// RMCP header (4) + Auth type (1) + Seq (4) + Session ID (4) + Msg len (1) + IPMI msg
	ipmiMsg := []byte{
		0x20,       // rsAddr (BMC)
		0x18,       // netFn=App(0x06)<<2 | LUN=0
		0x00,       // header checksum (computed below)
		0x81,       // rqAddr (remote console)
		0x00,       // rqSeq
		0x38,       // command: Get Channel Auth Capabilities
		0x8e,       // data: channel 0x0e (current), IPMI 2.0 extended (bit 7)
		0x04,       // data: privilege level = administrator
		0x00,       // data checksum (computed below)
	}
	ipmiMsg[2] = ipmiChecksum(ipmiMsg[0:2])
	ipmiMsg[8] = ipmiChecksum(ipmiMsg[3:8])

	// Wrap in IPMI 1.5 unauthenticated packet.
	packet := make([]byte, 0, 14+len(ipmiMsg))
	packet = append(packet, rmcpVersion, rmcpReserved, rmcpSeqNum, rmcpClassIPMI) // RMCP header
	packet = append(packet, 0x00)                                                  // Auth type: None
	packet = append(packet, 0x00, 0x00, 0x00, 0x00)                               // Sequence: 0
	packet = append(packet, 0x00, 0x00, 0x00, 0x00)                               // Session ID: 0
	packet = append(packet, byte(len(ipmiMsg)))                                    // Message length
	packet = append(packet, ipmiMsg...)

	resp, err := s.sendRecv(packet)
	if err != nil {
		return err
	}

	// We don't need to parse the response — just confirm we got one.
	if len(resp) < 14 {
		return ErrPacketTooShort{Expected: 14, Actual: len(resp)}
	}

	s.logger.Debug("bmc: get auth capabilities succeeded", "respLen", len(resp))
	return nil
}

// openSession performs the Open Session Request/Response exchange (steps 1-2).
func (s *rmcpSession) openSession(_ context.Context) error {
	// Build Open Session Request.
	// Per Table 13-17: Open Session Request format.
	payload := make([]byte, 32)
	payload[0] = 0x00 // Message tag
	payload[1] = s.privilege // Requested maximum privilege level
	payload[2] = 0x00 // Reserved
	payload[3] = 0x00 // Reserved
	binary.LittleEndian.PutUint32(payload[4:8], s.clientSessionID)

	// Authentication algorithm payload (8 bytes).
	payload[8] = 0x00  // Payload type: authentication algorithm
	payload[9] = 0x00  // Reserved
	payload[10] = 0x00 // Reserved
	payload[11] = 0x08 // Payload length
	payload[12] = s.authAlgo
	// payload[13:16] reserved (zeros)

	// Integrity algorithm payload (8 bytes).
	payload[16] = 0x01 // Payload type: integrity algorithm
	payload[17] = 0x00 // Reserved
	payload[18] = 0x00 // Reserved
	payload[19] = 0x08 // Payload length
	payload[20] = s.integrityAlgo
	// payload[21:24] reserved (zeros)

	// Confidentiality algorithm payload (8 bytes).
	payload[24] = 0x02 // Payload type: confidentiality algorithm
	payload[25] = 0x00 // Reserved
	payload[26] = 0x00 // Reserved
	payload[27] = 0x08 // Payload length
	payload[28] = s.cryptoAlgo
	// payload[29:32] reserved (zeros)

	packet := buildRMCPPlusUnauthPacket(payloadTypeOpenSessionReq, 0, 0, payload)

	s.logger.Debug("bmc: open session request", "hex", fmt.Sprintf("%x", packet))

	resp, err := s.sendRecv(packet)
	if err != nil {
		return err
	}

	// Parse Open Session Response.
	respPayload, err := extractUnauthPayload(resp, payloadTypeOpenSessionResp)
	if err != nil {
		return err
	}

	// Check status code in the response — even short responses contain it at byte 1.
	if len(respPayload) >= 2 && respPayload[1] != 0x00 {
		statusCode := respPayload[1]
		reason := rakpStatusString(statusCode)
		return ErrRAKPAuthFailed{Stage: "open session", Code: statusCode, Reason: reason}
	}

	if len(respPayload) < 36 {
		return ErrPacketTooShort{Expected: 36, Actual: len(respPayload)}
	}

	statusCode := respPayload[1]
	if statusCode != 0x00 {
		return ErrRAKPAuthFailed{
			Stage:  "open session response",
			Code:   statusCode,
			Reason: rakpStatusString(statusCode),
		}
	}

	s.bmcSessionID = binary.LittleEndian.Uint32(respPayload[8:12])

	// Verify BMC selected our requested algorithms.
	bmcAuthAlgo := respPayload[16]
	bmcIntegAlgo := respPayload[24]
	bmcCryptoAlgo := respPayload[32]

	if bmcAuthAlgo != s.authAlgo {
		return ErrRAKPAuthFailed{
			Stage:  "open session response",
			Reason: "BMC selected different authentication algorithm",
		}
	}
	if bmcIntegAlgo != s.integrityAlgo {
		return ErrRAKPAuthFailed{
			Stage:  "open session response",
			Reason: "BMC selected different integrity algorithm",
		}
	}
	if bmcCryptoAlgo != s.cryptoAlgo {
		return ErrRAKPAuthFailed{
			Stage:  "open session response",
			Reason: "BMC selected different confidentiality algorithm",
		}
	}

	return nil
}

// rakpExchange12 performs RAKP Message 1/2 exchange (steps 3-4).
func (s *rmcpSession) rakpExchange12(_ context.Context) error {
	// Build RAKP Message 1.
	// Per Table 13-18: RAKP Message 1 format.
	userBytes := []byte(s.username)
	payloadLen := 28 + len(userBytes)
	payload := make([]byte, payloadLen)
	payload[0] = 0x00 // Message tag
	// payload[1:4] reserved (zeros)
	binary.LittleEndian.PutUint32(payload[4:8], s.bmcSessionID)
	copy(payload[8:24], s.clientRand[:])
	payload[24] = s.privilege // Requested maximum privilege level (role)
	payload[25] = 0x00        // Reserved
	payload[26] = 0x00        // Reserved
	payload[27] = byte(len(userBytes))
	if len(userBytes) > 0 {
		copy(payload[28:], userBytes)
	}

	packet := buildRMCPPlusUnauthPacket(payloadTypeRAKP1, 0, 0, payload)

	resp, err := s.sendRecv(packet)
	if err != nil {
		return err
	}

	// Parse RAKP Message 2.
	respPayload, err := extractUnauthPayload(resp, payloadTypeRAKP2)
	if err != nil {
		return err
	}

	if len(respPayload) < 40 {
		return ErrPacketTooShort{Expected: 40, Actual: len(respPayload)}
	}

	statusCode := respPayload[1]
	if statusCode != 0x00 {
		return ErrRAKPAuthFailed{
			Stage:  "RAKP message 2",
			Code:   statusCode,
			Reason: rakpStatusString(statusCode),
		}
	}

	// respPayload[4:8] = client session ID (should match ours)
	respClientSID := binary.LittleEndian.Uint32(respPayload[4:8])
	if respClientSID != s.clientSessionID {
		return ErrRAKPAuthFailed{
			Stage:  "RAKP message 2",
			Reason: "client session ID mismatch",
		}
	}

	copy(s.bmcRand[:], respPayload[8:24])
	copy(s.bmcGUID[:], respPayload[24:40])

	// Verify BMC's key exchange authentication code (HMAC).
	// The HMAC is computed over:
	//   clientSessionID(4) + bmcSessionID(4) + clientRand(16) + bmcRand(16) +
	//   bmcGUID(16) + roleM(1) + userNameLengthM(1) + userNameM(n)
	// using the password (KG) as the HMAC key.
	hmacData := make([]byte, 0, 58+len(userBytes))
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.clientSessionID)
	hmacData = append(hmacData, sidBuf...)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	hmacData = append(hmacData, sidBuf...)
	hmacData = append(hmacData, s.clientRand[:]...)
	hmacData = append(hmacData, s.bmcRand[:]...)
	hmacData = append(hmacData, s.bmcGUID[:]...)
	hmacData = append(hmacData, s.privilege)
	hmacData = append(hmacData, byte(len(userBytes)))
	hmacData = append(hmacData, userBytes...)

	expectedMAC := s.computeAuthHMAC([]byte(s.password), hmacData)

	// The auth code follows the fixed fields in the response.
	authCodeOffset := 40
	authCodeLen := s.authHMACLen()
	if len(respPayload) < authCodeOffset+authCodeLen {
		return ErrRAKPAuthFailed{
			Stage:  "RAKP message 2",
			Reason: "response too short for auth code",
		}
	}

	receivedMAC := respPayload[authCodeOffset : authCodeOffset+authCodeLen]
	if !hmac.Equal(expectedMAC, receivedMAC) {
		return ErrRAKPAuthFailed{
			Stage:  "RAKP message 2",
			Reason: "BMC authentication code verification failed",
		}
	}

	return nil
}

// rakpExchange34 performs RAKP Message 3/4 exchange (steps 5-6).
func (s *rmcpSession) rakpExchange34(_ context.Context) error {
	// Build RAKP Message 3.
	// HMAC is computed over:
	//   bmcRand(16) + clientSessionID(4) + roleM(1) + userNameLengthM(1) + userNameM(n)
	// using the password as key.
	userBytes := []byte(s.username)

	hmacData := make([]byte, 0, 22+len(userBytes))
	hmacData = append(hmacData, s.bmcRand[:]...)
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.clientSessionID)
	hmacData = append(hmacData, sidBuf...)
	hmacData = append(hmacData, s.privilege)
	hmacData = append(hmacData, byte(len(userBytes)))
	hmacData = append(hmacData, userBytes...)

	authCode := s.computeAuthHMAC([]byte(s.password), hmacData)

	payloadLen := 8 + len(authCode)
	payload := make([]byte, payloadLen)
	payload[0] = 0x00 // Message tag
	payload[1] = 0x00 // Status code (no error)
	// payload[2:4] reserved
	binary.LittleEndian.PutUint32(payload[4:8], s.bmcSessionID)
	copy(payload[8:], authCode)

	packet := buildRMCPPlusUnauthPacket(payloadTypeRAKP3, 0, 0, payload)

	resp, err := s.sendRecv(packet)
	if err != nil {
		return err
	}

	// Parse RAKP Message 4.
	respPayload, err := extractUnauthPayload(resp, payloadTypeRAKP4)
	if err != nil {
		return err
	}

	if len(respPayload) < 8 {
		return ErrPacketTooShort{Expected: 8, Actual: len(respPayload)}
	}

	statusCode := respPayload[1]
	if statusCode != 0x00 {
		return ErrRAKPAuthFailed{
			Stage:  "RAKP message 4",
			Code:   statusCode,
			Reason: rakpStatusString(statusCode),
		}
	}

	// Verify the integrity check value in RAKP Message 4.
	// HMAC(SIK, clientRand(16) + bmcSessionID(4) + bmcGUID(16))
	integrityData := make([]byte, 0, 36)
	integrityData = append(integrityData, s.clientRand[:]...)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	integrityData = append(integrityData, sidBuf...)
	integrityData = append(integrityData, s.bmcGUID[:]...)

	expectedICV := s.computeAuthHMAC(s.sik, integrityData)

	// RAKP4 ICV is truncated per the integrity algorithm, not the full auth HMAC.
	icvOffset := 8
	icvLen := s.integrityHMACTruncLen()
	if icvLen == 0 {
		icvLen = s.authHMACLen() // Fallback for no integrity algorithm
	}
	truncatedExpected := expectedICV
	if len(truncatedExpected) > icvLen {
		truncatedExpected = truncatedExpected[:icvLen]
	}

	if len(respPayload) >= icvOffset+icvLen {
		receivedICV := respPayload[icvOffset : icvOffset+icvLen]
		s.logger.Debug("bmc: RAKP4 ICV verification",
			"expected", fmt.Sprintf("%x", truncatedExpected),
			"received", fmt.Sprintf("%x", receivedICV),
			"match", hmac.Equal(truncatedExpected, receivedICV))
		if !hmac.Equal(truncatedExpected, receivedICV) {
			return ErrRAKPAuthFailed{
				Stage:  "RAKP message 4",
				Reason: "integrity check value verification failed",
			}
		}
	} else {
		s.logger.Debug("bmc: RAKP4 ICV too short to verify",
			"payload_len", len(respPayload), "needed", icvOffset+icvLen)
	}

	return nil
}

// deriveKeys derives the Session Integrity Key (SIK), K1, and K2
// from the RAKP exchange parameters.
func (s *rmcpSession) deriveKeys() error {
	userBytes := []byte(s.username)

	// SIK = HMAC(KG, Rm || Rc || RoleM || ULengthM || UserNameM)
	// KG is the encryption key configured on the BMC. When not set, the
	// user password is used as KG (per IPMI 2.0 spec section 13.31).
	sikData := make([]byte, 0, 34+len(userBytes))
	sikData = append(sikData, s.clientRand[:]...)
	sikData = append(sikData, s.bmcRand[:]...)
	sikData = append(sikData, s.privilege)
	sikData = append(sikData, byte(len(userBytes)))
	sikData = append(sikData, userBytes...)

	kgKey := []byte(s.password)
	if len(s.kg) > 0 {
		kgKey = s.kg
	}
	s.sik = s.computeAuthHMAC(kgKey, sikData)

	// K1 = HMAC(SIK, 0x01 * 20) -- for integrity
	k1Input := make([]byte, 20)
	for i := range k1Input {
		k1Input[i] = 0x01
	}
	s.k1 = s.computeAuthHMAC(s.sik, k1Input)

	// K2 = HMAC(SIK, 0x02 * 20) -- for confidentiality
	k2Input := make([]byte, 20)
	for i := range k2Input {
		k2Input[i] = 0x02
	}
	s.k2 = s.computeAuthHMAC(s.sik, k2Input)

	return nil
}

// setPrivilegeLevel activates the requested privilege level on the session.
func (s *rmcpSession) setPrivilegeLevel(_ context.Context) error {
	s.logger.Debug("bmc: sending set privilege level",
		"privilege", s.privilege,
		"bmcSessionID", fmt.Sprintf("%08x", s.bmcSessionID),
		"clientSessionID", fmt.Sprintf("%08x", s.clientSessionID))
	resp, err := s.Send(netFnApp, cmdSetSessionPrivilege, []byte{s.privilege})
	if err != nil {
		return ErrRAKPAuthFailed{Stage: "set privilege level", Reason: err.Error()}
	}
	if len(resp) < 1 {
		return ErrRAKPAuthFailed{Stage: "set privilege level", Reason: "empty response"}
	}
	return nil
}

// wrapPayload wraps an IPMI message in an RMCP+ session envelope with
// encryption and integrity as negotiated.
func (s *rmcpSession) wrapPayload(ipmiMsg []byte) ([]byte, error) {
	seqNum := s.clientSeqNum.Add(1)

	var payload []byte
	var payloadType byte = payloadTypeIPMI
	confidential := s.cryptoAlgo != cryptoAlgoNone

	if confidential {
		encrypted, err := s.encryptPayload(ipmiMsg)
		if err != nil {
			return nil, err
		}
		payload = encrypted
		payloadType |= 0x80 // Set encrypted bit
	} else {
		payload = ipmiMsg
	}

	if s.integrityAlgo != integrityAlgoNone {
		payloadType |= 0x40 // Set authenticated bit
	}

	// Build RMCP+ session header.
	// RMCP header (4) + auth type (1) + payload type (1) +
	// session ID (4) + sequence (4) + payload length (2) +
	// payload + integrity pad + auth code
	headerLen := 4 + 1 + 1 + 4 + 4 + 2
	packetLen := headerLen + len(payload)

	// Calculate integrity padding.
	var integrityPad []byte
	var authCode []byte
	if s.integrityAlgo != integrityAlgoNone {
		// Pad so that (auth_type through next_header) is a multiple of 4 bytes.
		// The integrity data is: auth_type(1) + payload_type(1) + session_id(4) +
		// seq(4) + payload_len(2) + payload(n) + pad(p) + pad_length(1) + next_header(1).
		// We need: (12 + len(payload) + padLen + 2) % 4 == 0
		dataLen := 1 + 1 + 4 + 4 + 2 + len(payload) + 2 // +2 for pad_length and next_header
		padLen := (4 - (dataLen % 4)) % 4
		integrityPad = make([]byte, padLen+2) // pad bytes (0xFF) + pad length + next header
		for i := 0; i < padLen; i++ {
			integrityPad[i] = 0xFF // Per IPMI spec, pad bytes are 0xFF
		}
		integrityPad[padLen] = byte(padLen)
		integrityPad[padLen+1] = 0x07 // Next header = IPMI
		packetLen += len(integrityPad)

		// Auth code will be appended after we compute integrity.
		authCodeLen := s.integrityHMACTruncLen()
		packetLen += authCodeLen
	}

	packet := make([]byte, 0, packetLen)

	// RMCP header.
	packet = append(packet, rmcpVersion, rmcpReserved, rmcpSeqNum, rmcpClassIPMI)

	// IPMI 2.0 session header.
	packet = append(packet, authTypeRMCPPlus)
	packet = append(packet, payloadType)

	// Per IPMI 2.0 spec Table 13-8: The Session ID in the RMCP+ session
	// header for messages from the remote console to the BMC is the
	// "Managed System Session ID" (the BMC's session ID from Open Session Response).
	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	packet = append(packet, sidBuf...)

	seqBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBuf, seqNum)
	packet = append(packet, seqBuf...)

	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(payload)))
	packet = append(packet, lenBuf...)

	// Payload.
	packet = append(packet, payload...)

	// Integrity.
	if s.integrityAlgo != integrityAlgoNone {
		packet = append(packet, integrityPad...)

		// Compute HMAC over everything from auth type to end of integrity pad.
		authCode = s.computeIntegrity(packet[4:]) // Skip RMCP header
		packet = append(packet, authCode...)
	}

	return packet, nil
}

// unwrapResponse unwraps an RMCP+ response packet, verifying integrity and
// decrypting the payload.
func (s *rmcpSession) unwrapResponse(resp []byte, cmd, netfn byte) ([]byte, error) {
	if len(resp) < 16 {
		return nil, ErrPacketTooShort{Expected: 16, Actual: len(resp)}
	}

	// Verify RMCP header.
	if resp[0] != rmcpVersion || resp[3] != rmcpClassIPMI {
		return nil, ErrPacketTooShort{Expected: 16, Actual: len(resp)}
	}

	payloadType := resp[5]
	isEncrypted := payloadType&0x80 != 0
	isAuthenticated := payloadType&0x40 != 0

	// Session ID at [6:10], sequence at [10:14]
	payloadLen := binary.LittleEndian.Uint16(resp[14:16])
	payloadStart := 16
	payloadEnd := payloadStart + int(payloadLen)

	if payloadEnd > len(resp) {
		return nil, ErrPacketTooShort{Expected: payloadEnd, Actual: len(resp)}
	}

	// Verify integrity if authenticated.
	if isAuthenticated && s.integrityAlgo != integrityAlgoNone {
		if err := s.verifyResponseIntegrity(resp, payloadEnd); err != nil {
			return nil, err
		}
	}

	payload := resp[payloadStart:payloadEnd]

	// Decrypt if encrypted.
	if isEncrypted && s.cryptoAlgo != cryptoAlgoNone {
		decrypted, err := s.decryptPayload(payload)
		if err != nil {
			return nil, err
		}
		payload = decrypted
	}

	// Parse the IPMI response message.
	// Minimum: rsAddr(1) + netFn/rsLUN(1) + checksum(1) + rqAddr(1) +
	//          rqSeq/rqLUN(1) + cmd(1) + completionCode(1) + checksum(1) = 8
	if len(payload) < 8 {
		return nil, ErrPacketTooShort{Expected: 8, Actual: len(payload)}
	}

	completionCode := payload[6]
	if completionCode != 0x00 {
		return nil, ErrCompletionCode{
			Code:    completionCode,
			Command: cmd,
			NetFn:   netfn,
		}
	}

	// Return data bytes (between completion code and trailing checksum).
	if len(payload) > 8 {
		return payload[7 : len(payload)-1], nil
	}
	return nil, nil
}

// verifyResponseIntegrity verifies the integrity HMAC on a received response.
func (s *rmcpSession) verifyResponseIntegrity(resp []byte, payloadEnd int) error {
	truncLen := s.integrityHMACTruncLen()

	// Find integrity data: after payload there is pad + padLen(1) + nextHeader(1) + authCode
	// We need to find the pad boundary.
	remaining := resp[payloadEnd:]
	if len(remaining) < 2+truncLen {
		return ErrIntegrityCheckFailed{}
	}

	// The auth code is at the end.
	authCodeStart := len(resp) - truncLen
	integrityEnd := authCodeStart

	// Compute expected HMAC over auth type through end of integrity pad.
	expectedMAC := s.computeIntegrity(resp[4:integrityEnd])

	receivedMAC := resp[authCodeStart:]
	if !hmac.Equal(expectedMAC, receivedMAC) {
		return ErrIntegrityCheckFailed{}
	}

	return nil
}

// encryptPayload encrypts an IPMI message payload using AES-CBC-128.
// Per IPMI 2.0 spec: IV (16 bytes) prepended, IPMI-spec padding appended.
func (s *rmcpSession) encryptPayload(data []byte) ([]byte, error) {
	key := s.k2[:16] // AES-128 uses first 16 bytes of K2.

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncryptFailed{Reason: err.Error()}
	}

	// IPMI confidentiality padding:
	// Pad so that (data + pad + 1 byte padLength) is a multiple of 16 bytes.
	// Pad bytes are 0x01, 0x02, 0x03, ... up to 0x0F.
	unpadded := len(data) + 1 // +1 for the pad length byte
	padLen := (aes.BlockSize - (unpadded % aes.BlockSize)) % aes.BlockSize
	padded := make([]byte, len(data)+padLen+1)
	copy(padded, data)
	for i := 0; i < padLen; i++ {
		padded[len(data)+i] = byte(i + 1)
	}
	padded[len(padded)-1] = byte(padLen)

	// Generate random IV.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, ErrEncryptFailed{Reason: err.Error()}
	}

	// Encrypt.
	cbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	cbc.CryptBlocks(ciphertext, padded)

	// Output: IV + ciphertext
	result := make([]byte, aes.BlockSize+len(ciphertext))
	copy(result, iv)
	copy(result[aes.BlockSize:], ciphertext)

	return result, nil
}

// decryptPayload decrypts an AES-CBC-128 encrypted IPMI payload.
func (s *rmcpSession) decryptPayload(data []byte) ([]byte, error) {
	if len(data) < 2*aes.BlockSize {
		return nil, ErrDecryptFailed{Reason: "encrypted payload too short"}
	}

	key := s.k2[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptFailed{Reason: err.Error()}
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptFailed{Reason: "ciphertext length not a multiple of block size"}
	}

	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	// Remove IPMI confidentiality padding.
	if len(plaintext) == 0 {
		return nil, ErrDecryptFailed{Reason: "empty plaintext after decryption"}
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen >= len(plaintext) {
		return nil, ErrDecryptFailed{Reason: "invalid padding length"}
	}

	return plaintext[:len(plaintext)-padLen-1], nil
}

// computeAuthHMAC computes an HMAC using the session's authentication algorithm.
func (s *rmcpSession) computeAuthHMAC(key, data []byte) []byte {
	var h func() hash.Hash
	switch s.authAlgo {
	case authAlgoHMACSHA256:
		h = sha256.New
	case authAlgoHMACMD5:
		h = md5.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// authHMACLen returns the full HMAC output length for the authentication algorithm.
func (s *rmcpSession) authHMACLen() int {
	switch s.authAlgo {
	case authAlgoHMACSHA256:
		return sha256.Size
	case authAlgoHMACMD5:
		return md5.Size
	default:
		return sha1.Size
	}
}

// computeIntegrity computes a truncated integrity HMAC over the given data.
func (s *rmcpSession) computeIntegrity(data []byte) []byte {
	var h func() hash.Hash
	var truncLen int
	switch s.integrityAlgo {
	case integrityAlgoHMACSHA256_128:
		h = sha256.New
		truncLen = 16
	case integrityAlgoHMACMD5_128:
		h = md5.New
		truncLen = 16
	default: // HMAC-SHA1-96
		h = sha1.New
		truncLen = 12
	}
	mac := hmac.New(h, s.k1)
	mac.Write(data)
	full := mac.Sum(nil)
	return full[:truncLen]
}

// integrityHMACTruncLen returns the truncated HMAC length for integrity.
func (s *rmcpSession) integrityHMACTruncLen() int {
	switch s.integrityAlgo {
	case integrityAlgoHMACSHA256_128:
		return 16
	default:
		return 12
	}
}

// sendRecv sends a packet and reads the response with the configured timeout.
func (s *rmcpSession) sendRecv(packet []byte) ([]byte, error) {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, ErrUDPSend{Cause: err}
	}
	if _, err := s.conn.Write(packet); err != nil {
		return nil, ErrUDPSend{Cause: err}
	}

	if err := s.conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, ErrUDPRecv{Cause: err}
	}
	buf := make([]byte, maxUDPRecvSize)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, ErrUDPRecv{Cause: err}
	}

	s.logger.Debug("bmc: recv", "bytes", n, "hex", fmt.Sprintf("%x", buf[:n]))

	return buf[:n], nil
}

// buildRMCPPlusUnauthPacket builds an unauthenticated RMCP+ packet for
// session setup messages (Open Session, RAKP).
func buildRMCPPlusUnauthPacket(payloadType byte, sessionID, seqNum uint32, payload []byte) []byte {
	packet := make([]byte, 0, 16+len(payload))

	// RMCP header.
	packet = append(packet, rmcpVersion, rmcpReserved, rmcpSeqNum, rmcpClassIPMI)

	// IPMI 2.0 session header (unauthenticated).
	packet = append(packet, authTypeRMCPPlus)
	packet = append(packet, payloadType) // No encrypt/auth bits for setup messages

	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, sessionID)
	packet = append(packet, sidBuf...)

	seqBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBuf, seqNum)
	packet = append(packet, seqBuf...)

	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(payload)))
	packet = append(packet, lenBuf...)

	packet = append(packet, payload...)

	return packet
}

// extractUnauthPayload extracts the payload from an unauthenticated RMCP+ response.
func extractUnauthPayload(resp []byte, expectedPayloadType byte) ([]byte, error) {
	if len(resp) < 16 {
		return nil, ErrPacketTooShort{Expected: 16, Actual: len(resp)}
	}

	if resp[0] != rmcpVersion {
		return nil, ErrRAKPAuthFailed{Reason: "invalid RMCP version in response"}
	}
	if resp[3] != rmcpClassIPMI {
		return nil, ErrRAKPAuthFailed{Reason: "invalid RMCP class in response"}
	}

	payloadType := resp[5] & 0x3F // Mask off encrypt/auth bits
	if payloadType != expectedPayloadType {
		return nil, ErrRAKPAuthFailed{
			Reason: "unexpected payload type in response",
		}
	}

	payloadLen := binary.LittleEndian.Uint16(resp[14:16])
	payloadStart := 16
	payloadEnd := payloadStart + int(payloadLen)

	if payloadEnd > len(resp) {
		return nil, ErrPacketTooShort{Expected: payloadEnd, Actual: len(resp)}
	}

	return resp[payloadStart:payloadEnd], nil
}

// buildIPMIMessage constructs a standard IPMI message for encapsulation
// inside an RMCP+ session payload.
func buildIPMIMessage(netfn, cmd byte, data []byte) []byte {
	// IPMI message format (inside session):
	// rsAddr(1) + netFn/rsLUN(1) + headerChecksum(1) +
	// rqAddr(1) + rqSeq/rqLUN(1) + cmd(1) + data(n) + dataChecksum(1)
	msgLen := 7 + len(data)
	msg := make([]byte, msgLen)

	msg[0] = 0x20           // rsAddr: BMC slave address
	msg[1] = (netfn << 2)   // netFn shifted left 2 + rsLUN=0
	msg[2] = ipmiChecksum(msg[0:2])

	msg[3] = 0x81 // rqAddr: software ID (remote console)
	msg[4] = 0x00 // rqSeq/rqLUN
	msg[5] = cmd

	if len(data) > 0 {
		copy(msg[6:], data)
	}

	msg[msgLen-1] = ipmiChecksum(msg[3 : msgLen-1])

	return msg
}

// ipmiChecksum computes the IPMI checksum (2's complement of the sum).
func ipmiChecksum(data []byte) byte {
	var sum byte
	for _, b := range data {
		sum += b
	}
	return -sum
}
