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
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// IPMI command codes for SOL payload activation.
const (
	cmdActivatePayload   = 0x48
	cmdDeactivatePayload = 0x49
)

// SOL payload constants.
const (
	// solPayloadInstanceDefault is the IPMI 2.0 default SOL payload instance
	// (Table 24-2). Most BMCs route serial-console bytes to this instance.
	// A board whose BMC wires SOL to a second UART may route to instance
	// 0x02 instead. The activation site
	// accepts a per-call override so vendor quirks can supply the correct
	// instance from pkg/quirks.
	solPayloadInstanceDefault = 0x01
)

// SOL operation/status bits per IPMI 2.0 spec Table 15-3.
const (
	solStatusNACK            = 0x01
	solStatusRingDetect      = 0x02
	solStatusBreakDetect     = 0x04
	solStatusTransmitOverrun = 0x08
)

// SOL Activate Payload auxiliary data byte 2 bit definitions
// per IPMI 2.0 spec Table 24-2.
const (
	// solAuxHandshakeAssert sets bit 3 to assert CTS, DCD, and DSR on the
	// baseboard UART at SOL activation. Without this bit the serial device
	// (BIOS/OS) sees the modem-control signals low and will not transmit.
	solAuxHandshakeAssert = 0x08

	// solAuxAlertDefer sets bit 2 to defer shared serial alerts instead of
	// failing the activation when an alert is in progress.
	solAuxAlertDefer = 0x04
)

// solHeaderSize is the number of bytes in the SOL packet header
// (sequence, ack sequence, accepted char count, operation/status).
const solHeaderSize = 4

// SOLSession manages a Serial Over LAN session over an authenticated RMCP+
// session. It implements io.ReadWriteCloser for bidirectional character
// streaming with the BMC serial console.
type SOLSession struct {
	session          *rmcpSession
	logger           *slog.Logger
	seqNum           atomic.Uint32
	lastBMCSeqNum    atomic.Uint32
	lastBMCCharCount atomic.Uint32
	output           chan []byte
	done             chan struct{}
	// loopDone is closed when receiveLoop has returned. While the loop
	// runs it owns the socket's reads, so Deactivate waits on it before
	// sending Deactivate Payload — otherwise the loop could consume that
	// command's response. nil when no loop was started.
	loopDone chan struct{}
	active   atomic.Bool
	// payloadInstance is the IPMI 2.0 SOL payload instance this session
	// activated against. Stored so Deactivate sends the matching instance.
	payloadInstance byte
	// bytesReceived counts SOL data bytes the receive loop has emitted to
	// the output channel. Inspected by callers (e.g. the bmc console
	// CLI command) to detect a "session activated, no data ever arrived"
	// outcome — almost always a wrong-payload-instance symptom.
	bytesReceived atomic.Uint64
	// release, when set by the owning ipmiClient, returns the client's
	// lifecycle pin the console holds for as long as it is active. It
	// runs exactly once, from the first Deactivate.
	release     func()
	releaseOnce sync.Once
}

// releasePin returns the owning client's lifecycle pin, once.
func (sol *SOLSession) releasePin() {
	sol.releaseOnce.Do(func() {
		if sol.release != nil {
			sol.release()
		}
	})
}

// PayloadInstance returns the IPMI 2.0 SOL payload instance this session
// activated against (0x01 on every board measured so far; 0x02 where a
// BMC routes a second UART).
func (sol *SOLSession) PayloadInstance() byte {
	return sol.payloadInstance
}

// BytesReceived returns the number of SOL data bytes the BMC has streamed
// during the lifetime of this session. Zero after a successful Activate
// almost always indicates the payload instance does not match the UART
// the BMC routes serial-console output to.
func (sol *SOLSession) BytesReceived() uint64 {
	return sol.bytesReceived.Load()
}

// Compile-time interface checks.
var (
	_ io.Reader = (*SOLSession)(nil)
	_ io.Writer = (*SOLSession)(nil)
	_ io.Closer = (*SOLSession)(nil)
)

// ActivateSOL activates a SOL payload on the RMCP+ session and starts the
// background receive loop. The returned SOLSession implements io.ReadWriteCloser.
//
// Most BMCs route serial-console bytes to payload instance 0x01. Pass 0 to
// accept that default. A board whose BMC routes a second UART may use
// instance 0x02 — pkg/quirks supplies the correct instance via the
// SOLPayloadInstance field; callers should resolve the quirk and pass the
// resulting value here. Any value 0x01-0x0F is permitted per IPMI 2.0
// Table 24-2.
func (s *rmcpSession) ActivateSOL(ctx context.Context, payloadInstance byte) (*SOLSession, error) {
	if s.conn == nil || s.closed.Load() {
		return nil, ErrSessionClosed{}
	}

	// Default to instance 0x01 when the caller passes 0 (no preference).
	// This preserves prior behaviour for callers that don't yet consult
	// the quirk registry.
	if payloadInstance == 0 {
		payloadInstance = solPayloadInstanceDefault
	}

	// Build Activate Payload request data per IPMI 2.0 spec Table 24-2.
	// byte 0: payload type (0x01 = SOL)
	// byte 1: payload instance
	// byte 2-5: auxiliary data (encryption forced, authentication forced, etc.)
	activateData := make([]byte, 6)
	activateData[0] = payloadTypeSOL
	activateData[1] = payloadInstance

	// Auxiliary data byte 2 per IPMI 2.0 spec Table 24-2:
	//   bit 3: SOL startup handshake (0 = CTS/DCD/DSR deasserted, 1 = asserted)
	//   bit 2: shared serial alert behavior (0 = fail, 1 = defer to BMC)
	//   bit 1: test mode (0 = disabled)
	//   bit 0: authentication (0 = as negotiated in session)
	//
	// Bit 3 MUST be set to 1 so the BMC asserts CTS, DCD, and DSR on the
	// baseboard UART at activation time. Without these modem-control signals
	// the BIOS/OS serial console sees the link as "not ready" and will not
	// transmit -- the SOL receive loop sees only NUL bytes or nothing at all.
	//
	// Bit 2 is set to 1 (defer) so the BMC does not immediately fail the
	// activation if a shared serial alert is in progress; it queues the
	// alert for later delivery instead. This matches ipmitool behavior.
	activateData[2] = solAuxHandshakeAssert | solAuxAlertDefer
	activateData[3] = 0x00
	activateData[4] = 0x00
	activateData[5] = 0x00

	resp, err := s.Send(netFnApp, cmdActivatePayload, activateData)
	if err != nil {
		return nil, ErrSOLActivateFailed{Cause: err}
	}

	// Response data per IPMI 2.0 spec Table 24-3:
	//   bytes 0-3 : auxiliary data
	//   bytes 4-5 : inbound payload size
	//   bytes 6-7 : outbound payload size
	//   bytes 8-9 : payload UDP port number   <-- CRITICAL
	//   bytes 10-11: payload VLAN number
	//
	// The "payload UDP port" tells us where the BMC will send SOL data
	// packets. On many BMCs (Supermicro X10/X11, some Dell, some HPE) this
	// is a DIFFERENT port from the RMCP+ session port (623). If we keep
	// listening on 623, every SOL data packet sent by the BMC arrives at
	// the wrong port and is dropped silently -- receiveLoop sees nothing.
	// ipmitool re-binds its socket to the new port; we must do the same.
	if len(resp) < 12 {
		return nil, ErrSOLActivateFailed{Cause: ErrPacketTooShort{Expected: 12, Actual: len(resp)}}
	}

	inboundSize := binary.LittleEndian.Uint16(resp[4:6])
	outboundSize := binary.LittleEndian.Uint16(resp[6:8])
	solUDPPort := binary.LittleEndian.Uint16(resp[8:10])

	s.logger.Info("bmc: SOL payload activated",
		"payload_instance", payloadInstance,
		"inbound_payload_size", inboundSize,
		"outbound_payload_size", outboundSize,
		"sol_udp_port", solUDPPort)

	// If the BMC advertised a non-zero SOL port and it differs from our
	// current session port, redial the UDP socket to that port. We use the
	// same remote IP, just a different port. The IPMI session sequence
	// numbers and crypto state remain valid because the session is keyed
	// by the BMC session ID inside the RMCP+ header, not by the UDP 5-tuple.
	if solUDPPort != 0 {
		if err := s.rebindForSOL(solUDPPort); err != nil {
			return nil, ErrSOLActivateFailed{Cause: err}
		}
	}

	sol := &SOLSession{
		session:         s,
		logger:          s.logger,
		output:          make(chan []byte, 64),
		done:            make(chan struct{}),
		loopDone:        make(chan struct{}),
		payloadInstance: payloadInstance,
	}
	sol.active.Store(true)

	// Start the background receive loop.
	go sol.receiveLoop()

	return sol, nil
}

// receiveLoop continuously reads RMCP+ messages from the UDP connection and
// demuxes SOL data packets into the output channel.
func (sol *SOLSession) receiveLoop() {
	defer close(sol.output)
	if sol.loopDone != nil {
		defer close(sol.loopDone)
	}

	for sol.active.Load() {
		data, payloadType, err := sol.session.receiveSOLMessage()
		if err != nil {
			if sol.active.Load() {
				sol.logger.Debug("bmc: SOL receive error", "error", err)
			}
			continue
		}

		// Only process SOL payload type messages.
		if payloadType != payloadTypeSOL {
			continue
		}

		// Parse SOL packet header.
		if len(data) < solHeaderSize {
			continue
		}

		// byte 0: packet sequence number (BMC -> console)
		// byte 1: packet ACK/NACK sequence number
		// byte 2: accepted character count
		// byte 3: operation/status
		// byte 4+: character data
		bmcSeqNum := data[0]
		charData := data[solHeaderSize:]

		// Track the BMC's sequence number and character count for ACK responses.
		// These are read atomically by Write() and sendACK() to populate ACK fields.
		if bmcSeqNum != 0 {
			sol.lastBMCSeqNum.Store(uint32(bmcSeqNum))
			sol.lastBMCCharCount.Store(uint32(len(charData)))

			// Send an ACK back to the BMC so it knows we received the data and
			// will accept further input from the console.
			if err := sol.sendACK(); err != nil {
				sol.logger.Debug("bmc: SOL ACK send error", "error", err)
			}
		}

		if len(charData) == 0 {
			// ACK-only packet with no character data.
			continue
		}

		// Send the character data to the output channel.
		buf := make([]byte, len(charData))
		copy(buf, charData)

		select {
		case sol.output <- buf:
			sol.bytesReceived.Add(uint64(len(buf)))
		case <-sol.done:
			return
		}
	}
}

// sendACK sends an ACK-only SOL packet to the BMC acknowledging receipt of
// the last data packet. ACK-only packets have a sequence number of 0 and
// carry no character data.
func (sol *SOLSession) sendACK() error {
	ackSeq := sol.lastBMCSeqNum.Load()
	ackCharCount := sol.lastBMCCharCount.Load()

	solPacket := make([]byte, solHeaderSize)
	solPacket[0] = 0x00                // Sequence number 0 = ACK-only, no data
	solPacket[1] = byte(ackSeq & 0xFF) // ACK the BMC's sequence number
	solPacket[2] = byte(ackCharCount)  // Accepted character count
	solPacket[3] = 0x00                // Normal operation

	return sol.session.sendSOLMessage(solPacket)
}

// Read reads character data received from the BMC serial console.
// It blocks until data is available or the session is closed.
func (sol *SOLSession) Read(p []byte) (int, error) {
	if !sol.active.Load() {
		return 0, ErrSOLSessionClosed{}
	}

	data, ok := <-sol.output
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, data)
	return n, nil
}

// Write sends character data to the BMC serial console. The ACK fields are
// populated from the last received BMC packet so the BMC knows its data was
// accepted, enabling bidirectional communication.
func (sol *SOLSession) Write(p []byte) (int, error) {
	if !sol.active.Load() {
		return 0, ErrSOLSessionClosed{}
	}

	// Build SOL data packet.
	// byte 0: packet sequence number (console -> BMC)
	// byte 1: packet ACK/NACK sequence number
	// byte 2: accepted character count
	// byte 3: operation/status (0 = normal data)
	// byte 4+: character data
	seq := sol.seqNum.Add(1)
	ackSeq := sol.lastBMCSeqNum.Load()
	ackCharCount := sol.lastBMCCharCount.Load()

	solPacket := make([]byte, solHeaderSize+len(p))
	solPacket[0] = byte(seq & 0xFF)    // Sequence number wraps at 255
	solPacket[1] = byte(ackSeq & 0xFF) // ACK the BMC's last sequence number
	solPacket[2] = byte(ackCharCount)  // Accepted character count from last BMC packet
	solPacket[3] = 0x00                // Normal operation
	copy(solPacket[solHeaderSize:], p)

	if err := sol.session.sendSOLMessage(solPacket); err != nil {
		return 0, err
	}

	return len(p), nil
}

// SendBreak transmits a SOL serial-break to the BMC. The break is encoded by
// asserting the operation/status "generate break" bit (bit 4 of byte 3) per
// IPMI 2.0 spec Table 15-3 in an otherwise empty data packet. This is useful
// for entering kernel debuggers or interrupting boot loaders over the serial
// console.
func (sol *SOLSession) SendBreak() error {
	if !sol.active.Load() {
		return ErrSOLSessionClosed{}
	}

	seq := sol.seqNum.Add(1)
	ackSeq := sol.lastBMCSeqNum.Load()
	ackCharCount := sol.lastBMCCharCount.Load()

	const solOpGenerateBreak = 0x10

	solPacket := make([]byte, solHeaderSize)
	solPacket[0] = byte(seq & 0xFF)
	solPacket[1] = byte(ackSeq & 0xFF)
	solPacket[2] = byte(ackCharCount)
	solPacket[3] = solOpGenerateBreak

	return sol.session.sendSOLMessage(solPacket)
}

// Deactivate sends the Deactivate Payload command to the BMC and stops
// the receive loop.
func (sol *SOLSession) Deactivate(ctx context.Context) error {
	if !sol.active.Swap(false) {
		return nil
	}
	defer sol.releasePin()

	// Signal the receive loop to stop, and wait for it to give the socket
	// back (its current read returns within the session timeout) so the
	// Deactivate Payload response below is read by Send, not swallowed by
	// the loop as a non-SOL datagram.
	close(sol.done)
	if sol.loopDone != nil {
		<-sol.loopDone
	}

	// Best-effort deactivate: skip if the underlying connection is gone.
	if sol.session.conn != nil && !sol.session.closed.Load() {
		// Build Deactivate Payload request data per IPMI 2.0 spec Table 24-4.
		// Deactivate must reference the same payload instance Activate used,
		// otherwise the BMC ignores the request and leaves the session
		// hanging until an idle timeout fires.
		deactivateData := make([]byte, 6)
		deactivateData[0] = payloadTypeSOL
		deactivateData[1] = sol.payloadInstance
		// bytes 2-5: reserved

		_, err := sol.session.Send(netFnApp, cmdDeactivatePayload, deactivateData)
		if err != nil {
			return ErrSOLDeactivateFailed{Cause: err}
		}
	}

	sol.logger.Info("bmc: SOL payload deactivated")
	return nil
}

// Close deactivates the SOL payload and cleans up resources.
func (sol *SOLSession) Close() error {
	return sol.Deactivate(context.Background())
}

// wrapSOLPayload wraps a SOL data packet in an RMCP+ session envelope with
// encryption and integrity, using payloadTypeSOL instead of payloadTypeIPMI.
func (s *rmcpSession) wrapSOLPayload(solData []byte) ([]byte, error) {
	seqNum := s.clientSeqNum.Add(1)

	var payload []byte
	var payloadType byte = payloadTypeSOL
	confidential := s.cryptoAlgo != cryptoAlgoNone

	if confidential {
		encrypted, err := s.encryptPayload(solData)
		if err != nil {
			return nil, err
		}
		payload = encrypted
		payloadType |= 0x80 // Set encrypted bit
	} else {
		payload = solData
	}

	if s.integrityAlgo != integrityAlgoNone {
		payloadType |= 0x40 // Set authenticated bit
	}

	// Build RMCP+ session header (same layout as wrapPayload).
	headerLen := 4 + 1 + 1 + 4 + 4 + 2
	packetLen := headerLen + len(payload)

	var integrityPad []byte
	if s.integrityAlgo != integrityAlgoNone {
		dataLen := 1 + 1 + 4 + 4 + 2 + len(payload) + 2
		padLen := (4 - (dataLen % 4)) % 4
		integrityPad = make([]byte, padLen+2)
		for i := 0; i < padLen; i++ {
			integrityPad[i] = 0xFF
		}
		integrityPad[padLen] = byte(padLen)
		integrityPad[padLen+1] = 0x07

		authCodeLen := s.integrityHMACTruncLen()
		packetLen += len(integrityPad) + authCodeLen
	}

	packet := make([]byte, 0, packetLen)

	// RMCP header.
	packet = append(packet, rmcpVersion, rmcpReserved, rmcpSeqNum, rmcpClassIPMI)

	// IPMI 2.0 session header.
	packet = append(packet, authTypeRMCPPlus)
	packet = append(packet, payloadType)

	sidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sidBuf, s.bmcSessionID)
	packet = append(packet, sidBuf...)

	seqBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBuf, seqNum)
	packet = append(packet, seqBuf...)

	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(payload)))
	packet = append(packet, lenBuf...)

	packet = append(packet, payload...)

	// Integrity.
	if s.integrityAlgo != integrityAlgoNone {
		packet = append(packet, integrityPad...)
		authCode := s.computeIntegrity(packet[4:])
		packet = append(packet, authCode...)
	}

	return packet, nil
}

// rebindForSOL re-dials the session's UDP socket to a new remote port. The
// IPMI 2.0 spec lets the BMC advertise a separate UDP port for SOL data
// payloads in the Activate Payload response (Table 24-3 bytes 8-9). On
// hardware where that port differs from the RMCP+ session port (623), keeping
// the original socket means SOL packets sent to the new port are silently
// dropped -- receiveLoop sees nothing and the operator concludes "SOL is
// broken" while ipmitool (which DOES rebind) works fine on the same BMC.
//
// The session ID, sequence numbers, and crypto state are independent of the
// UDP 5-tuple -- they're encoded in the RMCP+ header -- so re-dialing to the
// new port preserves the active session without re-handshaking.
//
// The swap runs under exchangeMu: another operation on the shared client
// may be inside Send on the same session, and the socket must not be
// replaced or closed underneath its write-then-read.
func (s *rmcpSession) rebindForSOL(newPort uint16) error {
	s.exchangeMu.Lock()
	defer s.exchangeMu.Unlock()
	if s.conn == nil {
		return ErrSessionClosed{}
	}
	currentRemote, ok := s.conn.RemoteAddr().(*net.UDPAddr)
	if !ok || currentRemote == nil {
		return ErrUDPSend{Cause: ErrSessionClosed{}}
	}
	// No-op if the BMC advertised the same port we're already on.
	if uint16(currentRemote.Port) == newPort {
		return nil
	}

	newRemote := &net.UDPAddr{
		IP:   currentRemote.IP,
		Port: int(newPort),
		Zone: currentRemote.Zone,
	}

	newConn, err := net.DialUDP("udp", nil, newRemote)
	if err != nil {
		return ErrUDPSend{Cause: err}
	}

	// Swap the conn: close the old, install the new. exchangeMu excludes
	// any in-flight Send, and rebindForSOL runs during ActivateSOL --
	// before the SOL receive loop exists -- so no reader is on the old
	// socket when it closes.
	old := s.conn
	s.conn = newConn
	_ = old.Close()

	s.logger.Info("bmc: SOL UDP socket rebound",
		slog.String("old_remote", currentRemote.String()),
		slog.String("new_remote", newRemote.String()))
	return nil
}

// sendSOLMessage sends a SOL data packet over the encrypted RMCP+ session.
func (s *rmcpSession) sendSOLMessage(solData []byte) error {
	if s.conn == nil {
		return ErrSessionClosed{}
	}
	if s.closed.Load() {
		return ErrSessionClosed{}
	}

	packet, err := s.wrapSOLPayload(solData)
	if err != nil {
		return err
	}

	s.logger.Debug("bmc: SOL send", "packet_len", len(packet))

	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return ErrUDPSend{Cause: err}
	}
	_, err = s.conn.Write(packet)
	if err != nil {
		return ErrUDPSend{Cause: err}
	}

	return nil
}

// receiveSOLMessage reads an RMCP+ message and returns the decrypted payload
// and its payload type. This is used by the SOL receive loop to demux SOL
// packets from IPMI responses on the shared UDP connection.
func (s *rmcpSession) receiveSOLMessage() ([]byte, byte, error) {
	if s.conn == nil {
		return nil, 0, ErrSessionClosed{}
	}
	if s.closed.Load() {
		return nil, 0, ErrSessionClosed{}
	}

	if err := s.conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, 0, ErrUDPRecv{Cause: err}
	}

	buf := make([]byte, maxUDPRecvSize)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, 0, ErrUDPRecv{Cause: err}
	}

	resp := buf[:n]

	if len(resp) < 16 {
		return nil, 0, ErrPacketTooShort{Expected: 16, Actual: len(resp)}
	}

	if resp[0] != rmcpVersion || resp[3] != rmcpClassIPMI {
		return nil, 0, ErrPacketTooShort{Expected: 16, Actual: len(resp)}
	}

	rawPayloadType := resp[5]
	payloadType := rawPayloadType & 0x3F
	isEncrypted := rawPayloadType&0x80 != 0
	isAuthenticated := rawPayloadType&0x40 != 0

	payloadLen := binary.LittleEndian.Uint16(resp[14:16])
	payloadStart := 16
	payloadEnd := payloadStart + int(payloadLen)

	if payloadEnd > len(resp) {
		return nil, 0, ErrPacketTooShort{Expected: payloadEnd, Actual: len(resp)}
	}

	// Verify integrity if authenticated.
	if isAuthenticated && s.integrityAlgo != integrityAlgoNone {
		if err := s.verifyResponseIntegrity(resp, payloadEnd); err != nil {
			return nil, 0, err
		}
	}

	payload := resp[payloadStart:payloadEnd]

	// Decrypt if encrypted.
	if isEncrypted && s.cryptoAlgo != cryptoAlgoNone {
		decrypted, err := s.decryptPayload(payload)
		if err != nil {
			return nil, 0, err
		}
		payload = decrypted
	}

	return payload, payloadType, nil
}
