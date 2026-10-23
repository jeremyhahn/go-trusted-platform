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

package nbd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

// negotiation is the handshake phase of one connection.
type negotiation struct {
	server *Server
	// conn is the transport: the TCP connection, then the TLS connection
	// once STARTTLS completes.
	conn     net.Conn
	tls      bool
	noZeroes bool
	// identity is the verified client identity, set by the TLS handshake.
	identity string
	// refusal is the last option the server refused; it becomes the
	// session's error if the client gives up after it.
	refusal error
}

// optionResult is what an option handler decides: keep negotiating,
// enter transmission with vol, or end the session.
type optionResult struct {
	vol  *volume
	done bool
}

type optionHandler func(n *negotiation, ctx context.Context, data []byte) (optionResult, error)

// Options honoured before STARTTLS; every other option is answered with
// NBD_REP_ERR_TLS_REQD.
var plaintextOptions = map[uint32]optionHandler{
	optStartTLS:   (*negotiation).startTLS,
	optAbort:      (*negotiation).abort,
	optExportName: (*negotiation).exportNameBeforeTLS,
}

// Options honoured after STARTTLS; every other option is answered with
// NBD_REP_ERR_UNSUP.
var tlsOptions = map[uint32]optionHandler{
	optStartTLS:   (*negotiation).startTLSAgain,
	optAbort:      (*negotiation).abort,
	optExportName: (*negotiation).exportName,
	optInfo:       (*negotiation).info,
	optGo:         (*negotiation).goOption,
}

// run greets the client and negotiates options until the client enters
// transmission (a non-nil volume), aborts (nil, nil), or is refused.
func (n *negotiation) run(ctx context.Context) (*volume, error) {
	if err := n.greet(); err != nil {
		return nil, err
	}
	for {
		option, data, err := n.readOption()
		if errors.Is(err, io.EOF) {
			// The client left: report what it was refused, if anything.
			if n.refusal != nil {
				return nil, n.refusal
			}
			return nil, ErrProtocol{Reason: "client closed during negotiation", Cause: err}
		}
		if err != nil {
			return nil, err
		}

		handlers, fallback := plaintextOptions, repErrTLSReqd
		if n.tls {
			handlers, fallback = tlsOptions, repErrUnsup
		}
		handler, ok := handlers[option]
		if !ok {
			if err := n.refuse(option, fallback, n.fallbackRefusal(option)); err != nil {
				return nil, err
			}
			continue
		}

		result, err := handler(n, ctx, data)
		if err != nil || result.done {
			return result.vol, err
		}
	}
}

// fallbackRefusal is the typed error recorded for an option the current
// phase does not handle.
func (n *negotiation) fallbackRefusal(option uint32) error {
	if !n.tls {
		return ErrTLSRequired{Option: option}
	}
	return ErrProtocol{Reason: "unsupported option"}
}

// greet sends the fixed-newstyle greeting and reads the client flags.
func (n *negotiation) greet() error {
	greeting := make([]byte, 0, 18)
	greeting = binary.BigEndian.AppendUint64(greeting, nbdMagic)
	greeting = binary.BigEndian.AppendUint64(greeting, optionMagic)
	greeting = binary.BigEndian.AppendUint16(greeting, flagFixedNewstyle|flagNoZeroes)
	if _, err := n.conn.Write(greeting); err != nil {
		return ErrProtocol{Reason: "write greeting", Cause: err}
	}

	var raw [4]byte
	if _, err := io.ReadFull(n.conn, raw[:]); err != nil {
		return ErrProtocol{Reason: "read client flags", Cause: err}
	}
	flags := binary.BigEndian.Uint32(raw[:])
	if flags&clientFlagFixedNewstyle == 0 || flags&^clientFlagsKnown != 0 {
		return ErrUnsupportedClientFlags{Flags: flags}
	}
	n.noZeroes = flags&clientFlagNoZeroes != 0
	return nil
}

// readOption reads one option request. A clean EOF before the header is
// returned as io.EOF so run can report the refusal that preceded it.
func (n *negotiation) readOption() (uint32, []byte, error) {
	var header [16]byte
	if _, err := io.ReadFull(n.conn, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, ErrProtocol{Reason: "read option header", Cause: err}
	}
	if binary.BigEndian.Uint64(header[0:8]) != optionMagic {
		return 0, nil, ErrProtocol{Reason: "bad option magic"}
	}
	option := binary.BigEndian.Uint32(header[8:12])
	length := binary.BigEndian.Uint32(header[12:16])
	if length > maxOptionLength {
		return 0, nil, ErrProtocol{Reason: "option data too large"}
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(n.conn, data); err != nil {
		return 0, nil, ErrProtocol{Reason: "read option data", Cause: err}
	}
	return option, data, nil
}

// reply writes one option reply.
func (n *negotiation) reply(option, replyType uint32, data []byte) error {
	msg := make([]byte, 0, 20+len(data))
	msg = binary.BigEndian.AppendUint64(msg, optionReplyMagic)
	msg = binary.BigEndian.AppendUint32(msg, option)
	msg = binary.BigEndian.AppendUint32(msg, replyType)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(data)))
	msg = append(msg, data...)
	if _, err := n.conn.Write(msg); err != nil {
		return ErrProtocol{Reason: "write option reply", Cause: err}
	}
	return nil
}

// refuse answers option with an error reply and records why.
func (n *negotiation) refuse(option, replyType uint32, why error) error {
	n.refusal = why
	return n.reply(option, replyType, nil)
}

func (n *negotiation) startTLS(ctx context.Context, data []byte) (optionResult, error) {
	if len(data) != 0 {
		return optionResult{}, n.refuse(optStartTLS, repErrInvalid, ErrProtocol{Reason: "STARTTLS carries no data"})
	}
	if err := n.reply(optStartTLS, repAck, nil); err != nil {
		return optionResult{}, err
	}

	tlsConn := tls.Server(n.conn, n.server.tlsConfigFor(ctx, &n.identity))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return optionResult{}, handshakeError(err)
	}
	n.conn = tlsConn
	n.tls = true
	n.refusal = nil
	return optionResult{}, nil
}

// handshakeError keeps the typed refusal VerifyConnection returned and
// wraps any other handshake failure.
func handshakeError(err error) error {
	var (
		required  ErrClientCertificateRequired
		untrusted ErrClientCertificateUntrusted
		anchor    ErrTrustAnchor
		unknown   ErrUnknownIdentity
	)
	switch {
	case errors.As(err, &required), errors.As(err, &untrusted),
		errors.As(err, &anchor), errors.As(err, &unknown):
		return err
	default:
		return ErrTLSHandshake{Cause: err}
	}
}

func (n *negotiation) startTLSAgain(_ context.Context, _ []byte) (optionResult, error) {
	return optionResult{}, n.refuse(optStartTLS, repErrInvalid, ErrProtocol{Reason: "STARTTLS after TLS"})
}

func (n *negotiation) abort(_ context.Context, _ []byte) (optionResult, error) {
	if err := n.reply(optAbort, repAck, nil); err != nil {
		return optionResult{}, err
	}
	return optionResult{done: true}, n.refusal
}

// exportNameBeforeTLS ends the session: NBD_OPT_EXPORT_NAME has no error
// reply, so a plaintext request for an export can only be closed.
func (n *negotiation) exportNameBeforeTLS(_ context.Context, _ []byte) (optionResult, error) {
	return optionResult{done: true}, ErrTLSRequired{Option: optExportName}
}

// exportName enters transmission the old way: no error reply exists, so
// any refusal closes the connection.
func (n *negotiation) exportName(_ context.Context, data []byte) (optionResult, error) {
	name := string(data)
	if !n.permitted(name) {
		return optionResult{done: true}, ErrExportNotPermitted{Identity: n.identity, Export: name}
	}
	vol, err := n.server.volumes.open(n.identity)
	if err != nil {
		return optionResult{done: true}, err
	}

	msg := make([]byte, 0, 10+zeroPadLength)
	msg = binary.BigEndian.AppendUint64(msg, uint64(vol.size))
	msg = binary.BigEndian.AppendUint16(msg, exportFlags)
	if !n.noZeroes {
		msg = append(msg, make([]byte, zeroPadLength)...)
	}
	if _, err := n.conn.Write(msg); err != nil {
		return optionResult{done: true}, closeAfter(n.identity, vol.file, ErrProtocol{Reason: "write export reply", Cause: err})
	}
	return optionResult{vol: vol, done: true}, nil
}

func (n *negotiation) info(_ context.Context, data []byte) (optionResult, error) {
	return n.describe(optInfo, data)
}

func (n *negotiation) goOption(_ context.Context, data []byte) (optionResult, error) {
	return n.describe(optGo, data)
}

// describe answers NBD_OPT_INFO and NBD_OPT_GO; GO then enters
// transmission.
func (n *negotiation) describe(option uint32, data []byte) (optionResult, error) {
	name, requests, ok := parseInfoRequest(data)
	if !ok {
		return optionResult{}, n.refuse(option, repErrInvalid, ErrProtocol{Reason: "malformed info request"})
	}
	if !n.permitted(name) {
		return optionResult{}, n.refuse(option, repErrPolicy, ErrExportNotPermitted{Identity: n.identity, Export: name})
	}
	vol, err := n.server.volumes.open(n.identity)
	if err != nil {
		return optionResult{}, n.refuse(option, repErrPlatform, err)
	}

	if err := n.sendInfo(option, vol, requests); err != nil {
		return optionResult{done: true}, closeAfter(n.identity, vol.file, err)
	}
	if option == optGo {
		return optionResult{vol: vol, done: true}, nil
	}
	return optionResult{}, closeAfter(n.identity, vol.file, nil)
}

// sendInfo writes NBD_INFO_EXPORT, then each requested information type
// this server provides, then the final ACK.
func (n *negotiation) sendInfo(option uint32, vol *volume, requests []uint16) error {
	export := binary.BigEndian.AppendUint16(nil, infoExport)
	export = binary.BigEndian.AppendUint64(export, uint64(vol.size))
	export = binary.BigEndian.AppendUint16(export, exportFlags)
	if err := n.reply(option, repInfo, export); err != nil {
		return err
	}

	for _, request := range requests {
		var payload []byte
		switch request {
		case infoName:
			payload = binary.BigEndian.AppendUint16(nil, infoName)
			payload = append(payload, n.identity...)
		case infoBlockSize:
			payload = binary.BigEndian.AppendUint16(nil, infoBlockSize)
			payload = binary.BigEndian.AppendUint32(payload, 1)
			payload = binary.BigEndian.AppendUint32(payload, preferredBlockSize)
			payload = binary.BigEndian.AppendUint32(payload, maxPayload)
		default:
			continue
		}
		if err := n.reply(option, repInfo, payload); err != nil {
			return err
		}
	}
	return n.reply(option, repAck, nil)
}

// permitted reports whether name selects the client's own export: the
// empty default name or its identity. Nothing else is ever exported to it.
func (n *negotiation) permitted(name string) bool {
	return name == "" || strings.EqualFold(name, n.identity)
}

// parseInfoRequest decodes the data of NBD_OPT_INFO and NBD_OPT_GO:
// u32 name length, name, u16 request count, u16 requests.
func parseInfoRequest(data []byte) (string, []uint16, bool) {
	if len(data) < 4 {
		return "", nil, false
	}
	nameLength := uint64(binary.BigEndian.Uint32(data[0:4]))
	if uint64(len(data)) < 4+nameLength+2 {
		return "", nil, false
	}
	name := string(data[4 : 4+nameLength])
	rest := data[4+nameLength:]
	count := int(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if len(rest) != 2*count {
		return "", nil, false
	}
	requests := make([]uint16, count)
	for i := range requests {
		requests[i] = binary.BigEndian.Uint16(rest[2*i:])
	}
	return name, requests, true
}
