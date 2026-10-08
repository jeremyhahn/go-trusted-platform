// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vici

import (
	"encoding/binary"
	"io"
	"strconv"
)

// MaxPacketSize is the protocol's packet limit (VICI_MESSAGE_SIZE_MAX),
// excluding the 4-byte length prefix.
const MaxPacketSize = 512 * 1024

// Packet types (README, "Transport protocol").
const (
	pktCmdRequest      byte = 0
	pktCmdResponse     byte = 1
	pktCmdUnknown      byte = 2
	pktEventRegister   byte = 3
	pktEventUnregister byte = 4
	pktEventConfirm    byte = 5
	pktEventUnknown    byte = 6
	pktEvent           byte = 7
)

// packetNamed reports whether a packet type carries a name after its type.
func packetNamed(t byte) bool {
	switch t {
	case pktCmdRequest, pktEventRegister, pktEventUnregister, pktEvent:
		return true
	}
	return false
}

// packet is one decoded VICI packet.
type packet struct {
	kind    byte
	name    string
	message *Message
}

// writePacket frames and writes one packet. msg may be nil for packets
// that carry no message.
func writePacket(w io.Writer, kind byte, name string, msg *Message) error {
	b := make([]byte, 4, 64)
	b = append(b, kind)
	if packetNamed(kind) {
		if name == "" {
			return ErrEmptyName
		}
		if len(name) > maxNameLength {
			return &EncodeError{Key: name, Reason: "name length " + strconv.Itoa(len(name)) + " exceeds " + strconv.Itoa(maxNameLength)}
		}
		b = append(b, byte(len(name)))
		b = append(b, name...)
	}
	b, err := msg.appendTo(b, "")
	if err != nil {
		return err
	}
	if len(b)-4 > MaxPacketSize {
		return ErrMessageTooLarge
	}
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	_, err = w.Write(b)
	clear(b)
	return err
}

// readPacket reads and decodes one packet.
func readPacket(r io.Reader) (packet, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return packet{}, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 {
		return packet{}, &DecodeError{Offset: 0, Reason: "empty packet"}
	}
	if n > MaxPacketSize {
		return packet{}, ErrMessageTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return packet{}, err
	}
	p := packet{kind: body[0]}
	if p.kind > pktEvent {
		return packet{}, &DecodeError{Offset: 0, Reason: "unknown packet type " + strconv.Itoa(int(p.kind))}
	}
	pos := 1
	if packetNamed(p.kind) {
		if len(body) < 2 {
			return packet{}, &DecodeError{Offset: 1, Reason: "truncated packet name"}
		}
		l := int(body[1])
		if l == 0 || 2+l > len(body) {
			return packet{}, &DecodeError{Offset: 1, Reason: "bad packet name length " + strconv.Itoa(l)}
		}
		p.name = string(body[2 : 2+l])
		pos = 2 + l
	}
	p.message = NewMessage()
	if err := p.message.UnmarshalBinary(body[pos:]); err != nil {
		return packet{}, err
	}
	return p, nil
}
