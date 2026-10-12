package openflow

const (
	PacketInReasonNoMatch uint8 = 0
	PacketInReasonAction  uint8 = 1
)

const (
	PacketNoBuffer uint32 = 0xffffffff
)

// PacketIn is an OFPT_PACKET_IN message body.
type PacketIn struct {
	BufferID uint32
	TotalLen uint16
	Reason   uint8
	TableID  uint8
	Cookie   uint64
	Match    Match
	Data     []byte
}

// ParsePacketIn parses an OpenFlow 1.3 packet-in body.
func ParsePacketIn(body []byte) (PacketIn, error) {
	if len(body) < 24 {
		return PacketIn{}, ErrMessageTooShort
	}
	packet := PacketIn{
		BufferID: ByteOrder.Uint32(body[0:4]),
		TotalLen: ByteOrder.Uint16(body[4:6]),
		Reason:   body[6],
		TableID:  body[7],
		Cookie:   ByteOrder.Uint64(body[8:16]),
	}
	matchType := ByteOrder.Uint16(body[16:18])
	matchLen := int(ByteOrder.Uint16(body[18:20]))
	if matchType != OFPMTOXM || matchLen < 4 {
		return PacketIn{}, ErrInvalidMatch
	}
	matchEnd := 16 + align8(matchLen)
	dataStart := matchEnd + 2
	if dataStart > len(body) {
		return PacketIn{}, ErrMessageTooShort
	}
	if err := packet.Match.UnmarshalBinary(body[16:matchEnd]); err != nil {
		return PacketIn{}, &SentinelCauseError{Sentinel: ErrInvalidMatch, Cause: err}
	}
	packet.Data = append([]byte(nil), body[dataStart:]...)
	return packet, nil
}

func align8(n int) int {
	return (n + 7) &^ 7
}

// PacketOut is an OFPT_PACKET_OUT message.
type PacketOut struct {
	Header   Header
	BufferID uint32
	InPort   uint32
	Actions  []Action
	Data     []byte
}

// NewPacketOut creates a packet-out that emits Data through Actions.
func NewPacketOut(inPort uint32, actions []Action, data []byte) *PacketOut {
	return &PacketOut{
		Header:   *NewHeader(OFPTPacketOut, 0, 0),
		BufferID: PacketNoBuffer,
		InPort:   inPort,
		Actions:  actions,
		Data:     append([]byte(nil), data...),
	}
}

// MarshalBinary encodes the packet-out, refusing one too long for the
// 16-bit OpenFlow length field.
func (p *PacketOut) MarshalBinary() ([]byte, error) {
	actionsLen := 0
	for _, action := range p.Actions {
		actionsLen += int(action.Length())
	}
	length := HeaderSize + 16 + actionsLen + len(p.Data)
	if length > MaxMessageSize {
		return nil, &ErrMessageLengthOverflow{MessageType: OFPTPacketOut, Length: length}
	}
	p.Header.Type = OFPTPacketOut
	p.Header.Length = uint16(length)
	data := make([]byte, length)
	header, err := p.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[0:HeaderSize], header)
	offset := HeaderSize
	ByteOrder.PutUint32(data[offset:offset+4], p.BufferID)
	ByteOrder.PutUint32(data[offset+4:offset+8], p.InPort)
	ByteOrder.PutUint16(data[offset+8:offset+10], uint16(actionsLen))
	offset += 16
	for _, action := range p.Actions {
		actionData, err := action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[offset:offset+len(actionData)], actionData)
		offset += len(actionData)
	}
	copy(data[offset:], p.Data)
	return data, nil
}
