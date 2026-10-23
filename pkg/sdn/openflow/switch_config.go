package openflow

const (
	// OFPCFragNormal is the switch config flag for no special IP fragment
	// handling (OFPC_FRAG_NORMAL).
	OFPCFragNormal uint16 = 0

	// OFPCMLNoBuffer asks the switch to send the whole packet to the
	// controller rather than buffer it (OFPCML_NO_BUFFER).
	OFPCMLNoBuffer uint16 = 0xffff

	// switchConfigLength is the length of OFPT_SET_CONFIG and
	// OFPT_GET_CONFIG_REPLY: the header, flags and miss_send_len.
	switchConfigLength = HeaderSize + 4
)

// SwitchConfig is an OFPT_SET_CONFIG or OFPT_GET_CONFIG_REPLY message.
//
// Open vSwitch serves bridge.mgmt as a service connection, and a service
// connection receives no asynchronous message until the controller sets a
// nonzero MissSendLen.
type SwitchConfig struct {
	Header      Header
	Flags       uint16
	MissSendLen uint16
}

// NewSetConfig creates an OFPT_SET_CONFIG message.
func NewSetConfig(xid uint32, flags uint16, missSendLen uint16) *SwitchConfig {
	return &SwitchConfig{
		Header:      *NewHeader(OFPTSetConfig, switchConfigLength, xid),
		Flags:       flags,
		MissSendLen: missSendLen,
	}
}

// NewGetConfigRequest creates an OFPT_GET_CONFIG_REQUEST message, which
// is a bare header.
func NewGetConfigRequest(xid uint32) *Header {
	return NewHeader(OFPTGetConfigRequest, HeaderSize, xid)
}

// MarshalBinary encodes the switch config.
func (c *SwitchConfig) MarshalBinary() ([]byte, error) {
	c.Header.Length = switchConfigLength
	header, err := c.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, switchConfigLength)
	copy(data, header)
	ByteOrder.PutUint16(data[HeaderSize:HeaderSize+2], c.Flags)
	ByteOrder.PutUint16(data[HeaderSize+2:HeaderSize+4], c.MissSendLen)
	return data, nil
}

// UnmarshalBinary decodes a switch config message, header included.
func (c *SwitchConfig) UnmarshalBinary(data []byte) error {
	if len(data) < switchConfigLength {
		return ErrMessageTooShort
	}
	if err := c.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	c.Flags = ByteOrder.Uint16(data[HeaderSize : HeaderSize+2])
	c.MissSendLen = ByteOrder.Uint16(data[HeaderSize+2 : HeaderSize+4])
	return nil
}
