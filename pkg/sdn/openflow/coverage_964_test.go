package openflow

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatch_AddIPv4Masked(t *testing.T) {
	tests := []struct {
		name  string
		add   func(m *Match, ip net.IP, mask net.IPMask)
		field uint8
	}{
		{"source", (*Match).AddIPv4SrcMasked, OFPXMTOFBIPv4Src},
		{"destination", (*Match).AddIPv4DstMasked, OFPXMTOFBIPv4Dst},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := NewMatch()
			before := match.Length
			_, network, err := net.ParseCIDR("10.20.0.0/16")
			require.NoError(t, err)

			tt.add(match, network.IP, network.Mask)

			require.Len(t, match.Fields, 1)
			field := match.Fields[0]
			assert.Equal(t, uint16(OFPXMCOpenflowBasic), field.Class)
			assert.Equal(t, tt.field, field.Field)
			assert.True(t, field.HasMask)
			assert.Equal(t, uint8(8), field.Length, "a masked IPv4 payload is value plus mask")
			assert.Equal(t, []byte{10, 20, 0, 0}, field.Value, "the address is encoded as 4 bytes")
			assert.Equal(t, []byte{0xff, 0xff, 0, 0}, field.Mask)
			assert.Equal(t, before+12, match.Length, "OXM header, value and mask")

			data, err := match.MarshalBinary()
			require.NoError(t, err)
			decoded := NewMatch()
			require.NoError(t, decoded.UnmarshalBinary(data))
			require.Len(t, decoded.Fields, 1)
			assert.Equal(t, field.Value, decoded.Fields[0].Value)
			assert.Equal(t, field.Mask, decoded.Fields[0].Mask)
		})
	}
}

func TestInstructionMeter_MarshalBinary(t *testing.T) {
	instruction := NewInstructionMeter(0x01020304)
	assert.Equal(t, uint16(8), instruction.InstructionLength())

	data, err := instruction.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, data, int(instruction.InstructionLength()))
	assert.Equal(t, uint16(OFPITMeter), ByteOrder.Uint16(data[0:2]))
	assert.Equal(t, uint16(8), ByteOrder.Uint16(data[2:4]))
	assert.Equal(t, uint32(0x01020304), ByteOrder.Uint32(data[4:8]))
}

func TestTypedErrors_MessagesAndUnwrap(t *testing.T) {
	cause := &MessageError{Msg: "switch said no"}
	ofErr := &OFError{Type: OFPETMeterModFailed, Code: OFPMMFCOutOfMeters}

	tests := []struct {
		name    string
		err     error
		message string
		cause   error
	}{
		{"message", cause, "switch said no", nil},
		{"wrapped", &WrappedError{Msg: "add flow", Err: cause}, "add flow: switch said no", cause},
		{"batch flow", &BatchFlowError{Index: 2, Xid: 7, Err: ofErr}, "flow mod 2 (xid 7): meter mod failed: out of meters", ofErr},
		{"sentinel cause", &SentinelCauseError{Sentinel: ErrNotConnected, Cause: cause}, ErrNotConnected.Error() + ": switch said no", cause},
		{"meter unsupported", &ErrMeterUnsupported{MeterID: 5, Cause: ofErr}, "meter 5 unsupported by the datapath: meter mod failed: out of meters", ofErr},
		{"meter not found", &ErrMeterNotFound{MeterID: 9}, "meter 9 not found", nil},
		{"length overflow", &ErrMessageLengthOverflow{MessageType: OFPTFlowMod, Length: 70000}, "openflow message type 14 is 70000 bytes, over the 65535-byte limit", nil},
		{"packet-in disabled", &ErrPacketInDisabled{MissSendLen: 0}, "switch kept packet-ins disabled: miss_send_len 0", nil},
		{"invalid packet-in config", &ErrInvalidPacketInConfig{Field: "workers", Reason: "must be positive"}, "invalid packet-in config: workers must be positive", nil},
		{"duplicate route", &ErrDuplicatePacketInRoute{Key: PacketInKey{Reason: PacketInReasonAction, Cookie: 0xf5}}, "duplicate packet-in route: reason 1 cookie 0xf5", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.message, tt.err.Error())
			if tt.cause != nil {
				assert.ErrorIs(t, tt.err, tt.cause)
			}
		})
	}
}

func TestSentinelCauseError_MatchesSentinel(t *testing.T) {
	err := &SentinelCauseError{Sentinel: ErrNotConnected, Cause: &MessageError{Msg: "dial"}}
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.NotErrorIs(t, err, ErrConnectionClosed)
}

func TestErrMessageLengthOverflow_MatchesTooLong(t *testing.T) {
	var err error = &ErrMessageLengthOverflow{MessageType: OFPTPacketOut, Length: MaxMessageSize + 1}
	assert.ErrorIs(t, err, ErrMessageTooLong)
	var overflow *ErrMessageLengthOverflow
	require.True(t, errors.As(err, &overflow))
	assert.Equal(t, MaxMessageSize+1, overflow.Length)
}

func TestPacketInController_QueueDroppedCountsFullQueue(t *testing.T) {
	source := newPacketSource()
	controller, err := NewPacketInController(PacketInControllerConfig{
		Source:  source,
		Queue:   1,
		Workers: 1,
	})
	require.NoError(t, err)
	t.Cleanup(controller.Stop)
	require.Len(t, source.subscriptions, 1)

	assert.Zero(t, controller.QueueDropped())
	// Not started, so no worker drains the queue: the second packet is dropped.
	assert.True(t, source.subscriptions[0].Deliver(PacketIn{Cookie: 1}))
	assert.False(t, source.subscriptions[0].Deliver(PacketIn{Cookie: 2}))
	assert.Equal(t, uint64(1), controller.QueueDropped())
}
