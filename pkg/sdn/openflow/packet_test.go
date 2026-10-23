package openflow

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePacketIn(t *testing.T) {
	match := NewMatch()
	match.AddInPort(3)
	match.AddTunnelID(10100)
	body := packetInBody(t, match, []byte{1, 2, 3, 4})

	packet, err := ParsePacketIn(body)
	require.NoError(t, err)
	assert.Equal(t, PacketNoBuffer, packet.BufferID)
	assert.Equal(t, PacketInReasonAction, packet.Reason)
	assert.Equal(t, uint8(40), packet.TableID)
	assert.Equal(t, uint64(0xabc), packet.Cookie)
	assert.Len(t, packet.Match.Fields, 2)
	assert.Equal(t, []byte{1, 2, 3, 4}, packet.Data)
}

func TestParsePacketInRejectsShortBody(t *testing.T) {
	_, err := ParsePacketIn([]byte{1, 2, 3})
	assert.ErrorIs(t, err, ErrMessageTooShort)
}

func TestParsePacketInRejectsMalformedMatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(body []byte) []byte
		want   error
	}{
		{
			name: "standard match type",
			mutate: func(body []byte) []byte {
				binary.BigEndian.PutUint16(body[16:18], OFPMTStandard)
				return body
			},
			want: ErrInvalidMatch,
		},
		{
			name: "match length below the match header",
			mutate: func(body []byte) []byte {
				binary.BigEndian.PutUint16(body[18:20], 2)
				return body
			},
			want: ErrInvalidMatch,
		},
		{
			name: "match length past the end of the message",
			mutate: func(body []byte) []byte {
				binary.BigEndian.PutUint16(body[18:20], 512)
				return body
			},
			want: ErrMessageTooShort,
		},
		{
			name: "OXM field overrunning the declared match length",
			mutate: func(body []byte) []byte {
				// The in_port field needs 12 bytes of match; declare 10.
				binary.BigEndian.PutUint16(body[18:20], 10)
				return body
			},
			want: ErrInvalidMatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := NewMatch()
			match.AddInPort(3)
			body := tt.mutate(packetInBody(t, match, []byte{1, 2, 3, 4}))

			_, err := ParsePacketIn(body)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestPacketOutMarshalBinary(t *testing.T) {
	packet := NewPacketOut(3, []Action{NewActionOutput(OFPPInPort, 0)}, []byte{0xaa, 0xbb})
	packet.Header.Xid = 9

	data, err := packet.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x04, 0x0d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x09, // OFPT_PACKET_OUT, 42 bytes, xid 9
		0xff, 0xff, 0xff, 0xff, // buffer_id: none
		0x00, 0x00, 0x00, 0x03, // in_port 3
		0x00, 0x10, 0, 0, 0, 0, 0, 0, // actions_len 16, pad
		0x00, 0x00, 0x00, 0x10, 0xff, 0xff, 0xff, 0xf8, // output IN_PORT
		0x00, 0x00, 0, 0, 0, 0, 0, 0, // max_len, pad
		0xaa, 0xbb, // frame
	}, data)
}

func TestPacketOutRejectsLengthOverflow(t *testing.T) {
	packet := NewPacketOut(3, nil, make([]byte, MaxMessageSize))

	_, err := packet.MarshalBinary()
	assert.ErrorIs(t, err, ErrMessageTooLong)
	var overflow *ErrMessageLengthOverflow
	require.True(t, errors.As(err, &overflow))
	assert.Equal(t, HeaderSize+16+MaxMessageSize, overflow.Length)
	assert.Equal(t, uint8(OFPTPacketOut), overflow.MessageType)
}

// packetInBody encodes an OFPT_PACKET_IN body: buffer, total length,
// reason ACTION, table 40, cookie 0xabc, the match padded to eight bytes,
// two bytes of padding, then the frame.
func packetInBody(t *testing.T, match *Match, frame []byte) []byte {
	t.Helper()
	matchData, err := match.MarshalBinary()
	require.NoError(t, err)
	body := make([]byte, 16+len(matchData)+2+len(frame))
	binary.BigEndian.PutUint32(body[0:4], PacketNoBuffer)
	binary.BigEndian.PutUint16(body[4:6], uint16(len(frame)))
	body[6] = PacketInReasonAction
	body[7] = 40
	binary.BigEndian.PutUint64(body[8:16], 0xabc)
	copy(body[16:], matchData)
	copy(body[16+len(matchData)+2:], frame)
	return body
}
