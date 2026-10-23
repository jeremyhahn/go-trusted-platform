package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetConfigMarshalBinary(t *testing.T) {
	data, err := NewSetConfig(7, OFPCFragNormal, OFPCMLNoBuffer).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x04, 0x09, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x07, // OFPT_SET_CONFIG, 12 bytes, xid 7
		0x00, 0x00, 0xff, 0xff, // FRAG_NORMAL, miss_send_len NO_BUFFER
	}, data)
}

func TestGetConfigRequestMarshalBinary(t *testing.T) {
	data, err := NewGetConfigRequest(3).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x04, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03}, data)
}

func TestSwitchConfigUnmarshalBinary(t *testing.T) {
	var config SwitchConfig
	require.NoError(t, config.UnmarshalBinary([]byte{0x04, 0x08, 0x00, 0x0c, 0, 0, 0, 1, 0x00, 0x00, 0x00, 0x80}))
	assert.Equal(t, uint8(OFPTGetConfigReply), config.Header.Type)
	assert.Equal(t, uint16(0x80), config.MissSendLen)
}

func TestSwitchConfigUnmarshalBinaryRejectsShortReply(t *testing.T) {
	var config SwitchConfig
	assert.ErrorIs(t, config.UnmarshalBinary([]byte{0x04, 0x08, 0x00, 0x0a, 0, 0, 0, 1, 0x00, 0x00}), ErrMessageTooShort)
}
