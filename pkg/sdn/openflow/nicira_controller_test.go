package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionController2MarshalBinary(t *testing.T) {
	action, err := NewActionController2(709)
	require.NoError(t, err)

	data, err := action.MarshalBinary()
	require.NoError(t, err)
	want := []byte{
		0xff, 0xff, 0x00, 0x20, // OFPAT_EXPERIMENTER, 32 bytes
		0x00, 0x00, 0x23, 0x20, // Nicira vendor
		0x00, 0x25, 0, 0, 0, 0, 0, 0, // NXAST_CONTROLLER2, pad
		0x00, 0x00, 0x00, 0x06, 0xff, 0xff, 0x00, 0x00, // NXAC2PT_MAX_LEN: whole packet
		0x00, 0x05, 0x00, 0x08, 0x00, 0x00, 0x02, 0xc5, // NXAC2PT_METER_ID: 709
	}
	assert.Equal(t, want, data)
	assert.Equal(t, uint16(len(want)), action.Length())
}

func TestNewActionController2RejectsUnusableMeter(t *testing.T) {
	for _, meterID := range []uint32{0, OFPMMax + 1} {
		_, err := NewActionController2(meterID)
		var invalid *MessageError
		assert.ErrorAs(t, err, &invalid, "meter %d", meterID)
	}
}
