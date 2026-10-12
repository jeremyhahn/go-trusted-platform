package openflow

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeterModMarshalBinary(t *testing.T) {
	mod := NewMeterMod(OFPMCAdd, OFPMFKbps|OFPMFBurst, 709, []MeterBand{NewMeterBandDrop(512, 64)})
	mod.Header.Xid = 7

	data, err := mod.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x04, 0x1d, 0x00, 0x20, 0x00, 0x00, 0x00, 0x07, // OFPT_METER_MOD, 32 bytes, xid 7
		0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0xc5, // ADD, KBPS|BURST, meter 709
		0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, // drop band, rate 512
		0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // burst 64, pad
	}, data)
}

func TestMeterModRejectsLengthOverflow(t *testing.T) {
	bands := make([]MeterBand, MaxMessageSize/16)
	for i := range bands {
		bands[i] = NewMeterBandDrop(1, 1)
	}

	_, err := NewMeterMod(OFPMCAdd, OFPMFKbps, 1, bands).MarshalBinary()
	assert.ErrorIs(t, err, ErrMessageTooLong)
	var overflow *ErrMessageLengthOverflow
	require.True(t, errors.As(err, &overflow))
	assert.Equal(t, uint8(OFPTMeterMod), overflow.MessageType)
}

func TestParseMeterStats(t *testing.T) {
	data := meterStatsEntry(709, 5, 1000)

	stats, err := ParseMeterStats(data)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, uint32(709), stats[0].MeterID)
	assert.Equal(t, uint32(2), stats[0].FlowCount)
	assert.Equal(t, uint64(40), stats[0].PacketInCount)
	assert.Equal(t, []MeterBandStats{{PacketCount: 5, ByteCount: 1000}}, stats[0].Bands)
	assert.Equal(t, uint64(5), stats[0].BandPackets())
}

func TestParseMeterStatsRejectsMalformedEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{name: "truncated entry", mutate: func(d []byte) []byte { return d[:30] }, want: ErrMessageTooShort},
		{name: "length past the data", mutate: func(d []byte) []byte {
			binary.BigEndian.PutUint16(d[4:6], 72)
			return d
		}, want: ErrInvalidMessage},
		{name: "partial band", mutate: func(d []byte) []byte {
			binary.BigEndian.PutUint16(d[4:6], 48)
			return d
		}, want: ErrInvalidMessage},
		{name: "length below the fixed part", mutate: func(d []byte) []byte {
			binary.BigEndian.PutUint16(d[4:6], 0)
			return d
		}, want: ErrInvalidMessage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMeterStats(tt.mutate(meterStatsEntry(709, 5, 1000)))
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

// meterStatsEntry encodes one ofp_meter_stats with a single band.
func meterStatsEntry(meterID uint32, bandPackets, bandBytes uint64) []byte {
	data := make([]byte, 56)
	binary.BigEndian.PutUint32(data[0:4], meterID)
	binary.BigEndian.PutUint16(data[4:6], 56)
	binary.BigEndian.PutUint32(data[12:16], 2)
	binary.BigEndian.PutUint64(data[16:24], 40)
	binary.BigEndian.PutUint64(data[40:48], bandPackets)
	binary.BigEndian.PutUint64(data[48:56], bandBytes)
	return data
}
