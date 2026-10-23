package openflow

const (
	OFPMCAdd    uint16 = 0
	OFPMCModify uint16 = 1
	OFPMCDelete uint16 = 2

	OFPMFKbps  uint16 = 1 << 0
	OFPMFBurst uint16 = 1 << 2

	OFPMBTDrop uint16 = 1

	// OFPMMax is the last meter ID a switch can hold (OFPM_MAX); the IDs
	// above it are reserved virtual meters.
	OFPMMax uint32 = 0xffff0000
)

// OFPET_METER_MOD_FAILED codes.
const (
	OFPMMFCMeterExists  uint16 = 1  // ADD for a meter that already exists
	OFPMMFCInvalidMeter uint16 = 2  // Meter ID the datapath cannot hold
	OFPMMFCUnknownMeter uint16 = 3  // MODIFY or DELETE of a missing meter
	OFPMMFCOutOfMeters  uint16 = 10 // No meter slot left
)

const (
	// meterModFixedLength is the meter mod header plus command, flags and
	// meter ID.
	meterModFixedLength = HeaderSize + 8

	// meterStatsRequestLength is ofp_meter_multipart_request: the meter ID
	// and four bytes of padding.
	meterStatsRequestLength = 8

	// meterStatsLength is the fixed part of ofp_meter_stats.
	meterStatsLength = 40

	// meterBandStatsLength is one ofp_meter_band_stats.
	meterBandStatsLength = 16
)

// InstructionMeter applies a configured OpenFlow meter.
type InstructionMeter struct {
	MeterID uint32
}

// NewInstructionMeter creates a meter instruction.
func NewInstructionMeter(meterID uint32) *InstructionMeter {
	return &InstructionMeter{MeterID: meterID}
}

// InstructionLength returns the encoded instruction length.
func (i *InstructionMeter) InstructionLength() uint16 {
	return 8
}

// MarshalBinary encodes the meter instruction.
func (i *InstructionMeter) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPITMeter)
	ByteOrder.PutUint16(data[2:4], 8)
	ByteOrder.PutUint32(data[4:8], i.MeterID)
	return data, nil
}

// MeterBand is one meter band.
type MeterBand interface {
	Length() uint16
	MarshalBinary() ([]byte, error)
}

// MeterBandDrop drops traffic over the configured rate.
type MeterBandDrop struct {
	Rate      uint32
	BurstSize uint32
}

// NewMeterBandDrop creates a drop meter band.
func NewMeterBandDrop(rate uint32, burstSize uint32) *MeterBandDrop {
	return &MeterBandDrop{Rate: rate, BurstSize: burstSize}
}

// Length returns the encoded band length.
func (b *MeterBandDrop) Length() uint16 {
	return 16
}

// MarshalBinary encodes the drop meter band.
func (b *MeterBandDrop) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	ByteOrder.PutUint16(data[0:2], OFPMBTDrop)
	ByteOrder.PutUint16(data[2:4], b.Length())
	ByteOrder.PutUint32(data[4:8], b.Rate)
	ByteOrder.PutUint32(data[8:12], b.BurstSize)
	return data, nil
}

// MeterMod is an OFPT_METER_MOD message.
type MeterMod struct {
	Header  Header
	Command uint16
	Flags   uint16
	MeterID uint32
	Bands   []MeterBand
}

// NewMeterMod creates a meter modification message.
func NewMeterMod(command uint16, flags uint16, meterID uint32, bands []MeterBand) *MeterMod {
	return &MeterMod{
		Header:  *NewHeader(OFPTMeterMod, 0, 0),
		Command: command,
		Flags:   flags,
		MeterID: meterID,
		Bands:   bands,
	}
}

// MarshalBinary encodes the meter modification, refusing one too long
// for the 16-bit OpenFlow length field.
func (m *MeterMod) MarshalBinary() ([]byte, error) {
	length := meterModFixedLength
	for _, band := range m.Bands {
		length += int(band.Length())
	}
	if length > MaxMessageSize {
		return nil, &ErrMessageLengthOverflow{MessageType: OFPTMeterMod, Length: length}
	}
	m.Header.Type = OFPTMeterMod
	m.Header.Length = uint16(length)
	data := make([]byte, length)
	header, err := m.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[0:HeaderSize], header)
	offset := HeaderSize
	ByteOrder.PutUint16(data[offset:offset+2], m.Command)
	ByteOrder.PutUint16(data[offset+2:offset+4], m.Flags)
	ByteOrder.PutUint32(data[offset+4:offset+8], m.MeterID)
	offset += 8
	for _, band := range m.Bands {
		bandData, err := band.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[offset:offset+len(bandData)], bandData)
		offset += len(bandData)
	}
	return data, nil
}

// MeterBandStats counts what one meter band acted on. For a drop band
// these are the packets and bytes the meter discarded.
type MeterBandStats struct {
	PacketCount uint64
	ByteCount   uint64
}

// MeterStats is one meter's OFPMP_METER statistics.
type MeterStats struct {
	MeterID       uint32
	FlowCount     uint32
	PacketInCount uint64
	ByteInCount   uint64
	DurationSec   uint32
	DurationNsec  uint32
	Bands         []MeterBandStats
}

// BandPackets returns the packets every band of the meter acted on.
func (s MeterStats) BandPackets() uint64 {
	var total uint64
	for _, band := range s.Bands {
		total += band.PacketCount
	}
	return total
}

// meterStatsRequestBody encodes ofp_meter_multipart_request for one meter.
func meterStatsRequestBody(meterID uint32) []byte {
	body := make([]byte, meterStatsRequestLength)
	ByteOrder.PutUint32(body[0:4], meterID)
	return body
}

// ParseMeterStats parses the body of an OFPMP_METER reply: a sequence of
// ofp_meter_stats, each followed by its band statistics.
func ParseMeterStats(data []byte) ([]MeterStats, error) {
	var stats []MeterStats
	for len(data) > 0 {
		if len(data) < meterStatsLength {
			return nil, ErrMessageTooShort
		}
		length := int(ByteOrder.Uint16(data[4:6]))
		if length < meterStatsLength || length > len(data) || (length-meterStatsLength)%meterBandStatsLength != 0 {
			return nil, ErrInvalidMessage
		}
		entry := MeterStats{
			MeterID:       ByteOrder.Uint32(data[0:4]),
			FlowCount:     ByteOrder.Uint32(data[12:16]),
			PacketInCount: ByteOrder.Uint64(data[16:24]),
			ByteInCount:   ByteOrder.Uint64(data[24:32]),
			DurationSec:   ByteOrder.Uint32(data[32:36]),
			DurationNsec:  ByteOrder.Uint32(data[36:40]),
		}
		for band := data[meterStatsLength:length]; len(band) > 0; band = band[meterBandStatsLength:] {
			entry.Bands = append(entry.Bands, MeterBandStats{
				PacketCount: ByteOrder.Uint64(band[0:8]),
				ByteCount:   ByteOrder.Uint64(band[8:16]),
			})
		}
		stats = append(stats, entry)
		data = data[length:]
	}
	return stats, nil
}
