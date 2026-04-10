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

package bmc

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// sdrFullSensorRecord represents a parsed IPMI SDR Full Sensor Record (type 0x01).
// See IPMI spec section 43.1, Table 43-1.
type sdrFullSensorRecord struct {
	RecordID     uint16
	SensorNumber uint8
	SensorType   uint8
	EventType    uint8
	M            int16
	B            int16
	BExp         int8
	RExp         int8
	BaseUnit     uint8
	Name         string
}

// sensorReadingResponse holds the parsed response from Get Sensor Reading (cmd 0x2D).
type sensorReadingResponse struct {
	RawReading    uint8
	EventStatus   uint8
	ThresholdLow  uint8
	ThresholdHigh uint8
}

// IsValid returns true when the sensor reading is valid (scanning enabled and reading valid).
func (r *sensorReadingResponse) IsValid() bool {
	// Bit 6: reading/state unavailable, Bit 5: scanning disabled
	return r.EventStatus&0x60 == 0
}

// HasThresholds returns true when the response includes threshold event bytes.
func (r *sensorReadingResponse) HasThresholds() bool {
	return r.ThresholdLow != 0 || r.ThresholdHigh != 0
}

// ThresholdEvents returns the combined threshold event bits.
func (r *sensorReadingResponse) ThresholdEvents() uint8 {
	return r.ThresholdLow | r.ThresholdHigh
}

// parseFullSensorRecord parses a raw SDR Full Sensor Record (type 0x01)
// from the binary data returned by Get SDR.
//
// Raw buffer layout:
//
//	[0:1]  = Record ID (little-endian)
//	[2]    = SDR version
//	[3]    = Record type (0x01 for full sensor)
//	[4]    = Record length (body bytes after this)
//	[5:]   = Record body
//
// Record body offsets (0-based from byte 5):
//
//	 0: Sensor Owner ID
//	 1: Sensor Owner LUN
//	 2: Sensor Number
//	 3: Entity ID
//	 4: Entity Instance
//	 5: Sensor Initialization
//	 6: Sensor Capabilities
//	 7: Sensor Type
//	 8: Event/Reading Type
//	 9-14: Event masks (6 bytes)
//	15: Sensor Units 1
//	16: Sensor Units 2 (base unit)
//	17: Sensor Units 3 (modifier unit)
//	18: Linearization
//	19: M (lower 8 bits)
//	20: M (upper 2 bits) | Tolerance (lower 6 bits)
//	21: B (lower 8 bits)
//	22: B (upper 2 bits) | Accuracy (lower 6 bits)
//	23: Accuracy (upper 4) | Accuracy exp | Direction
//	24: R exponent (upper nibble) | B exponent (lower nibble)
//	25-30: Analog characteristics, nominal, normal max/min
//	31-36: Threshold values
//	37-41: Reserved / OEM
//	42: ID string type/length
//	43+: ID string (sensor name)
func parseFullSensorRecord(data []byte) (sdrFullSensorRecord, error) {
	if len(data) < 48 {
		return sdrFullSensorRecord{}, ErrSDRParse{
			Reason: fmt.Sprintf("full sensor record too short: %d bytes", len(data)),
		}
	}

	rec := sdrFullSensorRecord{
		RecordID: binary.LittleEndian.Uint16(data[0:2]),
	}

	body := data[5:]
	if len(body) < 43 {
		return sdrFullSensorRecord{}, ErrSDRParse{
			Reason: fmt.Sprintf("full sensor record body too short: %d bytes", len(body)),
		}
	}

	rec.SensorNumber = body[2]
	rec.SensorType = body[7]
	rec.EventType = body[8]
	rec.BaseUnit = body[16]

	// M: 10-bit signed value from body[19:20]
	mLow := uint16(body[19])
	mHigh := uint16(body[20]&0xC0) << 2
	rec.M = twosComplement10(mLow | mHigh)

	// B: 10-bit signed value from body[21:22]
	bLow := uint16(body[21])
	bHigh := uint16(body[22]&0xC0) << 2
	rec.B = twosComplement10(bLow | bHigh)

	// Exponents from body[24]: upper nibble = R exp, lower nibble = B exp
	rec.RExp = twosComplement4((body[24] >> 4) & 0x0F)
	rec.BExp = twosComplement4(body[24] & 0x0F)

	// Sensor name from body[42] (type/length) and body[43:] (string data)
	if len(body) > 42 {
		nameTypeLen := body[42]
		nameLen := int(nameTypeLen & 0x1F)
		if len(body) > 43 && nameLen > 0 {
			end := 43 + nameLen
			if end > len(body) {
				end = len(body)
			}
			rec.Name = strings.TrimRight(string(body[43:end]), "\x00 ")
		}
	}
	if rec.Name == "" {
		rec.Name = fmt.Sprintf("Sensor_%d", rec.SensorNumber)
	}

	return rec, nil
}

// twosComplement10 interprets a 10-bit unsigned value as a signed int16.
func twosComplement10(val uint16) int16 {
	val &= 0x03FF
	if val&0x0200 != 0 {
		return int16(val) - 0x0400
	}
	return int16(val)
}

// twosComplement4 interprets a 4-bit unsigned value as a signed int8.
func twosComplement4(val uint8) int8 {
	val &= 0x0F
	if val&0x08 != 0 {
		return int8(val) - 0x10
	}
	return int8(val)
}

// sensorUnitStrings maps IPMI sensor base unit codes to display strings.
// Per IPMI spec Table 43-15.
var sensorUnitStrings = map[uint8]string{
	0:  "unspecified",
	1:  "degrees C",
	2:  "degrees F",
	3:  "degrees K",
	4:  "Volts",
	5:  "Amps",
	6:  "Watts",
	7:  "Joules",
	8:  "Coulombs",
	9:  "VA",
	10: "Nits",
	11: "lumen",
	12: "lux",
	13: "Candela",
	14: "kPa",
	15: "PSI",
	16: "Newton",
	17: "CFM",
	18: "RPM",
	19: "Hz",
	20: "microsecond",
	21: "millisecond",
	22: "second",
	23: "minute",
	24: "hour",
	25: "day",
	26: "week",
	27: "mil",
	28: "inches",
	29: "feet",
	30: "cu in",
	31: "cu feet",
	32: "mm",
	33: "cm",
	34: "m",
	35: "cu cm",
	36: "cu m",
	37: "liters",
	38: "fluid ounce",
	39: "radians",
	40: "steradians",
	41: "revolutions",
	42: "cycles",
	43: "gravities",
	44: "ounce",
	45: "pound",
	46: "ft-lb",
	47: "oz-in",
	48: "gauss",
	49: "gilberts",
	50: "henry",
	51: "millihenry",
	52: "farad",
	53: "microfarad",
	54: "ohms",
	55: "siemens",
	56: "mole",
	57: "becquerel",
	58: "ppm",
	59: "reserved",
	60: "Db",
	61: "DbA",
	62: "DbC",
	63: "gray",
	64: "sievert",
	65: "color temp deg K",
	66: "bit",
	67: "kilobit",
	68: "megabit",
	69: "gigabit",
	70: "byte",
	71: "kilobyte",
	72: "megabyte",
	73: "gigabyte",
	74: "word",
	75: "dword",
	76: "qword",
	77: "line",
	78: "hit",
	79: "miss",
	80: "retry",
	81: "reset",
	82: "overrun/overflow",
	83: "underrun",
	84: "collision",
	85: "packets",
	86: "messages",
	87: "characters",
	88: "error",
	89: "correctable error",
	90: "uncorrectable error",
	91: "fatal error",
	92: "grams",
}

// sensorUnitString returns the display string for a base unit code.
func sensorUnitString(unit uint8) string {
	if s, ok := sensorUnitStrings[unit]; ok {
		return s
	}
	return "unspecified"
}
