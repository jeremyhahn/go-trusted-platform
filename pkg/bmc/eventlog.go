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
	"fmt"
	"strings"
	"time"
)

// IPMI sensor types (IPMI 2.0 §42.2, table 42-3) the event-log reader
// classifies. Redfish entries carry the same taxonomy as SensorType
// strings, mapped back onto these codes so consumers see one vocabulary.
const (
	// SensorTypeMemory is the DIMM / memory-controller sensor type.
	SensorTypeMemory uint8 = 0x0C
	// SensorTypeEventLoggingDisabled reports the BMC's own logging state:
	// "SEL full", "SEL almost full", "logging disabled".
	SensorTypeEventLoggingDisabled uint8 = 0x10
)

// Memory sensor-specific event offsets (IPMI 2.0 table 42-3, type 0x0C).
const (
	MemoryEventCorrectableECC      uint8 = 0x00
	MemoryEventUncorrectableECC    uint8 = 0x01
	MemoryEventParity              uint8 = 0x02
	MemoryEventScrubFailed         uint8 = 0x03
	MemoryEventDeviceDisabled      uint8 = 0x04
	MemoryEventCorrectableLimit    uint8 = 0x05
	MemoryEventPresenceDetected    uint8 = 0x06
	MemoryEventConfigurationError  uint8 = 0x07
	MemoryEventSpare               uint8 = 0x08
	MemoryEventThrottled           uint8 = 0x09
	MemoryEventCriticalOvertemp    uint8 = 0x0A
	memoryEventOffsetCount               = 0x0B
	loggingEventOffsetCount              = 0x06
	sensorSpecificEventReadingType uint8 = 0x6F
)

// Event Logging Disabled sensor-specific offsets (type 0x10).
const (
	LoggingEventCorrectableMemoryDisabled uint8 = 0x00
	LoggingEventTypeDisabled              uint8 = 0x01
	LoggingEventLogCleared                uint8 = 0x02
	LoggingEventAllDisabled               uint8 = 0x03
	LoggingEventSELFull                   uint8 = 0x04
	LoggingEventSELAlmostFull             uint8 = 0x05
)

// memoryEventDescriptions names the memory sensor offsets.
var memoryEventDescriptions = [memoryEventOffsetCount]string{
	"Correctable ECC",
	"Uncorrectable ECC",
	"Parity",
	"Memory scrub failed",
	"Memory device disabled",
	"Correctable ECC logging limit reached",
	"Presence detected",
	"Configuration error",
	"Spare",
	"Throttled",
	"Critical overtemperature",
}

// loggingEventDescriptions names the Event Logging Disabled offsets.
var loggingEventDescriptions = [loggingEventOffsetCount]string{
	"Correctable memory error logging disabled",
	"Event type logging disabled",
	"Log area reset/cleared",
	"All event logging disabled",
	"SEL full",
	"SEL almost full",
}

// sensorTypeNames maps the sensor-type codes the reader classifies to
// the names Redfish uses for the same sensors (DSP8010 LogEntry
// SensorType enumeration, spelled as the schema spells them), so both
// transports produce the same strings.
var sensorTypeNames = map[uint8]string{
	0x01:                           "Temperature",
	0x02:                           "Voltage",
	0x03:                           "Current",
	0x04:                           "Fan",
	0x05:                           "Physical Chassis Security",
	0x06:                           "Platform Security Violation Attempt",
	0x07:                           "Processor",
	0x08:                           "Power Supply / Converter",
	0x09:                           "PowerUnit",
	0x0A:                           "CoolingDevice",
	0x0B:                           "Other Units-based Sensor",
	SensorTypeMemory:               "Memory",
	0x0D:                           "Drive Slot/Bay",
	0x0E:                           "POST Memory Resize",
	0x0F:                           "System Firmware Progress",
	SensorTypeEventLoggingDisabled: "Event Logging Disabled",
	0x11:                           "Watchdog",
	0x12:                           "System Event",
	0x13:                           "Critical Interrupt",
	0x14:                           "Button/Switch",
	0x15:                           "Module/Board",
	0x16:                           "Microcontroller/Coprocessor",
	0x17:                           "Add-in Card",
	0x18:                           "Chassis",
	0x19:                           "ChipSet",
	0x1A:                           "Other FRU",
	0x1B:                           "Cable/Interconnect",
	0x1C:                           "Terminator",
	0x1D:                           "SystemBoot/Restart",
	0x1E:                           "Boot Error",
	0x1F:                           "BaseOSBoot/InstallationStatus",
	0x20:                           "OS Stop/Shutdown",
	0x21:                           "Slot/Connector",
	0x22:                           "System ACPI PowerState",
	0x23:                           "Watchdog",
	0x24:                           "Platform Alert",
	0x25:                           "Entity Presence",
	0x26:                           "Monitor ASIC/IC",
	0x27:                           "LAN",
	0x28:                           "Management Subsystem Health",
	0x29:                           "Battery",
	0x2A:                           "Session Audit",
	0x2B:                           "Version Change",
	0x2C:                           "FRUState",
}

// sensorTypeCodes is the inverse of sensorTypeNames for Redfish entries,
// keyed by normalizeSensorType so that a firmware that spaces or cases a
// name differently from the schema ("Power Supply/Converter", "FRU
// State", "chip set") still resolves. Where two codes share a name
// (Watchdog, 0x11 and 0x23) the lower code wins.
var sensorTypeCodes = func() map[string]uint8 {
	m := make(map[string]uint8, len(sensorTypeNames))
	for code, name := range sensorTypeNames {
		key := normalizeSensorType(name)
		if existing, dup := m[key]; !dup || code < existing {
			m[key] = code
		}
	}
	return m
}()

// normalizeSensorType folds case and drops whitespace so schema and
// vendor spellings of a sensor-type name compare equal.
func normalizeSensorType(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), ""))
}

// SensorTypeCode resolves a Redfish SensorType name to its IPMI code,
// tolerant of spacing and case; ok is false for an unknown name.
func SensorTypeCode(name string) (uint8, bool) {
	code, ok := sensorTypeCodes[normalizeSensorType(name)]
	return code, ok
}

// SensorTypeName returns the DSP8010 name for an IPMI sensor-type code,
// or "" when the code is not one the reader classifies.
func SensorTypeName(code uint8) string {
	return sensorTypeNames[code]
}

// EventLogEntry is one System Event Log record, in the shape both
// transports produce.
type EventLogEntry struct {
	// ID is the record identifier: the IPMI record ID, or the Redfish
	// LogEntry Id.
	ID string `json:"id" yaml:"id"`
	// Timestamp is when the BMC logged the event. Zero when the record
	// carries none (IPMI "unspecified" timestamps).
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	// SensorType is the DSP8010 sensor-type name ("Memory", "Event
	// Logging Disabled", ...). Empty when the code is unknown.
	SensorType string `json:"sensor_type" yaml:"sensor_type"`
	// SensorTypeCode is the IPMI sensor-type code; 0 when unknown.
	SensorTypeCode uint8 `json:"sensor_type_code" yaml:"sensor_type_code"`
	// SensorNumber identifies the sensor within the BMC.
	SensorNumber uint8 `json:"sensor_number" yaml:"sensor_number"`
	// Sensor is the sensor's ID string from the SDR ("DIMMB1") when the
	// transport can resolve it; empty otherwise.
	Sensor string `json:"sensor,omitempty" yaml:"sensor,omitempty"`
	// Message is the decoded event: "Uncorrectable ECC", "SEL full", or
	// the BMC's own text for Redfish entries.
	Message string `json:"message" yaml:"message"`
	// Asserted is false for a deassertion record.
	Asserted bool `json:"asserted" yaml:"asserted"`
	// EventOffset is the sensor-specific event offset (low nibble of
	// event data 1) for sensor-specific records; 0xFF when not applicable.
	EventOffset uint8 `json:"event_offset" yaml:"event_offset"`
	// EventData is the raw three event-data bytes (IPMI) or zero.
	EventData [3]byte `json:"event_data" yaml:"event_data"`
}

// IsMemoryFault reports whether the entry is an asserted memory error:
// correctable or uncorrectable ECC, parity, scrub failure, a disabled
// device, or the correctable-logging limit being hit.
func (e *EventLogEntry) IsMemoryFault() bool {
	if !e.Asserted || e.SensorTypeCode != SensorTypeMemory {
		return false
	}
	switch e.EventOffset {
	case MemoryEventCorrectableECC, MemoryEventUncorrectableECC, MemoryEventParity,
		MemoryEventScrubFailed, MemoryEventDeviceDisabled, MemoryEventCorrectableLimit:
		return true
	}
	return false
}

// IsLogFull reports whether the entry says the BMC stopped logging:
// "SEL full" or "all event logging disabled".
func (e *EventLogEntry) IsLogFull() bool {
	if !e.Asserted || e.SensorTypeCode != SensorTypeEventLoggingDisabled {
		return false
	}
	return e.EventOffset == LoggingEventSELFull || e.EventOffset == LoggingEventAllDisabled
}

// EventLog is the BMC's System Event Log as read by Client.GetEventLog.
type EventLog struct {
	// Entries is every record read, oldest first: IPMI record order, or
	// Redfish entries stable-sorted by Created (entries without a
	// timestamp sort first, in the order the service returned them).
	Entries []EventLogEntry `json:"entries" yaml:"entries"`
	// EntryCount is the count the BMC reports, which can exceed
	// len(Entries) when the read was capped.
	EntryCount int `json:"entry_count" yaml:"entry_count"`
	// Overflow is the BMC's own "log overflowed / full" flag (IPMI Get
	// SEL Info overflow bit, or a Redfish log at MaxNumberOfRecords).
	Overflow bool `json:"overflow" yaml:"overflow"`
	// FreeBytes is the free space the BMC reports; -1 when the transport
	// does not expose it.
	FreeBytes int `json:"free_bytes" yaml:"free_bytes"`
	// LastAddition is when the newest record was added; zero if unknown.
	LastAddition time.Time `json:"last_addition" yaml:"last_addition"`
	// Truncated is true when the reader stopped at its own entry cap
	// with records still unread. The entries present are complete and
	// in order; a consumer that needs the whole log must say so.
	Truncated bool `json:"truncated,omitempty" yaml:"truncated,omitempty"`
}

// Full reports whether the log has stopped accepting events: the BMC's
// overflow flag, no free space, or a logged "SEL full" event.
func (l *EventLog) Full() bool {
	if l.Overflow || l.FreeBytes == 0 {
		return true
	}
	for i := range l.Entries {
		if l.Entries[i].IsLogFull() {
			return true
		}
	}
	return false
}

// MemoryFaults returns the asserted memory-fault entries, oldest first.
func (l *EventLog) MemoryFaults() []EventLogEntry {
	var out []EventLogEntry
	for i := range l.Entries {
		if l.Entries[i].IsMemoryFault() {
			out = append(out, l.Entries[i])
		}
	}
	return out
}

// describeSensorSpecificEvent names a sensor-specific event offset for
// the sensor types the reader classifies; other types get a generic
// description carrying the raw offset.
func describeSensorSpecificEvent(sensorType, offset uint8) string {
	switch sensorType {
	case SensorTypeMemory:
		if int(offset) < len(memoryEventDescriptions) {
			return memoryEventDescriptions[offset]
		}
	case SensorTypeEventLoggingDisabled:
		if int(offset) < len(loggingEventDescriptions) {
			return loggingEventDescriptions[offset]
		}
	}
	name := sensorTypeNames[sensorType]
	if name == "" {
		name = "Sensor type " + hexByte(sensorType)
	}
	return name + " event offset " + hexByte(offset)
}

// hexByte formats a byte as 0xNN.
func hexByte(b uint8) string {
	return fmt.Sprintf("0x%02x", b)
}
