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
	"context"
	"errors"
	"testing"
)

func memoryEntry(offset uint8, asserted bool) EventLogEntry {
	return EventLogEntry{SensorTypeCode: SensorTypeMemory, SensorType: "Memory", EventOffset: offset, Asserted: asserted}
}

func TestEventLogEntry_IsMemoryFault(t *testing.T) {
	faults := []uint8{MemoryEventCorrectableECC, MemoryEventUncorrectableECC, MemoryEventParity,
		MemoryEventScrubFailed, MemoryEventDeviceDisabled, MemoryEventCorrectableLimit}
	for _, off := range faults {
		if e := memoryEntry(off, true); !e.IsMemoryFault() {
			t.Errorf("offset %#x should be a memory fault", off)
		}
	}
	benign := []uint8{MemoryEventPresenceDetected, MemoryEventSpare, MemoryEventThrottled, 0xFF}
	for _, off := range benign {
		if e := memoryEntry(off, true); e.IsMemoryFault() {
			t.Errorf("offset %#x should not be a memory fault", off)
		}
	}
	if e := memoryEntry(MemoryEventUncorrectableECC, false); e.IsMemoryFault() {
		t.Error("a deassertion is not a fault")
	}
	other := EventLogEntry{SensorTypeCode: 0x07, EventOffset: MemoryEventUncorrectableECC, Asserted: true}
	if other.IsMemoryFault() {
		t.Error("a processor event with offset 1 is not a memory fault")
	}
}

func TestEventLogEntry_IsLogFull(t *testing.T) {
	full := EventLogEntry{SensorTypeCode: SensorTypeEventLoggingDisabled, EventOffset: LoggingEventSELFull, Asserted: true}
	if !full.IsLogFull() {
		t.Error("SEL full should report full")
	}
	disabled := EventLogEntry{SensorTypeCode: SensorTypeEventLoggingDisabled, EventOffset: LoggingEventAllDisabled, Asserted: true}
	if !disabled.IsLogFull() {
		t.Error("all logging disabled should report full")
	}
	almost := EventLogEntry{SensorTypeCode: SensorTypeEventLoggingDisabled, EventOffset: LoggingEventSELAlmostFull, Asserted: true}
	if almost.IsLogFull() {
		t.Error("almost full is not full")
	}
	deasserted := EventLogEntry{SensorTypeCode: SensorTypeEventLoggingDisabled, EventOffset: LoggingEventSELFull, Asserted: false}
	if deasserted.IsLogFull() {
		t.Error("a deasserted SEL-full is not full")
	}
}

func TestEventLog_FullAndMemoryFaults(t *testing.T) {
	log := &EventLog{FreeBytes: -1, Entries: []EventLogEntry{
		memoryEntry(MemoryEventCorrectableECC, true),
		{SensorTypeCode: 0x07, Asserted: true, EventOffset: 0},
		memoryEntry(MemoryEventUncorrectableECC, true),
		memoryEntry(MemoryEventPresenceDetected, true),
	}}
	if log.Full() {
		t.Error("no overflow, unknown free space and no SEL-full entry: not full")
	}
	if got := len(log.MemoryFaults()); got != 2 {
		t.Errorf("expected 2 memory faults, got %d", got)
	}

	if !(&EventLog{Overflow: true, FreeBytes: -1}).Full() {
		t.Error("overflow flag means full")
	}
	if !(&EventLog{FreeBytes: 0}).Full() {
		t.Error("zero free bytes means full")
	}
	withEvent := &EventLog{FreeBytes: 100, Entries: []EventLogEntry{
		{SensorTypeCode: SensorTypeEventLoggingDisabled, EventOffset: LoggingEventSELFull, Asserted: true},
	}}
	if !withEvent.Full() {
		t.Error("a logged SEL-full event means full")
	}
	if (&EventLog{FreeBytes: 100}).MemoryFaults() != nil {
		t.Error("no entries: no faults")
	}
}

func TestDescribeSensorSpecificEvent(t *testing.T) {
	cases := []struct {
		sensorType, offset uint8
		want               string
	}{
		{SensorTypeMemory, MemoryEventUncorrectableECC, "Uncorrectable ECC"},
		{SensorTypeMemory, 0x1F, "Memory event offset 0x1f"},
		{SensorTypeEventLoggingDisabled, LoggingEventSELFull, "SEL full"},
		{0x07, 0x02, "Processor event offset 0x02"},
		{0x99, 0x01, "Sensor type 0x99 event offset 0x01"},
	}
	for _, tc := range cases {
		if got := describeSensorSpecificEvent(tc.sensorType, tc.offset); got != tc.want {
			t.Errorf("describe(%#x, %#x) = %q, want %q", tc.sensorType, tc.offset, got, tc.want)
		}
	}
}

func TestSensorTypeName(t *testing.T) {
	if got := SensorTypeName(SensorTypeMemory); got != "Memory" {
		t.Errorf("Memory name = %q", got)
	}
	if got := SensorTypeName(0xEE); got != "" {
		t.Errorf("unknown code should be empty, got %q", got)
	}
	if code, ok := SensorTypeCode("Event Logging Disabled"); !ok || code != SensorTypeEventLoggingDisabled {
		t.Error("inverse map must round-trip")
	}
	// Schema spelling, vendor spelling, and odd casing all resolve.
	for name, want := range map[string]uint8{
		"Power Supply / Converter": 0x08, "Power Supply/Converter": 0x08,
		"PowerUnit": 0x09, "Power Unit": 0x09,
		"FRUState": 0x2C, "FRU State": 0x2C,
		"chip set": 0x19, "ChipSet": 0x19,
		"System ACPI PowerState": 0x22, "system acpi power state": 0x22,
		"Watchdog": 0x11, "memory": SensorTypeMemory,
	} {
		if code, ok := SensorTypeCode(name); !ok || code != want {
			t.Errorf("SensorTypeCode(%q) = %#x, %v; want %#x", name, code, ok, want)
		}
	}
	if _, ok := SensorTypeCode("Unicorn"); ok {
		t.Error("unknown names do not resolve")
	}
	for code, name := range sensorTypeNames {
		if got, ok := SensorTypeCode(name); !ok || (got != code && name != "Watchdog") {
			t.Errorf("name %q for %#x does not round-trip (got %#x)", name, code, got)
		}
	}
}

func TestMockClient_GetEventLog(t *testing.T) {
	m := NewMockClient()
	log, err := m.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log == nil || log.FreeBytes != -1 || len(log.Entries) != 0 {
		t.Fatalf("expected an empty default log, got %+v", log)
	}
	m.Log = &EventLog{Overflow: true}
	got, err := m.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("configured log must not error: %v", err)
	}
	if !got.Overflow {
		t.Error("configured log should be returned")
	}
	sentinel := errors.New("boom")
	m.GetEventLogErr = sentinel
	if _, err := m.GetEventLog(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("expected injected error, got %v", err)
	}
	if m.GetEventLogCalls() != 3 {
		t.Errorf("expected 3 calls, got %d", m.GetEventLogCalls())
	}
}

func TestErrEventLogRead(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrEventLogRead{Operation: "info", Cause: cause}
	if err.Error() != "bmc: event log info failed: timeout" {
		t.Errorf("Error() = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("Unwrap should expose the cause")
	}
	if (ErrEventLogRead{Operation: "entry 3"}).Error() != "bmc: event log entry 3 failed" {
		t.Error("cause-less message")
	}
}
