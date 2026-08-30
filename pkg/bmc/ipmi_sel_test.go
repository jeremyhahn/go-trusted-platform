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
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// selInfo builds a Get SEL Info response.
func selInfo(entries, free uint16, lastAdd uint32, overflow bool) []byte {
	resp := make([]byte, 14)
	resp[0] = 0x51
	binary.LittleEndian.PutUint16(resp[1:3], entries)
	binary.LittleEndian.PutUint16(resp[3:5], free)
	binary.LittleEndian.PutUint32(resp[5:9], lastAdd)
	binary.LittleEndian.PutUint32(resp[9:13], lastAdd)
	if overflow {
		resp[13] = selInfoOverflowBit
	}
	return resp
}

// selRecord builds a 16-byte system event record.
func selRecord(id uint16, ts uint32, sensorType, sensorNum, eventDir uint8, data [3]byte) []byte {
	rec := make([]byte, selRecordSize)
	binary.LittleEndian.PutUint16(rec[0:2], id)
	rec[2] = selRecordTypeSystemEvent
	binary.LittleEndian.PutUint32(rec[3:7], ts)
	rec[7], rec[8] = 0x20, 0x00
	rec[9] = 0x04
	rec[10] = sensorType
	rec[11] = sensorNum
	rec[12] = eventDir
	copy(rec[13:16], data[:])
	return rec
}

// selEntryResponse wraps a record with its next-record id.
func selEntryResponse(next uint16, rec []byte) []byte {
	resp := make([]byte, 2, 2+len(rec))
	binary.LittleEndian.PutUint16(resp[0:2], next)
	return append(resp, rec...)
}

// sequencedSession answers Get SEL Entry with a different record per
// request, in order, and everything else from the fake's tables.
type sequencedSession struct {
	*fakeIPMISession
	entries [][]byte
	calls   int
}

func (s *sequencedSession) Send(netfn, cmd byte, data []byte) ([]byte, error) {
	if netfn == netFnStorage && cmd == cmdGetSELEntry {
		s.calls++
		if s.calls > len(s.entries) {
			return nil, errors.New("walked past the last record")
		}
		return s.entries[s.calls-1], nil
	}
	return s.fakeIPMISession.Send(netfn, cmd, data)
}

const testTimestamp = uint32(1_700_000_000)

func TestIPMIGetEventLog_ParsesRecordsAndNames(t *testing.T) {
	fake := newFakeIPMISession()
	fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(3, 0, testTimestamp, true)
	// SDR repository: one full record naming sensor 0x1A "DIMMB1".
	fake.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 0x01, 0x00, 0x00, 0x00, 0x00}
	fake.responses[ipmiKey(netFnStorage, cmdReserveSDRRepository)] = []byte{0x01, 0x00}
	fake.responses[ipmiKey(netFnStorage, cmdGetSDR)] = selEntryResponse(0xFFFF, fullSensorRecord(0x1A, SensorTypeMemory, "DIMMB1"))

	session := &sequencedSession{fakeIPMISession: fake, entries: [][]byte{
		selEntryResponse(1, selRecord(0, testTimestamp, SensorTypeMemory, 0x1A, sensorSpecificEventReadingType, [3]byte{0xA0 | MemoryEventCorrectableECC, 0x00, 0x01})),
		selEntryResponse(2, selRecord(1, testTimestamp+60, SensorTypeEventLoggingDisabled, 0x40, sensorSpecificEventReadingType, [3]byte{LoggingEventSELFull, 0xFF, 0xFF})),
		selEntryResponse(0xFFFF, selRecord(2, selTimestampUnspecified, SensorTypeMemory, 0x1A, sensorSpecificEventReadingType|selEventDirDeassert, [3]byte{MemoryEventUncorrectableECC, 0, 0})),
	}}
	client := oemTestClient(session)

	log, err := client.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !log.Overflow || log.FreeBytes != 0 || log.EntryCount != 3 {
		t.Errorf("header mis-parsed: %+v", log)
	}
	if !log.LastAddition.Equal(time.Unix(int64(testTimestamp), 0)) {
		t.Errorf("last addition = %v", log.LastAddition)
	}
	if len(log.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(log.Entries))
	}

	first := log.Entries[0]
	if first.ID != "0" || first.SensorType != "Memory" || first.Sensor != "DIMMB1" || first.SensorNumber != 0x1A {
		t.Errorf("first entry identity: %+v", first)
	}
	if first.Message != "Correctable ECC" || first.EventOffset != MemoryEventCorrectableECC || !first.Asserted || !first.IsMemoryFault() {
		t.Errorf("first entry decode: %+v", first)
	}
	if first.EventData != [3]byte{0xA0, 0x00, 0x01} {
		t.Errorf("event data not preserved: %v", first.EventData)
	}

	second := log.Entries[1]
	if second.Message != "SEL full" || !second.IsLogFull() || second.Sensor != "" {
		t.Errorf("second entry: %+v", second)
	}
	if !second.Timestamp.Equal(time.Unix(int64(testTimestamp)+60, 0)) {
		t.Errorf("second timestamp = %v", second.Timestamp)
	}

	third := log.Entries[2]
	if third.Asserted || third.IsMemoryFault() || !third.Timestamp.IsZero() {
		t.Errorf("deasserted/unspecified-timestamp entry: %+v", third)
	}
	if !log.Full() || len(log.MemoryFaults()) != 1 {
		t.Errorf("classification: full=%v faults=%d", log.Full(), len(log.MemoryFaults()))
	}
}

func TestIPMIGetEventLog_EmptyLogSkipsWalk(t *testing.T) {
	fake := newFakeIPMISession()
	fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(0, 8192, 0, false)
	client := oemTestClient(fake)

	log, err := client.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(log.Entries) != 0 || log.Full() || log.FreeBytes != 8192 {
		t.Errorf("empty log: %+v", log)
	}
	if fake.countSends(netFnStorage, cmdGetSELEntry) != 0 || fake.countSends(netFnStorage, cmdGetSDRRepositoryInfo) != 0 {
		t.Error("an empty SEL must not walk entries or read the SDR")
	}
}

func TestIPMIGetEventLog_Errors(t *testing.T) {
	t.Run("info transport error", func(t *testing.T) {
		fake := newFakeIPMISession()
		sentinel := errors.New("no route")
		fake.errs[ipmiKey(netFnStorage, cmdGetSELInfo)] = sentinel
		_, err := oemTestClient(fake).GetEventLog(context.Background())
		var readErr ErrEventLogRead
		if !errors.As(err, &readErr) || readErr.Operation != "info" || !errors.Is(err, sentinel) {
			t.Fatalf("expected ErrEventLogRead{info} wrapping the cause, got %v", err)
		}
	})
	t.Run("info too short", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = []byte{0x51, 0x01}
		_, err := oemTestClient(fake).GetEventLog(context.Background())
		var short ErrSDRResponseTooShort
		if !errors.As(err, &short) {
			t.Fatalf("expected a too-short error, got %v", err)
		}
	})
	t.Run("entry error mid-walk", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(2, 100, 0, false)
		fake.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = errors.New("sdr unavailable")
		fake.errs[ipmiKey(netFnStorage, cmdGetSELEntry)] = errors.New("reservation cancelled")
		_, err := oemTestClient(fake).GetEventLog(context.Background())
		var readErr ErrEventLogRead
		if !errors.As(err, &readErr) || readErr.Operation != "entry 0" {
			t.Fatalf("expected ErrEventLogRead{entry 0}, got %v", err)
		}
	})
	t.Run("entry too short", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(1, 100, 0, false)
		fake.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = errors.New("sdr unavailable")
		fake.responses[ipmiKey(netFnStorage, cmdGetSELEntry)] = []byte{0xFF, 0xFF, 0x00}
		_, err := oemTestClient(fake).GetEventLog(context.Background())
		var readErr ErrEventLogRead
		if !errors.As(err, &readErr) {
			t.Fatalf("expected ErrEventLogRead, got %v", err)
		}
	})
	t.Run("closed client", func(t *testing.T) {
		client := oemTestClient(newFakeIPMISession())
		client.closed.Store(true)
		_, err := client.GetEventLog(context.Background())
		var closed ErrClientClosed
		if !errors.As(err, &closed) {
			t.Fatalf("expected ErrClientClosed, got %v", err)
		}
	})
	t.Run("unopened client does not panic", func(t *testing.T) {
		// No session yet: ensureOpen tries to connect to the configured
		// (unreachable) endpoint and returns a typed error instead of a
		// nil-session panic.
		client := oemTestClient(nil)
		client.config.Address = "127.0.0.1"
		client.config.Port = 1
		_, err := client.GetEventLog(context.Background())
		var connErr ErrConnectionFailed
		if !errors.As(err, &connErr) {
			t.Fatalf("expected ErrConnectionFailed, got %v", err)
		}
	})
	t.Run("cancelled context stops the walk", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(2, 100, 0, false)
		fake.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = errors.New("sdr unavailable")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := oemTestClient(fake).GetEventLog(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if fake.countSends(netFnStorage, cmdGetSELEntry) != 0 {
			t.Error("no entry read after cancellation")
		}
	})
}

func TestIPMIGetEventLog_StalledWalkIsAnError(t *testing.T) {
	fake := newFakeIPMISession()
	fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(5, 100, 0, false)
	fake.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = errors.New("sdr unavailable")
	// The BMC keeps answering "next is record 0" for record 0.
	fake.responses[ipmiKey(netFnStorage, cmdGetSELEntry)] = selEntryResponse(0, selRecord(0, 0, 0x07, 0x01, sensorSpecificEventReadingType, [3]byte{}))
	client := oemTestClient(fake)

	_, err := client.GetEventLog(context.Background())
	var stalled ErrEventLogWalkStalled
	if !errors.As(err, &stalled) || stalled.RecordID != 0 || stalled.Read != 1 || stalled.Reported != 5 {
		t.Fatalf("a repeated next-id must fail the read, not return a partial log: %v", err)
	}
	if fake.countSends(netFnStorage, cmdGetSELEntry) != 1 {
		t.Errorf("the walk stops at the first repeat, got %d reads", fake.countSends(netFnStorage, cmdGetSELEntry))
	}
}

func TestIPMIGetEventLog_EntryCapFlagsTruncation(t *testing.T) {
	fake := newFakeIPMISession()
	fake.responses[ipmiKey(netFnStorage, cmdGetSELInfo)] = selInfo(0xFFFF, 100, 0, false)
	fake.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = errors.New("sdr unavailable")
	// Every record says the next one is id+1: an endless log.
	session := &countingSELSession{fakeIPMISession: fake}
	client := oemTestClient(session)

	log, err := client.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(log.Entries) != selMaxEntries || !log.Truncated {
		t.Fatalf("expected the cap to stop the walk and flag it: entries=%d truncated=%v", len(log.Entries), log.Truncated)
	}
	if log.Entries[0].Message != "Processor event offset 0x00" {
		t.Errorf("generic sensor-specific message: %q", log.Entries[0].Message)
	}
}

// countingSELSession answers every Get SEL Entry with the requested
// record and a next id of request+1.
type countingSELSession struct {
	*fakeIPMISession
}

func (s *countingSELSession) Send(netfn, cmd byte, data []byte) ([]byte, error) {
	if netfn == netFnStorage && cmd == cmdGetSELEntry {
		id := binary.LittleEndian.Uint16(data[2:4])
		return selEntryResponse(id+1, selRecord(id, 0, 0x07, 0x01, sensorSpecificEventReadingType, [3]byte{})), nil
	}
	return s.fakeIPMISession.Send(netfn, cmd, data)
}

func TestParseSELRecord_OEMAndThresholdRecords(t *testing.T) {
	oem := make([]byte, selRecordSize)
	oem[2] = 0xC0
	binary.LittleEndian.PutUint32(oem[3:7], testTimestamp)
	oem[7], oem[8], oem[9] = 0x7C, 0x2A, 0x00 // Supermicro IANA 10876
	oem[10], oem[11], oem[12], oem[13], oem[14], oem[15] = 0xAA, 0xBB, 0xCC, 1, 2, 3
	entry := parseSELRecord(oem, nil)
	if entry.Message != "OEM record type 0xc0 (manufacturer 10876) data aabbcc010203" || entry.EventData != [3]byte{1, 2, 3} || entry.EventOffset != 0xFF {
		t.Errorf("timestamped OEM record: %+v", entry)
	}
	if !entry.Timestamp.Equal(time.Unix(int64(testTimestamp), 0)) {
		t.Errorf("timestamped OEM record must keep its timestamp: %v", entry.Timestamp)
	}

	oemNoTS := make([]byte, selRecordSize)
	oemNoTS[2] = 0xE5
	for i := 3; i < selRecordSize; i++ {
		oemNoTS[i] = byte(i)
	}
	entry = parseSELRecord(oemNoTS, nil)
	if entry.Message != "OEM record type 0xe5 data 0304050607080a0b0c0d0e0f" && entry.Message != "OEM record type 0xe5 data 030405060708090a0b0c0d0e0f" {
		t.Errorf("non-timestamped OEM record: %+v", entry)
	}
	if !entry.Timestamp.IsZero() {
		t.Error("non-timestamped OEM records carry no time")
	}

	reserved := make([]byte, selRecordSize)
	reserved[2] = 0x10
	entry = parseSELRecord(reserved, nil)
	if !strings.HasPrefix(entry.Message, "reserved record type 0x10") {
		t.Errorf("reserved record: %+v", entry)
	}

	threshold := selRecord(7, testTimestamp, 0x01, 0x05, 0x01, [3]byte{0x52, 0x30, 0x40})
	entry = parseSELRecord(threshold, map[uint8]string{0x05: "CPU Temp"})
	if entry.Message != "Temperature event (reading type 0x01)" || entry.Sensor != "CPU Temp" || entry.EventOffset != 0xFF {
		t.Errorf("threshold record: %+v", entry)
	}

	unknown := selRecord(8, testTimestamp, 0xEE, 0x05, 0x03, [3]byte{})
	entry = parseSELRecord(unknown, nil)
	if entry.Message != "Sensor type 0xee event (reading type 0x03)" || entry.SensorType != "" {
		t.Errorf("unknown sensor type: %+v", entry)
	}
}

func TestSELTimestamp(t *testing.T) {
	if !selTimestamp(selTimestampUnspecified).IsZero() {
		t.Error("unspecified must be zero")
	}
	if !selTimestamp(selTimestampInitMax - 1).IsZero() {
		t.Error("BMC-uptime range must be zero")
	}
	if got := selTimestamp(testTimestamp); !got.Equal(time.Unix(int64(testTimestamp), 0)) {
		t.Errorf("wall clock = %v", got)
	}
}

// fullSensorRecord builds a minimal SDR Full Sensor Record (type 0x01)
// carrying a sensor number, type and ID string, in the layout
// parseFullSensorRecord reads.
func fullSensorRecord(sensorNum, sensorType uint8, name string) []byte {
	body := make([]byte, 43+len(name))
	body[2] = sensorNum
	body[7] = sensorType
	body[42] = 0xC0 | uint8(len(name))
	copy(body[43:], name)
	rec := make([]byte, 5, 5+len(body))
	rec[0], rec[1] = 0x01, 0x00
	rec[2] = 0x51
	rec[3] = sdrRecordTypeFull
	rec[4] = uint8(len(body))
	return append(rec, body...)
}
