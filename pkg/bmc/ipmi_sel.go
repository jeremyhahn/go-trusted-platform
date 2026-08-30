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
	"encoding/hex"
	"log/slog"
	"strconv"
	"time"
)

const (
	// selRecordTypeSystemEvent is the standard 16-byte system event record.
	selRecordTypeSystemEvent = 0x02
	// OEM records (IPMI 2.0 §32.2, §32.3) carry vendor data: 0xC0-0xDF
	// with a timestamp and manufacturer id, 0xE0-0xFF without.
	selRecordTypeOEMTimestampedMin    = 0xC0
	selRecordTypeOEMTimestampedMax    = 0xDF
	selRecordTypeOEMNonTimestampedMin = 0xE0
	// selRecordSize is the fixed SEL record length (IPMI 2.0 §32.1).
	selRecordSize = 16
	// selInfoMinLength is the shortest Get SEL Info response the reader
	// accepts: version, entries, free space, add and erase timestamps,
	// operation-support byte.
	selInfoMinLength = 14
	// selInfoOverflowBit flags that events were dropped because the SEL
	// was full (operation-support byte, bit 7).
	selInfoOverflowBit = 0x80
	// selMaxEntries caps a read so a runaway "next record" chain on a
	// buggy BMC cannot spin forever; real SELs top out well below it.
	selMaxEntries = 4096
	// selFirstRecordID and selLastRecordID bracket a full-log walk.
	selFirstRecordID = 0x0000
	selLastRecordID  = 0xFFFF
	// selTimestampUnspecified marks a record with no usable timestamp.
	selTimestampUnspecified = 0xFFFFFFFF
	// selTimestampInitMax is the upper bound of the "BMC uptime, not
	// wall clock" timestamp range (0x00000000–0x20000000).
	selTimestampInitMax = 0x20000000
	// selEventDirDeassert is the event direction bit (byte 12, bit 7).
	selEventDirDeassert = 0x80
)

// GetEventLog reads the SEL through Get SEL Info and a Get SEL Entry walk
// (IPMI 2.0 §31). Sensor numbers are resolved to SDR ID strings when the
// SDR repository can be read; a failed SDR read degrades to unnamed
// sensors rather than failing the log.
func (c *ipmiClient) GetEventLog(ctx context.Context) (*EventLog, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrEventLogRead{Operation: "info", Cause: err}
	}
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	infoResp, err := c.session.Send(netFnStorage, cmdGetSELInfo, nil)
	if err != nil {
		return nil, ErrEventLogRead{Operation: "info", Cause: err}
	}
	if len(infoResp) < selInfoMinLength {
		return nil, ErrEventLogRead{Operation: "info", Cause: ErrSDRResponseTooShort{
			Operation: "SEL info", Length: len(infoResp), Expected: selInfoMinLength}}
	}
	log := &EventLog{
		EntryCount:   int(binary.LittleEndian.Uint16(infoResp[1:3])),
		FreeBytes:    int(binary.LittleEndian.Uint16(infoResp[3:5])),
		LastAddition: selTimestamp(binary.LittleEndian.Uint32(infoResp[5:9])),
		Overflow:     infoResp[13]&selInfoOverflowBit != 0,
	}
	if log.EntryCount == 0 {
		return log, nil
	}

	names := c.sensorNames()

	nextID := uint16(selFirstRecordID)
	for len(log.Entries) < selMaxEntries && nextID != selLastRecordID {
		// The session has no per-command context; honour cancellation
		// between records so a long SEL walk can be abandoned.
		if err := ctx.Err(); err != nil {
			return nil, ErrEventLogRead{Operation: "entry " + strconv.Itoa(int(nextID)), Cause: err}
		}
		req := make([]byte, 6)
		binary.LittleEndian.PutUint16(req[0:2], 0) // no reservation: whole-record reads
		binary.LittleEndian.PutUint16(req[2:4], nextID)
		req[4] = 0    // offset into record
		req[5] = 0xFF // read the entire record
		resp, err := c.session.Send(netFnStorage, cmdGetSELEntry, req)
		if err != nil {
			return nil, ErrEventLogRead{Operation: "entry " + strconv.Itoa(int(nextID)), Cause: err}
		}
		if len(resp) < 2+selRecordSize {
			return nil, ErrEventLogRead{Operation: "entry " + strconv.Itoa(int(nextID)), Cause: ErrSDRResponseTooShort{
				Operation: "SEL entry", Length: len(resp), Expected: 2 + selRecordSize}}
		}
		following := binary.LittleEndian.Uint16(resp[0:2])
		log.Entries = append(log.Entries, parseSELRecord(resp[2:2+selRecordSize], names))
		if following == nextID {
			// A BMC that echoes the same ID would loop forever, and a
			// log read up to that point is not the log: the caller
			// would classify a partial record as complete.
			return nil, ErrEventLogRead{Operation: "entry " + strconv.Itoa(int(nextID)),
				Cause: ErrEventLogWalkStalled{RecordID: nextID, Read: len(log.Entries), Reported: log.EntryCount}}
		}
		nextID = following
	}
	if nextID != selLastRecordID {
		// The safety cap stopped the walk with records still unread.
		log.Truncated = true
		c.logger.Warn("bmc: SEL walk truncated at the entry cap",
			slog.Int("cap", selMaxEntries),
			slog.Int("reported", log.EntryCount))
	}
	return log, nil
}

// sensorNames maps sensor numbers to SDR ID strings, best effort.
func (c *ipmiClient) sensorNames() map[uint8]string {
	records, err := c.readSDRRepository()
	if err != nil {
		c.logger.Debug("bmc: SDR read for SEL sensor names failed, entries stay unnamed",
			slog.String("error", err.Error()))
		return nil
	}
	names := make(map[uint8]string, len(records))
	for _, r := range records {
		names[r.SensorNumber] = r.Name
	}
	return names
}

// parseSELRecord decodes one 16-byte SEL record (IPMI 2.0 table 32-1):
//
//	0-1  record id      2 type      3-6 timestamp    7-8 generator id
//	9    evm rev        10 sensor type   11 sensor number
//	12   event dir (bit 7) | event/reading type (bits 6:0)
//	13-15 event data 1..3
func parseSELRecord(rec []byte, names map[uint8]string) EventLogEntry {
	entry := EventLogEntry{
		ID:          strconv.Itoa(int(binary.LittleEndian.Uint16(rec[0:2]))),
		Asserted:    true,
		EventOffset: 0xFF,
	}
	switch {
	case rec[2] >= selRecordTypeOEMTimestampedMin && rec[2] <= selRecordTypeOEMTimestampedMax:
		// Timestamped OEM record: timestamp at 3-6, manufacturer id at
		// 7-9, six OEM-defined bytes at 10-15.
		entry.Timestamp = selTimestamp(binary.LittleEndian.Uint32(rec[3:7]))
		manufacturer := uint32(rec[7]) | uint32(rec[8])<<8 | uint32(rec[9])<<16
		entry.Message = "OEM record type " + hexByte(rec[2]) + " (manufacturer " + strconv.Itoa(int(manufacturer)) + ") data " + hex.EncodeToString(rec[10:16])
		copy(entry.EventData[:], rec[13:16])
		return entry
	case rec[2] >= selRecordTypeOEMNonTimestampedMin:
		// Non-timestamped OEM record: thirteen OEM-defined bytes at 3-15.
		entry.Message = "OEM record type " + hexByte(rec[2]) + " data " + hex.EncodeToString(rec[3:16])
		copy(entry.EventData[:], rec[13:16])
		return entry
	case rec[2] != selRecordTypeSystemEvent:
		entry.Message = "reserved record type " + hexByte(rec[2]) + " data " + hex.EncodeToString(rec[3:16])
		copy(entry.EventData[:], rec[13:16])
		return entry
	}
	entry.Timestamp = selTimestamp(binary.LittleEndian.Uint32(rec[3:7]))
	entry.SensorTypeCode = rec[10]
	entry.SensorType = sensorTypeNames[rec[10]]
	entry.SensorNumber = rec[11]
	entry.Sensor = names[rec[11]]
	entry.Asserted = rec[12]&selEventDirDeassert == 0
	copy(entry.EventData[:], rec[13:16])

	readingType := rec[12] &^ selEventDirDeassert
	if readingType == sensorSpecificEventReadingType {
		entry.EventOffset = rec[13] & 0x0F
		entry.Message = describeSensorSpecificEvent(rec[10], entry.EventOffset)
	} else {
		name := entry.SensorType
		if name == "" {
			name = "Sensor type " + hexByte(rec[10])
		}
		entry.Message = name + " event (reading type " + hexByte(readingType) + ")"
	}
	return entry
}

// selTimestamp converts an IPMI SEL timestamp to wall-clock time. The
// "unspecified" sentinel and the BMC-uptime range (a BMC that has not
// learned the time yet) both yield the zero time.
func selTimestamp(ts uint32) time.Time {
	if ts == selTimestampUnspecified || ts < selTimestampInitMax {
		return time.Time{}
	}
	return time.Unix(int64(ts), 0).UTC()
}
