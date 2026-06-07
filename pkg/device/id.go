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

package device

import (
	"sync/atomic"
	"time"
)

// deviceIDCounter is a process-local monotonic counter combined with a
// time-derived prefix to mint unique uint64 device IDs whose values fit
// inside the JavaScript safe-integer range. Used by every internal
// caller that allocates a new Device record — the REST CreateDevice
// handler, the ACME enrollment finalize hook, etc.
var deviceIDCounter atomic.Uint64

// NewID returns a unique uint64 device ID that is safe to serialise as
// a JSON number for browsers.
//
// JavaScript Numbers can only safely represent integers up to 2^53-1
// (9007199254740991). uint64 IDs above that lose precision when the
// WebUI rounds them in a JSON.parse, breaking subsequent GET/PUT/DELETE
// calls that round-trip the id through the URL.
//
// The id is composed as:
//
//	top 21 bits = seconds since 2024-01-01 (~30 years of headroom)
//	low 32 bits = a process-local monotonic counter
//
// This stays within 2^53-1 while remaining monotonic within a process
// and globally unique across daemon restarts (the time prefix advances
// each restart). Each caller that needs a Device id should funnel
// through this helper so the wire format stays consistent.
func NewID() uint64 {
	const epoch2024 = uint64(1704067200) // 2024-01-01T00:00:00Z
	const lowMask = uint64(1)<<32 - 1
	const hiMask = uint64(1)<<21 - 1

	now := uint64(time.Now().Unix())
	if now < epoch2024 {
		now = epoch2024
	}
	hi := (now - epoch2024) & hiMask
	lo := deviceIDCounter.Add(1) & lowMask
	id := (hi << 32) | lo
	if id == 0 {
		// Extremely unlikely (would need epoch=0 + counter wrap), but
		// the device service rejects a zero id, so guard against the
		// sentinel.
		id = 1
	}
	return id
}
