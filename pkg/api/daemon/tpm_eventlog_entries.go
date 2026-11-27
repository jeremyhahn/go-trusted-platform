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

package daemon

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// eventLogEntries converts the parsed TCG2 events into the proto
// EventLogEntry shape. gRPC GetEventLog answers them as they are and MCP
// platform_tpm_eventlog answers them through eventLogEntryMaps, so both
// transports carry the same fields (docs/SPEC.md:78).
func eventLogEntries(events []xkmssdk.TPMEvent) []*platformv1.EventLogEntry {
	entries := make([]*platformv1.EventLogEntry, 0, len(events))
	for _, ev := range events {
		digests := make([]*platformv1.EventDigest, 0, len(ev.Digests))
		for _, d := range ev.Digests {
			digests = append(digests, &platformv1.EventDigest{
				AlgorithmId: d.AlgorithmId,
				Digest:      d.Digest,
			})
		}
		entries = append(entries, &platformv1.EventLogEntry{
			EventNum:    uint32(ev.EventNum),
			PcrIndex:    uint32(ev.PCRIndex),
			EventType:   ev.EventType,
			DigestCount: uint32(ev.DigestCount),
			Digests:     digests,
			EventSize:   uint32(ev.EventSize),
			EventString: ev.EventString,
		})
	}
	return entries
}

// eventLogEntryMaps renders entries as the MCP tool result's `entries`:
// one map per event with the proto field names in snake_case.
func eventLogEntryMaps(entries []*platformv1.EventLogEntry) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		digests := make([]map[string]interface{}, 0, len(e.GetDigests()))
		for _, d := range e.GetDigests() {
			digests = append(digests, map[string]interface{}{
				"algorithm_id": d.GetAlgorithmId(),
				"digest":       d.GetDigest(),
			})
		}
		out = append(out, map[string]interface{}{
			"event_num":    e.GetEventNum(),
			"pcr_index":    e.GetPcrIndex(),
			"event_type":   e.GetEventType(),
			"digest_count": e.GetDigestCount(),
			"digests":      digests,
			"event_size":   e.GetEventSize(),
			"event_string": e.GetEventString(),
		})
	}
	return out
}
