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

package quicwire

// Wire body of the physical-TPM event log sub-opcode (OpTPM2Category ·
// SubOpTPM2EventLog). The server handler and the SDK QUIC transport share it,
// so both ends encode one shape; the entries mirror gRPC GetEventLogResponse
// (#2069).

// TPM2EventLogResponse represents an event log response: the raw TCG2 log
// and, when it parses, one entry per measured event.
type TPM2EventLogResponse struct {
	EventLog   []byte              `codec:"event_log"`
	Format     string              `codec:"format"`
	EventCount uint64              `codec:"event_count"`
	Timestamp  int64               `codec:"timestamp"`
	Entries    []TPM2EventLogEntry `codec:"entries"`
}

// TPM2EventLogEntry is one parsed PCR extend from the TCG2 event log.
type TPM2EventLogEntry struct {
	EventNum    uint32            `codec:"event_num"`
	PCRIndex    uint32            `codec:"pcr_index"`
	EventType   string            `codec:"event_type"`
	DigestCount uint32            `codec:"digest_count"`
	Digests     []TPM2EventDigest `codec:"digests"`
	EventSize   uint32            `codec:"event_size"`
	EventString string            `codec:"event_string"`
}

// TPM2EventDigest is one bank's hash digest of a TCG2 event (hex encoded).
type TPM2EventDigest struct {
	AlgorithmID string `codec:"algorithm_id"`
	Digest      string `codec:"digest"`
}
