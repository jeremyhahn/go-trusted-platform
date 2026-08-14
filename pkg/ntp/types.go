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

package ntp

import "time"

// LeapNotSynchronised is the leap status chronyd reports while the clock is
// not disciplined. It is the primary "am I synchronized?" signal.
const LeapNotSynchronised = "Not synchronised"

// UnsyncedStratum is the stratum chronyd reports when it has no reference.
const UnsyncedStratum = 0

// MaxStratum is the first stratum value that means "unusable" in NTP.
const MaxStratum = 16

// LargeStepThreshold is the correction magnitude that, observed AFTER the
// first-boot correction, is treated as an anomaly worth flagging in health
// status rather than silently accepted. A healthy disciplined clock stays
// orders of magnitude below this.
const LargeStepThreshold = time.Second

// Status is the platform's view of chronyd's tracking state.
type Status struct {
	// Synced reports whether chronyd currently disciplines the clock.
	Synced bool `json:"synced"`

	// Stratum is the node's distance from a reference clock. 0 means
	// unsynchronized; 16 means unusable.
	Stratum uint32 `json:"stratum"`

	// LeapStatus is chronyd's leap indicator ("Normal", "Insert second",
	// "Delete second", "Not synchronised").
	LeapStatus string `json:"leap_status"`

	// OffsetSeconds is the current system time offset. Positive means the
	// system clock is ahead of the reference.
	OffsetSeconds float64 `json:"offset_seconds"`

	// RootDispersion is the accumulated dispersion to the reference clock,
	// in seconds. It bounds the maximum error.
	RootDispersion float64 `json:"root_dispersion"`

	// RootDelay is the accumulated round-trip delay to the reference
	// clock, in seconds.
	RootDelay float64 `json:"root_delay"`

	// LastSync is the reference timestamp of the last successful update.
	LastSync time.Time `json:"last_sync"`

	// Mode echoes the configured serve/consume/both role.
	Mode string `json:"mode"`

	// ReferenceID is chronyd's hex reference identifier.
	ReferenceID string `json:"reference_id"`

	// ReferenceName is the human-readable name or address of the current
	// reference.
	ReferenceName string `json:"reference_name"`

	// SourcesReachable is the number of sources chronyd can currently
	// reach.
	SourcesReachable uint32 `json:"sources_reachable"`

	// SourcesTotal is the number of configured sources.
	SourcesTotal uint32 `json:"sources_total"`

	// Anomaly is set when a large correction was observed after the
	// first-boot correction, which on a trusted platform indicates either
	// a failing oscillator or a hostile time source.
	Anomaly bool `json:"anomaly"`

	// AnomalyReason explains Anomaly in operator-readable form.
	AnomalyReason string `json:"anomaly_reason,omitempty"`
}

// Healthy reports whether the node's clock can be trusted for attestation,
// certificate, and token validity decisions.
func (s *Status) Healthy() bool {
	if s == nil {
		return false
	}
	return s.Synced && !s.Anomaly && s.Stratum > UnsyncedStratum && s.Stratum < MaxStratum
}

// SourceState is the single-character selection state chronyd assigns to a
// source, expanded into a readable word.
type SourceState string

const (
	// SourceStateSelected is chronyd's current synchronization source.
	SourceStateSelected SourceState = "selected"

	// SourceStateCombined participates in the combined estimate.
	SourceStateCombined SourceState = "combined"

	// SourceStateExcluded was excluded by the combining algorithm.
	SourceStateExcluded SourceState = "excluded"

	// SourceStateUnreachable has not answered recently.
	SourceStateUnreachable SourceState = "unreachable"

	// SourceStateFalseTicker disagrees with the majority.
	SourceStateFalseTicker SourceState = "falseticker"

	// SourceStateJittery has too much variability to be usable.
	SourceStateJittery SourceState = "jittery"

	// SourceStateUnknown covers any state chronyd adds in the future.
	SourceStateUnknown SourceState = "unknown"
)

// sourceStates maps chronyd's single-character state column to the readable
// SourceState vocabulary (map-based for O(1) lookup).
var sourceStates = map[string]SourceState{
	"*": SourceStateSelected,
	"+": SourceStateCombined,
	"-": SourceStateExcluded,
	"?": SourceStateUnreachable,
	"x": SourceStateFalseTicker,
	"~": SourceStateJittery,
}

// parseSourceState converts chronyd's state column to a SourceState.
func parseSourceState(raw string) SourceState {
	if state, ok := sourceStates[raw]; ok {
		return state
	}
	return SourceStateUnknown
}

// SourceMode is chronyd's source-kind column, expanded into a readable word.
type SourceMode string

const (
	// SourceModeServer is a unicast NTP server.
	SourceModeServer SourceMode = "server"

	// SourceModePeer is a symmetric peer.
	SourceModePeer SourceMode = "peer"

	// SourceModeRefClock is a local reference clock (PPS, GPS).
	SourceModeRefClock SourceMode = "refclock"

	// SourceModeUnknown covers any mode chronyd adds in the future.
	SourceModeUnknown SourceMode = "unknown"
)

// sourceModes maps chronyd's mode column to the readable SourceMode
// vocabulary (map-based for O(1) lookup).
var sourceModes = map[string]SourceMode{
	"^": SourceModeServer,
	"=": SourceModePeer,
	"#": SourceModeRefClock,
}

// parseSourceMode converts chronyd's mode column to a SourceMode.
func parseSourceMode(raw string) SourceMode {
	if mode, ok := sourceModes[raw]; ok {
		return mode
	}
	return SourceModeUnknown
}

// Source is one configured time source and its live measurement state.
type Source struct {
	// Address is the source's host name or IP.
	Address string `json:"address"`

	// Mode is server, peer, or refclock.
	Mode SourceMode `json:"mode"`

	// State is chronyd's selection verdict for this source.
	State SourceState `json:"state"`

	// Stratum is the source's own distance from a reference clock.
	Stratum uint32 `json:"stratum"`

	// PollSeconds is the current polling interval in seconds.
	PollSeconds uint32 `json:"poll_seconds"`

	// Reach is the 8-bit reachability shift register. 255 means the last
	// eight polls all succeeded.
	Reach uint32 `json:"reach"`

	// LastRxSeconds is how long ago the last sample arrived.
	LastRxSeconds int64 `json:"last_rx_seconds"`

	// OffsetSeconds is the last measured offset for this source.
	OffsetSeconds float64 `json:"offset_seconds"`

	// Reachable reports whether chronyd has heard from the source
	// recently (any bit set in the reachability register).
	Reachable bool `json:"reachable"`
}
