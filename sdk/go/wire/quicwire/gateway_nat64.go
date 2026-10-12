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

// NAT64 sub-opcodes. The gateway category runs 0x01-0x2D, the load
// balancer claims 0x30-0x35 and perf 0x36-0x38, so the NAT64 translator
// takes the next free slot.
const (
	// OpGatewayNAT64Status returns the NAT64 translator's health.
	OpGatewayNAT64Status byte = 0x39
)

// NAT64StatusInfo is a point-in-time snapshot of the NAT64 translator.
// Every field except the identity pair is what the kernel reported, not
// what the configuration asked for: a started service whose instance has
// gone reports InstancePresent false.
type NAT64StatusInfo struct {
	Active          bool   `codec:"active"`
	InstancePresent bool   `codec:"instance_present"`
	Prefix          string `codec:"prefix"`
	Instance        string `codec:"instance"`
	Sessions        uint64 `codec:"sessions"`
	Pool4Used       uint64 `codec:"pool4_used"`
	ModuleVersion   string `codec:"module_version,omitempty"`
	FlowCount       int    `codec:"flow_count"`
	LastReconcile   int64  `codec:"last_reconcile,omitempty"`
	LastError       string `codec:"last_error,omitempty"`
}

// GatewayNAT64StatusRequest represents a NAT64 status request.
type GatewayNAT64StatusRequest struct{}

// GatewayNAT64StatusResponse represents a NAT64 status response.
type GatewayNAT64StatusResponse struct {
	Status    *NAT64StatusInfo `codec:"status"`
	Timestamp int64            `codec:"timestamp"`
}
