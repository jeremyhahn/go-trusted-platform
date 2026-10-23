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

package gateway

import (
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Gateway mode names, as the CLI and the MCP tools spell them. Each maps
// to one GatewayModeEnum bit.
const (
	ModeOverlay = "overlay"
	ModeEdge    = "edge"
	ModeTransit = "transit"
)

// modeOrder fixes the order ModeNames reports modes in: lowest bit first.
var modeOrder = []struct {
	name string
	bit  platformv1.GatewayModeEnum
}{
	{ModeOverlay, platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY},
	{ModeEdge, platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE},
	{ModeTransit, platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT},
}

// ErrUnknownGatewayMode reports a mode name that is not overlay, edge or
// transit.
type ErrUnknownGatewayMode struct {
	Mode string
}

func (e *ErrUnknownGatewayMode) Error() string {
	return fmt.Sprintf("unknown gateway mode %q (want %s, %s or %s)", e.Mode, ModeOverlay, ModeEdge, ModeTransit)
}

// ModesFromNames encodes mode names as the GatewayModeEnum bitmask that
// SetGatewayMode takes. An unknown name is an error rather than a silently
// dropped bit; no names encode as zero, which the server refuses.
func ModesFromNames(names []string) (uint32, error) {
	var modes uint32
	for _, name := range names {
		bit, ok := modeBit(name)
		if !ok {
			return 0, &ErrUnknownGatewayMode{Mode: name}
		}
		modes |= bit
	}
	return modes, nil
}

// modeBit returns the GatewayModeEnum bit for one mode name.
func modeBit(name string) (uint32, bool) {
	for _, m := range modeOrder {
		if m.name == name {
			return uint32(m.bit), true
		}
	}
	return 0, false
}

// ModeNames decodes a GatewayModeEnum bitmask into mode names, lowest bit
// first. Bits that name no mode are ignored.
func ModeNames(modes uint32) []string {
	names := make([]string, 0, len(modeOrder))
	for _, m := range modeOrder {
		if modes&uint32(m.bit) != 0 {
			names = append(names, m.name)
		}
	}
	return names
}
