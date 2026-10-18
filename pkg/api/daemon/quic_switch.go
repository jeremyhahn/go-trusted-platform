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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// QUIC switch handlers
// =============================================================================
//
// The SDK QUIC transport adapter routes every SwitchService method to
// OpSwitchCategory (0xCC) with the SwitchSub* sub-opcode in payload[0] and the
// platform.v1 request message in payload[1:]. Every sub-opcode calls the same
// SwitchService servicer the gRPC, MCP and Unix transports use, so the QUIC
// path has no logic of its own and answers each refusal with the gRPC code's
// QUIC status.

// switchQUICHandlers maps each switch sub-opcode to its SwitchService method.
var switchQUICHandlers = map[byte]appQUICHandler{
	quicwire.SwitchSubListPorts:     appQUICCall("SwitchListPorts", quicSwitchServer, platformv1.SwitchServiceServer.ListPorts),
	quicwire.SwitchSubGetPortStatus: appQUICCall("SwitchGetPortStatus", quicSwitchServer, platformv1.SwitchServiceServer.GetPortStatus),
	quicwire.SwitchSubSetPortVLAN:   appQUICCall("SwitchSetPortVLAN", quicSwitchServer, platformv1.SwitchServiceServer.SetPortVLAN),
	quicwire.SwitchSubEnablePort:    appQUICCall("SwitchEnablePort", quicSwitchServer, platformv1.SwitchServiceServer.EnablePort),
	quicwire.SwitchSubDisablePort:   appQUICCall("SwitchDisablePort", quicSwitchServer, platformv1.SwitchServiceServer.DisablePort),
}

func quicSwitchServer(h *QUICServiceHandler) platformv1.SwitchServiceServer {
	return h.switchServer
}

// SetSwitchServer wires the SwitchService servicer the switch sub-opcodes
// delegate to. Until it is set every switch sub-opcode answers unavailable.
func (h *QUICServiceHandler) SetSwitchServer(server platformv1.SwitchServiceServer) {
	h.switchServer = server
}
