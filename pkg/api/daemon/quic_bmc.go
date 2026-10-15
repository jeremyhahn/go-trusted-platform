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
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// QUIC BMC handlers
// =============================================================================
//
// OpBMCCategory (0x9F) carries every BMCService method: the first payload
// byte is the BMCSub* sub-opcode, the rest is the method's request message.
// Each sub-opcode calls the same BMCService servicer the gRPC, REST, MCP and
// embedded transports use, so the QUIC path has no logic of its own.

// bmcQUICHandlers maps each BMC sub-opcode to its BMCService method.
var bmcQUICHandlers = map[byte]appQUICHandler{
	quicwire.BMCSubEnroll:                appQUICCall("BMCEnrollBMC", quicBMCServer, platformv1.BMCServiceServer.EnrollBMC),
	quicwire.BMCSubRestore:               appQUICCall("BMCRestoreFactoryCert", quicBMCServer, platformv1.BMCServiceServer.RestoreFactoryCert),
	quicwire.BMCSubPowerOn:               appQUICCall("BMCPowerOn", quicBMCServer, platformv1.BMCServiceServer.PowerOn),
	quicwire.BMCSubPowerOff:              appQUICCall("BMCPowerOff", quicBMCServer, platformv1.BMCServiceServer.PowerOff),
	quicwire.BMCSubPowerReset:            appQUICCall("BMCPowerReset", quicBMCServer, platformv1.BMCServiceServer.PowerReset),
	quicwire.BMCSubPowerCycle:            appQUICCall("BMCPowerCycle", quicBMCServer, platformv1.BMCServiceServer.PowerCycle),
	quicwire.BMCSubPowerStatus:           appQUICCall("BMCPowerStatus", quicBMCServer, platformv1.BMCServiceServer.PowerStatus),
	quicwire.BMCSubSetBootDevice:         appQUICCall("BMCSetBootDevice", quicBMCServer, platformv1.BMCServiceServer.SetBootDevice),
	quicwire.BMCSubGetBootDevice:         appQUICCall("BMCGetBootDevice", quicBMCServer, platformv1.BMCServiceServer.GetBootDevice),
	quicwire.BMCSubMountISO:              appQUICCall("BMCMountISO", quicBMCServer, platformv1.BMCServiceServer.MountISO),
	quicwire.BMCSubUnmountISO:            appQUICCall("BMCUnmountISO", quicBMCServer, platformv1.BMCServiceServer.UnmountISO),
	quicwire.BMCSubVirtualMediaStatus:    appQUICCall("BMCVirtualMediaStatus", quicBMCServer, platformv1.BMCServiceServer.VirtualMediaStatus),
	quicwire.BMCSubGetSensors:            appQUICCall("BMCGetSensors", quicBMCServer, platformv1.BMCServiceServer.GetSensors),
	quicwire.BMCSubGetSystemInfo:         appQUICCall("BMCGetSystemInfo", quicBMCServer, platformv1.BMCServiceServer.GetSystemInfo),
	quicwire.BMCSubProvision:             appQUICCall("BMCProvision", quicBMCServer, platformv1.BMCServiceServer.Provision),
	quicwire.BMCSubProvisionStatus:       appQUICCall("BMCProvisionStatus", quicBMCServer, platformv1.BMCServiceServer.ProvisionStatus),
	quicwire.BMCSubGetWebCertificate:     appQUICCall("BMCGetWebCertificate", quicBMCServer, platformv1.BMCServiceServer.GetWebCertificate),
	quicwire.BMCSubReplaceWebCertificate: appQUICCall("BMCReplaceWebCertificate", quicBMCServer, platformv1.BMCServiceServer.ReplaceWebCertificate),
	quicwire.BMCSubListUsers:             appQUICCall("BMCListUsers", quicBMCServer, platformv1.BMCServiceServer.ListUsers),
	quicwire.BMCSubCreateUser:            appQUICCall("BMCCreateUser", quicBMCServer, platformv1.BMCServiceServer.CreateUser),
	quicwire.BMCSubDeleteUser:            appQUICCall("BMCDeleteUser", quicBMCServer, platformv1.BMCServiceServer.DeleteUser),
	quicwire.BMCSubSetUserPassword:       appQUICCall("BMCSetUserPassword", quicBMCServer, platformv1.BMCServiceServer.SetUserPassword),
	quicwire.BMCSubSetUserPrivilege:      appQUICCall("BMCSetUserPrivilege", quicBMCServer, platformv1.BMCServiceServer.SetUserPrivilege),
}

func quicBMCServer(h *QUICServiceHandler) platformv1.BMCServiceServer {
	return h.bmcServer
}

// SetBMCServer wires the BMCService servicer the OpBMCCategory handlers
// delegate to. Until it is set every BMC sub-opcode answers unavailable.
func (h *QUICServiceHandler) SetBMCServer(server platformv1.BMCServiceServer) {
	h.bmcServer = server
}

// handleBMCCategory handles the BMC category opcode (OpBMCCategory, 0x9F).
func (h *QUICServiceHandler) handleBMCCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.bmcServer == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "bmc"})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := bmcQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}
