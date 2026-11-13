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

package ipc

import (
	"context"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// Policy names the kernel-verified uids each IPC method admits. The
// supervisor is root, so ControlUIDs is {0} unless a test says otherwise;
// DatapathUIDs additionally admits the parser processes' uid to the
// kernel-programming process's narrow surface: the VPN peer RPCs, never
// ApplyDesired, which replaces the whole desired document and is the
// supervisor's alone. PlatformUIDs admits platformd's uid to
// GatewayServicesService (#660), the live load-balancer, NAT64 and perf
// surface, and to nothing else.
type Policy struct {
	// ControlUIDs may call every method. Empty means uid 0 only.
	ControlUIDs []uint32
	// DatapathUIDs may call the parser-facing DatapathService methods in
	// addition to ControlUIDs.
	DatapathUIDs []uint32
	// PlatformUIDs may call the GatewayServicesService methods in addition
	// to ControlUIDs. Empty admits no one beyond ControlUIDs: a platformd
	// running as root is already a control uid.
	PlatformUIDs []uint32
}

// admission decides whether a kernel-verified uid may call one method.
type admission func(p Policy, uid uint32) bool

// supervisorOnly admits the control uids alone.
func supervisorOnly(p Policy, uid uint32) bool {
	return admits(p.ControlUIDs, uid)
}

// supervisorOrParser admits the control uids and the parser class's uid.
func supervisorOrParser(p Policy, uid uint32) bool {
	return admits(p.ControlUIDs, uid) || admits(p.DatapathUIDs, uid)
}

// supervisorOrPlatform admits the control uids and platformd's uids.
func supervisorOrPlatform(p Policy, uid uint32) bool {
	return admits(p.ControlUIDs, uid) || slices.Contains(p.PlatformUIDs, uid)
}

// methodAdmissions is the authorization table, keyed by the full gRPC
// method. A method it does not name is refused (ErrUnknownService), so a
// method added to the contract is closed until it is placed here.
var methodAdmissions = map[string]admission{
	ipcv1.ProcessControlService_Status_FullMethodName:      supervisorOnly,
	ipcv1.ProcessControlService_Snapshot_FullMethodName:    supervisorOnly,
	ipcv1.DatapathService_ApplyDesired_FullMethodName:      supervisorOnly,
	ipcv1.DatapathService_InstallVPNPeer_FullMethodName:    supervisorOrParser,
	ipcv1.DatapathService_RemoveVPNPeer_FullMethodName:     supervisorOrParser,
	ipcv1.DatapathService_ReconcileVPNPeers_FullMethodName: supervisorOrParser,

	ipcv1.GatewayServicesService_LBStatus_FullMethodName:       supervisorOrPlatform,
	ipcv1.GatewayServicesService_ListVIPs_FullMethodName:       supervisorOrPlatform,
	ipcv1.GatewayServicesService_GetVIP_FullMethodName:         supervisorOrPlatform,
	ipcv1.GatewayServicesService_AddVIP_FullMethodName:         supervisorOrPlatform,
	ipcv1.GatewayServicesService_RemoveVIP_FullMethodName:      supervisorOrPlatform,
	ipcv1.GatewayServicesService_SetVIPBackends_FullMethodName: supervisorOrPlatform,
	ipcv1.GatewayServicesService_NAT64Status_FullMethodName:    supervisorOrPlatform,
	ipcv1.GatewayServicesService_PerfFlows_FullMethodName:      supervisorOrPlatform,
	ipcv1.GatewayServicesService_PerfDatapath_FullMethodName:   supervisorOrPlatform,
	ipcv1.GatewayServicesService_PerfConntrack_FullMethodName:  supervisorOrPlatform,
}

// admits reports whether uid is in the list, treating an empty list as
// {0}.
func admits(uids []uint32, uid uint32) bool {
	if len(uids) == 0 {
		return uid == 0
	}
	for _, u := range uids {
		if u == uid {
			return true
		}
	}
	return false
}

// admit applies the authorization table to one full gRPC method
// ("/pkg.Service/Method").
func (p Policy) admit(method string, creds peercred.UnixCredentials) error {
	allowed, ok := methodAdmissions[method]
	if !ok {
		return &ErrUnknownService{Method: method}
	}
	if allowed(p, creds.UID) {
		return nil
	}
	return &ErrPeerDenied{Method: method, UID: creds.UID, PID: creds.PID}
}

// unaryInterceptor enforces the policy on every unary RPC. It runs after
// the required peer-credential interceptor, so the credentials are in the
// context or the call never reached it.
func (p Policy) unaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		creds, ok := peercred.UnixCredentialsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, peercred.ErrCredentialsNotInContext{}.Error())
		}
		if err := p.admit(info.FullMethod, creds); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return handler(ctx, req)
	}
}
