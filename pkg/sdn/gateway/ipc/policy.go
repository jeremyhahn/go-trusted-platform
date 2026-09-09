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
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// Policy names the kernel-verified uids each IPC service admits. The
// supervisor is root, so ControlUIDs is {0} unless a test says otherwise;
// DatapathUIDs additionally admits the parser processes' uid so they can
// reach the kernel-programming process over its narrow surface.
type Policy struct {
	// ControlUIDs may call ProcessControlService. Empty means uid 0 only.
	ControlUIDs []uint32
	// DatapathUIDs may call DatapathService in addition to ControlUIDs.
	DatapathUIDs []uint32
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

// serviceOf extracts the fully qualified service name from a gRPC method
// ("/pkg.Service/Method").
func serviceOf(fullMethod string) string {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		return trimmed[:i]
	}
	return trimmed
}

// admit is the per-service authorization table, keyed by fully qualified
// service name.
func (p Policy) admit(service string, creds peercred.UnixCredentials) error {
	switch service {
	case ipcv1.ProcessControlService_ServiceDesc.ServiceName:
		if admits(p.ControlUIDs, creds.UID) {
			return nil
		}
	case ipcv1.DatapathService_ServiceDesc.ServiceName:
		if admits(p.ControlUIDs, creds.UID) || admits(p.DatapathUIDs, creds.UID) {
			return nil
		}
	default:
		return &ErrUnknownService{Method: service}
	}
	return &ErrPeerDenied{Service: service, UID: creds.UID, PID: creds.PID}
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
		if err := p.admit(serviceOf(info.FullMethod), creds); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return handler(ctx, req)
	}
}
