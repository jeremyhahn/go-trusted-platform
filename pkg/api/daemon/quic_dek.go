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

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// DEK sub-opcodes of OpKMSExtendedCategory (0xCD), subs 0x08-0x0D.
//
// The payload after the sub-opcode byte is the quicbaas.kms.v1
// DEKManagement request message and the reply is its response message. Each
// sub calls the DEKServerAdapter method the gRPC transport calls, so a DEK
// created on one transport is the same DEK on every other, and an error
// carries the class gRPC answers.

// DEKServiceInterface is the DEKManagement surface the QUIC DEK sub-opcodes
// call.
type DEKServiceInterface interface {
	CreateDEK(ctx context.Context, req *pb.CreateDEKRequest) (*pb.CreateDEKResponse, error)
	ListDEKs(ctx context.Context, req *pb.ListDEKsRequest) (*pb.ListDEKsResponse, error)
	GetDEK(ctx context.Context, req *pb.GetDEKRequest) (*pb.GetDEKResponse, error)
	GetDEKStatus(ctx context.Context, req *pb.GetDEKStatusRequest) (*pb.GetDEKStatusResponse, error)
	RotateDEK(ctx context.Context, req *pb.RotateDEKRequest) (*pb.RotateDEKResponse, error)
	DeleteDEK(ctx context.Context, req *pb.DeleteDEKRequest) (*pb.DeleteDEKResponse, error)
	SetDefaultDEK(ctx context.Context, req *pb.SetDefaultDEKRequest) (*pb.SetDefaultDEKResponse, error)
	SetDEKSafety(ctx context.Context, req *pb.SetDEKSafetyRequest) (*pb.SetDEKSafetyResponse, error)
	ClearDEKSafety(ctx context.Context, req *pb.ClearDEKSafetyRequest) (*pb.ClearDEKSafetyResponse, error)
}

// Compile-time check: the gRPC DEK adapter satisfies the QUIC interface.
var _ DEKServiceInterface = (*DEKServerAdapter)(nil)

// dekQUICDispatch maps the DEK sub-opcodes to their handlers. The KMS
// extended dispatcher consults it before the key-lifecycle table, so the DEK
// subs need only the DEK service.
var dekQUICDispatch = map[byte]kmsExtendedQUICHandler{
	quicwire.KMSSubCreateDEK:      dekPBHandler("DEKCreate", DEKServiceInterface.CreateDEK),
	quicwire.KMSSubListDEKs:       dekPBHandler("DEKList", DEKServiceInterface.ListDEKs),
	quicwire.KMSSubGetDEK:         dekPBHandler("DEKGet", DEKServiceInterface.GetDEK),
	quicwire.KMSSubGetDEKStatus:   dekPBHandler("DEKStatus", DEKServiceInterface.GetDEKStatus),
	quicwire.KMSSubRotateDEK:      dekPBHandler("DEKRotate", DEKServiceInterface.RotateDEK),
	quicwire.KMSSubDeleteDEK:      dekPBHandler("DEKDelete", DEKServiceInterface.DeleteDEK),
	quicwire.KMSSubSetDefaultDEK:  dekPBHandler("DEKSetDefault", DEKServiceInterface.SetDefaultDEK),
	quicwire.KMSSubSetDEKSafety:   dekPBHandler("DEKSetSafety", DEKServiceInterface.SetDEKSafety),
	quicwire.KMSSubClearDEKSafety: dekPBHandler("DEKClearSafety", DEKServiceInterface.ClearDEKSafety),
}

// dekPBHandler serves one DEK sub-operation through the DEK service, or
// answers unavailable when the daemon has none.
func dekPBHandler[Req, Resp any](op string, call func(DEKServiceInterface, context.Context, *Req) (*Resp, error)) kmsExtendedQUICHandler {
	return func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response {
		if h.dekService == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "dek"})
		}
		return servePBCall(h, ctx, payload, op, h.dekService, call)
	}
}

// SetDEKService wires the DEKManagement adapter behind the QUIC DEK
// sub-opcodes.
func (h *QUICServiceHandler) SetDEKService(svc DEKServiceInterface) {
	h.dekService = svc
}
