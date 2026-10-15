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

// OpClusterCategory (0x90) carries every ClusterService method: payload[0]
// selects the method, payload[1:] is its msgpack-encoded platform.v1 request,
// and the reply is the generated response message. Each sub-opcode calls the
// gRPC ClusterService servicer, so QUIC answers exactly as gRPC does — down
// to Unavailable when no cluster servicer is wired (the !cluster build).
var clusterQUICHandlers = map[byte]appQUICHandler{
	quicwire.ClusterSubBootstrap: appQUICCall("ClusterBootstrap", quicClusterServer, platformv1.ClusterServiceServer.Bootstrap),
	quicwire.ClusterSubJoin:      appQUICCall("ClusterJoin", quicClusterServer, platformv1.ClusterServiceServer.Join),
	quicwire.ClusterSubLeave:     appQUICCall("ClusterLeave", quicClusterServer, platformv1.ClusterServiceServer.Leave),
	quicwire.ClusterSubGetStatus: appQUICCall("ClusterGetStatus", quicClusterServer, platformv1.ClusterServiceServer.GetStatus),
	quicwire.ClusterSubListNodes: appQUICCall("ClusterListNodes", quicClusterServer, platformv1.ClusterServiceServer.ListNodes),
}

func quicClusterServer(h *QUICServiceHandler) platformv1.ClusterServiceServer { return h.clusterServer }

// SetClusterServer installs the ClusterService servicer the cluster category
// dispatches to.
func (h *QUICServiceHandler) SetClusterServer(server platformv1.ClusterServiceServer) {
	h.clusterServer = server
}

// handleClusterCategory dispatches an OpClusterCategory request through
// clusterQUICHandlers.
func (h *QUICServiceHandler) handleClusterCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.clusterServer == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "cluster"})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}
	handler, ok := clusterQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}
