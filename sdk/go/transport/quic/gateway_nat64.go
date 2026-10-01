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

package quic

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// decodeGatewayNAT64StatusReply decodes the NAT64 status sub-opcode's wire
// response into the gRPC reply. The default decode matched the reply's
// status field by name, then failed on last_reconcile: the wire carries
// Unix seconds and the reply a Timestamp message. Every status read after
// the first reconcile was an Internal error over QUIC, and last_error was
// dropped (#661 review).
func decodeGatewayNAT64StatusReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetNAT64StatusResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_GetNAT64Status_FullMethodName}
	}
	var wire quicapi.GatewayNAT64StatusResponse
	if err := quicapi.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	if wire.Status == nil {
		out.Status = nil
		return nil
	}
	s := wire.Status
	out.Status = &platformv1.NAT64Status{
		Active:          s.Active,
		InstancePresent: s.InstancePresent,
		Prefix:          s.Prefix,
		Instance:        s.Instance,
		Sessions:        s.Sessions,
		Pool4Used:       s.Pool4Used,
		ModuleVersion:   s.ModuleVersion,
		FlowCount:       uint32(s.FlowCount),
		LastError:       s.LastError,
	}
	// Zero means the service never converged; the server omits it.
	if s.LastReconcile != 0 {
		out.Status.LastReconcile = timestamppb.New(time.Unix(s.LastReconcile, 0))
	}
	return nil
}
