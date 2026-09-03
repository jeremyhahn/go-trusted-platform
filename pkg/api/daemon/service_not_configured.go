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
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ErrServiceNotConfigured reports that a service the daemon exposes on
// every transport has no backend on THIS node — the expected state for
// a role that does not host it (PXE and gatewayd live on the gateway
// role, so a control plane has neither).
//
// It is distinct from a configured service that is merely stopped: a
// stopped service is an operator-actionable condition on a node that
// does host it, and must keep surfacing as an error.
type ErrServiceNotConfigured struct {
	// Service is the platform service name as it appears in the REST
	// error envelope and on /api/v1/platform/service-registry.
	Service string
	// Detail is operator-facing prose. It is deliberately NOT part of
	// the contract — clients branch on the reason, never on this text.
	Detail string
}

func (e ErrServiceNotConfigured) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("%s is not configured on this node", e.Service)
}

// GRPCStatus renders the error as the canonical status every transport
// carries: codes.Unavailable (REST 503) plus a google.rpc.ErrorInfo
// detail holding response.ReasonServiceNotConfigured and the service
// name.
//
// The detail is what lets a caller tell "this node does not host the
// service" from "the service is down", and unlike a typed Go error it
// survives the gRPC wire, so gRPC, QUIC and MCP clients read the same
// discriminator the WebUI reads over REST.
func (e ErrServiceNotConfigured) GRPCStatus() *status.Status {
	st := status.New(codes.Unavailable, e.Error())
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: response.ReasonServiceNotConfigured,
		Domain: response.ErrorInfoDomain,
		Metadata: map[string]string{
			"service": e.Service,
		},
	})
	if err != nil {
		// WithDetails only fails if the detail cannot be marshalled,
		// which cannot happen for a fixed ErrorInfo. Answering without
		// the detail still yields the right status class.
		return st
	}
	return withDetails
}

// serviceNotConfigured returns the error a gRPC handler yields when its
// backend is absent on this node.
func serviceNotConfigured(service, detail string) error {
	return ErrServiceNotConfigured{Service: service, Detail: detail}.GRPCStatus().Err()
}
