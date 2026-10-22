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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// orchestratorQUICTestServer records the CancelJob request it receives and
// answers with cancelErr when one is set.
type orchestratorQUICTestServer struct {
	platformv1.UnimplementedOrchestratorServiceServer

	cancelled *platformv1.CancelOrchestratorJobRequest
	cancelErr error
}

func (s *orchestratorQUICTestServer) CancelJob(_ context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	s.cancelled = req
	if s.cancelErr != nil {
		return nil, s.cancelErr
	}
	return &platformv1.CancelOrchestratorJobResponse{JobId: req.GetJobId(), Cancelled: true}, nil
}

func newOrchestratorQUICHandler(server platformv1.OrchestratorServiceServer) *QUICServiceHandler {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	if server != nil {
		handler.SetOrchestratorService(server)
	}
	return handler
}

func orchestratorCategoryRequest(t *testing.T, sub byte, request any) *quicwire.Request {
	t.Helper()
	body, err := quicwire.EncodePayload(request)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return &quicwire.Request{Opcode: quicwire.OpOrchestratorCategory, Payload: append([]byte{sub}, body...)}
}

func TestQUICOrchestratorCancelJob(t *testing.T) {
	server := &orchestratorQUICTestServer{}
	handler := newOrchestratorQUICHandler(server)

	resp := handler.HandleRequest(context.Background(), orchestratorCategoryRequest(t, quicwire.OrchestratorSubCancelJob,
		&platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload %q", resp.Status, resp.Payload)
	}
	if server.cancelled.GetTenantId() != "acme" || server.cancelled.GetJobId() != "j1" {
		t.Fatalf("CancelJob received %v, want acme/j1", server.cancelled)
	}
	var decoded platformv1.CancelOrchestratorJobResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.GetJobId() != "j1" || !decoded.GetCancelled() {
		t.Fatalf("decoded = %v, want j1 cancelled", &decoded)
	}
}

func TestQUICOrchestratorCategoryRejectsBadRequests(t *testing.T) {
	ctx := context.Background()
	cancel := &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}

	t.Run("no service", func(t *testing.T) {
		resp := newOrchestratorQUICHandler(nil).HandleRequest(ctx,
			orchestratorCategoryRequest(t, quicwire.OrchestratorSubHealth, &platformv1.OrchestratorHealthRequest{}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x, want StatusUnavailable", resp.Status)
		}
	})

	t.Run("missing sub-opcode", func(t *testing.T) {
		handler := newOrchestratorQUICHandler(&orchestratorQUICTestServer{})
		resp := handler.handleOrchestratorCategory(ctx, &quicwire.Request{Opcode: quicwire.OpOrchestratorCategory})
		if resp.Status != quicwire.StatusInvalidRequest {
			t.Fatalf("status = 0x%02x, want StatusInvalidRequest", resp.Status)
		}
	})

	t.Run("unknown sub-opcode", func(t *testing.T) {
		handler := newOrchestratorQUICHandler(&orchestratorQUICTestServer{})
		resp := handler.handleOrchestratorCategory(ctx, &quicwire.Request{Opcode: quicwire.OpOrchestratorCategory, Payload: []byte{0x7F}})
		if resp.Status != quicwire.StatusNotImplemented {
			t.Fatalf("status = 0x%02x, want StatusNotImplemented", resp.Status)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		handler := newOrchestratorQUICHandler(&orchestratorQUICTestServer{})
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpOrchestratorCategory,
			Payload: []byte{quicwire.OrchestratorSubCancelJob, 0xC1},
		})
		if resp.Status != quicwire.StatusInvalidRequest {
			t.Fatalf("status = 0x%02x, want StatusInvalidRequest", resp.Status)
		}
	})

	t.Run("an unknown job is not found", func(t *testing.T) {
		handler := newOrchestratorQUICHandler(&orchestratorQUICTestServer{cancelErr: status.Error(codes.NotFound, "no job j1")})
		resp := handler.HandleRequest(ctx, orchestratorCategoryRequest(t, quicwire.OrchestratorSubCancelJob, cancel))
		if resp.Status != quicwire.StatusNotFound {
			t.Fatalf("status = 0x%02x, want StatusNotFound", resp.Status)
		}
	})
}
