package daemon

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestQUICTenantBarrierCategory_InitialAdminInvitation pins that the owner
// invitation is served on QUIC as a sub-opcode of the tenant category and
// reaches TenantGRPCServer.CreateInitialAdminInvitation, and that an unknown
// sub-opcode still answers StatusNotImplemented.
func TestQUICTenantBarrierCategory_InitialAdminInvitation(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	s := newInitialAdminServer(fake)
	h.tenantGRPC = s

	body, err := quicwire.EncodePayload(&platformv1.CreateInitialAdminInvitationRequest{
		TenantId: initialAdminTenantID(s),
		Email:    "owner@example.com",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	payload := append([]byte{quicwire.TenantBarrierSubInitialAdminInvitation}, body...)

	resp := h.handleTenantBarrierCategory(systemAdminCallerContext("42"),
		&quicwire.Request{Opcode: quicwire.OpTenantBarrierCategory, Payload: payload})
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02X payload %q, want StatusOK", resp.Status, resp.Payload)
	}
	if fake.calls != 1 {
		t.Fatalf("inviter calls = %d, want 1", fake.calls)
	}
	if fake.got.InvitedByID != 42 {
		t.Fatalf("invited_by = %d, want 42", fake.got.InvitedByID)
	}

	unknown := h.handleTenantBarrierCategory(systemAdminCallerContext("42"),
		&quicwire.Request{Opcode: quicwire.OpTenantBarrierCategory, Payload: []byte{0xFE}})
	if unknown == nil || unknown.Status != quicwire.StatusNotImplemented {
		t.Fatalf("unknown sub-opcode: got %+v, want StatusNotImplemented", unknown)
	}
}
