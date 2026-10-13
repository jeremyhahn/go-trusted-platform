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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func scopedQUICContext(scopes ...string) context.Context {
	return quic.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Scopes: scopes})
}

// TestPhase35QUICScopeCatalogsMatchDispatch fails when a sub-opcode is
// dispatched without a scope, which would leave it open to any token, or a
// scope is listed for a sub-opcode nothing handles.
func TestPhase35QUICScopeCatalogsMatchDispatch(t *testing.T) {
	check := func(name string, dispatched func(byte) bool, perms map[byte]quic.OpcodePermission, subs []byte) {
		for _, sub := range subs {
			if _, ok := perms[sub]; !ok {
				t.Errorf("%s sub-opcode 0x%02x is dispatched without a scope", name, sub)
			}
		}
		for sub := range perms {
			if !dispatched(sub) {
				t.Errorf("%s sub-opcode 0x%02x has a scope but no handler", name, sub)
			}
		}
	}

	var ceremony, piv, fido2 []byte
	for sub := range ceremonyQUICDispatch {
		ceremony = append(ceremony, sub)
	}
	for sub := range pivQUICDispatch {
		piv = append(piv, sub)
	}
	for sub := range fido2QUICDispatch {
		fido2 = append(fido2, sub)
	}
	check("ceremony", func(s byte) bool { _, ok := ceremonyQUICDispatch[s]; return ok }, quic.CeremonySubOpcodePermissions, ceremony)
	check("piv", func(s byte) bool { _, ok := pivQUICDispatch[s]; return ok }, quic.PIVSubOpcodePermissions, piv)
	check("fido2", func(s byte) bool { _, ok := fido2QUICDispatch[s]; return ok }, quic.FIDO2SubOpcodePermissions, fido2)
}

// TestErrResponseFrom_NotConfiguredNamesTheService proves a QUIC client can
// tell "backend not configured" from any other Unavailable: the payload carries
// the sentinel's message.
func TestErrResponseFrom_NotConfiguredNamesTheService(t *testing.T) {
	for _, sentinel := range []error{ErrCeremonyNotConfigured, ErrPIVNotConfigured, ErrFIDO2NotConfigured} {
		resp := errResponseFrom(sentinel)
		if resp.Status != quicwire.StatusUnavailable || string(resp.Payload) != sentinel.Error() {
			t.Errorf("%v: status=%d payload=%q", sentinel, resp.Status, resp.Payload)
		}
	}
	if resp := errResponseFrom(ErrPIVSlotRequired); resp.Status != quicwire.StatusInvalidArgument {
		t.Errorf("slot required: status=%d, want InvalidArgument", resp.Status)
	}
}

// TestPhase35QUICHandlersEnforceScopes drives the real category handlers: a
// token holding only read scopes reads, and is refused the write operations.
func TestPhase35QUICHandlersEnforceScopes(t *testing.T) {
	log := logging.DefaultLogger()
	ceremony := &ceremonyQUICHandlers{service: NewCeremonyService(log, &fakeCeremonyBackend{})}
	piv := &pivQUICHandlers{service: NewPIVService(log, &fakePIVBackend{})}
	fido2 := &fido2QUICHandlers{service: NewFIDO2Service(log, &fakeFIDO2Backend{})}

	cases := []struct {
		name   string
		handle func(context.Context, *quicwire.Request) *quicwire.Response
		opcode byte
		sub    byte
		held   []string
		want   byte
	}{
		{"piv list with piv:read", piv.Handle, quicwire.OpPIVCategory, quicwire.PIVSubListDevices, []string{"piv:read"}, quicwire.StatusOK},
		{"piv generate with piv:read", piv.Handle, quicwire.OpPIVCategory, quicwire.PIVSubGenerate, []string{"piv:read"}, quicwire.StatusPermissionDenied},
		{"piv list with fido2:read", piv.Handle, quicwire.OpPIVCategory, quicwire.PIVSubListDevices, []string{"fido2:read"}, quicwire.StatusPermissionDenied},
		{"fido2 list with fido2:read", fido2.Handle, quicwire.OpFIDO2Category, quicwire.FIDO2SubListDevices, []string{"fido2:read"}, quicwire.StatusOK},
		{"fido2 authenticate with fido2:read", fido2.Handle, quicwire.OpFIDO2Category, quicwire.FIDO2SubAuthenticate, []string{"fido2:read"}, quicwire.StatusPermissionDenied},
		{"ceremony status with ceremony:read", ceremony.Handle, quicwire.OpCeremonyCategory, quicwire.CeremonySubStatus, []string{"ceremony:read"}, quicwire.StatusOK},
		{"ceremony init with ceremony:read", ceremony.Handle, quicwire.OpCeremonyCategory, quicwire.CeremonySubInit, []string{"ceremony:read"}, quicwire.StatusPermissionDenied},
		{"ceremony sign csr with no scopes", ceremony.Handle, quicwire.OpCeremonyCategory, quicwire.CeremonySubSignCSR, nil, quicwire.StatusPermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.handle(scopedQUICContext(tc.held...), &quicwire.Request{Opcode: tc.opcode, Payload: []byte{tc.sub}})
			if resp.Status != tc.want {
				t.Errorf("status = %d, want %d", resp.Status, tc.want)
			}
		})
	}
}

// TestCeremonyQUICInitReturnsAdminBundle proves the QUIC Init reply carries
// the one-shot admin bundle and SPKI pin; without them the operator never
// receives the only copy of the admin key.
func TestCeremonyQUICInitReturnsAdminBundle(t *testing.T) {
	h := &ceremonyQUICHandlers{service: NewCeremonyService(logging.DefaultLogger(), &fakeCeremonyBackend{})}
	body, err := quicwire.EncodePayload(&quicwire.CeremonyInitReq{SOPIN: "so", UserPIN: "u"})
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	resp := h.Handle(scopedQUICContext("ceremony:write"), &quicwire.Request{
		Opcode:  quicwire.OpCeremonyCategory,
		Payload: append([]byte{quicwire.CeremonySubInit}, body...),
	})
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = %d, want OK", resp.Status)
	}
	var out quicwire.CeremonyInitResp
	if err := quicwire.DecodePayload(resp.Payload, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out.AdminCertPEM != "ADMIN-CERT" || out.AdminKeyPEM != "ADMIN-KEY" || out.SPKIPin != "PIN" {
		t.Errorf("admin bundle not returned: %+v", out)
	}
}
