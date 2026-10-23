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

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func newPXEQUICHandler(t *testing.T) *QUICServiceHandler {
	t.Helper()
	validator := &quicScopeValidator{scopes: []string{"*:*"}}
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	require.NoError(t, err)
	return handler
}

// TestHandlePXEOperation_Unavailable checks a direct PXE opcode answers
// Unavailable, not a panic, before a servicer is wired.
func TestHandlePXEOperation_Unavailable(t *testing.T) {
	h := newPXEQUICHandler(t)

	resp := h.handlePXEOperation(context.Background(), &quicwire.Request{Opcode: quicwire.OpPXEGetDevice})

	require.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// TestHandlePXEOperation_UnknownOpcode checks a byte outside the PXE table
// answers NotImplemented instead of reaching a servicer method.
func TestHandlePXEOperation_UnknownOpcode(t *testing.T) {
	h := newPXEQUICHandler(t)
	f := newPXESDKFixture()
	h.SetPXEServer(f.server)
	before := f.svc.recorded()

	resp := h.handlePXEOperation(context.Background(), &quicwire.Request{Opcode: quicwire.OpProvisioningCategory})

	require.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	require.Equal(t, before, f.svc.recorded())
}

// TestHandlePXECategorySub_Unavailable checks a PXE sub-opcode is claimed and
// answers Unavailable before a servicer is wired.
func TestHandlePXECategorySub_Unavailable(t *testing.T) {
	h := newPXEQUICHandler(t)

	resp, handled := h.handlePXECategorySub(context.Background(), &quicwire.Request{
		Opcode: quicwire.OpProvisioningCategory, Payload: []byte{quicwire.PXESubGetStatus},
	})

	require.True(t, handled)
	require.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// TestHandlePXECategorySub_LeavesOtherSubs checks the PXE dispatcher claims
// neither an empty payload nor a sub-opcode of another provisioning-category
// family, so those fall through to their own dispatchers.
func TestHandlePXECategorySub_LeavesOtherSubs(t *testing.T) {
	h := newPXEQUICHandler(t)
	h.SetPXEServer(newPXESDKFixture().server)

	for name, payload := range map[string][]byte{
		"empty payload":      nil,
		"EAB sub-opcode":     {quicwire.EABSubCreateCredential},
		"device sub-opcode":  {0x20},
		"unassigned PXE sub": {0x3F},
	} {
		t.Run(name, func(t *testing.T) {
			resp, handled := h.handlePXECategorySub(context.Background(), &quicwire.Request{
				Opcode: quicwire.OpProvisioningCategory, Payload: payload,
			})

			require.False(t, handled)
			require.Nil(t, resp)
		})
	}
}
