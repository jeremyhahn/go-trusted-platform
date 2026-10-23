// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// scopedQUICValidator stands in for the shared platform-token validator that
// selectQUICAuth installs: it accepts the framed token and grants a fixed
// scope set, so a test controls exactly what the caller may do.
type scopedQUICValidator struct {
	scopes []string
}

func (v scopedQUICValidator) ValidateToken(context.Context, string) (bool, error) {
	return true, nil
}

func (v scopedQUICValidator) AuthorizeToken(_ context.Context, _, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "operator", TenantID: "t1", Scopes: v.scopes}, nil
}

// newScopedQUICHandler builds a device-capable handler behind the platform
// token middleware, granting the caller only scopes.
func newScopedQUICHandler(t *testing.T, scopes ...string) *QUICServiceHandler {
	t.Helper()
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedQUICValidator{scopes: scopes}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(auth),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(newMockProfileService()))
	require.NoError(t, err)
	return handler
}

// deviceWriteRequests is one request per device write that QUIC carries: the
// sub-opcodes under OpProvisioningCategory and the top-level write opcodes.
func deviceWriteRequests() map[string]*quicwire.Request {
	sub := func(op byte) *quicwire.Request {
		return &quicwire.Request{Opcode: quicwire.OpProvisioningCategory, Payload: []byte{op}, Token: "t"}
	}
	return map[string]*quicwire.Request{
		"AssignProfile":             sub(quicwire.DeviceProfileSubAssign),
		"UnassignProfile":           sub(quicwire.DeviceProfileSubUnassign),
		"RecordAttestationCert":     sub(quicwire.DeviceSubRecordAttestCert),
		"CreateTemplate":            sub(quicwire.DeviceSubTemplateCreate),
		"CreateProfileFromTemplate": sub(quicwire.DeviceSubProfileFromTemplate),
		"DisableDevice":             sub(quicwire.DeviceSubDisable),
		"EnableDevice":              sub(quicwire.DeviceSubEnable),
		"AttestDevice":              {Opcode: quicwire.OpDeviceAttest, Token: "t"},
		"UpdateProfile":             {Opcode: quicwire.OpDeviceSetProfile, Token: "t"},
		"CreateProfile":             {Opcode: quicwire.OpDeviceCreateProfile, Token: "t"},
		"ActivateDevice":            {Opcode: quicwire.OpDeviceActivate, Token: "t"},
	}
}

func TestQUICDeviceWrites_RefuseAReadOnlyToken(t *testing.T) {
	handler := newScopedQUICHandler(t, "device:read")
	for name, req := range deviceWriteRequests() {
		t.Run(name, func(t *testing.T) {
			resp := handler.HandleRequest(context.Background(), req)
			assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status,
				"a device:read token must not reach a device write")
			assert.Contains(t, string(resp.Payload), "device")
		})
	}
}

func TestQUICDeviceWrites_ReachTheHandlerWithDeviceWrite(t *testing.T) {
	handler := newScopedQUICHandler(t, "device:write")
	for name, req := range deviceWriteRequests() {
		t.Run(name, func(t *testing.T) {
			resp := handler.HandleRequest(context.Background(), req)
			assert.NotEqual(t, quicwire.StatusPermissionDenied, resp.Status)
			assert.NotEqual(t, quicwire.StatusUnauthorized, resp.Status)
		})
	}
}

func TestQUICDeviceWrites_RefuseAMissingToken(t *testing.T) {
	handler := newScopedQUICHandler(t, "device:write")
	for name, req := range deviceWriteRequests() {
		t.Run(name, func(t *testing.T) {
			anonymous := *req
			anonymous.Token = ""
			resp := handler.HandleRequest(context.Background(), &anonymous)
			assert.Equal(t, quicwire.StatusUnauthorized, resp.Status)
		})
	}
}
