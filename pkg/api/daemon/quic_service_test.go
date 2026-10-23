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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newTestQUICServiceHandler builds a handler for tests that exercise the
// dispatch and the service handlers rather than authentication. Its
// middleware treats every caller as a certificate-authenticated peer, so
// tokenless requests reach any classified operation; unclassified operations
// are still refused, as in production. A test passing its own
// WithQUICAuthMiddleware overrides it.
func newTestQUICServiceHandler(logger *logging.Logger, opts ...QUICServiceHandlerOption) *QUICServiceHandler {
	peerAuthenticated := WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICPeerAuthenticated()))
	h, err := NewQUICServiceHandler(logger, append([]QUICServiceHandlerOption{peerAuthenticated}, opts...)...)
	if err != nil {
		panic(err) // unreachable: a middleware is always installed above
	}
	return h
}

// quicScopeValidator is a quic.ClaimsTokenValidator double that accepts any
// token and grants a fixed scope set.
type quicScopeValidator struct {
	scopes []string
}

func (v *quicScopeValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

func (v *quicScopeValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	authCtx := &platformtoken.AuthorizedContext{Subject: "test", Scopes: v.scopes}
	if requiredPerm != "" {
		if err := authCtx.RequireScope(requiredPerm); err != nil {
			return nil, err
		}
	}
	return authCtx, nil
}

func TestNewQUICServiceHandler_RequiresAuthMiddleware(t *testing.T) {
	cases := map[string][]QUICServiceHandlerOption{
		"no middleware option": nil,
		"nil middleware":       {WithQUICAuthMiddleware(nil)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			h, err := NewQUICServiceHandler(logging.DefaultLogger(), opts...)
			if h != nil {
				t.Fatal("a handler without an auth middleware must not be built")
			}
			var want ErrQUICAuthMiddlewareRequired
			if !errors.As(err, &want) {
				t.Fatalf("error = %v, want ErrQUICAuthMiddlewareRequired", err)
			}
		})
	}
}

func TestNewQUICServiceHandler_WithMiddleware(t *testing.T) {
	mw := quic.NewAuthMiddleware()
	h, err := NewQUICServiceHandler(nil, WithQUICAuthMiddleware(mw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.authMiddleware != mw {
		t.Fatal("the configured middleware was not installed")
	}
	if h.logger == nil {
		t.Fatal("a nil logger must fall back to the default logger")
	}
}

func TestQUICServiceHandler_HandleRequest_WithoutMiddlewareServesNothing(t *testing.T) {
	// A handler built as a bare literal bypasses the constructor; it must
	// still refuse, not dispatch unauthorized.
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}

	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth})

	if resp.Status != quicwire.StatusUnavailable {
		t.Fatalf("status = 0x%02X, want StatusUnavailable", resp.Status)
	}
}

func TestQUICServiceHandler_HandleRequest_AuthorizesBeforeDispatch(t *testing.T) {
	validator := &quicScopeValidator{scopes: []string{"kms:read"}}
	h, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name string
		req  *quicwire.Request
		want byte
	}{
		{"no token", &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey}, quicwire.StatusUnauthorized},
		{"missing scope", &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey, Token: "tok"}, quicwire.StatusPermissionDenied},
		{"unclassified opcode", &quicwire.Request{Opcode: quicwire.OpJWTVerify, Token: "tok"}, quicwire.StatusPermissionDenied},
		{"unclassified sub-opcode", &quicwire.Request{Opcode: quicwire.OpSecretsCategory, Token: "tok", Payload: []byte{0x7F}}, quicwire.StatusPermissionDenied},
		{"category without sub-opcode", &quicwire.Request{Opcode: quicwire.OpSecretsCategory, Token: "tok"}, quicwire.StatusInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.HandleRequest(context.Background(), tc.req)
			if resp.Status != tc.want {
				t.Fatalf("status = 0x%02X, want 0x%02X (payload %q)", resp.Status, tc.want, resp.Payload)
			}
		})
	}

	// With the scope the request passes the guard and reaches the KMS
	// dispatch, which reports the unconfigured service.
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSGetKey, Token: "tok"})
	if resp.Status == quicwire.StatusUnauthorized || resp.Status == quicwire.StatusPermissionDenied {
		t.Fatalf("a granted scope was refused: status 0x%02X payload %q", resp.Status, resp.Payload)
	}
}
