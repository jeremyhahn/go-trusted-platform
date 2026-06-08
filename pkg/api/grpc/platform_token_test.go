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

package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// claimsValidatorStub is a ClaimsTokenValidator test double. It records the
// inputs it received and returns a fixed AuthorizedContext or error.
type claimsValidatorStub struct {
	authCtx *platformtoken.AuthorizedContext
	err     error

	gotToken     string
	gotDPoPProof string
	gotHTM       string
	calls        int
}

// ValidateToken satisfies the bool-only TokenValidator interface so the stub is
// also usable where the legacy path is exercised. It is not consulted once the
// ClaimsTokenValidator assertion succeeds.
func (s *claimsValidatorStub) ValidateToken(ctx context.Context, token string) (bool, error) {
	return s.err == nil, s.err
}

func (s *claimsValidatorStub) AuthorizeToken(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	s.calls++
	s.gotToken = token
	s.gotDPoPProof = dpopProof
	s.gotHTM = htm
	if s.err != nil {
		return nil, s.err
	}
	return s.authCtx, nil
}

func bearerCtx(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestOIDCUnaryInterceptor_ClaimsPath_StashesAuthorizedContext(t *testing.T) {
	want := &platformtoken.AuthorizedContext{
		Subject:  "user-1",
		TenantID: "tenant-a",
		Scopes:   []string{"dns.write"},
	}
	stub := &claimsValidatorStub{authCtx: want}

	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	var seen *platformtoken.AuthorizedContext
	var scopeErr error
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		ac, ok := AuthorizedContextFromContext(ctx)
		if !ok {
			t.Fatal("AuthorizedContext not found in downstream context")
		}
		seen = ac
		// Downstream scope gate (scp -> RBAC).
		scopeErr = ac.RequireScope("dns.write")
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/dns.v1.DNS/AddRecord"}
	resp, err := interceptor(bearerCtx("tok-abc"), nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("handler not invoked, resp=%v", resp)
	}
	if stub.calls != 1 {
		t.Fatalf("AuthorizeToken called %d times, want 1", stub.calls)
	}
	if stub.gotToken != "tok-abc" {
		t.Errorf("token = %q, want tok-abc", stub.gotToken)
	}
	if stub.gotHTM != "/dns.v1.DNS/AddRecord" {
		t.Errorf("htm = %q, want full method", stub.gotHTM)
	}
	if seen != want {
		t.Error("stashed AuthorizedContext is not the validator's result")
	}
	if scopeErr != nil {
		t.Errorf("scope gate denied a granted scope: %v", scopeErr)
	}
}

func TestOIDCUnaryInterceptor_ClaimsPath_ScopeGateDenies(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "user-1",
		Scopes:  []string{"dns.read"},
	}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		ac, _ := AuthorizedContextFromContext(ctx)
		if err := ac.RequireScope("dns.write"); err != nil {
			return nil, err
		}
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/dns.v1.DNS/AddRecord"}
	_, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if err == nil {
		t.Fatal("expected scope-denied error from downstream handler")
	}
	var denied *platformtoken.ScopeDeniedError
	if !errors.As(err, &denied) {
		t.Errorf("expected ScopeDeniedError, got %T: %v", err, err)
	}
}

func TestOIDCUnaryInterceptor_ClaimsPath_DPoPMetadataForwarded(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u"}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	md := metadata.Pairs("authorization", "Bearer tok", DPoPMetadataKey, "proof-jwt")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	if _, err := interceptor(ctx, nil, info, handler); err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
	if stub.gotDPoPProof != "proof-jwt" {
		t.Errorf("dpop proof = %q, want proof-jwt", stub.gotDPoPProof)
	}
}

func TestOIDCUnaryInterceptor_ClaimsPath_InvalidTokenRejected(t *testing.T) {
	stub := &claimsValidatorStub{err: &platformtoken.InvalidTokenError{Detail: "bad sig"}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	_, err := interceptor(bearerCtx("bad"), nil, info, handler)
	if err == nil {
		t.Fatal("expected unauthenticated error for invalid token")
	}
	if called {
		t.Error("handler should not run on invalid token")
	}
}

func TestOIDCUnaryInterceptor_LegacyFallback_NoAuthorizedContext(t *testing.T) {
	// A bool-only validator must continue to work and must not populate an
	// AuthorizedContext (the legacy path is unchanged).
	legacy := &mockTokenValidator{valid: true}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(legacy))

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		if _, ok := AuthorizedContextFromContext(ctx); ok {
			t.Error("legacy path must not populate AuthorizedContext")
		}
		if _, ok := TokenFromContext(ctx); !ok {
			t.Error("legacy path must still stash the raw token")
		}
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	if _, err := interceptor(bearerCtx("tok"), nil, info, handler); err != nil {
		t.Fatalf("legacy interceptor error: %v", err)
	}
}

// streamStub is a minimal grpc.ServerStream carrying a context.
type streamStub struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *streamStub) Context() context.Context { return s.ctx }

func TestOIDCStreamInterceptor_ClaimsPath_StashesAuthorizedContext(t *testing.T) {
	want := &platformtoken.AuthorizedContext{Subject: "u", Scopes: []string{"kms.read"}}
	stub := &claimsValidatorStub{authCtx: want}
	interceptor := OIDCStreamInterceptor(WithTokenValidator(stub))

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		ac, ok := AuthorizedContextFromContext(ss.Context())
		if !ok {
			t.Fatal("AuthorizedContext missing from wrapped stream context")
		}
		if ac != want {
			t.Error("wrong AuthorizedContext in stream")
		}
		return nil
	}
	ss := &streamStub{ctx: bearerCtx("tok")}
	info := &grpc.StreamServerInfo{FullMethod: "/svc/Stream"}
	if err := interceptor(nil, ss, info, handler); err != nil {
		t.Fatalf("stream interceptor error: %v", err)
	}
}

func TestContextWithAuthorizedContext_Roundtrip(t *testing.T) {
	ac := &platformtoken.AuthorizedContext{Subject: "x"}
	ctx := ContextWithAuthorizedContext(context.Background(), ac)
	got, ok := AuthorizedContextFromContext(ctx)
	if !ok || got != ac {
		t.Fatal("roundtrip failed")
	}
	if _, ok := AuthorizedContextFromContext(context.Background()); ok {
		t.Error("empty context should not yield an AuthorizedContext")
	}
}

func TestDPoPProofFromContext(t *testing.T) {
	if got := dpopProofFromContext(context.Background()); got != "" {
		t.Errorf("no-metadata context proof = %q, want empty", got)
	}
	md := metadata.Pairs(DPoPMetadataKey, "abc")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if got := dpopProofFromContext(ctx); got != "abc" {
		t.Errorf("proof = %q, want abc", got)
	}
}
