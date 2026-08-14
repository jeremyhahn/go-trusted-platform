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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// ErrScopeDenied
// =============================================================================

func TestErrScopeDenied_Error(t *testing.T) {
	err := ErrScopeDenied{Method: "/platform.v1.DNSService/AddRecord", Scope: "dns:write"}
	got := err.Error()
	if !strings.Contains(got, "/platform.v1.DNSService/AddRecord") || !strings.Contains(got, "dns:write") {
		t.Errorf("Error() = %q, want method and scope present", got)
	}
}

// =============================================================================
// scopeForMethod catalog
// =============================================================================

func TestScopeForMethod_KnownMethods(t *testing.T) {
	cases := map[string]string{
		"/platform.v1.VTPMService/CreateTemplate":        "vtpm:write",
		"/platform.v1.VTPMService/GetTemplate":           "vtpm:read",
		"/platform.v1.VTPMService/DeleteTemplate":        "vtpm:delete",
		"/platform.v1.DNSService/AddRecord":              "dns:write",
		"/platform.v1.DNSService/ListRecords":            "dns:read",
		"/platform.v1.DNSService/DeleteZone":             "dns:delete",
		"/platform.v1.DeviceService/CreateDevice":        "device:write",
		"/platform.v1.DeviceService/GetDevice":           "device:read",
		"/platform.v1.DeviceService/DeleteDevice":        "device:delete",
		"/platform.v1.SDNService/CreateBridge":           "sdn:write",
		"/platform.v1.SDNService/ListBridges":            "sdn:read",
		"/platform.v1.SDNService/DeleteBridge":           "sdn:delete",
		"/platform.v1.KeyManagementService/GenerateKey":  "kms:write",
		"/platform.v1.KeyManagementService/GetKey":       "kms:read",
		"/platform.v1.KeyManagementService/DeleteKey":    "kms:delete",
		"/platform.v1.PlatformIAMService/CreateUser":     "iam:write",
		"/platform.v1.PlatformIAMService/GetUser":        "iam:read",
		"/platform.v1.PlatformIAMService/DeleteUser":     "iam:delete",
		"/platform.v1.CAService/IssueCertificate":        "ca:write",
		"/platform.v1.CAService/GetCAInfo":               "ca:read",
		"/platform.v1.CAService/UninstallCACertificates": "ca:delete",
	}
	for method, want := range cases {
		if got := scopeForMethod(method); got != want {
			t.Errorf("scopeForMethod(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestScopeForMethod_UnknownMethodIsUnscoped(t *testing.T) {
	if got := scopeForMethod("/platform.v1.PlatformDaemon/HealthCheck"); got != "" {
		t.Errorf("scopeForMethod(health) = %q, want empty", got)
	}
	if got := scopeForMethod("/some.unknown.Service/Method"); got != "" {
		t.Errorf("scopeForMethod(unknown) = %q, want empty", got)
	}
}

// TestGRPCMethodPermissions_WellFormed asserts every catalog entry is a
// well-formed colon "resource:action" scope with a known resource and action.
func TestGRPCMethodPermissions_WellFormed(t *testing.T) {
	validResources := map[string]bool{
		"vtpm": true, "dns": true, "device": true,
		"sdn": true, "kms": true, "iam": true, "ca": true,
		"proxy": true, "ntp": true,
	}
	validActions := map[string]bool{"read": true, "write": true, "delete": true}

	for method, scope := range buildGRPCMethodPermissions() {
		parts := strings.SplitN(scope, ":", 2)
		if len(parts) != 2 {
			t.Errorf("%s -> %q is not colon-delimited", method, scope)
			continue
		}
		if !validResources[parts[0]] {
			t.Errorf("%s -> %q has unknown resource %q", method, scope, parts[0])
		}
		if !validActions[parts[1]] {
			t.Errorf("%s -> %q has unknown action %q", method, scope, parts[1])
		}
		if !strings.HasPrefix(method, "/platform.v1.") {
			t.Errorf("method key %q is not a platform.v1 FullMethod", method)
		}
	}
}

// =============================================================================
// Interceptor-level scope enforcement (the Stage 5 gap closure)
// =============================================================================

// TestOIDCUnaryInterceptor_ScopeEnforced_Allows verifies a token carrying the
// method's required colon scope is allowed through to the handler.
func TestOIDCUnaryInterceptor_ScopeEnforced_Allows(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"dns:write"},
	}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.DNSService/AddRecord"}
	resp, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor denied a granted scope: %v", err)
	}
	if resp != "ok" || !called {
		t.Fatal("handler was not invoked")
	}
}

// TestOIDCUnaryInterceptor_ScopeEnforced_Denies verifies a token missing the
// method's required scope is rejected with codes.PermissionDenied before the
// handler runs.
func TestOIDCUnaryInterceptor_ScopeEnforced_Denies(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"dns:read"},
	}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.DNSService/AddRecord"}
	_, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if err == nil {
		t.Fatal("expected PermissionDenied for missing scope")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", got)
	}
	if called {
		t.Error("handler must not run when scope is denied")
	}
}

// TestOIDCUnaryInterceptor_UnscopedMethodAllowed verifies a method absent from
// the catalog is allowed once the token validates, even with no scopes.
func TestOIDCUnaryInterceptor_UnscopedMethodAllowed(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u"}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.PlatformDaemon/GetServiceStatus"}
	if _, err := interceptor(bearerCtx("tok"), nil, info, handler); err != nil {
		t.Fatalf("unscoped method should be allowed: %v", err)
	}
}

// TestOIDCUnaryInterceptor_SkipMethodBypassesScope verifies a method on the
// skip list never reaches scope enforcement (no validator interaction at all).
func TestOIDCUnaryInterceptor_SkipMethodBypassesScope(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u"}}
	interceptor := OIDCUnaryInterceptor(
		WithTokenValidator(stub),
		WithSkipMethods("/platform.v1.DNSService/AddRecord"),
	)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.DNSService/AddRecord"}
	if _, err := interceptor(context.Background(), nil, info, handler); err != nil {
		t.Fatalf("skip method should bypass auth+scope: %v", err)
	}
	if stub.calls != 0 {
		t.Errorf("validator called %d times for skip method, want 0", stub.calls)
	}
}

// TestOIDCUnaryInterceptor_LegacyValidator_NoScopeGate verifies the bool-only
// validator path never applies the scope gate (it has no AuthorizedContext).
func TestOIDCUnaryInterceptor_LegacyValidator_NoScopeGate(t *testing.T) {
	legacy := &mockTokenValidator{valid: true}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(legacy))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	// A method that WOULD require a scope on the claims path is still allowed on
	// the legacy path, because legacy enforcement is the AuthorizationChecker's
	// concern, not the interceptor's scope gate.
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.DNSService/AddRecord"}
	if _, err := interceptor(bearerCtx("tok"), nil, info, handler); err != nil {
		t.Fatalf("legacy validator path should not invoke scope gate: %v", err)
	}
}

// =============================================================================
// Stream interceptor scope enforcement
// =============================================================================

func TestOIDCStreamInterceptor_ScopeEnforced_Allows(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"sdn:read"},
	}}
	interceptor := OIDCStreamInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		called = true
		return nil
	}
	ss := &streamStub{ctx: bearerCtx("tok")}
	info := &grpc.StreamServerInfo{FullMethod: "/platform.v1.SDNService/StreamFlowLogs"}
	if err := interceptor(nil, ss, info, handler); err != nil {
		t.Fatalf("stream interceptor denied a granted scope: %v", err)
	}
	if !called {
		t.Fatal("stream handler was not invoked")
	}
}

func TestOIDCStreamInterceptor_ScopeEnforced_Denies(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"sdn:write"}, // wrong: needs sdn:read
	}}
	// Use a method requiring a scope the token lacks.
	stub.authCtx.Scopes = []string{"dns:read"}
	interceptor := OIDCStreamInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		called = true
		return nil
	}
	ss := &streamStub{ctx: bearerCtx("tok")}
	info := &grpc.StreamServerInfo{FullMethod: "/platform.v1.SDNService/StreamFlowLogs"}
	err := interceptor(nil, ss, info, handler)
	if err == nil {
		t.Fatal("expected PermissionDenied for missing scope")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", got)
	}
	if called {
		t.Error("stream handler must not run when scope is denied")
	}
}
