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

	quicbaaspb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
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
		"/platform.v1.CAService/InitCA":                  "ca:create",
		"/platform.v1.CAService/IssueCertificate":        "certs:generate",
		"/platform.v1.CAService/RevokeCertificate":       "certs:revoke",
		"/platform.v1.CAService/ListCertificates":        "certs:list",
		"/platform.v1.CAService/SignCSR":                 "ca:sign-csr",
		"/platform.v1.CAService/GetCAInfo":               "ca:read",
		"/platform.v1.CAService/UninstallCACertificates": "trust:write",
		"/platform.v1.PIVService/Sign":                   "piv:use",
		"/platform.v1.PIVService/Reset":                  "piv:delete",
		"/platform.v1.CeremonyService/SignCSR":           "ceremony:sign_csr",
		"/platform.v1.CeremonyService/ClaimCertBegin":    "ceremony:claim_cert",
		"/platform.v1.CeremonyService/Init":              "ceremony:initialize",
		"/platform.v1.CeremonyService/Status":            "ceremony:status",
		"/platform.v1.BarrierService/Init":               "seal:bootstrap",
		"/platform.v1.BarrierService/GetStatus":          "seal:status",

		"/quicbaas.kms.v1.SecretsManagement/ListSecrets": "secrets:list",

		// Only the unary Health/Check probe is pre-auth. The component report,
		// the service enumeration and the long-lived stream need a token.
		"/platform.v1.PlatformDaemon/GetHealth": "platform:read",
		"/grpc.health.v1.Health/List":           "platform:read",
		"/grpc.health.v1.Health/Watch":          "platform:read",
	}
	for method, want := range cases {
		if got := ScopeForMethod(method); got != want {
			t.Errorf("ScopeForMethod(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestScopeForMethod_UnknownMethodIsUnscoped(t *testing.T) {
	if got := ScopeForMethod("/grpc.health.v1.Health/Check"); got != "" {
		t.Errorf("ScopeForMethod(pre-auth health probe) = %q, want empty", got)
	}
	if got := ScopeForMethod("/some.unknown.Service/Method"); got != "" {
		t.Errorf("ScopeForMethod(unknown) = %q, want empty", got)
	}
}

func TestIsPreAuthMethod(t *testing.T) {
	preAuth := []string{
		"/grpc.health.v1.Health/Check",
		"/platform.v1.PlatformDaemon/Liveness",
		"/platform.v1.PlatformDaemon/Readiness",
		"/platform.v1.InvitationService/AcceptInvitation",
		"/platform.v1.ConfigDeliveryService/FetchConfig",
	}
	for _, method := range preAuth {
		if !isPreAuthMethod(method) {
			t.Errorf("isPreAuthMethod(%q) = false, want true", method)
		}
	}
	notPreAuth := []string{
		// Ceremony Init and Status are scoped on TCP: first boot uses the
		// Unix socket or the pre-auth REST /init route (#766).
		"/platform.v1.CeremonyService/Init",
		"/platform.v1.CeremonyService/Status",
		"/platform.v1.CeremonyService/SignCSR",
		"/platform.v1.ConfigDeliveryService/FulfillSession",
		"/platform.v1.PlatformDaemon/HealthCheck",
		"/platform.v1.PlatformDaemon/GetHealth",
		"/grpc.health.v1.Health/List",
		"/grpc.health.v1.Health/Watch",
		"",
	}
	for _, method := range notPreAuth {
		if isPreAuthMethod(method) {
			t.Errorf("isPreAuthMethod(%q) = true, want false", method)
		}
	}
}

// TestScopeForMethod_EveryDeviceServiceMethodIsScoped walks the generated
// DeviceService descriptor so an RPC added to device.proto cannot ship
// unscoped (the catalog is default-deny, so it would be refused for every
// caller), and pins the writes: DisableDevice and EnableDevice (#250) cut a
// device off the fabric and re-admit it, and AttestDevice /
// RecordAttestationCertificate persist trust state.
func TestScopeForMethod_EveryDeviceServiceMethodIsScoped(t *testing.T) {
	want := map[string]string{
		"AttestDevice":                 "device:write",
		"RecordAttestationCertificate": "device:write",
		"DisableDevice":                "device:write",
		"EnableDevice":                 "device:write",
		"CreateTemplate":               "device:write",
		"CreateProfileFromTemplate":    "device:write",
		"FindConfigForDevice":          "device:read",
	}
	// A diskless node's per-boot calls carry no token: the daemon lists them
	// in its gRPC skipMethods (pkg/api/daemon/daemon.go) and the boot service
	// authenticates the node's proof bound to the connection. A scope here
	// would never be checked, so they must stay unscoped.
	tokenExempt := map[string]bool{
		"BootCertificate": true,
		"BootDelivery":    true,
	}
	desc := platformv1.DeviceService_ServiceDesc
	names := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		names = append(names, m.MethodName)
	}
	for _, s := range desc.Streams {
		names = append(names, s.StreamName)
	}
	if len(names) == 0 {
		t.Fatal("DeviceService descriptor lists no RPCs")
	}
	for _, name := range names {
		method := "/" + desc.ServiceName + "/" + name
		got := ScopeForMethod(method)
		if tokenExempt[name] {
			if got != "" {
				t.Errorf("ScopeForMethod(%s) = %q, want no scope for a token-exempt boot call", method, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("%s has no scope; the default-deny catalog refuses it", method)
			continue
		}
		if scope, pinned := want[name]; pinned && got != scope {
			t.Errorf("ScopeForMethod(%s) = %q, want %q", method, got, scope)
		}
	}
}

// qrdbRegisteredActions pins the actions go-qrdb's permission registry
// (pkg/permission, v0.19.0-alpha) holds for the resource families it owns. A
// role can hold only a registered permission, and go-quicbaas may not add
// actions to these families, so a method mapped onto any other action here
// could never be authorized. The layer guard forbids importing go-qrdb, so the
// vocabulary is pinned: update it together with the dependency.
var qrdbRegisteredActions = map[string]map[string]bool{
	"barrier": {"unseal-share": true},
	"ca":      {"create": true, "read": true, "list": true, "update": true},
	"ceremony": {
		"initialize": true, "enroll_custodian": true, "revoke_custodian": true,
		"claim_cert": true, "claim_share_begin": true, "claim_share_complete": true,
		"sign_csr": true, "status": true,
	},
	"certs": {"generate": true, "export": true, "revoke": true, "list": true, "read": true},
	"piv":   {"read": true, "write": true, "use": true, "delete": true},
	"seal": {
		"bootstrap": true, "unseal": true, "seal": true, "status": true,
		"rotate_root_key": true, "rekey": true, "enable_encryption": true,
		"generate_recovery": true, "recover_with_keys": true, "initialize_shamir": true,
		"officer_register": true, "officer_list": true, "submit_seal_vote": true,
	},
	"secrets": {"read": true, "write": true, "delete": true, "list": true},
	"trust":   {"read": true, "write": true},
}

// wildcardOnlyScopes are platform actions in a go-qrdb family, each pinned to
// the one method that needs it. No role can be granted one by name, so only a
// wildcard (ca:*, *:*) covers it: certifying a KMS key for code signing stays
// with the platform admin, the same on every transport (#691).
var wildcardOnlyScopes = map[string]string{
	"ca:sign-csr": "/platform.v1.CAService/SignCSR",
}

// TestGRPCMethodPermissions_WellFormed asserts every catalog entry is a
// well-formed colon "resource:action" scope with a known resource and action.
// Platform-owned resources use the read/write/delete vocabulary; resources
// go-qrdb owns use the actions it registers.
func TestGRPCMethodPermissions_WellFormed(t *testing.T) {
	platformResources := map[string]bool{
		"vtpm": true, "dns": true, "device": true, "sdn": true, "kms": true,
		"iam": true, "proxy": true, "ntp": true, "platform": true,
		"attestation": true, "bmc": true, "cluster": true, "container": true,
		"vm": true, "provisioning": true, "eab": true, "fido2": true,
		"idevid": true, "invitation": true, "luks": true, "pxe": true,
		"registry": true, "switch": true, "tpm": true, "tenant": true,
		"vpn": true, "cache": true, "scheduler": true, "messaging": true,
	}
	platformActions := map[string]bool{"read": true, "write": true, "delete": true}
	// BMC, the daemon and the VPN posture policies carry the extra verbs; no
	// other resource may.
	extraActions := map[string]map[string]bool{
		"bmc":      {"power": true, "media": true, "admin": true},
		"platform": {"admin": true},
		"vpn":      {"admin": true},
	}

	for method, scope := range buildGRPCMethodPermissions() {
		parts := strings.SplitN(scope, ":", 2)
		if len(parts) != 2 {
			t.Errorf("%s -> %q is not colon-delimited", method, scope)
			continue
		}
		resource, action := parts[0], parts[1]
		if wildcardOnlyScopes[scope] == method {
			continue
		}
		if registered, ok := qrdbRegisteredActions[resource]; ok {
			if !registered[action] {
				t.Errorf("%s -> %q is not a permission go-qrdb registers", method, scope)
			}
			continue
		}
		if !platformResources[resource] {
			t.Errorf("%s -> %q has unknown resource %q", method, scope, resource)
			continue
		}
		if !platformActions[action] && !extraActions[resource][action] {
			t.Errorf("%s -> %q has unknown action %q", method, scope, action)
		}
	}
}

// =============================================================================
// Catalog contract: every registered method is classified
// =============================================================================

// registeredMethods returns the FullMethod of every unary and streaming method
// platformd can register on its gRPC server, read from the generated service
// descriptors so a new method or service is covered the day it is generated:
// the whole platform.v1 package, the QuicBaaS KMS services the daemon
// re-registers (kms_service.go), and the standard health service.
func registeredMethods(t *testing.T) map[string]bool {
	t.Helper()
	methods := make(map[string]bool)

	protoregistry.GlobalFiles.RangeFilesByPackage("platform.v1", func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			for j := 0; j < svc.Methods().Len(); j++ {
				methods["/"+string(svc.FullName())+"/"+string(svc.Methods().Get(j).Name())] = true
			}
		}
		return true
	})

	descs := []grpc.ServiceDesc{
		quicbaaspb.KeyManagement_ServiceDesc,
		quicbaaspb.Crypto_ServiceDesc,
		quicbaaspb.DEKManagement_ServiceDesc,
		quicbaaspb.SecretsManagement_ServiceDesc,
		grpc_health_v1.Health_ServiceDesc,
	}
	for _, desc := range descs {
		for _, m := range desc.Methods {
			methods["/"+desc.ServiceName+"/"+m.MethodName] = true
		}
		for _, s := range desc.Streams {
			methods["/"+desc.ServiceName+"/"+s.StreamName] = true
		}
	}

	// Guard against a vacuous pass: if the descriptors failed to load, the
	// loops above found nothing and every assertion below would hold.
	for _, sentinel := range []string{
		"/platform.v1.PlatformDaemon/StreamEvents",
		"/platform.v1.DNSService/AddRecord",
		"/quicbaas.kms.v1.Crypto/Encrypt",
		"/grpc.health.v1.Health/Watch",
	} {
		if !methods[sentinel] {
			t.Fatalf("service descriptors did not yield %s; the method enumeration is broken", sentinel)
		}
	}
	return methods
}

// TestGRPCMethodCatalog_CoversEveryRegisteredMethod fails when a generated
// method has neither a scope entry nor a pre-auth entry. The interceptor would
// refuse such a method outright, so the fix is to classify it, not to relax
// the interceptor.
func TestGRPCMethodCatalog_CoversEveryRegisteredMethod(t *testing.T) {
	for method := range registeredMethods(t) {
		if ScopeForMethod(method) == "" && !isPreAuthMethod(method) {
			t.Errorf("%s has no scope in buildGRPCMethodPermissions and is not in preAuthMethods", method)
		}
	}
}

// TestGRPCMethodCatalog_NoStaleEntries fails when a scope or pre-auth entry
// names a method no service declares, which is how a rename or a typo would
// silently leave the real method unclassified.
func TestGRPCMethodCatalog_NoStaleEntries(t *testing.T) {
	registered := registeredMethods(t)
	for method := range grpcMethodPermissions {
		if !registered[method] {
			t.Errorf("scope entry %s names no registered method", method)
		}
	}
	for method := range preAuthMethods {
		if !registered[method] {
			t.Errorf("pre-auth entry %s names no registered method", method)
		}
	}
}

// TestGRPCMethodCatalog_PreAuthIsNotScoped fails when a method is both
// pre-auth and scoped: the interceptor would never enforce the scope.
func TestGRPCMethodCatalog_PreAuthIsNotScoped(t *testing.T) {
	for method := range preAuthMethods {
		if scope := ScopeForMethod(method); scope != "" {
			t.Errorf("%s is pre-auth but also requires %q", method, scope)
		}
	}
}

// TestGRPCMethodPermissions_AttestationIsAWrite pins that the two
// attestation RPCs persist state and so are not grantable by device:read.
func TestGRPCMethodPermissions_AttestationIsAWrite(t *testing.T) {
	for _, method := range []string{
		"/platform.v1.DeviceService/AttestDevice",
		"/platform.v1.DeviceService/RecordAttestationCertificate",
	} {
		if got := ScopeForMethod(method); got != "device:write" {
			t.Errorf("ScopeForMethod(%q) = %q, want device:write", method, got)
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

// TestOIDCUnaryInterceptor_SignCSRNeedsItsOwnScope verifies certs:generate,
// which issues certificates for keys the CA generates, does not reach CSR signing:
// only ca:sign-csr or a wildcard covering it does.
func TestOIDCUnaryInterceptor_SignCSRNeedsItsOwnScope(t *testing.T) {
	cases := []struct {
		scopes []string
		allow  bool
	}{
		{[]string{"certs:generate", "ca:create", "ca:read", "ca:update"}, false},
		{[]string{"*:generate"}, false},
		{[]string{"ca:sign-csr"}, true},
		{[]string{"ca:*"}, true},
		{[]string{"*:*"}, true},
	}
	for _, tc := range cases {
		stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u", Scopes: tc.scopes}}
		interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))
		called := false
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			called = true
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.CAService/SignCSR"}
		_, err := interceptor(bearerCtx("tok"), nil, info, handler)
		if tc.allow {
			if err != nil || !called {
				t.Errorf("scopes %v: SignCSR refused: %v", tc.scopes, err)
			}
			continue
		}
		if status.Code(err) != codes.PermissionDenied || called {
			t.Errorf("scopes %v: SignCSR err = %v, called = %v; want PermissionDenied", tc.scopes, err, called)
		}
	}
}

// TestOIDCUnaryInterceptor_UnclassifiedMethodDenied verifies default deny: a
// method absent from the catalog is refused with PermissionDenied even for a
// token holding every scope, and the validator is never consulted.
func TestOIDCUnaryInterceptor_UnclassifiedMethodDenied(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"*:*"},
	}}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.UnclassifiedService/Anything"}
	_, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied", got)
	}
	if !strings.Contains(err.Error(), "/platform.v1.UnclassifiedService/Anything") {
		t.Errorf("error %q does not name the refused method", err)
	}
	if called {
		t.Error("handler must not run for an unclassified method")
	}
	if stub.calls != 0 {
		t.Errorf("validator called %d times for an unclassified method, want 0", stub.calls)
	}
}

// TestOIDCUnaryInterceptor_UnclassifiedMethodDenied_LegacyValidator verifies
// default deny also holds on the bool-only validator path.
func TestOIDCUnaryInterceptor_UnclassifiedMethodDenied_LegacyValidator(t *testing.T) {
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(&mockTokenValidator{valid: true}))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.UnclassifiedService/Anything"}
	_, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied", got)
	}
}

// TestOIDCUnaryInterceptor_PreAuthMethodNeedsNoToken verifies a pre-auth method
// is served with no Authorization header and without consulting the validator.
func TestOIDCUnaryInterceptor_PreAuthMethodNeedsNoToken(t *testing.T) {
	probes := []string{
		"/grpc.health.v1.Health/Check",
		"/platform.v1.PlatformDaemon/Liveness",
		"/platform.v1.PlatformDaemon/Readiness",
	}
	for _, method := range probes {
		stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u"}}
		interceptor := OIDCUnaryInterceptor(WithTokenValidator(stub))
		handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
		info := &grpc.UnaryServerInfo{FullMethod: method}
		if _, err := interceptor(context.Background(), nil, info, handler); err != nil {
			t.Fatalf("pre-auth method %s refused: %v", method, err)
		}
		if stub.calls != 0 {
			t.Errorf("validator called %d times for pre-auth %s, want 0", stub.calls, method)
		}
	}
}

func TestErrMethodNotClassified_Error(t *testing.T) {
	got := ErrMethodNotClassified{Method: "/platform.v1.X/Y"}.Error()
	if !strings.Contains(got, "/platform.v1.X/Y") || !strings.Contains(got, "permission denied") {
		t.Errorf("Error() = %q, want the method and a permission-denied message", got)
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

// TestOIDCUnaryInterceptor_LegacyValidator_ScopeGatedByChecker verifies the
// bool-only validator path applies the method's scope through the checker.
func TestOIDCUnaryInterceptor_LegacyValidator_ScopeGatedByChecker(t *testing.T) {
	// A bool-only validator's token carries no scopes, so the method's catalog
	// scope is decided by the AuthorizationChecker: a denial is a scope
	// denial naming the method's permission, never a pass-through (#768).
	legacy := &mockTokenValidator{valid: true}
	checker := &mockAuthorizationChecker{allowed: false}
	interceptor := OIDCUnaryInterceptor(WithTokenValidator(legacy), WithAuthorizationChecker(checker))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler must not run for a denied method")
		return nil, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/platform.v1.DNSService/AddRecord"}
	_, err := interceptor(bearerCtx("tok"), nil, info, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
	}
	if checker.resource != "dns" || checker.action != "write" {
		t.Errorf("checker asked (%q, %q), want (dns, write)", checker.resource, checker.action)
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

// TestOIDCStreamInterceptor_UnclassifiedMethodDenied verifies default deny on
// the stream path.
func TestOIDCStreamInterceptor_UnclassifiedMethodDenied(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{
		Subject: "u", Scopes: []string{"*:*"},
	}}
	interceptor := OIDCStreamInterceptor(WithTokenValidator(stub))

	called := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		called = true
		return nil
	}
	ss := &streamStub{ctx: bearerCtx("tok")}
	info := &grpc.StreamServerInfo{FullMethod: "/platform.v1.UnclassifiedService/Watch"}
	err := interceptor(nil, ss, info, handler)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied", got)
	}
	if called || stub.calls != 0 {
		t.Errorf("unclassified stream reached handler=%v validator calls=%d, want neither", called, stub.calls)
	}
}

// TestOIDCStreamInterceptor_HealthWatchNeedsToken verifies the health Watch
// stream is not served anonymously: it holds a stream open for as long as the
// caller likes, so only the unary Health/Check probe is pre-auth.
func TestOIDCStreamInterceptor_HealthWatchNeedsToken(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "u"}}
	interceptor := OIDCStreamInterceptor(WithTokenValidator(stub))
	called := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		called = true
		return nil
	}
	ss := &streamStub{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}
	err := interceptor(nil, ss, info, handler)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("status code = %v, want Unauthenticated", got)
	}
	if called {
		t.Error("anonymous health Watch stream reached the handler")
	}
}
