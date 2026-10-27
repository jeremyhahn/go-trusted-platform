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

// Dispatch-stub check (#317): every operation a transport serves must reach
// a real implementation.
//
// The check is static: it parses the source of the served build (the tag set
// this test binary was built with) and resolves each operation through the
// QUIC opcode dispatch, the registered gRPC services, the REST routes and the
// MCP tool switch to the definition that handles it. Static analysis was
// chosen over runtime introspection because the stubs are a property of the
// code, not of a running daemon: a runtime probe needs a fully wired daemon
// (TPM, storage, SDK) for every transport and still cannot tell a stub from a
// handler that refused a bad request, while the source shows the returned
// value directly and points at its file:line.
//
// Every stub still served on main is listed in stubExceptions. The table may
// only shrink; see docs/daemon/engineering.md "Dispatch-stub check".
package arch_test

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// stubException is one served stub the check tolerates until it is
// implemented: the operation as the check names it, the stub's file:line,
// and why it is still a stub.
type stubException struct {
	Operation string
	At        string
	Reason    string
}

// stubExceptions lists every stub served on main. It may only shrink: when a
// stub is implemented, the check reports its entry stale; delete the entry
// and lower stubExceptionCeiling to the new length. Never add an entry for a
// new stub — implement the operation instead.
var stubExceptions = []stubException{
	{"gRPC PlatformIAMService/CreateToken", "pkg/api/daemon/iam_grpc_service.go:1110", "token issuance runs through go-quicbaas OIDC flows; RPC answers Unimplemented"},
	{"gRPC PlatformIAMService/RevokeToken", "pkg/api/daemon/iam_grpc_service.go:1117", "token revocation runs through go-quicbaas OIDC flows; RPC answers Unimplemented"},
	{"QUIC quicwire.OpIAMTokenCreate", "pkg/api/daemon/quic_iam.go:137", "QUIC parity with the OIDC-only gRPC CreateToken"},
	{"QUIC quicwire.OpIAMTokenRevoke", "pkg/api/daemon/quic_iam.go:139", "QUIC parity with the OIDC-only gRPC RevokeToken"},
	{"gRPC CAService/InitCA", "sdk/go/gen/ca_grpc.pb.go:256", "daemon CAGRPCService does not override the generated fallback"},
	{"gRPC CAService/InstallCACertificates", "sdk/go/gen/ca_grpc.pb.go:259", "daemon CAGRPCService does not override the generated fallback"},
	{"gRPC CAService/UninstallCACertificates", "sdk/go/gen/ca_grpc.pb.go:262", "daemon CAGRPCService does not override the generated fallback"},
}

// stubExceptionCeiling is len(stubExceptions). It only ever goes down.
const stubExceptionCeiling = 7

// servedDispatchConfig is the dispatch surface the daemon serves.
func servedDispatchConfig(root, module string, tags []string) dispatchConfig {
	return dispatchConfig{
		Root:   root,
		Module: module,
		Tags:   tags,
		Scope:  []string{"pkg/api", "pkg/webservice"},
		Bindings: []dispatchBinding{{
			Interface: typeRef{pkg: "pkg/api/mcp", name: "ServiceProvider"},
			Impl:      typeRef{pkg: "pkg/api/daemon", name: "MCPServiceProvider"},
			WiredIn:   funcKey{Pkg: "pkg/api/daemon", Recv: "Daemon", Name: "createMCPServer"},
			Into:      funcKey{Pkg: "pkg/api/mcp", Name: "NewServer"},
			Arg:       0,
		}},
		Transports: []dispatchTransport{
			{Name: "QUIC", Roots: []funcKey{{Pkg: "pkg/api/daemon", Recv: "QUICServiceHandler", Name: "HandleRequest"}}},
			{Name: "gRPC", Register: []string{"pkg/api/daemon"}},
			{Name: "REST", Roots: []funcKey{
				{Pkg: "pkg/api/daemon", Recv: "RESTServer", Name: "*"},
				{Pkg: "pkg/webservice/v1", Recv: "Router", Name: "RegisterRoutes"},
			}},
			{Name: "MCP", Roots: []funcKey{{Pkg: "pkg/api/mcp", Recv: "ToolRegistry", Name: "ExecuteTool"}}},
		},
	}
}

// fixtureDispatchConfig is the same surface over testdata/dispatch.
func fixtureDispatchConfig() dispatchConfig {
	return dispatchConfig{
		Root:   filepath.Join("testdata", "dispatch"),
		Module: "example.test/dispatch",
		Scope:  []string{"quicsvc", "server", "clusterstub", "clusterreal"},
		Bindings: []dispatchBinding{{
			Interface: typeRef{pkg: "quicsvc", name: "Backend"},
			Impl:      typeRef{pkg: "quicsvc", name: "Store"},
			WiredIn:   funcKey{Pkg: "quicsvc", Name: "New"},
			Into:      funcKey{Pkg: "quicsvc", Name: "wrap"},
			Arg:       0,
		}},
		Transports: []dispatchTransport{
			{Name: "QUIC", Roots: []funcKey{{Pkg: "quicsvc", Recv: "Handler", Name: "HandleRequest"}}},
			{Name: "gRPC", Register: []string{"server"}},
		},
	}
}

// checkStubExceptions matches findings against the exception table on
// operation and file:line, both ways.
func checkStubExceptions(findings []dispatchFinding, exceptions []stubException) []error {
	type key struct{ op, at string }
	excepted := map[key]bool{}
	for _, e := range exceptions {
		excepted[key{e.Operation, e.At}] = true
	}
	live := map[key]bool{}
	var errs []error
	for _, f := range findings {
		live[key{f.Operation, f.At}] = true
		if !excepted[key{f.Operation, f.At}] {
			errs = append(errs, &DispatchStubError{Operation: f.Operation, At: f.At, Kind: f.Kind})
		}
	}
	for _, e := range exceptions {
		if !live[key{e.Operation, e.At}] {
			errs = append(errs, &StaleStubExceptionError{Operation: e.Operation, At: e.At})
		}
	}
	return errs
}

// servedBuildTags returns the -tags this test binary was built with, so the
// check reads the files of the build the daemon serves.
func servedBuildTags(t *testing.T) []string {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range info.Settings {
			if s.Key == "-tags" && s.Value != "" {
				return strings.Split(s.Value, ",")
			}
		}
	}
	t.Fatalf("test binary carries no -tags; run it as: make test-pkg PKG=./pkg/arch/")
	return nil
}

// modulePath reads the module path from go.mod.
func modulePath(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("go.mod has no module line")
	return ""
}

// fixtureLine returns "rel:line" for the fixture line carrying marker.
func fixtureLine(t *testing.T, rel, marker string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "dispatch", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, marker) {
			return rel + ":" + strconv.Itoa(i+1)
		}
	}
	t.Fatalf("fixture %s has no line marked %q", rel, marker)
	return ""
}

func findingAt(findings []dispatchFinding, op, at string) bool {
	for _, f := range findings {
		if f.Operation == op && f.At == at {
			return true
		}
	}
	return false
}

// TestDispatchedOperationsReachRealImplementations is the check itself.
func TestDispatchedOperationsReachRealImplementations(t *testing.T) {
	root := moduleRoot(t)
	cfg := servedDispatchConfig(root, modulePath(t, root), servedBuildTags(t))
	rep := runDispatchCheck(cfg)
	for _, err := range rep.Errs {
		t.Error(err)
	}
	for _, tr := range cfg.Transports {
		t.Logf("%s: %d operations reached", tr.Name, rep.Operations[tr.Name])
		if rep.Operations[tr.Name] == 0 {
			t.Errorf("%s: the walk reached no operations; its roots no longer match the served dispatch", tr.Name)
		}
	}
	for _, err := range checkStubExceptions(rep.Findings, stubExceptions) {
		t.Error(err)
	}
}

// TestDispatchCheck_ReportsDispatchedStub covers a stub switch arm and a stub
// handler reached through an interface field, and holds that a 501 answered
// on a guard branch before real work is not a stub.
func TestDispatchCheck_ReportsDispatchedStub(t *testing.T) {
	rep := runDispatchCheck(fixtureDispatchConfig())
	if len(rep.Errs) != 0 {
		t.Fatalf("fixture check errors: %v", errors.Join(rep.Errs...))
	}
	arm := fixtureLine(t, "quicsvc/handler.go", "stub: arm")
	handler := fixtureLine(t, "quicsvc/store.go", "stub: handler")
	errs := checkStubExceptions(rep.Findings, nil)
	for _, want := range []dispatchFinding{
		{Operation: "QUIC wire.OpDelete", At: arm},
		{Operation: "QUIC wire.OpGet", At: handler},
	} {
		var stub *DispatchStubError
		found := false
		for _, err := range errs {
			if errors.As(err, &stub) && stub.Operation == want.Operation && stub.At == want.At {
				found = true
			}
		}
		if !found {
			t.Errorf("no DispatchStubError for %s at %s; got %v", want.Operation, want.At, errors.Join(errs...))
		}
	}
	for _, f := range rep.Findings {
		if f.Operation == "QUIC wire.OpList" || strings.Contains(f.Operation, "Unknown") {
			t.Errorf("guarded 501 or unknown-opcode fallback reported as a stub: %+v", f)
		}
	}
}

// TestDispatchCheck_ResolvesSameNameConstructorByImport registers the stub
// one of two same-named constructors builds and expects the findings in that
// package, never in the real one.
func TestDispatchCheck_ResolvesSameNameConstructorByImport(t *testing.T) {
	rep := runDispatchCheck(fixtureDispatchConfig())
	if len(rep.Errs) != 0 {
		t.Fatalf("fixture check errors: %v", errors.Join(rep.Errs...))
	}
	join := fixtureLine(t, "clusterstub/service.go", "stub: producer")
	leave := fixtureLine(t, "gen/gen.go", "stub: embedded")
	if !findingAt(rep.Findings, "gRPC ClusterService/Join", join) {
		t.Errorf("Join stub not reported at %s; findings %+v", join, rep.Findings)
	}
	if !findingAt(rep.Findings, "gRPC ClusterService/Leave", leave) {
		t.Errorf("embedded Leave not reported at %s; findings %+v", leave, rep.Findings)
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.At, "clusterreal/") || f.Operation == "gRPC ClusterService/Status" {
			t.Errorf("finding resolved to the wrong package or an overridden method: %+v", f)
		}
	}
}

// TestDispatchCheck_ReportsStaleException holds that an exception no live
// stub matches fails the check, while matched ones pass.
func TestDispatchCheck_ReportsStaleException(t *testing.T) {
	rep := runDispatchCheck(fixtureDispatchConfig())
	exceptions := make([]stubException, 0, len(rep.Findings)+1)
	for _, f := range rep.Findings {
		exceptions = append(exceptions, stubException{Operation: f.Operation, At: f.At, Reason: "fixture"})
	}
	stale := fixtureLine(t, "quicsvc/handler.go", "real: list")
	exceptions = append(exceptions, stubException{Operation: "QUIC wire.OpList", At: stale, Reason: "fixture"})
	errs := checkStubExceptions(rep.Findings, exceptions)
	if len(errs) != 1 {
		t.Fatalf("want exactly the stale exception, got %v", errors.Join(errs...))
	}
	var staleErr *StaleStubExceptionError
	if !errors.As(errs[0], &staleErr) || staleErr.At != stale {
		t.Fatalf("want StaleStubExceptionError at %s, got %v", stale, errs[0])
	}
}

// TestDispatchCheck_ReportsUnverifiedBinding holds that an interface binding
// the wiring site does not make is an error, not a silent assumption.
func TestDispatchCheck_ReportsUnverifiedBinding(t *testing.T) {
	cfg := fixtureDispatchConfig()
	cfg.Bindings[0].Impl = typeRef{pkg: "quicsvc", name: "Handler"}
	rep := runDispatchCheck(cfg)
	var bindErr *DispatchBindingError
	if !errors.As(errors.Join(rep.Errs...), &bindErr) {
		t.Fatalf("want DispatchBindingError, got %v", errors.Join(rep.Errs...))
	}
	if findingAt(rep.Findings, "QUIC wire.OpGet", fixtureLine(t, "quicsvc/store.go", "stub: handler")) {
		t.Errorf("handler behind an unverified binding was resolved anyway")
	}
}

// TestDispatchCheck_ReportsUnresolvedRegistration holds that a registered
// service whose implementation type cannot be inferred is an error.
func TestDispatchCheck_ReportsUnresolvedRegistration(t *testing.T) {
	cfg := fixtureDispatchConfig()
	cfg.Transports = []dispatchTransport{{Name: "gRPC", Register: []string{"badserver"}}}
	rep := runDispatchCheck(cfg)
	var unresolved *DispatchUnresolvedError
	if !errors.As(errors.Join(rep.Errs...), &unresolved) {
		t.Fatalf("want DispatchUnresolvedError, got %v", errors.Join(rep.Errs...))
	}
	if want := fixtureLine(t, "badserver/server.go", "unresolved: impl"); unresolved.At != want {
		t.Errorf("unresolved at %s, want %s", unresolved.At, want)
	}
}

// TestDispatchCheck_ReportsMissingPackage holds that a root the check cannot
// load is an error rather than an empty, passing walk.
func TestDispatchCheck_ReportsMissingPackage(t *testing.T) {
	cfg := fixtureDispatchConfig()
	cfg.Transports = []dispatchTransport{{Name: "QUIC", Roots: []funcKey{{Pkg: "missing", Recv: "Handler", Name: "HandleRequest"}}}}
	rep := runDispatchCheck(cfg)
	var srcErr *DispatchSourceError
	if !errors.As(errors.Join(rep.Errs...), &srcErr) {
		t.Fatalf("want DispatchSourceError, got %v", errors.Join(rep.Errs...))
	}
}

var exceptionAt = regexp.MustCompile(`^[\w./-]+\.go:[1-9][0-9]*$`)

// TestStubExceptions_WellFormed holds the table's shape: it matches its
// ceiling, every entry is complete, and none is listed twice.
func TestStubExceptions_WellFormed(t *testing.T) {
	if len(stubExceptions) != stubExceptionCeiling {
		t.Errorf("stubExceptions has %d entries, ceiling is %d; the table only shrinks — lower the ceiling with it",
			len(stubExceptions), stubExceptionCeiling)
	}
	seen := map[string]bool{}
	for _, e := range stubExceptions {
		if e.Operation == "" || e.Reason == "" || !exceptionAt.MatchString(e.At) {
			t.Errorf("incomplete stub exception %+v", e)
		}
		if seen[e.Operation+"@"+e.At] {
			t.Errorf("duplicate stub exception %s at %s", e.Operation, e.At)
		}
		seen[e.Operation+"@"+e.At] = true
	}
}
