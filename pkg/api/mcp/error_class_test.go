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

package mcp

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	storagequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// TestCodeClass_Rules pins the naming convention the tool error codes
// follow onto their classes, one representative code per marker.
func TestCodeClass_Rules(t *testing.T) {
	tests := []struct {
		code string
		want codes.Code
	}{
		{"DEVICE_NOT_FOUND", codes.NotFound},
		{"KMS_KEY_ID_REQUIRED", codes.InvalidArgument},
		{"INVALID_ARGUMENTS", codes.InvalidArgument},
		{"DEVICE_HASH_ALGO_INVALID", codes.InvalidArgument},
		{"VM_DECODE_FAILED", codes.InvalidArgument},
		{"DNS_SERVICE_UNAVAILABLE", codes.Unavailable},
		{"ATTESTATION_REPORTING_NOT_CONFIGURED", codes.Unavailable},
		{"VM_NOT_RUNNING", codes.FailedPrecondition},
		{"OVERLAY_VNI_ALREADY_EXISTS", codes.AlreadyExists},
		{"TPM_NOT_INITIALIZED", codes.FailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := codeClass(tt.code); got != tt.want {
				t.Errorf("codeClass(%q) = %s, want %s", tt.code, got, tt.want)
			}
		})
	}
}

// TestCodeClass_FailureCodesAreUnclassified keeps codes that name a failure
// rather than a class out of every class, so they answer InternalError.
func TestCodeClass_FailureCodesAreUnclassified(t *testing.T) {
	for _, code := range append(unclassifiedCodes, "") {
		if got := codeClass(code); got != codes.Unknown {
			t.Errorf("codeClass(%q) = %s, want Unknown", code, got)
		}
	}
}

// unclassifiedCodes are the tool error codes that name a failure, not a
// caller mistake: they answer InternalError on purpose.
var unclassifiedCodes = []string{"IPAM_ALLOCATION_FAILED", "PXE_ZONE_RESOLUTION_FAILED", "LDEVID_NOT_SUPPORTED"}

// TestToolErrorCode_Classified covers each way a tool failure reaches a
// class: a tool error type's Code, a wrapped tool error, a struct error with
// its own GRPCStatus, a gRPC status error and a platform sentinel.
func TestToolErrorCode_Classified(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"tool error type", &DeviceError{Code: "DEVICE_NOT_FOUND", Message: "device 7"}, mcpwire.NotFound},
		{"wrapped tool error", fmt.Errorf("device_get: %w", &KMSError{Code: "KMS_KEY_ID_REQUIRED", Message: "key_id"}), mcpwire.InvalidParams},
		{"never-collected report", ErrNoDeviceReport{DeviceID: "7"}, mcpwire.NotFound},
		{"undecodable profile args", ErrDeviceProfileInvalidArgs{Cause: errors.New("bad json")}, mcpwire.InvalidParams},
		{"grpc status", status.Error(codes.AlreadyExists, "device exists"), mcpwire.AlreadyExists},
		{"permission denied status", status.Error(codes.PermissionDenied, "denied"), mcpwire.PermissionDenied},
		{"record not found sentinel", fmt.Errorf("get: %w", datastore.ErrRecordNotFound), mcpwire.NotFound},
		{"storage miss under device_get", fmt.Errorf("failed to get device: %w", storagequicbaas.ErrNotFound{EntityType: "Device", ID: 999999999}), mcpwire.NotFound},
		{"profile service not configured", ErrDeviceProfileNotConfigured, mcpwire.ServiceUnavailable},
		{"profile identity required", ErrDeviceProfileIdentityRequired, mcpwire.InvalidParams},
		{"bmc not configured", ErrBMCNotConfigured, mcpwire.ServiceUnavailable},
		{"pxe not configured", ErrPXENotConfigured, mcpwire.ServiceUnavailable},
		{"wrapped eab argument sentinel", fmt.Errorf("eab_create: %w", ErrEABKeyIDRequired), mcpwire.InvalidParams},
		{"hash algorithm out of range", ErrDeviceHashAlgoInvalid, mcpwire.InvalidParams},
		{"undecodable base64 argument", ErrInvalidArgument{Msg: "invalid nonce encoding", Cause: errors.New("illegal base64")}, mcpwire.InvalidParams},
		{"vm nonce", ErrVMInvalidNonce{Cause: errors.New("illegal base64")}, mcpwire.InvalidParams},
		{"vm evidence", ErrVMInvalidEvidence{Field: "quote"}, mcpwire.InvalidParams},
		{"provision profile id", ErrProvisionInvalidProfileID{Value: "x", Cause: errors.New("not a number")}, mcpwire.InvalidParams},
		{"provision digest", ErrProvisionInvalidDigest{Cause: errors.New("illegal base64")}, mcpwire.InvalidParams},
		{"daemon service name", ErrDaemonServiceNameRequired{}, mcpwire.InvalidParams},
		{"wrapped sdk not found", fmt.Errorf("kms_get_key: %w", sdkerrors.NewNotFound("kms", "no key")), mcpwire.NotFound},
		{"sdk invalid input", sdkerrors.NewInvalidInput("kms", "bad ciphertext"), mcpwire.InvalidParams},
		{"sdk precondition", sdkerrors.NewPreconditionFailed("kms", "key disabled"), mcpwire.FailedPrecondition},
		{"dns record name required", fmt.Errorf("dns_add_record: %w", dns.ErrRecordNameRequired{Type: "A"}), mcpwire.InvalidParams},
		{"dns record address", dns.ErrInvalidRecordAddress{Type: "AAAA", Value: "192.0.2.1"}, mcpwire.InvalidParams},
		{"dns tlsa usage", dns.ErrInvalidTLSAUsage{Usage: 5}, mcpwire.InvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolErrorCode(tt.err); got != tt.want {
				t.Errorf("toolErrorCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

// TestToolErrorCode_UnclassifiedIsInternal answers InternalError only for a
// failure no class covers.
func TestToolErrorCode_UnclassifiedIsInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"plain error", ErrMockServiceError},
		{"failure code", &SDNError{Code: "IPAM_ALLOCATION_FAILED", Message: "pool exhausted"}},
		{"internal status", status.Error(codes.Internal, "boom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolErrorCode(tt.err); got != mcpwire.InternalError {
				t.Errorf("toolErrorCode(%v) = %d, want InternalError", tt.err, got)
			}
		})
	}
}

// TestServer_ToolsCall_ErrorCodes runs a failing tool through the server and
// checks the JSON-RPC code it answers: the class code for a classified
// failure, InternalError for an unclassified one.
func TestServer_ToolsCall_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"not found", status.Error(codes.NotFound, "no such device"), mcpwire.NotFound},
		{"unavailable", status.Error(codes.Unavailable, "service down"), mcpwire.ServiceUnavailable},
		{"unclassified", ErrMockServiceError, mcpwire.InternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMockServiceProvider()
			svc.healthFunc = func(ctx context.Context) (interface{}, error) {
				return nil, tt.err
			}
			server := NewServer(svc, nil, newTestLogger())

			resp := server.handleRequest(ctx, &mcpwire.JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name":      "platform_health",
					"arguments": map[string]interface{}{},
				},
			})

			if resp.Error == nil {
				t.Fatal("expected an error response")
			}
			if resp.Error.Code != tt.want {
				t.Errorf("code = %d, want %d", resp.Error.Code, tt.want)
			}
		})
	}
}

// TestErrInvalidArgument_Error covers the message with and without a cause
// and the cause's reachability through errors.Is.
func TestErrInvalidArgument_Error(t *testing.T) {
	cause := errors.New("illegal base64 data at input byte 4")
	err := ErrInvalidArgument{Msg: "invalid nonce encoding", Cause: cause}
	if got, want := err.Error(), "invalid nonce encoding: illegal base64 data at input byte 4"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("status.Code = %s, want InvalidArgument", got)
	}
}

func TestErrInvalidArgument_NoCause(t *testing.T) {
	err := ErrInvalidArgument{Msg: "key_id is required"}
	if got := err.Error(); got != "key_id is required" {
		t.Errorf("Error() = %q, want the message alone", got)
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() is not nil for an error without a cause")
	}
}

// unclassifiedErrorTypes are this package's error types that deliberately
// carry no class of their own, with the reason.
var unclassifiedErrorTypes = map[string]string{
	"ErrVMOperationFailedError": "a backend failure; its cause carries any class",
	"SentinelCauseError":        "a wrapper; the sentinel it wraps carries the class",
	"AuthorizationError":        "answered by handleAuthError before a tool runs",
	"QuicBaaSAuthError":         "authentication, before a tool runs",
	"OAuthMetadataError":        "the OAuth metadata endpoint, not a tool",
	"HTTPTLSRequiredError":      "server start-up, not a tool",
	"HTTPListenError":           "server start-up, not a tool",
}

// toolErrorDecls is what the completeness tests read from the package source.
type toolErrorDecls struct {
	errorTypes      map[string]bool // types with an Error method
	classifiedTypes map[string]bool // types with a GRPCStatus method
	sentinels       []string        // package-level errors.New sentinels
	tabled          map[string]bool // sentinels listed in sentinelClasses
	codes           []string        // Code literals of classified error types
}

// parseToolErrorDecls parses the package's non-test files: reflection
// cannot enumerate package-level variables, the source can.
func parseToolErrorDecls(t *testing.T) toolErrorDecls {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	decls := toolErrorDecls{
		errorTypes:      map[string]bool{},
		classifiedTypes: map[string]bool{},
		tabled:          map[string]bool{},
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
		for _, decl := range file.Decls {
			collectToolErrorDecl(decl, &decls)
		}
	}
	// Code literals are read in a second pass: the classified set must be
	// complete before a literal's type is looked up in it.
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !decls.classifiedTypes[typeName(lit.Type)] {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok || typeName(kv.Key) != "Code" {
					continue
				}
				if value, ok := kv.Value.(*ast.BasicLit); ok && value.Kind == token.STRING {
					decls.codes = append(decls.codes, strings.Trim(value.Value, `"`))
				}
			}
			return true
		})
	}
	return decls
}

// collectToolErrorDecl records one top-level declaration.
func collectToolErrorDecl(decl ast.Decl, decls *toolErrorDecls) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil || len(d.Recv.List) == 0 {
			return
		}
		receiver := typeName(d.Recv.List[0].Type)
		switch d.Name.Name {
		case "Error":
			decls.errorTypes[receiver] = true
		case "GRPCStatus":
			decls.classifiedTypes[receiver] = true
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					break
				}
				if isErrorsNew(vs.Values[i]) {
					decls.sentinels = append(decls.sentinels, name.Name)
				}
				if name.Name == "sentinelClasses" {
					collectTabledSentinels(vs.Values[i], decls.tabled)
				}
			}
		}
	}
}

// collectTabledSentinels records the first field of each sentinelClasses row.
func collectTabledSentinels(table ast.Expr, tabled map[string]bool) {
	lit, ok := table.(*ast.CompositeLit)
	if !ok {
		return
	}
	for _, row := range lit.Elts {
		if rowLit, ok := row.(*ast.CompositeLit); ok && len(rowLit.Elts) > 0 {
			tabled[typeName(rowLit.Elts[0])] = true
		}
	}
}

// isErrorsNew reports whether expr is a call to errors.New.
func isErrorsNew(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && typeName(sel.X) == "errors" && sel.Sel.Name == "New"
}

// typeName returns the bare identifier of expr: T for T and *T, the selected
// name for pkg.T, "" for anything else.
func typeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return typeName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// TestEveryToolErrorIsClassified is the completeness check: an error type,
// errors.New sentinel or Code a tool can return without a class answers
// -32603, so a new one fails here until it is classified or listed with a
// reason.
func TestEveryToolErrorIsClassified(t *testing.T) {
	decls := parseToolErrorDecls(t)
	if len(decls.errorTypes) == 0 || len(decls.sentinels) == 0 || len(decls.codes) == 0 {
		t.Fatalf("parsed nothing: %d types, %d sentinels, %d codes",
			len(decls.errorTypes), len(decls.sentinels), len(decls.codes))
	}
	for name := range decls.errorTypes {
		if !decls.classifiedTypes[name] && unclassifiedErrorTypes[name] == "" {
			t.Errorf("error type %s has no GRPCStatus method and no entry in unclassifiedErrorTypes", name)
		}
	}
	for _, name := range decls.sentinels {
		if !decls.tabled[name] {
			t.Errorf("sentinel %s is not in sentinelClasses", name)
		}
	}
	unclassified := make(map[string]bool, len(unclassifiedCodes))
	for _, code := range unclassifiedCodes {
		unclassified[code] = true
	}
	for _, code := range decls.codes {
		if codeClass(code) == codes.Unknown && !unclassified[code] {
			t.Errorf("code %q matches no codeClassRules marker and is not in unclassifiedCodes", code)
		}
	}
}

// TestUnclassifiedErrorTypesHaveNoStaleEntries keeps the exemption list
// honest: an entry must name an error type that exists and is unclassified.
func TestUnclassifiedErrorTypesHaveNoStaleEntries(t *testing.T) {
	decls := parseToolErrorDecls(t)
	for name := range unclassifiedErrorTypes {
		if !decls.errorTypes[name] {
			t.Errorf("unclassifiedErrorTypes lists %s, which is not an error type in this package", name)
		}
		if decls.classifiedTypes[name] {
			t.Errorf("unclassifiedErrorTypes lists %s, which has a GRPCStatus method", name)
		}
	}
}
