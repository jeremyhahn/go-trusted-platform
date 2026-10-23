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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// idevidCallRecorder records which IDevID, IAK or LDevID provider method a
// tool call reached, so a test can prove a denied call never ran the handler.
type idevidCallRecorder struct {
	*mockServiceProvider
	called []string
}

func (r *idevidCallRecorder) hit(method string) { r.called = append(r.called, method) }

func (r *idevidCallRecorder) IDevIDGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
	r.hit("IDevIDGenerate")
	return r.mockServiceProvider.IDevIDGenerate(ctx, req)
}

func (r *idevidCallRecorder) IDevIDInfo(ctx context.Context) (interface{}, error) {
	r.hit("IDevIDInfo")
	return r.mockServiceProvider.IDevIDInfo(ctx)
}

func (r *idevidCallRecorder) IDevIDExists(ctx context.Context) (bool, error) {
	r.hit("IDevIDExists")
	return r.mockServiceProvider.IDevIDExists(ctx)
}

func (r *idevidCallRecorder) IDevIDDelete(ctx context.Context) error {
	r.hit("IDevIDDelete")
	return r.mockServiceProvider.IDevIDDelete(ctx)
}

func (r *idevidCallRecorder) IDevIDCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
	r.hit("IDevIDCSR")
	return r.mockServiceProvider.IDevIDCSR(ctx, req)
}

func (r *idevidCallRecorder) IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	r.hit("IDevIDInstallCert")
	return r.mockServiceProvider.IDevIDInstallCert(ctx, certificatePEM)
}

func (r *idevidCallRecorder) IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	r.hit("IDevIDGetCert")
	return r.mockServiceProvider.IDevIDGetCert(ctx, includePEM)
}

func (r *idevidCallRecorder) IDevIDDeleteCert(ctx context.Context) error {
	r.hit("IDevIDDeleteCert")
	return r.mockServiceProvider.IDevIDDeleteCert(ctx)
}

func (r *idevidCallRecorder) IAKGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
	r.hit("IAKGenerate")
	return r.mockServiceProvider.IAKGenerate(ctx, req)
}

func (r *idevidCallRecorder) IAKInfo(ctx context.Context) (interface{}, error) {
	r.hit("IAKInfo")
	return r.mockServiceProvider.IAKInfo(ctx)
}

func (r *idevidCallRecorder) IAKExists(ctx context.Context) (bool, error) {
	r.hit("IAKExists")
	return r.mockServiceProvider.IAKExists(ctx)
}

func (r *idevidCallRecorder) IAKDelete(ctx context.Context) error {
	r.hit("IAKDelete")
	return r.mockServiceProvider.IAKDelete(ctx)
}

func (r *idevidCallRecorder) IAKCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
	r.hit("IAKCSR")
	return r.mockServiceProvider.IAKCSR(ctx, req)
}

func (r *idevidCallRecorder) IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	r.hit("IAKInstallCert")
	return r.mockServiceProvider.IAKInstallCert(ctx, certificatePEM)
}

func (r *idevidCallRecorder) IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	r.hit("IAKGetCert")
	return r.mockServiceProvider.IAKGetCert(ctx, includePEM)
}

func (r *idevidCallRecorder) IAKDeleteCert(ctx context.Context) error {
	r.hit("IAKDeleteCert")
	return r.mockServiceProvider.IAKDeleteCert(ctx)
}

// CreateLDevID makes the recorder an LDevIDCreator, as the daemon provider is.
func (r *idevidCallRecorder) DeviceAttributes(_ context.Context) (interface{}, error) {
	r.hit("DeviceAttributes")
	return map[string]interface{}{"tpm_manufacturer": "mock"}, nil
}

func (r *idevidCallRecorder) ActivateCredential(_ context.Context, _, _ []byte) ([]byte, error) {
	r.hit("ActivateCredential")
	return []byte("secret"), nil
}

func (r *idevidCallRecorder) CreateLDevID(_ context.Context, _ *CreateLDevIDMCPRequest) (interface{}, error) {
	r.hit("CreateLDevID")
	return map[string]interface{}{"handle": 1}, nil
}

// classifiedIDevIDTool is one IDevID or IAK tool #304 classified: the scope of
// its gRPC IDevIDService twin, arguments that pass the executor's own checks,
// and the provider method the call reaches once authorized.
type classifiedIDevIDTool struct {
	tool   string
	scope  string
	args   map[string]interface{}
	method string
}

var installArgs = map[string]interface{}{"certificate_pem": "-----BEGIN CERTIFICATE-----"}

var classifiedIDevIDTools = []classifiedIDevIDTool{
	{"idevid_info", "idevid:read", nil, "IDevIDInfo"},
	{"idevid_exists", "idevid:read", nil, "IDevIDExists"},
	{"idevid_get_cert", "idevid:read", nil, "IDevIDGetCert"},
	{"idevid_generate", "idevid:write", nil, "IDevIDGenerate"},
	{"idevid_csr", "idevid:write", nil, "IDevIDCSR"},
	{"idevid_install_cert", "idevid:write", installArgs, "IDevIDInstallCert"},
	{"idevid_create_ldevid", "idevid:write", nil, "CreateLDevID"},
	{"idevid_delete", "idevid:delete", nil, "IDevIDDelete"},
	{"idevid_delete_cert", "idevid:delete", nil, "IDevIDDeleteCert"},

	// The IAK tools are served by the same gRPC IDevIDService.
	{"iak_info", "idevid:read", nil, "IAKInfo"},
	{"iak_exists", "idevid:read", nil, "IAKExists"},
	{"iak_get_cert", "idevid:read", nil, "IAKGetCert"},
	{"iak_generate", "idevid:write", nil, "IAKGenerate"},
	{"iak_csr", "idevid:write", nil, "IAKCSR"},
	{"iak_install_cert", "idevid:write", installArgs, "IAKInstallCert"},
	{"iak_delete", "idevid:delete", nil, "IAKDelete"},
	{"iak_delete_cert", "idevid:delete", nil, "IAKDeleteCert"},

	// Served by the same TPM calls as gRPC IDevIDService.
	{"device_attributes", "idevid:read", nil, "DeviceAttributes"},
	{"activate_credential", "idevid:write", map[string]interface{}{
		"credential_blob": "AQ==", "secret": "AQ==",
	}, "ActivateCredential"},
}

// TestIDevIDToolsCarryGRPCScope pins each classified IDevID and IAK tool to the
// scope of its gRPC twin in method_permissions.go.
func TestIDevIDToolsCarryGRPCScope(t *testing.T) {
	catalog := toolPermissionCatalog()
	for _, tc := range classifiedIDevIDTools {
		got, ok := catalog[tc.tool]
		if !ok {
			t.Errorf("%s is not classified", tc.tool)
			continue
		}
		if got != tc.scope {
			t.Errorf("%s scope = %q, want %q", tc.tool, got, tc.scope)
		}
	}
}

// callIDevIDTool drives tools/call through the server, the path a client
// takes, with a caller holding exactly the scopes granted says.
func callIDevIDTool(t *testing.T, tc classifiedIDevIDTool, granted func(scope string) bool) (*mcpwire.JSONRPCResponse, *idevidCallRecorder) {
	t.Helper()
	provider := &idevidCallRecorder{mockServiceProvider: newMockServiceProvider()}
	server := NewServer(provider, nil, newTestLogger())
	server.SetAuthorizationService(&mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return granted(resource + ":" + action), nil
		},
	}, nil)

	args := map[string]interface{}{"_token": "token"}
	for k, v := range tc.args {
		args[k] = v
	}
	resp := server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": tc.tool, "arguments": args},
	})
	return resp, provider
}

func TestIDevIDTools_CallerWithScopeGetsAnswer(t *testing.T) {
	for _, tc := range classifiedIDevIDTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider := callIDevIDTool(t, tc, func(scope string) bool { return scope == tc.scope })
			if resp.Error != nil {
				t.Fatalf("caller holding %s got error %d: %s", tc.scope, resp.Error.Code, resp.Error.Message)
			}
			if len(provider.called) != 1 || provider.called[0] != tc.method {
				t.Fatalf("handler calls = %v, want [%s]", provider.called, tc.method)
			}
		})
	}
}

func TestIDevIDTools_CallerWithoutScopeDeniedBeforeHandler(t *testing.T) {
	for _, tc := range classifiedIDevIDTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider := callIDevIDTool(t, tc, func(scope string) bool { return scope != tc.scope })
			if resp.Error == nil {
				t.Fatalf("caller without %s got an answer: %v", tc.scope, resp.Result)
			}
			if resp.Error.Code != mcpwire.PermissionDenied {
				t.Fatalf("error code = %d, want PermissionDenied (%d)", resp.Error.Code, mcpwire.PermissionDenied)
			}
			if len(provider.called) != 0 {
				t.Fatalf("denied call reached the handler: %v", provider.called)
			}
		})
	}
}
