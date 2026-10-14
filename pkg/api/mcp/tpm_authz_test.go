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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// tpmCallRecorder records which TPM provider method a tool call reached, so
// a test can prove a denied call never ran the handler.
type tpmCallRecorder struct {
	*mockServiceProvider
	called []string
}

func (r *tpmCallRecorder) hit(method string) { r.called = append(r.called, method) }

func (r *tpmCallRecorder) TPMInfo(ctx context.Context) (interface{}, error) {
	r.hit("TPMInfo")
	return r.mockServiceProvider.TPMInfo(ctx)
}

func (r *tpmCallRecorder) TPMProvision(ctx context.Context, ownerPassword string) (interface{}, error) {
	r.hit("TPMProvision")
	return r.mockServiceProvider.TPMProvision(ctx, ownerPassword)
}

func (r *tpmCallRecorder) TPMClear(ctx context.Context, ownerPassword string) (interface{}, error) {
	r.hit("TPMClear")
	return r.mockServiceProvider.TPMClear(ctx, ownerPassword)
}

func (r *tpmCallRecorder) TPMGetEK(ctx context.Context) (interface{}, error) {
	r.hit("TPMGetEK")
	return r.mockServiceProvider.TPMGetEK(ctx)
}

func (r *tpmCallRecorder) TPMGetEKCert(ctx context.Context) (interface{}, error) {
	r.hit("TPMGetEKCert")
	return r.mockServiceProvider.TPMGetEKCert(ctx)
}

func (r *tpmCallRecorder) TPMImportEKCert(ctx context.Context, certDER []byte) (interface{}, error) {
	r.hit("TPMImportEKCert")
	return r.mockServiceProvider.TPMImportEKCert(ctx, certDER)
}

func (r *tpmCallRecorder) TPMCreateEK(ctx context.Context) (interface{}, error) {
	r.hit("TPMCreateEK")
	return r.mockServiceProvider.TPMCreateEK(ctx)
}

func (r *tpmCallRecorder) TPMGetSRK(ctx context.Context, handle uint32) (interface{}, error) {
	r.hit("TPMGetSRK")
	return r.mockServiceProvider.TPMGetSRK(ctx, handle)
}

func (r *tpmCallRecorder) TPMCreateSRK(ctx context.Context) (interface{}, error) {
	r.hit("TPMCreateSRK")
	return r.mockServiceProvider.TPMCreateSRK(ctx)
}

func (r *tpmCallRecorder) TPMGetIAK(ctx context.Context) (interface{}, error) {
	r.hit("TPMGetIAK")
	return r.mockServiceProvider.TPMGetIAK(ctx)
}

func (r *tpmCallRecorder) TPMCreateIAK(ctx context.Context) (interface{}, error) {
	r.hit("TPMCreateIAK")
	return r.mockServiceProvider.TPMCreateIAK(ctx)
}

func (r *tpmCallRecorder) TPMReadPCRs(ctx context.Context, indices []int) (interface{}, error) {
	r.hit("TPMReadPCRs")
	return r.mockServiceProvider.TPMReadPCRs(ctx, indices)
}

func (r *tpmCallRecorder) TPMEventLog(ctx context.Context) (interface{}, error) {
	r.hit("TPMEventLog")
	return r.mockServiceProvider.TPMEventLog(ctx)
}

func (r *tpmCallRecorder) TPMRandom(ctx context.Context, numBytes int) ([]byte, error) {
	r.hit("TPMRandom")
	return r.mockServiceProvider.TPMRandom(ctx, numBytes)
}

func (r *tpmCallRecorder) TPMNVRead(ctx context.Context, index uint32, size, offset uint16, password string) ([]byte, error) {
	r.hit("TPMNVRead")
	return r.mockServiceProvider.TPMNVRead(ctx, index, size, offset, password)
}

func (r *tpmCallRecorder) TPMNVWrite(ctx context.Context, index uint32, data []byte, offset uint16, password string) (interface{}, error) {
	r.hit("TPMNVWrite")
	return r.mockServiceProvider.TPMNVWrite(ctx, index, data, offset, password)
}

func (r *tpmCallRecorder) TPMNVDelete(ctx context.Context, index uint32, parentPassword string) (interface{}, error) {
	r.hit("TPMNVDelete")
	return r.mockServiceProvider.TPMNVDelete(ctx, index, parentPassword)
}

func (r *tpmCallRecorder) TPMMakeCredential(ctx context.Context, akName, secret, ekCert, iakPub []byte) (interface{}, error) {
	r.hit("TPMMakeCredential")
	return r.mockServiceProvider.TPMMakeCredential(ctx, akName, secret, ekCert, iakPub)
}

func (r *tpmCallRecorder) TPMActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) (interface{}, error) {
	r.hit("TPMActivateCredential")
	return r.mockServiceProvider.TPMActivateCredential(ctx, credentialBlob, encryptedSecret)
}

func (r *tpmCallRecorder) TPMSeal(ctx context.Context, data []byte, pcrs []uint32, cn, password string) ([]byte, error) {
	r.hit("TPMSeal")
	return r.mockServiceProvider.TPMSeal(ctx, data, pcrs, cn, password)
}

func (r *tpmCallRecorder) TPMUnseal(ctx context.Context, cn, password string) ([]byte, error) {
	r.hit("TPMUnseal")
	return r.mockServiceProvider.TPMUnseal(ctx, cn, password)
}

func (r *tpmCallRecorder) VTPMGet(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMGet")
	return r.mockServiceProvider.VTPMGet(ctx, name)
}

func (r *tpmCallRecorder) VTPMValidate(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMValidate")
	return r.mockServiceProvider.VTPMValidate(ctx, name)
}

func (r *tpmCallRecorder) VTPMExport(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMExport")
	return r.mockServiceProvider.VTPMExport(ctx, name)
}

func (r *tpmCallRecorder) VTPMImport(ctx context.Context, data []byte) (interface{}, error) {
	r.hit("VTPMImport")
	return r.mockServiceProvider.VTPMImport(ctx, data)
}

func (r *tpmCallRecorder) VTPMCreateTemplate(ctx context.Context, id, description, algorithm string, secureBoot bool) (interface{}, error) {
	r.hit("VTPMCreateTemplate")
	return r.mockServiceProvider.VTPMCreateTemplate(ctx, id, description, algorithm, secureBoot)
}

func (r *tpmCallRecorder) VTPMGetTemplate(ctx context.Context, id string) (interface{}, error) {
	r.hit("VTPMGetTemplate")
	return r.mockServiceProvider.VTPMGetTemplate(ctx, id)
}

func (r *tpmCallRecorder) VTPMDeleteTemplate(ctx context.Context, id string) error {
	r.hit("VTPMDeleteTemplate")
	return r.mockServiceProvider.VTPMDeleteTemplate(ctx, id)
}

func (r *tpmCallRecorder) VTPMListTemplates(ctx context.Context) (interface{}, error) {
	r.hit("VTPMListTemplates")
	return r.mockServiceProvider.VTPMListTemplates(ctx)
}

func (r *tpmCallRecorder) VTPMCloneTemplate(ctx context.Context, templateID, hostname string, labels map[string]string) (interface{}, error) {
	r.hit("VTPMCloneTemplate")
	return r.mockServiceProvider.VTPMCloneTemplate(ctx, templateID, hostname, labels)
}

func (r *tpmCallRecorder) VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMGetBundlePath")
	return r.mockServiceProvider.VTPMGetBundlePath(ctx, name)
}

func (r *tpmCallRecorder) VTPMGetTPMSocketPath(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMGetTPMSocketPath")
	return r.mockServiceProvider.VTPMGetTPMSocketPath(ctx, name)
}

func (r *tpmCallRecorder) VTPMGetNVRAMPath(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMGetNVRAMPath")
	return r.mockServiceProvider.VTPMGetNVRAMPath(ctx, name)
}

func (r *tpmCallRecorder) VTPMIsRunning(ctx context.Context, name string) (interface{}, error) {
	r.hit("VTPMIsRunning")
	return r.mockServiceProvider.VTPMIsRunning(ctx, name)
}

// classifiedTPMTool is one platform TPM tool #304 classified: the scope of
// its gRPC TPMService twin, arguments that pass the executor's own checks,
// and the provider method the call reaches once authorized.
type classifiedTPMTool struct {
	tool   string
	scope  string
	args   map[string]interface{}
	method string
}

const testNVIndex = float64(0x01500016)

var classifiedTPMTools = []classifiedTPMTool{
	{"platform_tpm_info", "tpm:read", nil, "TPMInfo"},
	{"platform_tpm_ek", "tpm:read", nil, "TPMGetEK"},
	{"platform_tpm_ek_cert", "tpm:read", nil, "TPMGetEKCert"},
	{"platform_tpm_srk", "tpm:read", nil, "TPMGetSRK"},
	{"platform_tpm_iak", "tpm:read", nil, "TPMGetIAK"},
	{"platform_tpm_pcrs", "tpm:read", nil, "TPMReadPCRs"},
	{"platform_tpm_eventlog", "tpm:read", nil, "TPMEventLog"},
	{"platform_tpm_random", "tpm:read", nil, "TPMRandom"},
	{"platform_tpm_nv_read", "tpm:read", map[string]interface{}{"index": testNVIndex, "size": float64(4)}, "TPMNVRead"},
	{"platform_tpm_make_credential", "tpm:read", map[string]interface{}{
		"ak_name": "AQ==", "secret": "AQ==", "ek_cert": "AQ==", "iak_pub": "AQ==",
	}, "TPMMakeCredential"},
	{"platform_tpm_provision", "tpm:write", nil, "TPMProvision"},
	{"platform_tpm_ek_create", "tpm:write", nil, "TPMCreateEK"},
	{"platform_tpm_ek_import_cert", "tpm:write", map[string]interface{}{"certificate": "AQ=="}, "TPMImportEKCert"},
	{"platform_tpm_srk_create", "tpm:write", nil, "TPMCreateSRK"},
	{"platform_tpm_iak_create", "tpm:write", nil, "TPMCreateIAK"},
	{"platform_tpm_nv_write", "tpm:write", map[string]interface{}{"index": testNVIndex, "data": "AQ=="}, "TPMNVWrite"},
	{"platform_tpm_activate_credential", "tpm:write", map[string]interface{}{
		"credential_blob": "AQ==", "encrypted_secret": "AQ==",
	}, "TPMActivateCredential"},
	{"platform_tpm_clear", "tpm:delete", nil, "TPMClear"},
	{"platform_tpm_nv_delete", "tpm:delete", map[string]interface{}{"index": testNVIndex}, "TPMNVDelete"},
	{"platform_tpm_seal", "tpm:write", map[string]interface{}{"data": "AQ=="}, "TPMSeal"},
	// gRPC Unseal is tpm:read; releasing a secret is held to tpm:write here.
	{"platform_tpm_unseal", "tpm:write", map[string]interface{}{"cn": "app-key"}, "TPMUnseal"},

	// vTPM bundles and templates: the scopes of gRPC VTPMService.
	{"vtpm_get", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMGet"},
	{"vtpm_validate", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMValidate"},
	{"vtpm_export", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMExport"},
	{"vtpm_get_bundle_path", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMGetBundlePath"},
	{"vtpm_get_tpm_socket_path", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMGetTPMSocketPath"},
	{"vtpm_get_nvram_path", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMGetNVRAMPath"},
	{"vtpm_is_running", "vtpm:read", map[string]interface{}{"name": "b1"}, "VTPMIsRunning"},
	{"vtpm_import", "vtpm:write", map[string]interface{}{"data": "AQ=="}, "VTPMImport"},
	{"vtpm_template_get", "vtpm:read", map[string]interface{}{"id": "t1"}, "VTPMGetTemplate"},
	{"vtpm_template_list", "vtpm:read", map[string]interface{}{}, "VTPMListTemplates"},
	{"vtpm_template_create", "vtpm:write", map[string]interface{}{"id": "t1", "algorithm": "ECC"}, "VTPMCreateTemplate"},
	{"vtpm_template_clone", "vtpm:write", map[string]interface{}{"template_id": "t1", "hostname": "h1"}, "VTPMCloneTemplate"},
	{"vtpm_template_delete", "vtpm:delete", map[string]interface{}{"id": "t1"}, "VTPMDeleteTemplate"},
}

// TestTPMToolsCarryGRPCScope pins each classified TPM tool to the scope of
// its gRPC twin in method_permissions.go. A drift here is a tool that answers
// on MCP to a caller gRPC would refuse, or the reverse.
func TestTPMToolsCarryGRPCScope(t *testing.T) {
	catalog := toolPermissionCatalog()
	for _, tc := range classifiedTPMTools {
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

// callTPMTool drives tools/call through the server, the path a client takes,
// with a caller holding every scope except the ones withheld.
func callTPMTool(t *testing.T, tc classifiedTPMTool, granted func(scope string) bool) (*mcpwire.JSONRPCResponse, *tpmCallRecorder) {
	t.Helper()
	provider := &tpmCallRecorder{mockServiceProvider: newMockServiceProvider()}
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

func TestTPMTools_CallerWithScopeGetsAnswer(t *testing.T) {
	for _, tc := range classifiedTPMTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider := callTPMTool(t, tc, func(scope string) bool { return scope == tc.scope })
			if resp.Error != nil {
				t.Fatalf("caller holding %s got error %d: %s", tc.scope, resp.Error.Code, resp.Error.Message)
			}
			if len(provider.called) != 1 || provider.called[0] != tc.method {
				t.Fatalf("handler calls = %v, want [%s]", provider.called, tc.method)
			}
		})
	}
}

func TestTPMTools_CallerWithoutScopeDeniedBeforeHandler(t *testing.T) {
	for _, tc := range classifiedTPMTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp, provider := callTPMTool(t, tc, func(scope string) bool { return scope != tc.scope })
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

// TestTPMSealTool_ForwardsPolicyArgs: the seal tool hands the PCRs, CN and
// password to the provider, which runs them through the gRPC Seal. The tool
// used to drop the CN and password and the provider ignored the PCRs.
func TestTPMSealTool_ForwardsPolicyArgs(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(context.Background(), "platform_tpm_seal", map[string]interface{}{
		"data":     "AQ==",
		"pcrs":     []interface{}{float64(0), float64(7)},
		"cn":       "app-key",
		"password": "pw",
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	call := svc.tpmCall
	if call.cn != "app-key" || call.password != "pw" || len(call.pcrs) != 2 || call.pcrs[1] != 7 {
		t.Fatalf("provider got cn=%q password=%q pcrs=%v", call.cn, call.password, call.pcrs)
	}

	if _, err := registry.ExecuteTool(context.Background(), "platform_tpm_unseal", map[string]interface{}{
		"cn": "app-key", "password": "pw",
	}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if svc.tpmCall.cn != "app-key" || svc.tpmCall.password != "pw" {
		t.Fatalf("unseal provider got cn=%q password=%q", svc.tpmCall.cn, svc.tpmCall.password)
	}
}

func TestTPMSealTool_NegativePCRIsInvalidArgument(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(context.Background(), "platform_tpm_seal", map[string]interface{}{
		"data": "AQ==",
		"pcrs": []interface{}{float64(-1)},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error %v has class %s, want InvalidArgument", err, status.Code(err))
	}
	if svc.tpmCall.data != nil {
		t.Fatal("a refused seal reached the provider")
	}
}
