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
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// bundleAliasCase calls a vtpm_bundle_* tool and its vtpm_* twin with the same
// request, each in its own documented argument names.
type bundleAliasCase struct {
	alias     string
	twin      string
	aliasArgs map[string]interface{}
	twinArgs  map[string]interface{}
	// backend is the call the service must receive from both tools.
	backend string
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

var bundleAliasCases = []bundleAliasCase{
	{
		alias:     "vtpm_bundle_create",
		twin:      "vtpm_create",
		aliasArgs: map[string]interface{}{"hostname": "web-1", "ek_algorithm": "ECC", "secure_boot_enabled": true, "labels": map[string]interface{}{"env": "prod"}},
		twinArgs:  map[string]interface{}{"name": "web-1", "algorithm": "ECC", "secure_boot_enabled": true, "labels": map[string]interface{}{"env": "prod"}},
		backend:   "VTPMCreate web-1 ECC secureBoot=true labels=map[env:prod]",
	},
	{
		alias:     "vtpm_bundle_get",
		twin:      "vtpm_get",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1"},
		twinArgs:  map[string]interface{}{"name": "b-1"},
		backend:   "VTPMGet b-1",
	},
	{
		alias:     "vtpm_bundle_list",
		twin:      "vtpm_list",
		aliasArgs: map[string]interface{}{"mode": "template", "labels": map[string]interface{}{"env": "prod"}, "limit": float64(5), "offset": float64(2)},
		twinArgs:  map[string]interface{}{"mode": "template", "labels": map[string]interface{}{"env": "prod"}, "limit": float64(5), "offset": float64(2)},
		backend:   "VTPMList mode=template labels=map[env:prod] limit=5 offset=2",
	},
	{
		alias:     "vtpm_bundle_delete",
		twin:      "vtpm_delete",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1"},
		twinArgs:  map[string]interface{}{"name": "b-1"},
		backend:   "VTPMDelete b-1",
	},
	{
		alias:     "vtpm_bundle_quote",
		twin:      "vtpm_quote",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1", "nonce": b64("nonce"), "pcrs": []interface{}{float64(0), float64(7)}},
		twinArgs:  map[string]interface{}{"name": "b-1", "nonce": b64("nonce"), "pcrs": []interface{}{float64(0), float64(7)}},
		backend:   "VTPMQuote b-1 nonce [0 7]",
	},
	{
		alias:     "vtpm_bundle_pcr_read",
		twin:      "vtpm_read_pcr",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1", "pcr_index": float64(7)},
		twinArgs:  map[string]interface{}{"name": "b-1", "pcr": float64(7)},
		backend:   "VTPMReadPCR b-1 7",
	},
	{
		alias:     "vtpm_bundle_pcr_extend",
		twin:      "vtpm_extend_pcr",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1", "pcr_index": float64(16), "data": b64("measurement")},
		twinArgs:  map[string]interface{}{"name": "b-1", "pcr": float64(16), "data": b64("measurement")},
		backend:   "VTPMExtendPCR b-1 16 measurement",
	},
	{
		alias:     "vtpm_bundle_seal",
		twin:      "vtpm_seal",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1", "data": b64("secret"), "pcrs": []interface{}{float64(7)}, "auth_value": "pw"},
		twinArgs:  map[string]interface{}{"name": "b-1", "data": b64("secret"), "pcrs": []interface{}{float64(7)}, "auth_value": "pw"},
		backend:   "VTPMSeal b-1 secret [7] auth=pw",
	},
	{
		alias:     "vtpm_bundle_unseal",
		twin:      "vtpm_unseal",
		aliasArgs: map[string]interface{}{"bundle_id": "b-1", "sealed_data": b64("blob"), "auth_value": "pw"},
		twinArgs:  map[string]interface{}{"name": "b-1", "sealed": b64("blob"), "auth_value": "pw"},
		backend:   "VTPMUnseal b-1 blob auth=pw",
	},
}

// vtpmBackendRecorder records each vTPM service call and answers it with
// fail when fail is set.
type vtpmBackendRecorder struct {
	*mockServiceProvider
	calls []string
}

func newVTPMBackendRecorder(fail error) *vtpmBackendRecorder {
	rec := &vtpmBackendRecorder{mockServiceProvider: newMockServiceProvider()}
	m := rec.mockServiceProvider
	m.vtpmCreateFunc = func(_ context.Context, name, algorithm string, secureBoot bool, labels map[string]string) (interface{}, error) {
		rec.record("VTPMCreate %s %s secureBoot=%t labels=%v", name, algorithm, secureBoot, labels)
		return map[string]interface{}{"id": name}, fail
	}
	m.vtpmGetFunc = func(_ context.Context, name string) (interface{}, error) {
		rec.record("VTPMGet %s", name)
		return map[string]interface{}{"id": name}, fail
	}
	m.vtpmListFunc = func(_ context.Context, opts *vtpm.ListOptions) ([]interface{}, error) {
		rec.record("VTPMList mode=%s labels=%v limit=%d offset=%d", opts.Mode, opts.Labels, opts.Limit, opts.Offset)
		return []interface{}{map[string]interface{}{"id": "b-1"}}, fail
	}
	m.vtpmDeleteFunc = func(_ context.Context, name string) error {
		rec.record("VTPMDelete %s", name)
		return fail
	}
	m.vtpmQuoteFunc = func(_ context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
		rec.record("VTPMQuote %s %s %v", name, nonce, pcrs)
		return map[string]interface{}{"quote": "q"}, fail
	}
	m.vtpmReadPCRFunc = func(_ context.Context, name string, pcr int) ([]byte, error) {
		rec.record("VTPMReadPCR %s %d", name, pcr)
		return []byte("digest"), fail
	}
	m.vtpmExtendPCRFunc = func(_ context.Context, name string, pcr int, data []byte) error {
		rec.record("VTPMExtendPCR %s %d %s", name, pcr, data)
		return fail
	}
	m.vtpmSealFunc = func(_ context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error) {
		rec.record("VTPMSeal %s %s %v auth=%s", name, data, pcrs, authValue)
		return []byte("sealed"), fail
	}
	m.vtpmUnsealFunc = func(_ context.Context, name string, sealed []byte, authValue string) ([]byte, error) {
		rec.record("VTPMUnseal %s %s auth=%s", name, sealed, authValue)
		return []byte("plain"), fail
	}
	return rec
}

func (r *vtpmBackendRecorder) record(format string, args ...interface{}) {
	r.calls = append(r.calls, fmt.Sprintf(format, args...))
}

// runVTPMTool executes one tool against a fresh recorder and returns its
// result, the backend calls it made, and its error.
func runVTPMTool(fail error, tool string, args map[string]interface{}) (interface{}, []string, error) {
	rec := newVTPMBackendRecorder(fail)
	registry := NewToolRegistry(rec, newTestLogger())
	result, err := registry.ExecuteTool(context.Background(), tool, args)
	return result, rec.calls, err
}

// Each alias reaches the same backend call as its twin and answers with the
// same result.
func TestVTPMBundleAlias_ParityWithTwin(t *testing.T) {
	for _, tc := range bundleAliasCases {
		t.Run(tc.alias, func(t *testing.T) {
			aliasResult, aliasCalls, aliasErr := runVTPMTool(nil, tc.alias, tc.aliasArgs)
			twinResult, twinCalls, twinErr := runVTPMTool(nil, tc.twin, tc.twinArgs)
			if aliasErr != nil || twinErr != nil {
				t.Fatalf("alias error = %v, twin error = %v; want both nil", aliasErr, twinErr)
			}
			want := []string{tc.backend}
			if !reflect.DeepEqual(aliasCalls, want) {
				t.Errorf("alias backend calls = %q, want %q", aliasCalls, want)
			}
			if !reflect.DeepEqual(twinCalls, want) {
				t.Errorf("twin backend calls = %q, want %q", twinCalls, want)
			}
			if !reflect.DeepEqual(aliasResult, twinResult) {
				t.Errorf("alias result = %v, twin result = %v", aliasResult, twinResult)
			}
		})
	}
}

// An unknown bundle reaches the caller as the backend's typed error, the same
// error from the alias and from its twin.
func TestVTPMBundleAlias_UnknownBundleIsBackendError(t *testing.T) {
	notFound := vtpm.ErrBundleNotFound{ID: "b-1"}
	for _, tc := range bundleAliasCases {
		t.Run(tc.alias, func(t *testing.T) {
			_, _, aliasErr := runVTPMTool(notFound, tc.alias, tc.aliasArgs)
			_, _, twinErr := runVTPMTool(notFound, tc.twin, tc.twinArgs)
			var aliasNF, twinNF vtpm.ErrBundleNotFound
			if !errors.As(aliasErr, &aliasNF) || !errors.As(twinErr, &twinNF) {
				t.Fatalf("alias error = %v, twin error = %v; want ErrBundleNotFound from both", aliasErr, twinErr)
			}
			if aliasNF != twinNF {
				t.Errorf("alias error = %v, twin error = %v", aliasNF, twinNF)
			}
		})
	}
}

// Bad input is refused with ErrInvalidArgument before the backend is called,
// by the alias and by its twin alike.
func TestVTPMBundleAlias_BadInputIsInvalidArgument(t *testing.T) {
	tests := []struct {
		name      string
		alias     string
		aliasArgs map[string]interface{}
		twin      string
		twinArgs  map[string]interface{}
	}{
		{"create unknown algorithm", "vtpm_bundle_create", map[string]interface{}{"hostname": "h", "ek_algorithm": "DSA"},
			"vtpm_create", map[string]interface{}{"name": "h", "algorithm": "DSA"}},
		{"list unknown mode", "vtpm_bundle_list", map[string]interface{}{"mode": "golden"},
			"vtpm_list", map[string]interface{}{"mode": "golden"}},
		{"list negative limit", "vtpm_bundle_list", map[string]interface{}{"limit": float64(-1)},
			"vtpm_list", map[string]interface{}{"limit": float64(-1)}},
		{"list negative offset", "vtpm_bundle_list", map[string]interface{}{"offset": float64(-3)},
			"vtpm_list", map[string]interface{}{"offset": float64(-3)}},
		{"quote nonce not base64", "vtpm_bundle_quote", map[string]interface{}{"bundle_id": "b-1", "nonce": "!!"},
			"vtpm_quote", map[string]interface{}{"name": "b-1", "nonce": "!!"}},
		{"pcr_extend data not base64", "vtpm_bundle_pcr_extend", map[string]interface{}{"bundle_id": "b-1", "pcr_index": float64(1), "data": "!!"},
			"vtpm_extend_pcr", map[string]interface{}{"name": "b-1", "pcr": float64(1), "data": "!!"}},
		{"seal data not base64", "vtpm_bundle_seal", map[string]interface{}{"bundle_id": "b-1", "data": "!!"},
			"vtpm_seal", map[string]interface{}{"name": "b-1", "data": "!!"}},
		{"unseal sealed_data not base64", "vtpm_bundle_unseal", map[string]interface{}{"bundle_id": "b-1", "sealed_data": "!!"},
			"vtpm_unseal", map[string]interface{}{"name": "b-1", "sealed": "!!"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, aliasCalls, aliasErr := runVTPMTool(nil, tc.alias, tc.aliasArgs)
			_, _, twinErr := runVTPMTool(nil, tc.twin, tc.twinArgs)
			var aliasInvalid, twinInvalid ErrInvalidArgument
			if !errors.As(aliasErr, &aliasInvalid) || !errors.As(twinErr, &twinInvalid) {
				t.Fatalf("alias error = %v, twin error = %v; want ErrInvalidArgument from both", aliasErr, twinErr)
			}
			if aliasInvalid.Msg != twinInvalid.Msg {
				t.Errorf("alias message %q, twin message %q", aliasInvalid.Msg, twinInvalid.Msg)
			}
			if len(aliasCalls) != 0 {
				t.Errorf("refused input reached the backend: %q", aliasCalls)
			}
		})
	}
}

// Only the documented argument name selects the bundle: a twin-named argument
// sent to the alias is dropped, not used.
func TestVTPMBundleAlias_TwinArgumentNameIsIgnored(t *testing.T) {
	args := map[string]interface{}{"bundle_id": "right", "name": "wrong", "pcr": float64(9)}
	want := map[string]string{
		"vtpm_bundle_get":      "VTPMGet right",
		"vtpm_bundle_delete":   "VTPMDelete right",
		"vtpm_bundle_pcr_read": "VTPMReadPCR right 0",
	}
	for alias, call := range want {
		t.Run(alias, func(t *testing.T) {
			_, calls, err := runVTPMTool(nil, alias, args)
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(calls, []string{call}) {
				t.Errorf("backend calls = %q, want %q", calls, call)
			}
		})
	}
}

func TestVTPMBundleAlias_CarriesTwinScope(t *testing.T) {
	catalog := toolPermissionCatalog()
	for _, tc := range bundleAliasCases {
		scope, ok := catalog[tc.alias]
		if !ok || scope == "" {
			t.Errorf("%s has no catalog scope", tc.alias)
			continue
		}
		if scope != catalog[tc.twin] {
			t.Errorf("%s scope = %q, want its twin %s scope %q", tc.alias, scope, tc.twin, catalog[tc.twin])
		}
	}
}

func callVTPMAliasViaServer(tc bundleAliasCase, granted func(scope string) bool) (*mcpwire.JSONRPCResponse, *vtpmBackendRecorder) {
	rec := newVTPMBackendRecorder(nil)
	server := NewServer(rec, nil, newTestLogger())
	server.SetAuthorizationService(&mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return granted(resource + ":" + action), nil
		},
	}, nil)
	args := map[string]interface{}{"_token": "token"}
	for k, v := range tc.aliasArgs {
		args[k] = v
	}
	resp := server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": tc.alias, "arguments": args},
	})
	return resp, rec
}

func TestVTPMBundleAlias_CallerWithoutScopeIsRefused(t *testing.T) {
	catalog := toolPermissionCatalog()
	for _, tc := range bundleAliasCases {
		t.Run(tc.alias, func(t *testing.T) {
			scope := catalog[tc.twin]
			resp, rec := callVTPMAliasViaServer(tc, func(s string) bool { return s != scope })
			if resp.Error == nil {
				t.Fatalf("caller without %s got an answer: %v", scope, resp.Result)
			}
			if resp.Error.Code != mcpwire.PermissionDenied {
				t.Fatalf("error code = %d, want PermissionDenied (%d)", resp.Error.Code, mcpwire.PermissionDenied)
			}
			if len(rec.calls) != 0 {
				t.Fatalf("refused call reached the backend: %q", rec.calls)
			}
		})
	}
}

func TestVTPMBundleAlias_CallerWithScopeReachesBackend(t *testing.T) {
	catalog := toolPermissionCatalog()
	for _, tc := range bundleAliasCases {
		t.Run(tc.alias, func(t *testing.T) {
			scope := catalog[tc.twin]
			resp, rec := callVTPMAliasViaServer(tc, func(s string) bool { return s == scope })
			if resp.Error != nil {
				t.Fatalf("caller with %s refused: %v", scope, resp.Error)
			}
			if want := []string{tc.backend}; !reflect.DeepEqual(rec.calls, want) {
				t.Fatalf("backend calls = %q, want %q", rec.calls, want)
			}
		})
	}
}
