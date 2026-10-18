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
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The daemon round trip lives in pkg/api/daemon (TestTPMQuoteParity_*),
// which drives the real platform_tpm_quote and platform_tpm_verify_quote
// tools.

// platform_tpm_quote reads a base64 "nonce" and integer "pcrs"; the builder
// sends exactly that once the arguments are JSON-encoded (#482).
func TestBuildTPMQuoteArgs_SendsTheToolsNames(t *testing.T) {
	if _, ok := mcpArgBuilders[platformv1.TPMService_Quote_FullMethodName]; !ok {
		t.Fatalf("no MCP argument builder for %s", platformv1.TPMService_Quote_FullMethodName)
	}

	args, err := buildTPMQuoteArgs(&platformv1.QuoteRequest{
		Nonce:      []byte("nonce"),
		PcrIndices: []uint32{0, 7},
		PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]interface{}{"nonce": "bm9uY2U=", "pcrs": []interface{}{float64(0), float64(7)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire args = %v, want %v", got, want)
	}
}

func TestBuildTPMQuoteArgs_RefusesWrongArgs(t *testing.T) {
	var wrong ErrUnexpectedArgsType
	if _, err := buildTPMQuoteArgs(&platformv1.VerifyQuoteRequest{}); !errors.As(err, &wrong) {
		t.Fatalf("wrong args type: got %v, want ErrUnexpectedArgsType", err)
	}
}

// The quote and certify methods are routed, so a raw TPMService client
// reaches the tools instead of codes.Unimplemented.
func TestTPMQuoteMethodsAreRouted(t *testing.T) {
	want := map[string]string{
		platformv1.TPMService_Quote_FullMethodName:                 "platform_tpm_quote",
		platformv1.TPMService_VerifyQuote_FullMethodName:           "platform_tpm_verify_quote",
		platformv1.TPMService_Certify_FullMethodName:               "platform_tpm_certify",
		platformv1.TPMService_GetCapabilities_FullMethodName:       "platform_tpm_capabilities",
		platformv1.TPMService_GetPlatformAttributes_FullMethodName: "platform_tpm_platform",
		platformv1.TPMService_ExtendPCR_FullMethodName:             "platform_tpm_pcr_extend",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
	}
}
