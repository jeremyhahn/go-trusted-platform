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

// TPM quote argument mapping for the MCP transport (#482).
//
// platform_tpm_verify_quote takes the pb VerifyQuoteRequest's own JSON names
// (ak_public, channel_binding, signature_algorithm, bytes as base64), and both
// quote tools answer in the pb replies' names, so the generic JSON round-trip
// carries them. platform_tpm_quote takes the PCR selection as "pcrs", not
// "pcr_indices", so Quote has its own argument builder.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	mcpArgBuilders[platformv1.TPMService_Quote_FullMethodName] = buildTPMQuoteArgs
}

// buildTPMQuoteArgs maps the pb quote request onto the platform_tpm_quote
// arguments: the nonce as base64 and the PCR indices under "pcrs".
func buildTPMQuoteArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.QuoteRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_Quote_FullMethodName}
	}
	return map[string]interface{}{
		"nonce": in.GetNonce(),
		"pcrs":  in.GetPcrIndices(),
	}, nil
}
