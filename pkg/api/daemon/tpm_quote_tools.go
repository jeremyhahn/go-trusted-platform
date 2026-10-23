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

package daemon

import (
	"context"
	"encoding/base64"
	"log/slog"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tpmQuoteTools serves the platform_tpm_quote and platform_tpm_verify_quote
// MCP tools on the TPM gRPC service, so every MCP service provider quotes
// and verifies exactly as REST, gRPC, QUIC and Unix do: one channel-bound
// quote and one verifier (#482).
type tpmQuoteTools struct {
	tpm    xkmssdk.TrustedPlatformModule
	logger *slog.Logger
}

// service returns the TPM gRPC service over the tools' TPM, or
// ErrServiceNotAvailable when the daemon has none.
func (t tpmQuoteTools) service() (*TPMGRPCService, error) {
	if t.tpm == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}
	svc := NewTPMGRPCService(logging.NewFromSlog(t.logger))
	svc.SetTPM2Service(t.tpm)
	return svc, nil
}

// quote produces a quote over pcrs bound to the caller's connection and
// returns it with its binding and scheme, base64-encoded for JSON.
func (t tpmQuoteTools) quote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error) {
	svc, err := t.service()
	if err != nil {
		return nil, err
	}

	pcrIndices := make([]uint32, len(pcrs))
	for i, pcr := range pcrs {
		pcrIndices[i] = uint32(pcr)
	}

	quote, err := svc.Quote(ctx, &platformv1.QuoteRequest{Nonce: nonce, PcrIndices: pcrIndices})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"quote":               base64.StdEncoding.EncodeToString(quote.GetQuote()),
		"signature":           base64.StdEncoding.EncodeToString(quote.GetSignature()),
		"event_log":           base64.StdEncoding.EncodeToString(quote.GetEventLog()),
		"channel_binding":     base64.StdEncoding.EncodeToString(quote.GetChannelBinding()),
		"signature_algorithm": quote.GetSignatureAlgorithm(),
	}, nil
}

// verify checks a quote under the scheme it declares, against req.AKPublic
// or, when that is empty, the platform IAK.
func (t tpmQuoteTools) verify(ctx context.Context, req *mcp.TPMVerifyQuoteRequest) (interface{}, error) {
	svc, err := t.service()
	if err != nil {
		return nil, err
	}

	result, err := svc.VerifyQuote(ctx, &platformv1.VerifyQuoteRequest{
		Quote:              req.Quote,
		Signature:          req.Signature,
		Nonce:              req.Nonce,
		ChannelBinding:     req.ChannelBinding,
		AkPublic:           req.AKPublic,
		SignatureAlgorithm: req.SignatureAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"verified": result.GetVerified(),
		"message":  result.GetMessage(),
	}, nil
}
