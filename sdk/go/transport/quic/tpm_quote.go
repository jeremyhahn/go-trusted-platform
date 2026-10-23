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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TPMService Quote and VerifyQuote ride the physical-TPM category opcode
// (OpTPM2Category, 0x99) with their sub-opcode in payload[0], the framing
// pkg/api/quic.TPM2Handler decodes. The server reads the snake_case
// quicwire bodies, not the pb messages, so both directions translate. The
// fields carried are the ones TPMService honours on gRPC (#482).
var tpmQuoteRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.TPMService_Quote_FullMethodName: requestEncoder(platformv1.TPMService_Quote_FullMethodName,
		func(r *platformv1.QuoteRequest) (interface{}, error) {
			return &quicwire.TPM2QuoteRequest{PCRIndices: r.GetPcrIndices(), Nonce: r.GetNonce()}, nil
		}),
	platformv1.TPMService_VerifyQuote_FullMethodName: requestEncoder(platformv1.TPMService_VerifyQuote_FullMethodName,
		func(r *platformv1.VerifyQuoteRequest) (interface{}, error) {
			return &quicwire.TPM2VerifyQuoteRequest{
				Quote:              r.GetQuote(),
				Signature:          r.GetSignature(),
				Nonce:              r.GetNonce(),
				AKPublic:           r.GetAkPublic(),
				ChannelBinding:     r.GetChannelBinding(),
				SignatureAlgorithm: r.GetSignatureAlgorithm(),
			}, nil
		}),
}

var tpmQuoteResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.TPMService_Quote_FullMethodName: responseDecoder(platformv1.TPMService_Quote_FullMethodName,
		func(w *quicwire.TPM2QuoteResponse, out *platformv1.QuoteResponse) error {
			out.Quote = w.Quote
			out.Signature = w.Signature
			out.EventLog = w.EventLog
			out.ChannelBinding = w.ChannelBinding
			out.SignatureAlgorithm = w.SignatureAlgorithm
			return nil
		}),
	platformv1.TPMService_VerifyQuote_FullMethodName: responseDecoder(platformv1.TPMService_VerifyQuote_FullMethodName,
		func(w *quicwire.TPM2VerifyQuoteResponse, out *platformv1.VerifyQuoteResponse) error {
			out.Verified = w.Verified
			out.Message = w.Message
			return nil
		}),
}

// init registers the codecs; the routes are in the adapter.go maps.
func init() {
	registerCategoryCodecs(tpmQuoteRequestEncoders, tpmQuoteResponseDecoders)
}
