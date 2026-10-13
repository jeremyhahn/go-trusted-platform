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

package quicwire

// Wire bodies of the physical-TPM quote sub-opcodes (OpTPM2Category ·
// SubOpTPM2Quote / SubOpTPM2VerifyQuote). The server handler and the SDK
// QUIC transport share them, so both ends encode one shape (#482).

// TPM2QuoteRequest represents a TPM quote request.
type TPM2QuoteRequest struct {
	PCRIndices []uint32 `codec:"pcr_indices"`
	Nonce      []byte   `codec:"nonce"`
}

// TPM2QuoteResponse represents a TPM quote response.
type TPM2QuoteResponse struct {
	Quote     []byte `codec:"quote"`
	Signature []byte `codec:"signature"`
	EventLog  []byte `codec:"event_log"`
	// ChannelBinding is the TLS exporter of the connection the request
	// arrived on; the TPM quoted SHA-256(nonce || ChannelBinding) (#482).
	ChannelBinding []byte `codec:"channel_binding"`
	Timestamp      int64  `codec:"timestamp"`
	// SignatureAlgorithm names the scheme the IAK signed Signature
	// under; a verifier needs it, because an RSA AK signs either
	// RSASSA or RSA-PSS and the raw signature does not say which.
	SignatureAlgorithm string `codec:"signature_algorithm"`
}

// TPM2VerifyQuoteRequest represents a TPM quote verification request.
// Field names mirror the gRPC VerifyQuoteRequest proto.
type TPM2VerifyQuoteRequest struct {
	Quote     []byte `codec:"quote"`
	Signature []byte `codec:"signature"`
	Nonce     []byte `codec:"nonce"`
	// AKPublic is the PKIX DER of the attestation key that signed the
	// quote; when it is empty the node verifies against its IAK.
	AKPublic []byte `codec:"ak_public"`
	// ChannelBinding, when set, is the binding the quote was produced
	// under; the quote must then carry SHA-256(Nonce || ChannelBinding).
	ChannelBinding []byte `codec:"channel_binding"`
	// SignatureAlgorithm is the scheme the quote declares, as the quote
	// response returned it; an absent or unknown scheme fails verification.
	SignatureAlgorithm string `codec:"signature_algorithm"`
}

// TPM2VerifyQuoteResponse represents a TPM quote verification response.
type TPM2VerifyQuoteResponse struct {
	Verified  bool   `codec:"verified"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}
