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

package vm

// QuoteEvidence is the TPM quote evidence a device submits for verification,
// JSON-encoded on every transport.
//
// PCRs are the values the device READ from its TPM for the quoted selection.
// They are not trusted as-is: the verifier proves they hash to the digest the
// TPM signed, then compares them against the baseline recorded on the
// device's profile. The attester never supplies the expected state (#373).
type QuoteEvidence struct {
	// Quote is the marshaled TPMS_ATTEST structure the TPM produced.
	Quote []byte `json:"quote"`
	// Signature is the attestation-key signature over Quote.
	Signature []byte `json:"signature"`
	// Nonce is the verifier-issued anti-replay value that must appear in
	// the quote's extraData.
	Nonce []byte `json:"nonce"`
	// PCRs maps PCR index to the SHA-256 value the device read for it. The
	// index set must exactly match the quote's PCR selection.
	PCRs map[int][]byte `json:"pcrs"`
}
