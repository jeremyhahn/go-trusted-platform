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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the AttestationService
// quote surface between the platform SDK client and the daemon. The canonical
// contract is the platform.v1 protobuf messages themselves: the SDK QUIC
// transport adapter encodes the pb request structs directly and the daemon
// decodes the payload into the same pb types (and vice versa for responses).
// The quote messages carry no protobuf oneofs, so they round-trip the msgpack
// payload codec cleanly. roundTripPBWire lives in
// quic_container_wire_compat_test.go.

// TestQUICAttestWireCompatGetQuote round-trips GetAttestationQuote (OpAttestQuote).
func TestQUICAttestWireCompatGetQuote(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	roundTripPBWire(t,
		&platformv1.GetAttestationQuoteRequest{
			Config: &platformv1.AttestationQuoteConfig{
				AkHandle:      0x81000003,
				PcrIndices:    []uint32{0, 1, 7},
				HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
			},
			Nonce: nonce,
		},
		&platformv1.GetAttestationQuoteRequest{})
	roundTripPBWire(t,
		&platformv1.GetAttestationQuoteResponse{
			Status: &platformv1.Status{Success: true, Message: "quote generated successfully"},
			Quote: &platformv1.AttestationQuote{
				QuoteData: []byte{0xaa, 0xbb},
				Signature: []byte{0xcc, 0xdd},
				Nonce:     nonce,
				PcrValues: []*platformv1.AttestationPCRValue{
					{Index: 7, Value: []byte{0x01}, Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
				},
			},
		},
		&platformv1.GetAttestationQuoteResponse{})
}

// TestQUICAttestWireCompatVerifyQuote round-trips VerifyAttestationQuote
// (OpAttestVerify), including the expected/actual PCR slices a flat decode
// would have dropped.
func TestQUICAttestWireCompatVerifyQuote(t *testing.T) {
	roundTripPBWire(t,
		&platformv1.VerifyAttestationQuoteRequest{
			Quote: &platformv1.AttestationQuote{
				QuoteData: []byte{0xaa},
				Signature: []byte{0xbb},
				Nonce:     []byte{0xcc},
			},
			AkPublicKeyPem: []byte("-----BEGIN PUBLIC KEY-----\n"),
			ExpectedNonce:  []byte{0xcc},
			ExpectedPcrs: []*platformv1.AttestationPCRValue{
				{Index: 0, Value: []byte{0x00}, Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
			},
		},
		&platformv1.VerifyAttestationQuoteRequest{})
	roundTripPBWire(t,
		&platformv1.VerifyAttestationQuoteResponse{
			Status:   &platformv1.Status{Success: true},
			Verified: true,
			Message:  "quote verification completed",
			ActualPcrs: []*platformv1.AttestationPCRValue{
				{Index: 0, Value: []byte{0x00}, Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
			},
		},
		&platformv1.VerifyAttestationQuoteResponse{})
}

// TestQUICAttestWireCompatCollectHost round-trips CollectHostAttestation on
// its dedicated OpAttestCollectHost (0x72) opcode — the request is byte-shape
// identical to GetAttestationQuoteRequest, which is exactly why it needed a
// distinct opcode to disambiguate the response.
func TestQUICAttestWireCompatCollectHost(t *testing.T) {
	nonce := []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	roundTripPBWire(t,
		&platformv1.CollectHostAttestationRequest{
			Config: &platformv1.AttestationQuoteConfig{AkHandle: 0x81000003, PcrIndices: []uint32{0, 7}},
			Nonce:  nonce,
		},
		&platformv1.CollectHostAttestationRequest{})
	roundTripPBWire(t,
		&platformv1.CollectHostAttestationResponse{
			Status: &platformv1.Status{Success: true, Message: "host attestation collected successfully"},
			Attestation: &platformv1.HostAttestation{
				QuoteData:          []byte{0x01, 0x02},
				Signature:          []byte{0x03, 0x04},
				SignatureAlgorithm: "RSASSA_PSS",
				Nonce:              nonce,
				Pcrs: []*platformv1.AttestationPCRValue{
					{Index: 7, Value: []byte{0xff}, Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
				},
			},
		},
		&platformv1.CollectHostAttestationResponse{})
}
