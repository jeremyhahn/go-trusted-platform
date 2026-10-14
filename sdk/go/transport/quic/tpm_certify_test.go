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

//go:build codec_msgpack

package quic

import (
	"bytes"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

const certifyMethod = platformv1.TPMService_Certify_FullMethodName

func TestTPMCertify_RoutesToTheTPM2SubOpcode(t *testing.T) {
	if got := grpcMethodToOpcodeMap[certifyMethod]; got != quicwire.OpTPM2Category {
		t.Errorf("opcode = 0x%02x, want 0x%02x", got, quicwire.OpTPM2Category)
	}
	if got := categorySubOpcodeMap[certifyMethod]; got != quicwire.SubOpTPM2Certify {
		t.Errorf("sub-opcode = 0x%02x, want 0x%02x", got, quicwire.SubOpTPM2Certify)
	}
}

func TestTPMCertify_RequestAndReplyRoundTrip(t *testing.T) {
	encoded, err := categoryRequestEncoders[certifyMethod](&platformv1.CertifyRequest{
		KeyHandle: 0x81000001, KeyPassword: "pw", Nonce: []byte("n"),
	})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	want := &quicwire.TPM2CertifyRequest{KeyHandle: 0x81000001, KeyPassword: "pw", Nonce: []byte("n")}
	got, ok := encoded.(*quicwire.TPM2CertifyRequest)
	if !ok || got.KeyHandle != want.KeyHandle || got.KeyPassword != want.KeyPassword || !bytes.Equal(got.Nonce, want.Nonce) {
		t.Fatalf("wire request = %#v, want %#v", encoded, want)
	}

	payload, err := quicwire.EncodePayload(&quicwire.TPM2CertifyResponse{
		CertifyInfo:        []byte("attest"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: "ECDSA-SHA256",
		AttestingKeyPublic: []byte("iak"),
		AttestedKeyPublic:  []byte("key"),
		Nonce:              []byte("n"),
	})
	if err != nil {
		t.Fatalf("encode reply: %v", err)
	}
	reply := &platformv1.CertifyResponse{}
	if err := categoryResponseDecoders[certifyMethod](payload, reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if string(reply.GetCertifyInfo()) != "attest" || string(reply.GetSignature()) != "sig" ||
		reply.GetSignatureAlgorithm() != "ECDSA-SHA256" || string(reply.GetAttestingKeyPublic()) != "iak" ||
		string(reply.GetAttestedKeyPublic()) != "key" || string(reply.GetNonce()) != "n" {
		t.Errorf("reply = %v, want every wire field carried", reply)
	}
}

func TestTPMCertify_RefusesTheWrongTypes(t *testing.T) {
	_, err := categoryRequestEncoders[certifyMethod](&platformv1.QuoteRequest{})
	var argsErr ErrInvalidArgsType
	if !errors.As(err, &argsErr) {
		t.Errorf("encode a QuoteRequest: err = %v, want ErrInvalidArgsType", err)
	}

	err = categoryResponseDecoders[certifyMethod](nil, &platformv1.QuoteResponse{})
	var replyErr ErrInvalidReplyType
	if !errors.As(err, &replyErr) {
		t.Errorf("decode into a QuoteResponse: err = %v, want ErrInvalidReplyType", err)
	}

	err = categoryResponseDecoders[certifyMethod]([]byte{0xFF}, &platformv1.CertifyResponse{})
	var decodeErr ErrDecodingFailed
	if !errors.As(err, &decodeErr) {
		t.Errorf("decode a garbage payload: err = %v, want ErrDecodingFailed", err)
	}
}
