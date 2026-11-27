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
	"context"
	"strings"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The server answers TPMService GetEventLog, GetRandom, MakeCredential and
// ActivateCredential on QUIC (0x99·0x13 / 0x14 / 0x20 / 0x21); the SDK
// transport must reach them instead of answering Unimplemented (#2069).

func TestInvoke_TPMGetEventLog_MapsTheEntries(t *testing.T) {
	want := []quicwire.TPM2EventLogEntry{
		{
			EventNum: 0, PCRIndex: 0, EventType: "EV_S_CRTM_VERSION", DigestCount: 1,
			Digests:   []quicwire.TPM2EventDigest{{AlgorithmID: "sha256", Digest: strings.Repeat("ab", 32)}},
			EventSize: 16, EventString: "test",
		},
		{
			EventNum: 1, PCRIndex: 7, EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", DigestCount: 1,
			Digests:   []quicwire.TPM2EventDigest{{AlgorithmID: "sha256", Digest: strings.Repeat("cd", 32)}},
			EventSize: 32, EventString: "SecureBoot",
		},
	}
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2EventLogResponse{
		EventLog: []byte("raw-log"), Format: "tcg2", EventCount: 2, Entries: want,
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.GetEventLogResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_GetEventLog_FullMethodName,
		&platformv1.GetEventLogRequest{}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2EventLog)
	if len(sender.rawPayload) != 1 {
		t.Errorf("payload = %x, want the sub-opcode only (empty body)", sender.rawPayload)
	}
	if !bytes.Equal(reply.GetEventLog(), []byte("raw-log")) || reply.GetFormat() != "tcg2" || reply.GetEventCount() != 2 {
		t.Errorf("reply = %v, want the raw log, format and count", reply)
	}
	if len(reply.GetEntries()) != len(want) {
		t.Fatalf("entries = %d, want %d", len(reply.GetEntries()), len(want))
	}
	for i, w := range want {
		got := reply.GetEntries()[i]
		if got.GetEventNum() != w.EventNum || got.GetPcrIndex() != w.PCRIndex || got.GetEventType() != w.EventType ||
			got.GetDigestCount() != w.DigestCount || got.GetEventSize() != w.EventSize || got.GetEventString() != w.EventString {
			t.Errorf("entry %d = %v, want %+v", i, got, w)
		}
		if len(got.GetDigests()) != 1 || got.GetDigests()[0].GetAlgorithmId() != w.Digests[0].AlgorithmID ||
			got.GetDigests()[0].GetDigest() != w.Digests[0].Digest {
			t.Errorf("entry %d digests = %v, want %+v", i, got.GetDigests(), w.Digests)
		}
	}
}

func TestInvoke_TPMGetRandom_SendsTheCountAndMapsTheBytes(t *testing.T) {
	random := []byte("0123456789abcdef")
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2RandomResponse{RandomBytes: random})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.GetRandomResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_GetRandom_FullMethodName,
		&platformv1.GetRandomRequest{NumBytes: 16}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2Random)
	var got quicwire.TPM2RandomRequest
	if err := quicwire.DecodePayload(sender.rawPayload[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if got.NumBytes != 16 {
		t.Errorf("server request = %+v, want NumBytes 16", got)
	}
	if !bytes.Equal(reply.GetRandomBytes(), random) {
		t.Errorf("random bytes = %x, want %x", reply.GetRandomBytes(), random)
	}
}

// TestInvoke_TPMGetAK_RoutesToGetIAKAndMapsTheName reads the platform AK
// through the GetIAK sub-op and carries its TPM name (#2069).
func TestInvoke_TPMGetAK_RoutesToGetIAKAndMapsTheName(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2KeyResponse{
		Handle:    0x81010002,
		PublicKey: []byte("ak-pub"),
		Algorithm: "ECDSA",
		Name:      []byte("ak-name"),
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.GetAKResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_GetAK_FullMethodName,
		&platformv1.GetAKRequest{}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2GetIAK)
	if len(sender.rawPayload) != 1 {
		t.Errorf("payload = %x, want only the sub-opcode byte", sender.rawPayload)
	}
	if reply.GetHandle() != 0x81010002 {
		t.Errorf("handle = %#x, want 0x81010002", reply.GetHandle())
	}
	if !bytes.Equal(reply.GetPublicKey(), []byte("ak-pub")) {
		t.Errorf("public key = %q, want ak-pub", reply.GetPublicKey())
	}
	if !bytes.Equal(reply.GetName(), []byte("ak-name")) {
		t.Errorf("name = %q, want ak-name", reply.GetName())
	}
}

// GetIAK takes no selector, so a request that names a handle or an
// algorithm is refused before any send rather than answered with the IAK.
func TestInvoke_TPMGetAK_RefusesUnsupportedSelectors(t *testing.T) {
	cases := []struct {
		name  string
		req   *platformv1.GetAKRequest
		field string
	}{
		{"Handle: 0x81010003", &platformv1.GetAKRequest{Handle: 0x81010003}, "handle"},
		{"Algorithm: KEY_ALGORITHM_RSA_4096", &platformv1.GetAKRequest{Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096}, "algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			err := conn.Invoke(context.Background(), platformv1.TPMService_GetAK_FullMethodName,
				tc.req, &platformv1.GetAKResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Invoke() error = %v, want InvalidArgument", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name %s", err.Error(), tc.field)
			}
			if sender.rawCalls != 0 || sender.boundCalls != 0 {
				t.Errorf("sends = raw %d bound %d, want none", sender.rawCalls, sender.boundCalls)
			}
		})
	}
}

func TestInvoke_TPMMakeCredential_SendsTheInputsAndMapsTheBlob(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2MakeCredentialResponse{
		CredentialBlob: []byte("blob"), EncryptedSecret: []byte("enc-secret"), Secret: []byte("secret"),
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.MakeCredentialResponse{}
	req := &platformv1.MakeCredentialRequest{
		AkName: []byte("ak-name"), Secret: []byte("secret"), EkCert: []byte("ek-cert"), IakPub: []byte("iak-pub"),
	}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_MakeCredential_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2MakeCred)
	var got quicwire.TPM2MakeCredentialRequest
	if err := quicwire.DecodePayload(sender.rawPayload[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if !bytes.Equal(got.AKName, []byte("ak-name")) || !bytes.Equal(got.Secret, []byte("secret")) ||
		!bytes.Equal(got.EKCert, []byte("ek-cert")) || !bytes.Equal(got.IAKPub, []byte("iak-pub")) {
		t.Errorf("server request = %+v, want the AK name, secret, EK cert and IAK public", got)
	}
	if !bytes.Equal(reply.GetCredentialBlob(), []byte("blob")) || !bytes.Equal(reply.GetEncryptedSecret(), []byte("enc-secret")) ||
		!bytes.Equal(reply.GetSecret(), []byte("secret")) {
		t.Errorf("reply = %v, want the blob, encrypted secret and secret", reply)
	}
}

func TestInvoke_TPMActivateCredential_SendsTheBlobAndMapsTheSecret(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2ActivateCredentialResponse{
		Secret: []byte("recovered"),
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.TPMActivateCredentialResponse{}
	req := &platformv1.TPMActivateCredentialRequest{CredentialBlob: []byte("blob"), EncryptedSecret: []byte("enc-secret")}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_ActivateCredential_FullMethodName, req, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2ActivateCred)
	var got quicwire.TPM2ActivateCredentialRequest
	if err := quicwire.DecodePayload(sender.rawPayload[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if !bytes.Equal(got.CredentialBlob, []byte("blob")) || !bytes.Equal(got.EncryptedSecret, []byte("enc-secret")) {
		t.Errorf("server request = %+v, want the blob and encrypted secret", got)
	}
	if !bytes.Equal(reply.GetSecret(), []byte("recovered")) {
		t.Errorf("secret = %q, want the recovered secret", reply.GetSecret())
	}
}
