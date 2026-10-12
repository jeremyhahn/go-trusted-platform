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
	"context"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/internal/cawire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestDecodeIssuedCertificate_RejectsWrongReplyAndBadPayload(t *testing.T) {
	decode := decodeIssuedCertificate(platformv1.CAService_SignCSR_FullMethodName)
	var wrong ErrInvalidReplyType
	if err := decode(nil, &platformv1.SignCSRRequest{}); !errors.As(err, &wrong) ||
		wrong.Method != platformv1.CAService_SignCSR_FullMethodName {
		t.Fatalf("wrong reply type: got %v, want ErrInvalidReplyType for SignCSR", err)
	}
	var bad ErrDecodingFailed
	if err := decode([]byte{0xc1}, &platformv1.IssueCertificateResponse{}); !errors.As(err, &bad) {
		t.Fatalf("bad payload: got %v, want ErrDecodingFailed", err)
	}
}

// fullIssueRequest sets every field of the pb issue request.
func fullIssueRequest() *platformv1.IssueCertificateRequest {
	return &platformv1.IssueCertificateRequest{Request: &platformv1.CertificateRequest{
		Subject: &platformv1.Subject{
			CommonName: "cn", Organization: "o", OrganizationalUnit: "ou", Country: "US",
			Province: "st", Locality: "l", Address: "street", PostalCode: "zip",
		},
		Sans: &platformv1.SubjectAlternativeNames{
			DnsNames: []string{"d"}, IpAddresses: []string{"192.0.2.1"},
			EmailAddresses: []string{"e@x"}, Uris: []string{"spiffe://x/y"},
		},
		ValidDays:    7,
		KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		StoreType:    "pkcs8",
		KeyUsage:     []string{"DIGITAL_SIGNATURE"},
		ExtKeyUsage:  []string{"CLIENT_AUTH"},
		IsCa:         true,
		MaxPathLen:   1,
	}}
}

// The daemon reads a flat CAIssueRequest with a string key algorithm; the
// encoder carries every pb field onto it (#691).
func TestEncodeIssueCertificateRequest_FlattensEveryField(t *testing.T) {
	got, err := encodeIssueCertificateRequest(fullIssueRequest())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := &caIssueRequestWire{
		Subject: &caSubjectWire{
			CommonName: "cn", Organization: "o", OrganizationalUnit: "ou", Country: "US",
			Province: "st", Locality: "l", Address: "street", PostalCode: "zip",
		},
		Sans:         &caSANsWire{DNS: []string{"d"}, IPs: []string{"192.0.2.1"}, Email: []string{"e@x"}, URIs: []string{"spiffe://x/y"}},
		ValidDays:    7,
		KeyAlgorithm: "RSA-3072",
		StoreType:    "pkcs8",
		KeyUsage:     []string{"DIGITAL_SIGNATURE"},
		ExtKeyUsage:  []string{"CLIENT_AUTH"},
		IsCA:         true,
		MaxPathLen:   1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("encode = %+v, want %+v", got, want)
	}

	empty, err := encodeIssueCertificateRequest(&platformv1.IssueCertificateRequest{})
	if err != nil {
		t.Fatalf("encode empty: %v", err)
	}
	if req := empty.(*caIssueRequestWire); req.Subject != nil || req.Sans != nil {
		t.Fatalf("an empty request encodes as %+v, want no subject for the daemon to refuse", req)
	}
}

func TestEncodeIssueCertificateRequest_RefusesWrongArgsAndUnknownAlgorithm(t *testing.T) {
	var wrong ErrInvalidArgsType
	if _, err := encodeIssueCertificateRequest(&platformv1.GetCertificateRequest{}); !errors.As(err, &wrong) {
		t.Fatalf("wrong args type: got %v, want ErrInvalidArgsType", err)
	}
	req := fullIssueRequest()
	req.Request.KeyAlgorithm = platformv1.KeyAlgorithm(99)
	if _, err := encodeIssueCertificateRequest(req); err == nil {
		t.Fatal("an unknown key algorithm encoded; the gRPC service refuses it")
	}
}

// refusingSender fails the test if a request reaches the wire.
type refusingSender struct{ t *testing.T }

func (s refusingSender) Send(context.Context, byte, interface{}, interface{}) error {
	s.t.Fatal("the request was sent")
	return nil
}

func (s refusingSender) SendRequest(context.Context, byte, []byte) (*quicwire.Response, error) {
	s.t.Fatal("the request was sent")
	return nil, nil
}

// Invoke refuses a request its encoder cannot translate before anything
// goes on the wire.
func TestInvoke_IssueCertificate_RefusesAnUnknownAlgorithmBeforeSending(t *testing.T) {
	a := &Adapter{client: &quicwire.Client{}}
	a.connected.Store(true)
	conn := &quicClientConn{adapter: a, sender: refusingSender{t: t}}
	req := fullIssueRequest()
	req.Request.KeyAlgorithm = platformv1.KeyAlgorithm(99)

	err := conn.Invoke(context.Background(), platformv1.CAService_IssueCertificate_FullMethodName,
		req, &platformv1.IssueCertificateResponse{})

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Invoke() error = %v, want InvalidArgument", err)
	}
}

// The daemon answers get with CAGetResponse; every certificate field lands
// on GetCertificateResponse, including the DER and usages (#691).
func TestDecodeGetCertificateReply_CarriesEveryField(t *testing.T) {
	payload, err := quicwire.EncodePayload(&caCertificateReplyWire{
		Certificate: &caCertificateWire{
			Serial: "0a", Issuer: "root", NotBefore: 100, NotAfter: 200, Status: "EXPIRED",
			KeyAlgorithm: "ED25519", SignatureAlgorithm: "Ed25519", IsCA: true, MaxPathLen: 2,
			KeyUsage: []string{"CERT_SIGN"}, ExtKeyUsage: []string{"ANY"}, FingerprintSHA256: "ff",
			Pem: "pem", Der: []byte{1, 2}, Subject: &caSubjectWire{CommonName: "cn"},
		},
		Timestamp: 300,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	reply := &platformv1.GetCertificateResponse{}
	if err := decodeGetCertificateReply(payload, reply); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := &platformv1.GetCertificateResponse{
		Certificate: &platformv1.Certificate{
			Serial: "0a", Issuer: "root", NotBefore: cawire.Time(100), NotAfter: cawire.Time(200),
			Status:       platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, SignatureAlgorithm: "Ed25519",
			IsCa: true, MaxPathLen: 2, KeyUsage: []string{"CERT_SIGN"}, ExtKeyUsage: []string{"ANY"},
			FingerprintSha256: "ff", Pem: []byte("pem"), Der: []byte{1, 2},
			Subject: &platformv1.Subject{CommonName: "cn"},
		},
		Timestamp: cawire.Time(300),
	}
	if !proto.Equal(reply, want) {
		t.Fatalf("decode = %v, want %v", reply, want)
	}
}

func TestDecodeGetCertificateReply_RejectsWrongReplyAndBadPayload(t *testing.T) {
	var wrong ErrInvalidReplyType
	if err := decodeGetCertificateReply(nil, &platformv1.IssueCertificateResponse{}); !errors.As(err, &wrong) {
		t.Fatalf("wrong reply type: got %v, want ErrInvalidReplyType", err)
	}
	var bad ErrDecodingFailed
	if err := decodeGetCertificateReply([]byte{0xc1}, &platformv1.GetCertificateResponse{}); !errors.As(err, &bad) {
		t.Fatalf("bad payload: got %v, want ErrDecodingFailed", err)
	}
}

func TestCertificateToProto_NilStaysNil(t *testing.T) {
	if got := certificateToProto(nil); got != nil {
		t.Fatalf("certificateToProto(nil) = %v, want nil", got)
	}
}
