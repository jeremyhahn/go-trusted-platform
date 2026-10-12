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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/internal/cawire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// certificateIssuedMessage is the status message the gRPC and REST
// transports return with an issued certificate. The QUIC reply carries no
// status: a non-OK answer arrives as an error instead.
const certificateIssuedMessage = "certificate issued successfully"

// The structs below mirror the daemon's CA wire structs in
// pkg/api/quic/ca_handlers.go key for key (the codec keys on the codec
// tags). The SDK module cannot import the daemon, so a change to either side
// must be made to both.

// caSubjectWire mirrors the daemon's Subject.
type caSubjectWire struct {
	CommonName         string `codec:"common_name"`
	Organization       string `codec:"organization"`
	OrganizationalUnit string `codec:"organizational_unit"`
	Country            string `codec:"country"`
	Province           string `codec:"province"`
	Locality           string `codec:"locality"`
	Address            string `codec:"address"`
	PostalCode         string `codec:"postal_code"`
}

// caSANsWire mirrors the daemon's SANs.
type caSANsWire struct {
	DNS   []string `codec:"dns"`
	IPs   []string `codec:"ips"`
	Email []string `codec:"email"`
	URIs  []string `codec:"uris"`
}

// caIssueRequestWire mirrors the daemon's CAIssueRequest.
type caIssueRequestWire struct {
	Subject      *caSubjectWire `codec:"subject"`
	Sans         *caSANsWire    `codec:"sans"`
	ValidDays    int32          `codec:"valid_days"`
	KeyAlgorithm string         `codec:"key_algorithm"`
	StoreType    string         `codec:"store_type"`
	KeyUsage     []string       `codec:"key_usage"`
	ExtKeyUsage  []string       `codec:"ext_key_usage"`
	IsCA         bool           `codec:"is_ca"`
	MaxPathLen   int32          `codec:"max_path_len"`
}

// caCertificateWire mirrors the daemon's Certificate.
type caCertificateWire struct {
	Serial             string         `codec:"serial"`
	Subject            *caSubjectWire `codec:"subject"`
	Issuer             string         `codec:"issuer"`
	NotBefore          int64          `codec:"not_before"`
	NotAfter           int64          `codec:"not_after"`
	Status             string         `codec:"status"`
	KeyAlgorithm       string         `codec:"key_algorithm"`
	SignatureAlgorithm string         `codec:"signature_algorithm"`
	IsCA               bool           `codec:"is_ca"`
	MaxPathLen         int32          `codec:"max_path_len"`
	KeyUsage           []string       `codec:"key_usage"`
	ExtKeyUsage        []string       `codec:"ext_key_usage"`
	FingerprintSHA256  string         `codec:"fingerprint_sha256"`
	Pem                string         `codec:"pem"`
	Der                []byte         `codec:"der"`
	Sans               *caSANsWire    `codec:"sans"`
}

// caCertificateReplyWire mirrors the daemon's CAIssueResponse and
// CAGetResponse, which share one shape.
type caCertificateReplyWire struct {
	Certificate *caCertificateWire `codec:"certificate"`
	Timestamp   int64              `codec:"timestamp"`
}

// The daemon speaks its own CA wire structs — a flat issue request with a
// string key algorithm, and certificates with unix-second times, string
// enums and a plaintext PEM — which the field-name codec cannot pair with
// the pb messages, so these methods translate both ways (#691).
func init() {
	categoryResponseDecoders[platformv1.CAService_SignCSR_FullMethodName] =
		decodeIssuedCertificate(platformv1.CAService_SignCSR_FullMethodName)
	methodRequestEncoders[platformv1.CAService_IssueCertificate_FullMethodName] = encodeIssueCertificateRequest
	methodResponseDecoders[platformv1.CAService_IssueCertificate_FullMethodName] =
		decodeIssuedCertificate(platformv1.CAService_IssueCertificate_FullMethodName)
	methodResponseDecoders[platformv1.CAService_GetCertificate_FullMethodName] = decodeGetCertificateReply
}

// encodeIssueCertificateRequest flattens the pb issue request into the
// daemon's CAIssueRequest. A missing request or subject is sent empty, and
// the daemon refuses it for its missing common name, as the gRPC service
// does.
func encodeIssueCertificateRequest(args interface{}) (interface{}, error) {
	in, ok := args.(*platformv1.IssueCertificateRequest)
	if !ok {
		return nil, ErrInvalidArgsType{Method: platformv1.CAService_IssueCertificate_FullMethodName}
	}
	req := in.GetRequest()
	algorithm, err := cawire.KeyAlgorithmName(req.GetKeyAlgorithm())
	if err != nil {
		return nil, err
	}
	out := &caIssueRequestWire{
		ValidDays:    req.GetValidDays(),
		KeyAlgorithm: algorithm,
		StoreType:    req.GetStoreType(),
		KeyUsage:     req.GetKeyUsage(),
		ExtKeyUsage:  req.GetExtKeyUsage(),
		IsCA:         req.GetIsCa(),
		MaxPathLen:   req.GetMaxPathLen(),
	}
	if s := req.GetSubject(); s != nil {
		out.Subject = &caSubjectWire{
			CommonName:         s.GetCommonName(),
			Organization:       s.GetOrganization(),
			OrganizationalUnit: s.GetOrganizationalUnit(),
			Country:            s.GetCountry(),
			Province:           s.GetProvince(),
			Locality:           s.GetLocality(),
			Address:            s.GetAddress(),
			PostalCode:         s.GetPostalCode(),
		}
	}
	if s := req.GetSans(); s != nil {
		out.Sans = &caSANsWire{
			DNS:   s.GetDnsNames(),
			IPs:   s.GetIpAddresses(),
			Email: s.GetEmailAddresses(),
			URIs:  s.GetUris(),
		}
	}
	return out, nil
}

// decodeIssuedCertificate places the daemon's CAIssueResponse, the answer
// to both issue and sign-csr, on IssueCertificateResponse.
func decodeIssuedCertificate(method string) categoryResponseDecoder {
	return func(payload []byte, reply interface{}) error {
		out, ok := reply.(*platformv1.IssueCertificateResponse)
		if !ok {
			return ErrInvalidReplyType{Method: method}
		}
		var wire caCertificateReplyWire
		if err := quicwire.DecodePayload(payload, &wire); err != nil {
			return ErrDecodingFailed{Err: err}
		}
		out.Status = &platformv1.Status{Success: true, Message: certificateIssuedMessage}
		out.Timestamp = cawire.Time(wire.Timestamp)
		out.Certificate = certificateToProto(wire.Certificate)
		return nil
	}
}

// decodeGetCertificateReply places the daemon's CAGetResponse on
// GetCertificateResponse.
func decodeGetCertificateReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetCertificateResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.CAService_GetCertificate_FullMethodName}
	}
	var wire caCertificateReplyWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Timestamp = cawire.Time(wire.Timestamp)
	out.Certificate = certificateToProto(wire.Certificate)
	return nil
}

// certificateToProto converts the daemon's QUIC certificate to the pb the
// gRPC service sends. A nil certificate stays nil.
func certificateToProto(c *caCertificateWire) *platformv1.Certificate {
	if c == nil {
		return nil
	}
	out := &platformv1.Certificate{
		Serial:             c.Serial,
		Issuer:             c.Issuer,
		NotBefore:          cawire.Time(c.NotBefore),
		NotAfter:           cawire.Time(c.NotAfter),
		Status:             cawire.Status(c.Status),
		KeyAlgorithm:       cawire.KeyAlgorithm(c.KeyAlgorithm),
		SignatureAlgorithm: c.SignatureAlgorithm,
		IsCa:               c.IsCA,
		MaxPathLen:         c.MaxPathLen,
		KeyUsage:           c.KeyUsage,
		ExtKeyUsage:        c.ExtKeyUsage,
		FingerprintSha256:  c.FingerprintSHA256,
		Pem:                []byte(c.Pem),
		Der:                c.Der,
	}
	if s := c.Subject; s != nil {
		out.Subject = &platformv1.Subject{
			CommonName:         s.CommonName,
			Organization:       s.Organization,
			OrganizationalUnit: s.OrganizationalUnit,
			Country:            s.Country,
			Province:           s.Province,
			Locality:           s.Locality,
			Address:            s.Address,
			PostalCode:         s.PostalCode,
		}
	}
	if s := c.Sans; s != nil {
		out.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       s.DNS,
			IpAddresses:    s.IPs,
			EmailAddresses: s.Email,
			Uris:           s.URIs,
		}
	}
	return out
}
