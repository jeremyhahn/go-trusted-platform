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

package authenticodetest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidTestTSAPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	asn1Null         = asn1.RawValue{Tag: asn1.TagNull}
)

const (
	tsaStatusGranted    = 0
	tsaSignerInfoV1     = 1
	tsaSignedDataV3     = 3
	timestampReplyMIME  = "application/timestamp-reply"
	tsaCertificateLabel = "Trusted Platform test TSA"
)

// TSAOptions shapes how a test TSA answers. The zero value is a TSA that
// grants every request with a correct token.
type TSAOptions struct {
	// Status is the RFC 3161 PKIStatus to answer with. Anything other than
	// granted (0) is a refusal and carries no token.
	Status int
	// HTTPStatus, when non-zero, is returned instead of a TimeStampResp.
	HTTPStatus int
	// AlterImprint stamps a hash other than the one requested.
	AlterImprint bool
	// AlterNonce answers with a nonce other than the one requested.
	AlterNonce bool
	// OmitTimeStampingEKU issues the TSA certificate without the
	// id-kp-timeStamping extended key usage.
	OmitTimeStampingEKU bool
}

// TSA is an in-process RFC 3161 time-stamp authority. It signs tokens with
// its own RSA key under a self-signed time-stamping certificate.
type TSA struct {
	// URL is the address to post time-stamp queries to.
	URL string

	t      *testing.T
	opts   TSAOptions
	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial atomic.Int64
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tsaImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tsaRequest struct {
	Version        int
	MessageImprint tsaImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
}

type tsaStatus struct {
	Status       int
	StatusString []string `asn1:"optional,utf8"`
}

type tsaResponse struct {
	Status tsaStatus
	Token  asn1.RawValue `asn1:"optional"`
}

type tsaInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tsaImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

type tsaIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type tsaSignerInfo struct {
	Version            int
	SID                tsaIssuerSerial
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

type tsaEncapsulatedContent struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type tsaSignedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContent     tsaEncapsulatedContent
	Certificates     asn1.RawValue
	SignerInfos      []tsaSignerInfo `asn1:"set"`
}

type tsaAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// NewTSA starts a test TSA that answers as opts says. It is closed when the
// test ends.
func NewTSA(t *testing.T, opts TSAOptions) *TSA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("tsa: generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: tsaCertificateLabel},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if opts.OmitTimeStampingEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tsa: create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tsa: parse certificate: %v", err)
	}

	tsa := &TSA{t: t, opts: opts, key: key, cert: cert}
	server := httptest.NewServer(tsa)
	t.Cleanup(server.Close)
	tsa.URL = server.URL
	return tsa
}

// ServeHTTP answers one RFC 3161 time-stamp query.
func (a *TSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.opts.HTTPStatus != 0 {
		http.Error(w, http.StatusText(a.opts.HTTPStatus), a.opts.HTTPStatus)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req tsaRequest
	if _, err := asn1.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reply, err := a.reply(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", timestampReplyMIME)
	if _, err := w.Write(reply); err != nil {
		a.t.Errorf("tsa: write reply: %v", err)
	}
}

// reply encodes the TimeStampResp for req.
func (a *TSA) reply(req *tsaRequest) ([]byte, error) {
	if a.opts.Status != tsaStatusGranted {
		return asn1.Marshal(tsaResponse{Status: tsaStatus{Status: a.opts.Status, StatusString: []string{"refused by test TSA"}}})
	}
	token, err := a.token(req)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(tsaResponse{Status: tsaStatus{Status: tsaStatusGranted}, Token: asn1.RawValue{FullBytes: token}})
}

// token builds and signs the time-stamp token (a CMS SignedData over a
// TSTInfo) for req.
func (a *TSA) token(req *tsaRequest) ([]byte, error) {
	hashed := append([]byte(nil), req.MessageImprint.HashedMessage...)
	if a.opts.AlterImprint && len(hashed) > 0 {
		hashed[0] ^= 0xff
	}
	nonce := req.Nonce
	if a.opts.AlterNonce && nonce != nil {
		nonce = new(big.Int).Add(nonce, big.NewInt(1))
	}
	tstDER, err := asn1.Marshal(tsaInfo{
		Version:        1,
		Policy:         oidTestTSAPolicy,
		MessageImprint: tsaImprint{HashAlgorithm: req.MessageImprint.HashAlgorithm, HashedMessage: hashed},
		SerialNumber:   big.NewInt(a.serial.Add(1)),
		GenTime:        time.Now().UTC().Truncate(time.Second),
		Nonce:          nonce,
	})
	if err != nil {
		return nil, err
	}
	eContent, err := asn1.Marshal(tstDER)
	if err != nil {
		return nil, err
	}

	tstDigest := sha256.Sum256(tstDER)
	attrs, err := encodeAttributes(
		attributeValue{oidContentType, oidTSTInfo},
		attributeValue{oidMessageDigest, tstDigest[:]},
	)
	if err != nil {
		return nil, err
	}
	attrsSet, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs})
	if err != nil {
		return nil, err
	}
	attrsDigest := sha256.Sum256(attrsSet)
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, attrsDigest[:])
	if err != nil {
		return nil, err
	}

	sha256Alg := algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1Null}
	sdDER, err := asn1.Marshal(tsaSignedData{
		Version:          tsaSignedDataV3,
		DigestAlgorithms: []algorithmIdentifier{sha256Alg},
		EncapContent: tsaEncapsulatedContent{
			ContentType: oidTSTInfo,
			Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: eContent},
		},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: a.cert.Raw},
		SignerInfos: []tsaSignerInfo{{
			Version:            tsaSignerInfoV1,
			SID:                tsaIssuerSerial{Issuer: asn1.RawValue{FullBytes: a.cert.RawIssuer}, Serial: a.cert.SerialNumber},
			DigestAlgorithm:    sha256Alg,
			SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
			SignatureAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1Null},
			Signature:          signature,
		}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(tsaEncapsulatedContent{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
}

type attributeValue struct {
	oid   asn1.ObjectIdentifier
	value any
}

// encodeAttributes DER-encodes each attribute as SEQUENCE { type, SET { value } }
// and returns their concatenation.
func encodeAttributes(values ...attributeValue) ([]byte, error) {
	var out []byte
	for _, v := range values {
		valueDER, err := asn1.Marshal(v.value)
		if err != nil {
			return nil, err
		}
		attr, err := asn1.Marshal(tsaAttribute{
			Type:   v.oid,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valueDER},
		})
		if err != nil {
			return nil, err
		}
		out = append(out, attr...)
	}
	return out, nil
}
