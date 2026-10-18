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

package authenticode

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for TSA signer digests
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"time"
)

var (
	// oidSPCRFC3161Timestamp is the unauthenticated attribute that carries an
	// RFC 3161 time-stamp token in an Authenticode signature (signtool /tr,
	// osslsigncode -ts).
	oidSPCRFC3161Timestamp = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}

	// oidTSTInfo is id-ct-TSTInfo, the content type of a time-stamp token.
	oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// tsaDigestHashes maps the digest algorithms a TSA may sign a token with
	// to their hash functions.
	tsaDigestHashes = map[string]crypto.Hash{
		oidSHA256.String(): crypto.SHA256,
		oidSHA384.String(): crypto.SHA384,
		oidSHA512.String(): crypto.SHA512,
	}
)

const (
	timestampQueryContentType = "application/timestamp-query"
	timestampReplyContentType = "application/timestamp-reply"

	// maxTimestampResponse bounds the TSA reply read into memory.
	maxTimestampResponse = 1 << 20

	// timestampHTTPTimeout bounds one round trip to the TSA.
	timestampHTTPTimeout = 30 * time.Second

	// RFC 3161 PKIStatus values that carry a time-stamp token.
	pkiStatusGranted         = 0
	pkiStatusGrantedWithMods = 1
)

// messageImprint is the RFC 3161 MessageImprint: the hash being stamped.
type messageImprint struct {
	HashAlgorithm pkixAlgorithmIdentifier
	HashedMessage []byte
}

// timeStampReq is the RFC 3161 TimeStampReq.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// pkiStatusInfo is the RFC 3161 PKIStatusInfo.
type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp is the RFC 3161 TimeStampResp.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// tstAccuracy is the RFC 3161 Accuracy.
type tstAccuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tstInfo is the RFC 3161 TSTInfo the TSA signs.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       tstAccuracy   `asn1:"optional"`
	Ordering       bool          `asn1:"optional"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// timestampAttribute countersigns signature, the signer's encrypted digest,
// at the configured TSA and returns the unauthenticated attribute that
// carries the token.
func (s *Signer) timestampAttribute(signature []byte) (attribute, error) {
	token, err := s.requestTimestamp(signature)
	if err != nil {
		return attribute{}, err
	}
	tokenSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      token,
	})
	if err != nil {
		return attribute{}, &TimestampError{URL: s.timestampURL, Reason: "failed to marshal timestamp attribute", Err: err}
	}
	return attribute{
		Type:   oidSPCRFC3161Timestamp,
		Values: asn1.RawValue{FullBytes: tokenSet},
	}, nil
}

// requestTimestamp sends an RFC 3161 request for the SHA-256 of signature to
// the TSA and returns the time-stamp token, verified against signature and
// the request nonce.
func (s *Signer) requestTimestamp(signature []byte) ([]byte, error) {
	imprint := sha256.Sum256(signature)
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "failed to generate nonce", Err: err}
	}
	query, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkixAlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1NULL},
			HashedMessage: imprint[:],
		},
		Nonce:   nonce,
		CertReq: true,
	})
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "failed to marshal request", Err: err}
	}

	reply, err := s.postTimestampQuery(query)
	if err != nil {
		return nil, err
	}

	var resp timeStampResp
	rest, err := asn1.Unmarshal(reply, &resp)
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "malformed response", Err: err}
	}
	if len(rest) > 0 {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "trailing data after response"}
	}
	if resp.Status.Status != pkiStatusGranted && resp.Status.Status != pkiStatusGrantedWithMods {
		return nil, &TimestampError{
			URL:    s.timestampURL,
			Reason: fmt.Sprintf("request refused with status %d %q", resp.Status.Status, resp.Status.StatusString),
		}
	}
	token := resp.TimeStampToken.FullBytes
	if len(token) == 0 {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "response carries no time-stamp token"}
	}

	info, err := s.verifyTimestampToken(token, signature)
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "time-stamp token does not verify", Err: err}
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "time-stamp token nonce does not match the request"}
	}
	return token, nil
}

// postTimestampQuery posts an encoded TimeStampReq to the TSA and returns the
// raw reply body.
func (s *Signer) postTimestampQuery(query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.timestampURL, bytes.NewReader(query))
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "failed to build request", Err: err}
	}
	req.Header.Set("Content-Type", timestampQueryContentType)
	req.Header.Set("Accept", timestampReplyContentType)

	client := &http.Client{Timeout: timestampHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "request failed", Err: err}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTimestampResponse+1))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "failed to read response", Err: readErr}
	}
	if closeErr != nil {
		return nil, &TimestampError{URL: s.timestampURL, Reason: "failed to close response", Err: closeErr}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &TimestampError{URL: s.timestampURL, Reason: fmt.Sprintf("HTTP status %d", resp.StatusCode)}
	}
	if len(body) > maxTimestampResponse {
		return nil, &TimestampError{URL: s.timestampURL, Reason: fmt.Sprintf("response exceeds %d bytes", maxTimestampResponse)}
	}
	return body, nil
}

// verifyEmbeddedTimestamps verifies every RFC 3161 token in si's
// unauthenticated attributes against si's encrypted digest. A signature
// without a timestamp has nothing to verify here.
func (s *Signer) verifyEmbeddedTimestamps(si *signerInfo) error {
	for _, attr := range si.UnauthenticatedAttributes {
		if !attr.Type.Equal(oidSPCRFC3161Timestamp) {
			continue
		}
		var set asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.FullBytes, &set); err != nil {
			return &WrappedError{Msg: "failed to parse timestamp attribute SET", Err: err}
		}
		var token asn1.RawValue
		rest, err := asn1.Unmarshal(set.Bytes, &token)
		if err != nil {
			return &WrappedError{Msg: "failed to parse time-stamp token", Err: err}
		}
		if len(rest) > 0 {
			return &MessageError{Msg: "timestamp attribute holds more than one token"}
		}
		if _, err := s.verifyTimestampToken(token.FullBytes, si.EncryptedDigest); err != nil {
			return err
		}
	}
	return nil
}

// verifyTimestampToken checks that token is a time-stamp token over the
// SHA-256 of signature, signed by the time-stamping certificate it carries,
// and returns its TSTInfo.
func (s *Signer) verifyTimestampToken(token, signature []byte) (*tstInfo, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(token, &ci)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse time-stamp token", Err: err}
	}
	if len(rest) > 0 {
		return nil, &MessageError{Msg: "trailing data after time-stamp token"}
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, &MessageError{Msg: fmt.Sprintf("time-stamp token is not SignedData: %v", ci.ContentType)}
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, &WrappedError{Msg: "failed to parse time-stamp SignedData", Err: err}
	}
	if !sd.ContentInfo.ContentType.Equal(oidTSTInfo) {
		return nil, &MessageError{Msg: fmt.Sprintf("time-stamp token does not carry TSTInfo: %v", sd.ContentInfo.ContentType)}
	}
	var tstDER []byte
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &tstDER); err != nil {
		return nil, &WrappedError{Msg: "failed to parse TSTInfo content", Err: err}
	}
	var info tstInfo
	if _, err := asn1.Unmarshal(tstDER, &info); err != nil {
		return nil, &WrappedError{Msg: "failed to parse TSTInfo", Err: err}
	}

	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported time-stamp imprint algorithm: %v", info.MessageImprint.HashAlgorithm.Algorithm)}
	}
	expectedImprint := sha256.Sum256(signature)
	if !bytes.Equal(info.MessageImprint.HashedMessage, expectedImprint[:]) {
		return nil, &MessageError{Msg: "time-stamp imprint does not match the signature"}
	}

	if len(sd.SignerInfos) != 1 {
		return nil, &MessageError{Msg: fmt.Sprintf("time-stamp token has %d signers, want 1", len(sd.SignerInfos))}
	}
	tsaSigner := &sd.SignerInfos[0]
	hash, ok := tsaDigestHashes[tsaSigner.DigestAlgorithm.Algorithm.String()]
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported time-stamp digest algorithm: %v", tsaSigner.DigestAlgorithm.Algorithm)}
	}
	tsaCert, err := timestampSignerCertificate(sd.Certificates.Bytes, tsaSigner.IssuerAndSerialNumber)
	if err != nil {
		return nil, err
	}
	if err := s.verifySignedAttributes(tsaCert, tsaSigner, hash); err != nil {
		return nil, &WrappedError{Msg: "time-stamp signature verification failed", Err: err}
	}
	messageDigest, err := s.extractMessageDigestAttribute(tsaSigner.AuthenticatedAttributes)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract time-stamp messageDigest", Err: err}
	}
	if !bytes.Equal(messageDigest, digest(hash, tstDER)) {
		return nil, &MessageError{Msg: "time-stamp messageDigest does not match TSTInfo"}
	}
	return &info, nil
}

// timestampSignerCertificate returns the certificate in certsDER that issued
// the TSA's signature, and requires it to be a time-stamping certificate.
func timestampSignerCertificate(certsDER []byte, id issuerAndSerial) (*x509.Certificate, error) {
	if len(certsDER) == 0 {
		return nil, &MessageError{Msg: "time-stamp token carries no TSA certificate"}
	}
	certs, err := x509.ParseCertificates(certsDER)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse TSA certificates", Err: err}
	}
	for _, cert := range certs {
		if cert.SerialNumber.Cmp(id.SerialNumber) != 0 || !bytes.Equal(cert.RawIssuer, id.IssuerName.FullBytes) {
			continue
		}
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
			return nil, &MessageError{Msg: "TSA certificate is not valid for time stamping"}
		}
		return cert, nil
	}
	return nil, &MessageError{Msg: "time-stamp token does not carry its signer's certificate"}
}

// digest returns the hash of data under hash.
func digest(hash crypto.Hash, data []byte) []byte {
	h := hash.New()
	h.Write(data)
	return h.Sum(nil)
}
