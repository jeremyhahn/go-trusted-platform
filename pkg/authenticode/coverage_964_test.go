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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cov964Signature is the signer's encrypted digest the time-stamp tokens in
// this file are built over.
var cov964Signature = []byte("cov964-encrypted-digest")

// cov964Certificate returns an in-memory self-signed ECDSA certificate with
// the given serial number and its key.
func cov964Certificate(t *testing.T, serial int64) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "cov964"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// cov964Explicit0 wraps payload in the [0] EXPLICIT tag ContentInfo uses.
func cov964Explicit0(payload []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: payload}
}

// cov964ContentInfo encodes a ContentInfo of contentType around content.
func cov964ContentInfo(t *testing.T, contentType asn1.ObjectIdentifier, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(contentInfo{ContentType: contentType, Content: cov964Explicit0(content)})
	require.NoError(t, err)
	return der
}

// cov964TSTInfo encodes a TSTInfo stamping imprint under algorithm.
func cov964TSTInfo(t *testing.T, algorithm asn1.ObjectIdentifier, imprint []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(tstInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 964},
		MessageImprint: messageImprint{
			HashAlgorithm: pkixAlgorithmIdentifier{Algorithm: algorithm, Parameters: asn1NULL},
			HashedMessage: imprint,
		},
		SerialNumber: big.NewInt(964),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	})
	require.NoError(t, err)
	return der
}

// cov964OctetString encodes data as an OCTET STRING, the eContent form.
func cov964OctetString(t *testing.T, data []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(data)
	require.NoError(t, err)
	return der
}

// cov964TokenParts are the pieces of a time-stamp token; each test case
// starts from a valid set and breaks one of them.
type cov964TokenParts struct {
	eContentType asn1.ObjectIdentifier
	eContent     []byte
	certs        []byte
	signers      []signerInfo
}

// cov964ValidParts returns token parts that pass every check up to the TSA
// signature: a SHA-256 imprint of cov964Signature, one SHA-256 signer and
// the signer's time-stamping certificate.
func cov964ValidParts(t *testing.T, cert *x509.Certificate) cov964TokenParts {
	t.Helper()
	imprint := sha256.Sum256(cov964Signature)
	return cov964TokenParts{
		eContentType: oidTSTInfo,
		eContent:     cov964OctetString(t, cov964TSTInfo(t, oidSHA256, imprint[:])),
		certs:        cert.Raw,
		signers:      []signerInfo{cov964SignerInfo(cert, oidSHA256, cert.SerialNumber)},
	}
}

// cov964SignerInfo names the signer by cert's issuer and serial.
func cov964SignerInfo(cert *x509.Certificate, digestAlgorithm asn1.ObjectIdentifier, serial *big.Int) signerInfo {
	return signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: serial,
		},
		DigestAlgorithm:           pkixAlgorithmIdentifier{Algorithm: digestAlgorithm, Parameters: asn1NULL},
		DigestEncryptionAlgorithm: pkixAlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1NULL},
		EncryptedDigest:           []byte{0x01},
	}
}

// cov964Token encodes parts as a SignedData ContentInfo.
func cov964Token(t *testing.T, parts cov964TokenParts) []byte {
	t.Helper()
	sd := signedData{
		Version:                    3,
		DigestAlgorithmIdentifiers: []pkixAlgorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1NULL}},
		ContentInfo:                contentInfo{ContentType: parts.eContentType, Content: cov964Explicit0(parts.eContent)},
		SignerInfos:                parts.signers,
	}
	if len(parts.certs) > 0 {
		sd.Certificates = cov964Explicit0(parts.certs)
	}
	der, err := asn1.Marshal(sd)
	require.NoError(t, err)
	return cov964ContentInfo(t, oidSignedData, der)
}

// cov964RequireMessage asserts err is a typed MessageError or WrappedError
// (possibly behind others) whose message contains want.
func cov964RequireMessage(t *testing.T, err error, want string) {
	t.Helper()
	require.Error(t, err)
	var msgErr *MessageError
	var wrapErr *WrappedError
	if !errors.As(err, &msgErr) && !errors.As(err, &wrapErr) {
		t.Fatalf("error %T %q is neither MessageError nor WrappedError", err, err)
	}
	assert.Contains(t, err.Error(), want)
}

func TestCov964VerifyTimestampTokenRejectsMalformedTokens(t *testing.T) {
	_, cert := cov964Certificate(t, 7)
	_, otherCert := cov964Certificate(t, 8)
	sha256Imprint := sha256.Sum256(cov964Signature)
	wrongImprint := sha256.Sum256([]byte("another signature"))

	tests := []struct {
		name  string
		token func(t *testing.T) []byte
		want  string
	}{
		{
			name:  "not DER",
			token: func(*testing.T) []byte { return []byte{0x01} },
			want:  "failed to parse time-stamp token",
		},
		{
			name: "trailing data",
			token: func(t *testing.T) []byte {
				return append(cov964Token(t, cov964ValidParts(t, cert)), 0x00)
			},
			want: "trailing data after time-stamp token",
		},
		{
			name: "content type is not SignedData",
			token: func(t *testing.T) []byte {
				return cov964ContentInfo(t, oidTSTInfo, cov964OctetString(t, []byte{0x01}))
			},
			want: "time-stamp token is not SignedData",
		},
		{
			name: "SignedData does not parse",
			token: func(t *testing.T) []byte {
				return cov964ContentInfo(t, oidSignedData, []byte{0x02, 0x01, 0x01})
			},
			want: "failed to parse time-stamp SignedData",
		},
		{
			name: "encapsulated content is not TSTInfo",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.eContentType = oidSignedData
				return cov964Token(t, parts)
			},
			want: "time-stamp token does not carry TSTInfo",
		},
		{
			name: "eContent is not an OCTET STRING",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.eContent = []byte{0x02, 0x01, 0x01}
				return cov964Token(t, parts)
			},
			want: "failed to parse TSTInfo content",
		},
		{
			name: "TSTInfo does not parse",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.eContent = cov964OctetString(t, []byte{0x02, 0x01, 0x01})
				return cov964Token(t, parts)
			},
			want: "failed to parse TSTInfo",
		},
		{
			name: "imprint algorithm is not SHA-256",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.eContent = cov964OctetString(t, cov964TSTInfo(t, oidSHA384, sha256Imprint[:]))
				return cov964Token(t, parts)
			},
			want: "unsupported time-stamp imprint algorithm",
		},
		{
			name: "imprint is over another signature",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.eContent = cov964OctetString(t, cov964TSTInfo(t, oidSHA256, wrongImprint[:]))
				return cov964Token(t, parts)
			},
			want: "time-stamp imprint does not match the signature",
		},
		{
			name: "no signer",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.signers = nil
				return cov964Token(t, parts)
			},
			want: "time-stamp token has 0 signers, want 1",
		},
		{
			name: "two signers",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.signers = append(parts.signers, parts.signers[0])
				return cov964Token(t, parts)
			},
			want: "time-stamp token has 2 signers, want 1",
		},
		{
			name: "unsupported TSA digest algorithm",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.signers = []signerInfo{cov964SignerInfo(cert, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}, cert.SerialNumber)}
				return cov964Token(t, parts)
			},
			want: "unsupported time-stamp digest algorithm",
		},
		{
			name: "no TSA certificate",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.certs = nil
				return cov964Token(t, parts)
			},
			want: "time-stamp token carries no TSA certificate",
		},
		{
			name: "TSA certificates do not parse",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.certs = []byte{0x02, 0x01, 0x01}
				return cov964Token(t, parts)
			},
			want: "failed to parse TSA certificates",
		},
		{
			name: "signer certificate is not in the token",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.certs = otherCert.Raw
				return cov964Token(t, parts)
			},
			want: "time-stamp token does not carry its signer's certificate",
		},
		{
			name: "signer serial matches no certificate",
			token: func(t *testing.T) []byte {
				parts := cov964ValidParts(t, cert)
				parts.signers = []signerInfo{cov964SignerInfo(cert, oidSHA256, big.NewInt(964964))}
				return cov964Token(t, parts)
			},
			want: "time-stamp token does not carry its signer's certificate",
		},
		{
			name: "signer carries no signed attributes",
			token: func(t *testing.T) []byte {
				return cov964Token(t, cov964ValidParts(t, cert))
			},
			want: "no authenticated attributes to verify",
		},
	}

	s := &Signer{ctx: context.Background(), logger: logging.DefaultLogger()}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := s.verifyTimestampToken(tc.token(t), cov964Signature)
			assert.Nil(t, info)
			cov964RequireMessage(t, err, tc.want)
		})
	}
}

// cov964Set encodes elements as an ASN.1 SET, the form an attribute's values
// take.
func cov964Set(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	var body []byte
	for _, element := range elements {
		body = append(body, element...)
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body})
	require.NoError(t, err)
	return der
}

func TestCov964VerifyEmbeddedTimestamps(t *testing.T) {
	_, cert := cov964Certificate(t, 7)
	token := cov964Token(t, cov964ValidParts(t, cert))

	tests := []struct {
		name   string
		values []byte
		attrID asn1.ObjectIdentifier
		want   string
	}{
		{
			name:   "attribute SET does not parse",
			attrID: oidSPCRFC3161Timestamp,
			values: []byte{0x31, 0x05, 0x01},
			want:   "failed to parse timestamp attribute SET",
		},
		{
			name:   "token inside the SET does not parse",
			attrID: oidSPCRFC3161Timestamp,
			values: []byte{0x31, 0x02, 0x30, 0x05},
			want:   "failed to parse time-stamp token",
		},
		{
			name:   "more than one token",
			attrID: oidSPCRFC3161Timestamp,
			values: cov964Set(t, token, token),
			want:   "timestamp attribute holds more than one token",
		},
		{
			name:   "the one token is verified",
			attrID: oidSPCRFC3161Timestamp,
			values: cov964Set(t, token),
			want:   "no authenticated attributes to verify",
		},
		{
			name:   "other unauthenticated attributes are ignored",
			attrID: asn1.ObjectIdentifier{1, 2, 3, 964},
			values: []byte{0xff},
		},
	}

	s := &Signer{ctx: context.Background(), logger: logging.DefaultLogger()}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			si := &signerInfo{
				EncryptedDigest: cov964Signature,
				UnauthenticatedAttributes: []attribute{
					{Type: tc.attrID, Values: asn1.RawValue{FullBytes: tc.values}},
				},
			}
			err := s.verifyEmbeddedTimestamps(si)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			cov964RequireMessage(t, err, tc.want)
		})
	}
}

// cov964TSA serves body as the reply to every time-stamp query and returns
// a Signer pointed at it.
func cov964TSA(t *testing.T, body []byte) *Signer {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", timestampReplyContentType)
		if _, err := w.Write(body); err != nil {
			t.Errorf("write reply: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return &Signer{ctx: context.Background(), timestampURL: server.URL, logger: logging.DefaultLogger()}
}

func TestCov964RequestTimestampRejectsBadReplies(t *testing.T) {
	granted, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: pkiStatusGranted}})
	require.NoError(t, err)
	notAContentInfo, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x02, 0x01, 0x01}})
	require.NoError(t, err)
	grantedWithBadToken, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: pkiStatusGrantedWithMods},
		TimeStampToken: asn1.RawValue{FullBytes: notAContentInfo},
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		reply     []byte
		reason    string
		wantCause bool
	}{
		{name: "reply is not DER", reply: []byte("not a TimeStampResp"), reason: "malformed response", wantCause: true},
		{name: "trailing data after the reply", reply: append(append([]byte{}, granted...), 0x00), reason: "trailing data after response"},
		{name: "granted without a token", reply: granted, reason: "response carries no time-stamp token"},
		{name: "token does not verify", reply: grantedWithBadToken, reason: "time-stamp token does not verify", wantCause: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := cov964TSA(t, tc.reply)
			token, err := s.requestTimestamp(cov964Signature)
			assert.Nil(t, token)
			var tsErr *TimestampError
			require.ErrorAs(t, err, &tsErr)
			assert.Equal(t, s.timestampURL, tsErr.URL)
			assert.Equal(t, tc.reason, tsErr.Reason)
			assert.Equal(t, tc.wantCause, tsErr.Unwrap() != nil)
		})
	}
}

func TestCov964TimestampErrorMessage(t *testing.T) {
	cause := &MessageError{Msg: "connection refused"}
	withCause := &TimestampError{URL: "http://tsa.example", Reason: "request failed", Err: cause}
	assert.Equal(t, "authenticode: timestamp from http://tsa.example: request failed: connection refused", withCause.Error())
	assert.ErrorIs(t, withCause, cause)

	withoutCause := &TimestampError{URL: "http://tsa.example", Reason: "HTTP status 500"}
	assert.Equal(t, "authenticode: timestamp from http://tsa.example: HTTP status 500", withoutCause.Error())
	assert.NoError(t, withoutCause.Unwrap())
}

func TestCov964FileErrorsWrapTheirCause(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")

	_, keyErr := LoadPrivateKeyPEM(missing)
	var kfe *KeyFileError
	require.ErrorAs(t, keyErr, &kfe)
	assert.Equal(t, KeyFileRead, kfe.Stage)
	assert.Contains(t, kfe.Error(), "authenticode: read private key "+missing)
	assert.ErrorIs(t, keyErr, fs.ErrNotExist)

	_, certErr := LoadCertificate(missing)
	var cfe *CertFileError
	require.ErrorAs(t, certErr, &cfe)
	assert.Equal(t, KeyFileRead, cfe.Stage)
	assert.Contains(t, cfe.Error(), "authenticode: read certificate "+missing)
	assert.ErrorIs(t, certErr, fs.ErrNotExist)
}

func TestCov964KeyCertMismatchAndSignerNotFound(t *testing.T) {
	key, _ := cov964Certificate(t, 1)
	_, otherCert := cov964Certificate(t, 2)

	signer, err := NewCryptoSigner(context.Background(), key, otherCert, nil)
	assert.Nil(t, signer)
	var mismatch *KeyCertMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, "authenticode: the certificate's public key does not match the signing key", mismatch.Error())

	cert, err := signerCertificate([]*x509.Certificate{otherCert}, issuerAndSerial{
		IssuerName:   asn1.RawValue{FullBytes: otherCert.RawIssuer},
		SerialNumber: big.NewInt(964),
	})
	assert.Nil(t, cert)
	var notFound *ErrSignerCertificateNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "no certificate matches the signer's issuer and serial number 964", notFound.Error())
}

func TestCov964SignerBackendServesOnlyItsKey(t *testing.T) {
	key, _ := cov964Certificate(t, 1)
	backend := &signerBackend{signer: key}
	ctx := context.Background()

	assert.Equal(t, "crypto-signer", string(backend.Type()))
	caps := backend.Capabilities()
	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)

	got, err := backend.GetKey(ctx, nil)
	require.NoError(t, err)
	assert.Same(t, key, got)

	keys, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, keys)
	assert.NoError(t, backend.Close())

	generated, err := backend.GenerateKey(ctx, nil)
	assert.Nil(t, generated)
	decrypter, decErr := backend.Decrypter(ctx, nil)
	assert.Nil(t, decrypter)

	refusals := []struct {
		name string
		err  error
		want string
	}{
		{name: "GenerateKey", err: err, want: "crypto-signer backend: keys are not generated here"},
		{name: "DeleteKey", err: backend.DeleteKey(ctx, nil), want: "crypto-signer backend: keys are not deleted here"},
		{name: "Decrypter", err: decErr, want: "crypto-signer backend: decryption is not offered"},
		{name: "RotateKey", err: backend.RotateKey(ctx, nil), want: "crypto-signer backend: keys are not rotated here"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			var msgErr *MessageError
			require.ErrorAs(t, tc.err, &msgErr)
			assert.Equal(t, tc.want, msgErr.Msg)
		})
	}
}

func TestCov964WriteSignedClosesOutputWhenSigningFails(t *testing.T) {
	out, err := os.CreateTemp(t.TempDir(), "cov964-*")
	require.NoError(t, err)

	verifier := NewVerifier(context.Background(), nil).(*Signer)
	err = verifier.writeSigned(nil, out)
	assert.ErrorIs(t, err, ErrNoSigningKey)
	assert.ErrorIs(t, out.Close(), os.ErrClosed)
}

func TestCov964SPCContentMustBeASequence(t *testing.T) {
	_, cert := cov964Certificate(t, 1)
	s := &Signer{ctx: context.Background(), cert: cert, logger: logging.DefaultLogger()}
	notASequence := []byte{0x02, 0x01, 0x01}

	digest, err := s.computeAttributesDigest(notASequence, time.Now())
	assert.Nil(t, digest)
	cov964RequireMessage(t, err, "failed to extract SPC inner content")

	sig, err := s.createPKCS7SignatureWithTime(notASequence, []byte{0x01}, time.Now(), nil)
	assert.Nil(t, sig)
	cov964RequireMessage(t, err, "failed to extract SPC inner content")
}
