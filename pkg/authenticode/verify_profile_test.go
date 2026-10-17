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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/stretchr/testify/require"
)

var oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

// signedTestPE signs a minimal PE and returns the signer, which also
// verifies, with the signed image.
func signedTestPE(t *testing.T) (*Signer, []byte) {
	t.Helper()
	signer, ok := newTestSigner(t, "").(*Signer)
	require.True(t, ok)
	var out bytes.Buffer
	unsigned := authenticodetest.MinimalPE(authenticodetest.MachineAMD64)
	require.NoError(t, signer.Sign(bytes.NewReader(unsigned), &out))
	return signer, out.Bytes()
}

// reembed parses the image's SignedData, lets mutate edit it, and embeds
// the re-encoded SignedData in place of the original. The signature value
// is left as it was, so only what the signature does not cover can change
// without the cryptographic check failing.
func reembed(t *testing.T, s *Signer, image []byte, mutate func(*signedData)) []byte {
	t.Helper()
	pe, err := parsePE(image)
	require.NoError(t, err)
	signature, err := s.extractSignature(pe)
	require.NoError(t, err)

	var ci contentInfo
	_, err = asn1.Unmarshal(signature, &ci)
	require.NoError(t, err)
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	require.NoError(t, err)

	mutate(&sd)

	sdBytes, err := asn1.Marshal(sd)
	require.NoError(t, err)
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes}
	encoded, err := asn1.Marshal(ci)
	require.NoError(t, err)
	out, err := s.embedSignature(pe, encoded)
	require.NoError(t, err)
	return out
}

// setContentTypeAttribute replaces the value of the signed content-type
// attribute with oid.
func setContentTypeAttribute(t *testing.T, si *signerInfo, oid asn1.ObjectIdentifier) {
	t.Helper()
	value, err := asn1.Marshal(oid)
	require.NoError(t, err)
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: value})
	require.NoError(t, err)
	for i := range si.AuthenticatedAttributes {
		if si.AuthenticatedAttributes[i].Type.Equal(oidAttributeContentType) {
			si.AuthenticatedAttributes[i].Values = asn1.RawValue{FullBytes: set}
			return
		}
	}
	t.Fatal("signed image carries no content-type attribute")
}

// setImageDigestAlgorithm rewrites the digest algorithm inside the
// SpcIndirectDataContent.
func setImageDigestAlgorithm(t *testing.T, sd *signedData, oid asn1.ObjectIdentifier) {
	t.Helper()
	var spc spcIndirectDataContent
	_, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &spc)
	require.NoError(t, err)
	spc.MessageDigest.DigestAlgorithm.Algorithm = oid
	encoded, err := asn1.Marshal(spc)
	require.NoError(t, err)
	sd.ContentInfo.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encoded}
}

func TestVerifyAcceptsReencodedSignedData(t *testing.T) {
	s, image := signedTestPE(t)
	require.NoError(t, s.Verify(bytes.NewReader(image)))
	require.NoError(t, s.Verify(bytes.NewReader(reembed(t, s, image, func(*signedData) {}))),
		"re-encoding an untouched SignedData keeps the image valid")
}

func TestVerifyFindsSignerCertificateBySignerIdentifier(t *testing.T) {
	s, image := signedTestPE(t)
	// A certificate with the signer's subject but another serial and key:
	// taken as the signer, it would fail the signature.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: s.cert.Subject}
	otherDER, err := x509.CreateCertificate(rand.Reader, template, template, &otherKey.PublicKey, otherKey)
	require.NoError(t, err)
	other, err := x509.ParseCertificate(otherDER)
	require.NoError(t, err)

	withOtherFirst := reembed(t, s, image, func(sd *signedData) {
		sd.Certificates = asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: append(append([]byte{}, other.Raw...), sd.Certificates.Bytes...),
		}
	})
	require.NoError(t, s.Verify(bytes.NewReader(withOtherFirst)),
		"the signer is the certificate the SignerInfo names, wherever it sits")

	// ExtractCertificate reports the same signer, so a caller comparing it
	// with an expected certificate cannot be shown a decoy put first.
	extracted, err := s.ExtractCertificate(bytes.NewReader(withOtherFirst))
	require.NoError(t, err)
	require.True(t, extracted.Equal(s.cert), "extracted %s serial %v", extracted.Subject, extracted.SerialNumber)
}

func TestExtractCertificateRefusesUnnamedSigner(t *testing.T) {
	s, image := signedTestPE(t)
	tampered := reembed(t, s, image, func(sd *signedData) {
		sid := &sd.SignerInfos[0].IssuerAndSerialNumber
		sid.SerialNumber = new(big.Int).Add(sid.SerialNumber, big.NewInt(1))
	})
	_, err := s.ExtractCertificate(bytes.NewReader(tampered))
	require.ErrorIs(t, err, ErrSignerIdentifier)
}

func TestVerifyRefusesTamperedSignedData(t *testing.T) {
	otherIssuer, err := asn1.Marshal(pkix.Name{CommonName: "someone else"}.ToRDNSequence())
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(t *testing.T, sd *signedData)
		want   error
	}{
		{
			name: "signer serial names no embedded certificate",
			mutate: func(t *testing.T, sd *signedData) {
				sid := &sd.SignerInfos[0].IssuerAndSerialNumber
				sid.SerialNumber = new(big.Int).Add(sid.SerialNumber, big.NewInt(1))
			},
			want: ErrSignerIdentifier,
		},
		{
			name: "signer issuer names no embedded certificate",
			mutate: func(t *testing.T, sd *signedData) {
				sd.SignerInfos[0].IssuerAndSerialNumber.IssuerName = asn1.RawValue{FullBytes: otherIssuer}
			},
			want: ErrSignerIdentifier,
		},
		{
			name: "eContentType is id-data",
			mutate: func(t *testing.T, sd *signedData) {
				sd.ContentInfo.ContentType = oidData
			},
			want: ErrContentType,
		},
		{
			name: "content-type attribute is id-data",
			mutate: func(t *testing.T, sd *signedData) {
				setContentTypeAttribute(t, &sd.SignerInfos[0], oidData)
			},
			want: ErrContentType,
		},
		{
			name: "content-type attribute missing",
			mutate: func(t *testing.T, sd *signedData) {
				si := &sd.SignerInfos[0]
				var kept []attribute
				for _, attr := range si.AuthenticatedAttributes {
					if !attr.Type.Equal(oidAttributeContentType) {
						kept = append(kept, attr)
					}
				}
				si.AuthenticatedAttributes = kept
			},
			want: ErrContentType,
		},
		{
			name: "signer digest algorithm is SHA-1",
			mutate: func(t *testing.T, sd *signedData) {
				sd.SignerInfos[0].DigestAlgorithm.Algorithm = oidSHA1
			},
			want: ErrDigestAlgorithm,
		},
		{
			name: "digestAlgorithms do not list the signer's",
			mutate: func(t *testing.T, sd *signedData) {
				sd.DigestAlgorithmIdentifiers[0].Algorithm = oidSHA384
			},
			want: ErrDigestAlgorithm,
		},
		{
			name: "image digest algorithm is SHA-384",
			mutate: func(t *testing.T, sd *signedData) {
				setImageDigestAlgorithm(t, sd, oidSHA384)
			},
			want: ErrDigestAlgorithm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, image := signedTestPE(t)
			tampered := reembed(t, s, image, func(sd *signedData) { tt.mutate(t, sd) })
			err := s.Verify(bytes.NewReader(tampered))
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestVerifyCertificateTableHeader(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(winCert []byte, pkcs7Len int)
		want   error
	}{
		{
			name: "dwLength covering the padding still verifies",
			mutate: func(winCert []byte, _ int) {
				binary.LittleEndian.PutUint32(winCert[0:4], uint32(len(winCert)))
			},
		},
		{
			name: "revision 1.0",
			mutate: func(winCert []byte, _ int) {
				binary.LittleEndian.PutUint16(winCert[4:6], 0x0100)
			},
			want: ErrCertificateHeader,
		},
		{
			name: "X.509 certificate type",
			mutate: func(winCert []byte, _ int) {
				binary.LittleEndian.PutUint16(winCert[6:8], 0x0001)
			},
			want: ErrCertificateHeader,
		},
		{
			name: "dwLength past the table entry",
			mutate: func(winCert []byte, _ int) {
				binary.LittleEndian.PutUint32(winCert[0:4], uint32(len(winCert)+8))
			},
			want: ErrCertificateHeader,
		},
		{
			name: "dwLength short of the PKCS#7",
			mutate: func(winCert []byte, pkcs7Len int) {
				binary.LittleEndian.PutUint32(winCert[0:4], uint32(winCertificateHeaderSize+pkcs7Len-1))
			},
			want: ErrCertificateHeader,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, image := signedTestPE(t)
			pe, err := parsePE(image)
			require.NoError(t, err)
			signature, err := s.extractSignature(pe)
			require.NoError(t, err)

			tampered := append([]byte{}, image...)
			tt.mutate(tampered[pe.certTableOffset:pe.certTableOffset+pe.certTableSize], len(signature))

			err = s.Verify(bytes.NewReader(tampered))
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
		})
	}
}
