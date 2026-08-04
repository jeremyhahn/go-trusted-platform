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

package modulesign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
)

// OIDs used by the detached CMS SignedData envelope.
var (
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// asn1NULL is the DER encoding of ASN.1 NULL (05 00).
var asn1NULL = asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal}

// contentInfo is the CMS ContentInfo SEQUENCE. It doubles as the
// EncapsulatedContentInfo: for a detached signature the encapsulated content
// (eContent) is absent, so leaving Content as the zero RawValue omits it.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the CMS SignedData SEQUENCE. Certificates and CRLs are omitted
// (the kernel uses CMS_NOCERTS and matches the signer by issuer + serial against
// its keyring).
type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo contentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

// signerInfo is the CMS SignerInfo SEQUENCE. SignedAttrs carries the [0] IMPLICIT
// SET OF Attribute directly as a RawValue so the exact attribute bytes that are
// signed (re-tagged as a universal SET) are reused here verbatim.
type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

// issuerAndSerial is the CMS IssuerAndSerialNumber SignerIdentifier.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// algorithmIdentifier is an X.509 AlgorithmIdentifier.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// attribute is a CMS Attribute: an OID type plus a SET OF values.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// buildDetachedCMS builds the DER-encoded detached CMS SignedData over content.
// The private key is never seen here: the digest of the signed attributes is
// handed to the injected signer, exactly as authenticode hands its attribute
// digest to the keystore signer.
func buildDetachedCMS(content []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	attrContent, err := signedAttributes(content)
	if err != nil {
		return nil, err
	}

	// CMS rule: the signature is computed over the signed attributes encoded as a
	// universal SET OF (tag 0x31), not over the stored [0] IMPLICIT form.
	setForSigning, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attrContent,
	})
	if err != nil {
		return nil, ErrASN1Marshal{Stage: "signed attributes set", Err: err}
	}

	digest := sha256.Sum256(setForSigning)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, ErrSign{Err: err}
	}

	sigAlg, err := signatureAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}

	si := signerInfo{
		Version: 1,
		SID: issuerAndSerial{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1NULL},
		SignedAttrs: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      attrContent,
		},
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1NULL}},
		EncapContentInfo: contentInfo{ContentType: oidData},
		SignerInfos:      []signerInfo{si},
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, ErrASN1Marshal{Stage: "signed data", Err: err}
	}

	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		return nil, ErrASN1Marshal{Stage: "content info", Err: err}
	}
	return der, nil
}

// signedAttributes builds the DER SET OF content (without the outer SET tag) for
// the two authenticated attributes: contentType (id-data) and messageDigest
// (SHA-256 of content). Elements are sorted by their DER encoding so the result
// is a valid DER SET OF. No signingTime is included, keeping the output
// deterministic for golden tests.
func signedAttributes(content []byte) ([]byte, error) {
	digest := sha256.Sum256(content)

	contentType, err := newAttribute(oidAttributeContentType, oidData)
	if err != nil {
		return nil, err
	}
	messageDigest, err := newAttribute(oidAttributeMessageDigest, digest[:])
	if err != nil {
		return nil, err
	}

	encoded := make([][]byte, 0, 2)
	for _, a := range []attribute{contentType, messageDigest} {
		der, err := asn1.Marshal(a)
		if err != nil {
			return nil, ErrASN1Marshal{Stage: "attribute", Err: err}
		}
		encoded = append(encoded, der)
	}
	sort.Slice(encoded, func(i, j int) bool {
		return bytes.Compare(encoded[i], encoded[j]) < 0
	})

	var out []byte
	for _, der := range encoded {
		out = append(out, der...)
	}
	return out, nil
}

// newAttribute builds a CMS attribute whose single value is the DER encoding of
// value wrapped in a SET.
func newAttribute(oid asn1.ObjectIdentifier, value any) (attribute, error) {
	valueDER, err := asn1.Marshal(value)
	if err != nil {
		return attribute{}, ErrASN1Marshal{Stage: "attribute value", Err: err}
	}
	valueSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      valueDER,
	})
	if err != nil {
		return attribute{}, ErrASN1Marshal{Stage: "attribute value set", Err: err}
	}
	return attribute{Type: oid, Values: asn1.RawValue{FullBytes: valueSet}}, nil
}

// signatureAlgorithm maps the public key type to the CMS signatureAlgorithm
// identifier. RSA uses rsaEncryption with NULL parameters (matching sign-file /
// sbsign, not sha256WithRSAEncryption); ECDSA uses ecdsa-with-SHA256 with absent
// parameters.
func signatureAlgorithm(pub crypto.PublicKey) (algorithmIdentifier, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1NULL}, nil
	case *ecdsa.PublicKey:
		return algorithmIdentifier{Algorithm: oidECDSAWithSHA256}, nil
	default:
		return algorithmIdentifier{}, ErrUnsupportedKeyType{KeyType: fmt.Sprintf("%T", pub)}
	}
}
