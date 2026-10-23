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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// OIDs for Authenticode and PKCS#7
var (
	// PKCS#7 OIDs
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// Authenticode OIDs
	oidSPCIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSPCPEImageData         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}

	// Algorithm OIDs
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// peFile represents a parsed PE/COFF file
type peFile struct {
	data              []byte
	dosHeader         *dosHeader
	ntHeaders         *ntHeaders
	sections          []*pe.Section
	certTableOffset   uint32
	certTableSize     uint32
	checksumOffset    uint32
	securityDirOffset uint32
}

// dosHeader represents the DOS header (first 64 bytes)
type dosHeader struct {
	Magic    uint16 // "MZ"
	PEOffset uint32 // Offset to PE header
}

// ntHeaders represents the NT headers (PE signature + file header + optional header)
type ntHeaders struct {
	Signature            uint32 // "PE\0\0"
	Machine              uint16
	NumberOfSections     uint16
	SizeOfOptionalHeader uint16
	Magic                uint16 // 0x10b (PE32) or 0x20b (PE32+)
}

// ASN.1 structures for PKCS#7 SignedData

// contentInfo represents PKCS#7 ContentInfo
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData represents PKCS#7 SignedData
type signedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []pkixAlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs                       []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo    `asn1:"set"`
}

// signerInfo represents PKCS#7 SignerInfo
type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkixAlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkixAlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// issuerAndSerial contains the issuer name and serial number
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// attribute represents a PKCS#7 attribute
// The value is a SET OF ANY - FullBytes should contain the complete SET-encoded value
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // FullBytes contains the SET with its contents
}

// spcIndirectDataContent is the Authenticode-specific content
type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndValue
	MessageDigest digestInfo
}

// spcAttributeTypeAndValue represents the SPC data type
type spcAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value spcPEImageData `asn1:"optional"`
}

// spcPEImageData represents the PE image data (can be empty for signing)
// The File field is an SpcLink which is a CHOICE type - we use RawValue to construct it manually
// Note: File uses explicit tag 0, containing the SpcLink choice structure
type spcPEImageData struct {
	Flags asn1.BitString `asn1:"optional"`
	File  asn1.RawValue  `asn1:"optional"`
}

// digestInfo contains the hash algorithm and digest value
type digestInfo struct {
	DigestAlgorithm pkixAlgorithmIdentifier
	Digest          []byte
}

// pkixAlgorithmIdentifier is a simplified algorithm identifier
// Note: Some algorithms require NULL parameters for proper ASN.1 encoding
type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// parsePE parses a PE/COFF file
func parsePE(data []byte) (_ *peFile, err error) {
	if len(data) < 64 {
		return nil, &MessageError{Msg: "file too small to be a valid PE"}
	}

	// Parse DOS header
	dosHdr := &dosHeader{
		Magic:    binary.LittleEndian.Uint16(data[0:2]),
		PEOffset: binary.LittleEndian.Uint32(data[60:64]),
	}

	if dosHdr.Magic != 0x5A4D { // "MZ"
		return nil, &MessageError{Msg: fmt.Sprintf("invalid DOS magic: 0x%04X", dosHdr.Magic)}
	}

	if int(dosHdr.PEOffset) >= len(data) {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid PE offset: %d", dosHdr.PEOffset)}
	}

	// Parse NT headers
	ntHdr := &ntHeaders{
		Signature: binary.LittleEndian.Uint32(data[dosHdr.PEOffset : dosHdr.PEOffset+4]),
	}

	if ntHdr.Signature != 0x00004550 { // "PE\0\0"
		return nil, &MessageError{Msg: fmt.Sprintf("invalid PE signature: 0x%08X", ntHdr.Signature)}
	}

	coffHdrOffset := dosHdr.PEOffset + 4
	ntHdr.Machine = binary.LittleEndian.Uint16(data[coffHdrOffset : coffHdrOffset+2])
	ntHdr.NumberOfSections = binary.LittleEndian.Uint16(data[coffHdrOffset+2 : coffHdrOffset+4])
	ntHdr.SizeOfOptionalHeader = binary.LittleEndian.Uint16(data[coffHdrOffset+16 : coffHdrOffset+18])

	optHdrOffset := coffHdrOffset + 20
	ntHdr.Magic = binary.LittleEndian.Uint16(data[optHdrOffset : optHdrOffset+2])

	var certTableOffset, certTableSize uint32
	var checksumOffset, securityDirOffset uint32

	switch ntHdr.Magic {
	case 0x10b: // PE32
		checksumOffset = optHdrOffset + 64
		securityDirOffset = optHdrOffset + 128
		certTableOffset = binary.LittleEndian.Uint32(data[securityDirOffset : securityDirOffset+4])
		certTableSize = binary.LittleEndian.Uint32(data[securityDirOffset+4 : securityDirOffset+8])
	case 0x20b: // PE32+
		checksumOffset = optHdrOffset + 64
		securityDirOffset = optHdrOffset + 144
		certTableOffset = binary.LittleEndian.Uint32(data[securityDirOffset : securityDirOffset+4])
		certTableSize = binary.LittleEndian.Uint32(data[securityDirOffset+4 : securityDirOffset+8])
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported PE magic: 0x%04X", ntHdr.Magic)}
	}

	// Parse using debug/pe for sections
	peReader := bytes.NewReader(data)
	pef, err := pe.NewFile(peReader)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse PE with debug/pe", Err: err}
	}
	defer func() {
		if cerr := pef.Close(); cerr != nil && err == nil {
			err = &WrappedError{Msg: "failed to close PE file", Err: cerr}
		}
	}()

	return &peFile{
		data:              data,
		dosHeader:         dosHdr,
		ntHeaders:         ntHdr,
		sections:          pef.Sections,
		certTableOffset:   certTableOffset,
		certTableSize:     certTableSize,
		checksumOffset:    checksumOffset,
		securityDirOffset: securityDirOffset,
	}, nil
}

// computeAuthenticodeDigest computes the Authenticode digest of a PE file
// This is the hash that gets signed, excluding the checksum and signature sections
func (s *Signer) computeAuthenticodeDigest(pe *peFile) ([]byte, error) {
	hasher := sha256.New()

	// Hash from beginning up to checksum (excluding checksum)
	if _, err := hasher.Write(pe.data[0:pe.checksumOffset]); err != nil {
		return nil, err
	}

	// Skip checksum (4 bytes), continue after it
	checksumEnd := pe.checksumOffset + 4

	// Hash from after checksum to security directory (excluding security directory)
	if _, err := hasher.Write(pe.data[checksumEnd:pe.securityDirOffset]); err != nil {
		return nil, err
	}

	// Skip security directory (8 bytes), continue after it
	securityDirEnd := pe.securityDirOffset + 8

	// If there's no existing signature, hash to end of file
	if pe.certTableOffset == 0 {
		if _, err := hasher.Write(pe.data[securityDirEnd:]); err != nil {
			return nil, err
		}
		// The certificate table must be aligned to 8-byte boundary according to PE spec.
		// sbsign includes padding bytes in the PE digest, so we must do the same.
		fileLen := uint32(len(pe.data))
		alignedLen := (fileLen + 7) & ^uint32(7)
		if alignedLen > fileLen {
			padding := make([]byte, alignedLen-fileLen)
			if _, err := hasher.Write(padding); err != nil {
				return nil, err
			}
		}
	} else {
		// Hash from after security directory to start of signature table
		if _, err := hasher.Write(pe.data[securityDirEnd:pe.certTableOffset]); err != nil {
			return nil, err
		}
	}

	return hasher.Sum(nil), nil
}

// extractSequenceContent extracts the inner content from a DER-encoded SEQUENCE,
// stripping the SEQUENCE tag and length bytes. This is needed for messageDigest
// computation per PKCS#7/CMS - the hash is of the content value, not the full TLV.
func extractSequenceContent(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, &MessageError{Msg: "data too short"}
	}

	// Verify it's a SEQUENCE (tag 0x30)
	if data[0] != 0x30 {
		return nil, &MessageError{Msg: fmt.Sprintf("expected SEQUENCE tag (0x30), got 0x%02x", data[0])}
	}

	// Parse length field
	var contentStart int
	var contentLen int

	switch {
	case data[1] < 0x80:
		// Short form: length is in the second byte
		contentLen = int(data[1])
		contentStart = 2
	case data[1] == 0x81:
		// Long form with 1 length byte
		if len(data) < 3 {
			return nil, &MessageError{Msg: "data too short for long-form length"}
		}
		contentLen = int(data[2])
		contentStart = 3
	case data[1] == 0x82:
		// Long form with 2 length bytes
		if len(data) < 4 {
			return nil, &MessageError{Msg: "data too short for long-form length"}
		}
		contentLen = int(data[2])<<8 | int(data[3])
		contentStart = 4
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported length encoding: 0x%02x", data[1])}
	}

	if contentStart+contentLen > len(data) {
		return nil, &MessageError{Msg: fmt.Sprintf("content length exceeds data: start=%d, len=%d, total=%d", contentStart, contentLen, len(data))}
	}

	return data[contentStart : contentStart+contentLen], nil
}

// computeAttributesDigest computes the digest of authenticated attributes for signing
func (s *Signer) computeAttributesDigest(spcContent []byte, signingTime time.Time) ([]byte, error) {
	// Content type attribute - marshal the OID and wrap in SET
	contentTypeValue, err := asn1.Marshal(oidSPCIndirectDataContent)
	if err != nil {
		return nil, err
	}
	contentTypeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contentTypeValue,
	})
	if err != nil {
		return nil, err
	}

	// Message digest attribute (hash of the SPC content inner data)
	// Per PKCS#7/CMS, the messageDigest is the hash of the eContent value (the DER content)
	// WITHOUT the outer SEQUENCE tag/length. We need to extract just the inner bytes.
	innerContent, err := extractSequenceContent(spcContent)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract SPC inner content", Err: err}
	}
	spcDigest := sha256.Sum256(innerContent)
	messageDigestValue, err := asn1.Marshal(spcDigest[:])
	if err != nil {
		return nil, err
	}
	messageDigestSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      messageDigestValue,
	})
	if err != nil {
		return nil, err
	}

	// Signing time attribute - wrap in SET
	signingTimeValue, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	signingTimeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      signingTimeValue,
	})
	if err != nil {
		return nil, err
	}

	// Build SET OF attributes (must be DER-encoded as SET for signing)
	// Each attribute value is already wrapped in a SET
	attrs := []attribute{
		{Type: oidAttributeContentType, Values: asn1.RawValue{FullBytes: contentTypeSet}},
		{Type: oidAttributeSigningTime, Values: asn1.RawValue{FullBytes: signingTimeSet}},
		{Type: oidAttributeMessageDigest, Values: asn1.RawValue{FullBytes: messageDigestSet}},
	}

	// Marshal as SET (implicit tag for signing)
	attrBytes, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, err
	}

	// Change the tag from SEQUENCE to SET for proper PKCS#7 signing
	// ASN.1 SET tag is 0x31, SEQUENCE is 0x30
	if len(attrBytes) > 0 && attrBytes[0] == 0x30 {
		attrBytes[0] = 0x31
	}

	// Hash the attributes
	hash := sha256.Sum256(attrBytes)
	return hash[:], nil
}

// winCertificateHeaderSize is sizeof(WIN_CERTIFICATE) without bCertificate.
const winCertificateHeaderSize = 8

// embedSignature embeds the PKCS#7 signature into the PE file
func (s *Signer) embedSignature(pe *peFile, signature []byte) ([]byte, error) {
	// WIN_CERTIFICATE structure
	// DWORD dwLength;
	// WORD wRevision;
	// WORD wCertificateType;
	// BYTE bCertificate[ANYSIZE_ARRAY];
	//
	// dwLength covers the header and the PKCS#7 DER, nothing more; the
	// entry is then padded to an 8-byte boundary and the padding belongs
	// to the certificate table, not to the certificate. That is what
	// sbsign writes. It matters because not every verifier tolerates
	// trailing bytes after the DER: OpenSSL (OVMF) ignores them, but
	// mbedTLS (U-Boot 2025+) rejects the message with
	// MBEDTLS_ERR_ASN1_LENGTH_MISMATCH when dwLength includes them, and
	// the Raspberry Pi image never boots.
	dwLength := uint32(winCertificateHeaderSize + len(signature))
	certLen := (dwLength + 7) & ^uint32(7) // the table entry, padded

	winCert := make([]byte, certLen)
	binary.LittleEndian.PutUint32(winCert[0:4], dwLength)
	binary.LittleEndian.PutUint16(winCert[4:6], 0x0200) // WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(winCert[6:8], 0x0002) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	copy(winCert[8:], signature)

	// Create new PE with signature
	newPE := make([]byte, 0, len(pe.data)+len(winCert)+8) // +8 for potential padding

	// If there's an existing signature, remove it
	if pe.certTableOffset > 0 {
		newPE = append(newPE, pe.data[:pe.certTableOffset]...)
	} else {
		newPE = append(newPE, pe.data...)
	}

	// Align certificate table to 8-byte boundary (required by PE spec)
	currentLen := uint32(len(newPE))
	alignedOffset := (currentLen + 7) & ^uint32(7)
	if alignedOffset > currentLen {
		padding := make([]byte, alignedOffset-currentLen)
		newPE = append(newPE, padding...)
	}

	// Append new signature at aligned offset
	certOffset := uint32(len(newPE))
	newPE = append(newPE, winCert...)

	// Update security directory in PE header
	binary.LittleEndian.PutUint32(newPE[pe.securityDirOffset:pe.securityDirOffset+4], certOffset)
	binary.LittleEndian.PutUint32(newPE[pe.securityDirOffset+4:pe.securityDirOffset+8], certLen)

	// Update checksum
	checksum := s.computePEChecksum(newPE)
	binary.LittleEndian.PutUint32(newPE[pe.checksumOffset:pe.checksumOffset+4], checksum)

	return newPE, nil
}

// computePEChecksum computes the PE checksum
func (s *Signer) computePEChecksum(data []byte) uint32 {
	var checksum uint64
	checksumOffset := s.getChecksumOffset(data)

	// Sum all 16-bit words (PE checksum uses 16-bit, not 32-bit)
	for i := 0; i < len(data); i += 2 {
		// Skip the checksum field itself
		if i >= int(checksumOffset) && i < int(checksumOffset)+4 {
			continue
		}

		var word uint16
		if i+2 <= len(data) {
			word = binary.LittleEndian.Uint16(data[i : i+2])
		} else if i+1 <= len(data) {
			word = uint16(data[i])
		}

		checksum += uint64(word)
		// Fold carries
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	}

	// Final fold
	checksum = (checksum & 0xFFFF) + (checksum >> 16)

	// Add file size
	checksum += uint64(len(data))

	return uint32(checksum)
}

// getChecksumOffset returns the offset of the checksum field in a PE file
func (s *Signer) getChecksumOffset(data []byte) uint32 {
	if len(data) < 64 {
		return 0
	}
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	// Checksum is at offset 64 in the optional header
	return peOffset + 4 + 20 + 64
}

// extractSignature extracts the PKCS#7 signature from a PE file
func (s *Signer) extractSignature(pe *peFile) ([]byte, error) {
	if pe.certTableOffset == 0 || pe.certTableSize == 0 {
		return nil, nil // Not signed
	}

	if pe.certTableOffset+pe.certTableSize > uint32(len(pe.data)) {
		return nil, &MessageError{Msg: "invalid certificate table bounds"}
	}

	winCert := pe.data[pe.certTableOffset : pe.certTableOffset+pe.certTableSize]

	// WIN_CERTIFICATE structure:
	// DWORD dwLength;      // 4 bytes - header + certificate (see embedSignature)
	// WORD wRevision;      // 2 bytes
	// WORD wCertificateType; // 2 bytes
	// BYTE bCertificate[];  // variable; the table entry is padded to 8 bytes
	if len(winCert) < 8 {
		return nil, &MessageError{Msg: "invalid WIN_CERTIFICATE structure"}
	}

	// Get the data after the 8-byte header. The PKCS#7 size is taken from
	// the ASN.1 structure itself, so images signed before dwLength stopped
	// covering the padding (and images from other signers) still extract.
	pkcs7Data := winCert[8:]

	// Parse the ASN.1 length to get the actual PKCS#7 size
	// PKCS#7 is a SEQUENCE (tag 0x30)
	if len(pkcs7Data) < 2 || pkcs7Data[0] != 0x30 {
		return nil, &MessageError{Msg: "invalid PKCS#7 structure: expected SEQUENCE"}
	}

	var pkcs7Len int
	switch {
	case pkcs7Data[1] < 0x80:
		// Short form length
		pkcs7Len = 2 + int(pkcs7Data[1])
	case pkcs7Data[1] == 0x81:
		// Long form with 1 length byte
		if len(pkcs7Data) < 3 {
			return nil, &MessageError{Msg: "invalid PKCS#7 length encoding"}
		}
		pkcs7Len = 3 + int(pkcs7Data[2])
	case pkcs7Data[1] == 0x82:
		// Long form with 2 length bytes
		if len(pkcs7Data) < 4 {
			return nil, &MessageError{Msg: "invalid PKCS#7 length encoding"}
		}
		pkcs7Len = 4 + (int(pkcs7Data[2])<<8 | int(pkcs7Data[3]))
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported PKCS#7 length encoding: 0x%02x", pkcs7Data[1])}
	}

	if pkcs7Len > len(pkcs7Data) {
		return nil, &MessageError{Msg: "PKCS#7 length exceeds available data"}
	}

	return pkcs7Data[:pkcs7Len], nil
}

// verifyPKCS7Signature verifies the PKCS#7 signature
func (s *Signer) verifyPKCS7Signature(pe *peFile, signature []byte) error {
	// Parse the ContentInfo
	var ci contentInfo
	rest, err := asn1.Unmarshal(signature, &ci)
	if err != nil {
		return &WrappedError{Msg: "failed to parse ContentInfo", Err: err}
	}
	if len(rest) > 0 {
		return &MessageError{Msg: "trailing data after ContentInfo"}
	}

	if !ci.ContentType.Equal(oidSignedData) {
		return &MessageError{Msg: fmt.Sprintf("unexpected content type: %v", ci.ContentType)}
	}

	// Parse SignedData
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return &WrappedError{Msg: "failed to parse SignedData", Err: err}
	}

	if len(sd.SignerInfos) == 0 {
		return &MessageError{Msg: "no signer info in PKCS#7"}
	}

	// Compute expected Authenticode digest
	expectedDigest, err := s.computeAuthenticodeDigest(pe)
	if err != nil {
		return &WrappedError{Msg: "failed to compute Authenticode digest", Err: err}
	}

	// Extract and verify the digest from the SPC content
	actualDigest, err := s.extractDigestFromContent(sd.ContentInfo.Content.Bytes)
	if err != nil {
		return &WrappedError{Msg: "failed to extract digest from content", Err: err}
	}

	if !bytes.Equal(expectedDigest, actualDigest) {
		return &MessageError{Msg: "Authenticode digest mismatch"}
	}

	// Extract the signing certificate
	cert, err := s.extractCertificateFromPKCS7(signature)
	if err != nil {
		return &WrappedError{Msg: "failed to extract certificate", Err: err}
	}

	// Verify the cryptographic signature
	signerInfo := sd.SignerInfos[0]
	if err := s.verifyCryptographicSignature(cert, &signerInfo, sd.ContentInfo.Content.Bytes); err != nil {
		return &WrappedError{Msg: "cryptographic signature verification failed", Err: err}
	}

	if err := s.verifyEmbeddedTimestamps(&signerInfo); err != nil {
		return &WrappedError{Msg: "timestamp verification failed", Err: err}
	}

	return nil
}

// verifyCryptographicSignature verifies the RSA/ECDSA signature over the authenticated attributes
func (s *Signer) verifyCryptographicSignature(cert *x509.Certificate, signerInfo *signerInfo, content []byte) error {
	if err := s.verifySignedAttributes(cert, signerInfo, crypto.SHA256); err != nil {
		return err
	}

	// Verify the messageDigest attribute matches the content digest
	messageDigest, err := s.extractMessageDigestAttribute(signerInfo.AuthenticatedAttributes)
	if err != nil {
		return &WrappedError{Msg: "failed to extract messageDigest attribute", Err: err}
	}

	// For Authenticode, the messageDigest is the hash of the SPC content's inner bytes
	// (the SEQUENCE content without tag and length)
	innerContent, err := extractSequenceContent(content)
	if err != nil {
		return &WrappedError{Msg: "failed to extract SPC inner content", Err: err}
	}
	expectedMessageDigest := sha256.Sum256(innerContent)

	if !bytes.Equal(messageDigest, expectedMessageDigest[:]) {
		return &MessageError{Msg: "messageDigest attribute mismatch"}
	}

	return nil
}

// encodeAuthenticatedAttributesForVerification encodes attributes with SET tag for signature verification
// verifySignedAttributes checks signerInfo's signature over its authenticated
// attributes, hashed with hash, against cert's public key.
func (s *Signer) verifySignedAttributes(cert *x509.Certificate, signerInfo *signerInfo, hash crypto.Hash) error {
	// The signature is computed over the DER-encoded authenticated attributes
	// with the IMPLICIT [0] tag replaced with SET tag (0x31)
	if len(signerInfo.AuthenticatedAttributes) == 0 {
		return &MessageError{Msg: "no authenticated attributes to verify"}
	}

	// Re-encode authenticated attributes with SET tag for verification
	// The attributes are stored with IMPLICIT [0] tag, but signature is over SET encoding
	attrsData, err := s.encodeAuthenticatedAttributesForVerification(signerInfo.AuthenticatedAttributes)
	if err != nil {
		return &WrappedError{Msg: "failed to encode attributes for verification", Err: err}
	}

	// Hash the attributes
	attrHash := digest(hash, attrsData)

	// Verify the signature based on key type
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// RSA PKCS#1 v1.5 signature verification
		err = rsa.VerifyPKCS1v15(pubKey, hash, attrHash, signerInfo.EncryptedDigest)
		if err != nil {
			return &WrappedError{Msg: "RSA signature verification failed", Err: err}
		}
	case *ecdsa.PublicKey:
		// ECDSA signature verification
		if !ecdsa.VerifyASN1(pubKey, attrHash, signerInfo.EncryptedDigest) {
			return &MessageError{Msg: "ECDSA signature verification failed"}
		}
	default:
		return &MessageError{Msg: fmt.Sprintf("unsupported public key type: %T", pubKey)}
	}
	return nil
}

func (s *Signer) encodeAuthenticatedAttributesForVerification(attrs []attribute) ([]byte, error) {
	// Re-marshal each attribute and wrap in SET
	var attrBytes []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to marshal attribute", Err: err}
		}
		attrBytes = append(attrBytes, encoded...)
	}

	// Wrap in SET (tag 0x31)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attrBytes,
	})
}

// extractMessageDigestAttribute extracts the messageDigest from authenticated attributes
func (s *Signer) extractMessageDigestAttribute(attrs []attribute) ([]byte, error) {
	for _, attr := range attrs {
		if attr.Type.Equal(oidAttributeMessageDigest) {
			// The value is a SET containing an OCTET STRING
			var setWrapper asn1.RawValue
			_, err := asn1.Unmarshal(attr.Values.FullBytes, &setWrapper)
			if err != nil {
				return nil, &WrappedError{Msg: "failed to parse messageDigest SET", Err: err}
			}

			var digest []byte
			_, err = asn1.Unmarshal(setWrapper.Bytes, &digest)
			if err != nil {
				return nil, &WrappedError{Msg: "failed to parse messageDigest value", Err: err}
			}
			return digest, nil
		}
	}
	return nil, &MessageError{Msg: "messageDigest attribute not found"}
}

// extractDigestFromContent extracts the message digest from SPC_INDIRECT_DATA_CONTENT
func (s *Signer) extractDigestFromContent(content []byte) ([]byte, error) {
	var spc spcIndirectDataContent
	_, err := asn1.Unmarshal(content, &spc)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse SPC content", Err: err}
	}

	return spc.MessageDigest.Digest, nil
}

// extractCertificateFromPKCS7 extracts the signing certificate from PKCS#7
func (s *Signer) extractCertificateFromPKCS7(signature []byte) (*x509.Certificate, error) {
	// Parse ContentInfo
	var ci contentInfo
	_, err := asn1.Unmarshal(signature, &ci)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse ContentInfo", Err: err}
	}

	// Parse SignedData
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse SignedData", Err: err}
	}

	// The certificates are stored in sd.Certificates.Bytes
	// which contains the concatenated raw DER certificates
	certBytes := sd.Certificates.Bytes
	if len(certBytes) == 0 {
		return nil, &MessageError{Msg: "no certificates in PKCS#7"}
	}

	// Parse certificates from the raw bytes
	// Each certificate is a SEQUENCE (tag 0x30)
	var certs []*x509.Certificate
	// The loop is labelled because every length-decoding failure below abandons
	// the whole certificate list, not just the enclosing switch.
parseCerts:
	for len(certBytes) > 0 {
		// Find certificate boundary (SEQUENCE tag 0x30)
		if certBytes[0] != 0x30 {
			break
		}

		// Calculate certificate length
		var certLen int
		switch {
		case certBytes[1] < 0x80:
			certLen = int(certBytes[1]) + 2
		case certBytes[1] == 0x81:
			if len(certBytes) < 3 {
				break parseCerts
			}
			certLen = int(certBytes[2]) + 3
		case certBytes[1] == 0x82:
			if len(certBytes) < 4 {
				break parseCerts
			}
			certLen = int(certBytes[2])<<8 + int(certBytes[3]) + 4
		default:
			break parseCerts // Unsupported length
		}

		if certLen > len(certBytes) {
			break
		}

		cert, err := x509.ParseCertificate(certBytes[:certLen])
		if err != nil {
			return nil, &WrappedError{Msg: "failed to parse certificates", Err: err}
		}
		certs = append(certs, cert)
		certBytes = certBytes[certLen:]
	}

	if len(certs) == 0 {
		return nil, &MessageError{Msg: "no certificates in PKCS#7"}
	}

	return certs[0], nil
}

// extractSigningTime extracts the signing time from PKCS#7 signature
func extractSigningTime(signature []byte) (time.Time, error) {
	// Parse ContentInfo
	var ci contentInfo
	_, err := asn1.Unmarshal(signature, &ci)
	if err != nil {
		return time.Time{}, &WrappedError{Msg: "failed to parse ContentInfo", Err: err}
	}

	// Parse SignedData
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return time.Time{}, &WrappedError{Msg: "failed to parse SignedData", Err: err}
	}

	if len(sd.SignerInfos) == 0 {
		return time.Time{}, &MessageError{Msg: "no signer info"}
	}

	// Find signing time attribute
	for _, attr := range sd.SignerInfos[0].AuthenticatedAttributes {
		if attr.Type.Equal(oidAttributeSigningTime) {
			// The attribute value is wrapped in a SET, need to unwrap it first
			var setWrapper asn1.RawValue
			_, err := asn1.Unmarshal(attr.Values.FullBytes, &setWrapper)
			if err != nil {
				return time.Time{}, &WrappedError{Msg: "failed to parse signing time SET", Err: err}
			}

			var t time.Time
			_, err = asn1.Unmarshal(setWrapper.Bytes, &t)
			if err != nil {
				return time.Time{}, &WrappedError{Msg: "failed to parse signing time value", Err: err}
			}
			return t, nil
		}
	}

	return time.Time{}, &MessageError{Msg: "signing time not found"}
}
