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
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"os"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Authenticode provides PE/COFF (Windows Authenticode) signing functionality
// This enables signing of EFI binaries (UKIs) for UEFI Secure Boot
type Authenticode interface {
	// Sign signs a PE/COFF file (like a UKI) with Authenticode signature
	// This enables UEFI Secure Boot verification
	Sign(input io.Reader, output io.Writer) error

	// SignFile signs a PE/COFF file and writes the signed output
	SignFile(inputPath, outputPath string) error

	// Verify verifies an Authenticode signature on a PE/COFF file
	Verify(input io.Reader) error

	// VerifyFile verifies an Authenticode signature on a file
	VerifyFile(path string) error

	// ExtractCertificate extracts the signing certificate from a signed PE/COFF file
	ExtractCertificate(input io.Reader) (*x509.Certificate, error)

	// ExtractCertificateFile extracts the signing certificate from a signed file
	ExtractCertificateFile(path string) (*x509.Certificate, error)
}

// Signer implements Authenticode signing using keystore integration
type Signer struct {
	ctx          context.Context
	keystore     xkmssdk.KeyProvider
	keyAttrs     *xkmssdk.KeyAttributes
	cert         *x509.Certificate
	certChain    []*x509.Certificate
	timestampURL string
	logger       *logging.Logger
}

// SignerOptions configures Authenticode signing
type SignerOptions struct {
	// KeyStore is the keystore backend (TPM, PKCS#11, or PKCS8)
	KeyStore xkmssdk.KeyProvider

	// KeyAttributes identifies which key to use for signing
	KeyAttributes *xkmssdk.KeyAttributes

	// Certificate is the code signing certificate
	Certificate *x509.Certificate

	// CertChain is the certificate chain (optional)
	CertChain []*x509.Certificate

	// TimestampURL is the RFC3161 timestamp server URL (optional)
	TimestampURL string

	// Logger for diagnostic output
	Logger *logging.Logger
}

// NewSigner creates a new Authenticode signer with keystore integration
func NewSigner(ctx context.Context, opts *SignerOptions) (Authenticode, error) {
	if opts.KeyStore == nil {
		return nil, &MessageError{Msg: "keystore is required"}
	}

	if opts.KeyAttributes == nil {
		return nil, &MessageError{Msg: "key attributes are required"}
	}

	if opts.Certificate == nil {
		return nil, &MessageError{Msg: "certificate is required"}
	}

	if opts.Logger == nil {
		return nil, &MessageError{Msg: "logger is required"}
	}

	// Verify the key exists
	_, err := opts.KeyStore.Signer(ctx, opts.KeyAttributes)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get signer from keystore", Err: err}
	}

	return &Signer{
		ctx:          ctx,
		keystore:     opts.KeyStore,
		keyAttrs:     opts.KeyAttributes,
		cert:         opts.Certificate,
		certChain:    opts.CertChain,
		timestampURL: opts.TimestampURL,
		logger:       opts.Logger,
	}, nil
}

// Sign signs a PE/COFF file with Authenticode signature
// This implementation properly supports hardware-backed keys (TPM, PKCS#11, etc.)
// by signing the authenticated attributes digest rather than the PE digest directly.
func (s *Signer) Sign(input io.Reader, output io.Writer) error {
	s.logger.Info("[AUTHENTICODE] Starting Authenticode signing")

	// Read the entire PE file
	peData, err := io.ReadAll(input)
	if err != nil {
		return &WrappedError{Msg: "failed to read PE file", Err: err}
	}

	// Parse PE structure
	pe, err := parsePE(peData)
	if err != nil {
		return &WrappedError{Msg: "failed to parse PE", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] PE file parsed", "size", len(peData))

	// Compute Authenticode digest (hash of PE excluding signature section)
	peDigest, err := s.computeAuthenticodeDigest(pe)
	if err != nil {
		return &WrappedError{Msg: "failed to compute PE digest", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Authenticode PE digest computed", "digest_size", len(peDigest))

	// Build the SPC content that will be embedded in PKCS#7
	spcContent, err := s.buildSPCContent(peDigest)
	if err != nil {
		return &WrappedError{Msg: "failed to build SPC content", Err: err}
	}

	// Build authenticated attributes and compute their digest
	// This is what actually gets signed in PKCS#7
	signingTime := time.Now().UTC()
	attrDigest, err := s.computeAttributesDigest(spcContent, signingTime)
	if err != nil {
		return &WrappedError{Msg: "failed to compute attributes digest", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Authenticated attributes digest computed")

	// Get signer from keystore (TPM, PKCS#11, or PKCS8)
	signer, err := s.keystore.Signer(s.ctx, s.keyAttrs)
	if err != nil {
		return &WrappedError{Msg: "failed to get signer from keystore", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Signer retrieved from keystore", "backend", s.keystore.Type())

	// Sign the authenticated attributes digest using the keystore signer
	// This is where the magic happens - signing with hardware-backed keys!
	// IMPORTANT: We must specify crypto.SHA256 so the signer knows to create
	// a proper PKCS#1 v1.5 signature with DigestInfo wrapper
	signerOpts := &xkmssdk.SignerOpts{
		KeyAttributes: s.keyAttrs,
		Hash:          crypto.SHA256,
	}

	signature, err := signer.Sign(nil, attrDigest, signerOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to sign", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Signed with keystore", "signature_size", len(signature), "backend", s.keystore.Type())

	// Create PKCS#7 signature structure with the pre-computed signature
	// IMPORTANT: Must pass the SAME spcContent bytes that were used for signing
	pkcs7Sig, err := s.createPKCS7SignatureWithTime(spcContent, signature, signingTime)
	if err != nil {
		return &WrappedError{Msg: "failed to create PKCS#7 signature", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] PKCS#7 signature created", "size", len(pkcs7Sig))

	// Optional: Add timestamp
	if s.timestampURL != "" {
		s.logger.Info("[AUTHENTICODE] Adding RFC3161 timestamp", "url", s.timestampURL)
		pkcs7Sig, err = s.addTimestamp(pkcs7Sig, attrDigest)
		if err != nil {
			s.logger.Warn("Failed to add timestamp (non-fatal)", "error", err)
		} else {
			s.logger.Info("[AUTHENTICODE] Timestamp added successfully")
		}
	}

	// Embed signature in PE file
	signedPE, err := s.embedSignature(pe, pkcs7Sig)
	if err != nil {
		return &WrappedError{Msg: "failed to embed signature", Err: err}
	}

	// Write signed PE to output
	if _, err := output.Write(signedPE); err != nil {
		return &WrappedError{Msg: "failed to write signed PE", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Authenticode signing completed successfully")
	return nil
}

// asn1NULL is the DER encoding of ASN.1 NULL
var asn1NULL = asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal}

// buildSPCString builds an SpcString (BMPString) for the file link
// This is the "<<<Obsolete>>>" string in UTF-16BE format
func buildSPCString() []byte {
	obsolete := "<<<Obsolete>>>"
	// Convert to UTF-16BE (BMP string)
	var buf bytes.Buffer
	for _, r := range obsolete {
		buf.WriteByte(byte(r >> 8))
		buf.WriteByte(byte(r))
	}
	return buf.Bytes()
}

// buildSPCContent creates the SPC_INDIRECT_DATA_CONTENT for the PE digest
func (s *Signer) buildSPCContent(peDigest []byte) ([]byte, error) {
	// Build the SpcLink for the file link
	// Structure: [0] { [2] { [0] BMPString } }
	spcLinkValue, err := buildSPCLink()
	if err != nil {
		return nil, err
	}

	spcContent := spcIndirectDataContent{
		Data: spcAttributeTypeAndValue{
			Type: oidSPCPEImageData,
			Value: spcPEImageData{
				// Flags is an empty BIT STRING (0 unused bits, 0 bytes)
				// This matches sbsign's encoding: 03 01 00
				Flags: asn1.BitString{Bytes: []byte{}, BitLength: 0},
				File:  spcLinkValue,
			},
		},
		MessageDigest: digestInfo{
			DigestAlgorithm: pkixAlgorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1NULL,
			},
			Digest: peDigest,
		},
	}

	return asn1.Marshal(spcContent)
}

// buildSPCLink builds the SpcLink structure for the file link
// Returns: [0] { [2] { [0] BMPString } }
func buildSPCLink() (asn1.RawValue, error) {
	// Build SPC string (BMP/UTF-16BE encoding of "<<<Obsolete>>>")
	spcString := buildSPCString()

	// Inner context tag [0] containing the BMP string
	spcStringValue := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      spcString,
	}
	spcStringValueBytes, err := asn1.Marshal(spcStringValue)
	if err != nil {
		return asn1.RawValue{}, &WrappedError{Msg: "failed to marshal SPC string value", Err: err}
	}

	// SpcLink choice [2] for SpcString
	spcStringChoice := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      spcStringValueBytes,
	}
	spcStringChoiceBytes, err := asn1.Marshal(spcStringChoice)
	if err != nil {
		return asn1.RawValue{}, &WrappedError{Msg: "failed to marshal SPC string choice", Err: err}
	}

	// Outer explicit context tag [0] wrapping the SpcLink
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      spcStringChoiceBytes,
	}, nil
}

// createPKCS7SignatureWithTime creates a PKCS#7 SignedData structure with specific signing time
// spcContentBytes is the pre-marshaled SPC content - must use the SAME bytes that were used for signing
func (s *Signer) createPKCS7SignatureWithTime(spcContentBytes, signature []byte, signingTime time.Time) ([]byte, error) {
	// Content type attribute - marshal the OID and wrap in SET
	contentTypeValue, err := asn1.Marshal(oidSPCIndirectDataContent)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal content type", Err: err}
	}
	contentTypeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contentTypeValue,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal content type SET", Err: err}
	}

	// Message digest attribute (hash of the SPC content inner data)
	// Per PKCS#7/CMS, the messageDigest is the hash of the content value
	// WITHOUT the outer SEQUENCE tag/length
	innerContent, err := extractSequenceContent(spcContentBytes)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract SPC inner content", Err: err}
	}
	spcDigest := sha256.Sum256(innerContent)
	messageDigestValue, err := asn1.Marshal(spcDigest[:])
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal message digest", Err: err}
	}
	messageDigestSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      messageDigestValue,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal message digest SET", Err: err}
	}

	// Signing time attribute
	signingTimeValue, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal signing time", Err: err}
	}
	signingTimeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      signingTimeValue,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal signing time SET", Err: err}
	}

	// Build authenticated attributes with pre-encoded SET values
	authenticatedAttrs := []attribute{
		{
			Type:   oidAttributeContentType,
			Values: asn1.RawValue{FullBytes: contentTypeSet},
		},
		{
			Type:   oidAttributeSigningTime,
			Values: asn1.RawValue{FullBytes: signingTimeSet},
		},
		{
			Type:   oidAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: messageDigestSet},
		},
	}

	// Build signer info
	// Note: RSA signature algorithm uses rsaEncryption OID with NULL parameter (not rsaWithSHA256)
	// This matches what sbsign produces
	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: s.cert.RawIssuer},
			SerialNumber: s.cert.SerialNumber,
		},
		DigestAlgorithm: pkixAlgorithmIdentifier{
			Algorithm:  oidSHA256,
			Parameters: asn1NULL,
		},
		AuthenticatedAttributes: authenticatedAttrs,
		DigestEncryptionAlgorithm: pkixAlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1NULL,
		},
		EncryptedDigest: signature,
	}

	// Build certificate chain
	var certBytes []byte
	certs := []*x509.Certificate{s.cert}
	certs = append(certs, s.certChain...)

	for _, cert := range certs {
		certBytes = append(certBytes, cert.Raw...)
	}

	// Build SignedData structure
	sd := signedData{
		Version: 1,
		DigestAlgorithmIdentifiers: []pkixAlgorithmIdentifier{
			{Algorithm: oidSHA256, Parameters: asn1NULL},
		},
		ContentInfo: contentInfo{
			ContentType: oidSPCIndirectDataContent,
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      spcContentBytes,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: []signerInfo{si},
	}

	signedDataBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal SignedData", Err: err}
	}

	// Wrap in ContentInfo
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(ci)
}

// SignFile signs a PE/COFF file and writes the signed output
func (s *Signer) SignFile(inputPath, outputPath string) error {
	s.logger.Info("[AUTHENTICODE] Signing file", "input", inputPath, "output", outputPath)

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return &WrappedError{Msg: "failed to open input file", Err: err}
	}
	defer func() { _ = inputFile.Close() }()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return &WrappedError{Msg: "failed to create output file", Err: err}
	}
	defer func() { _ = outputFile.Close() }()

	if err := s.Sign(inputFile, outputFile); err != nil {
		_ = os.Remove(outputPath)
		return err
	}

	// Make executable
	if err := os.Chmod(outputPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] File signed successfully", "output", outputPath)
	return nil
}

// Verify verifies an Authenticode signature
func (s *Signer) Verify(input io.Reader) error {
	s.logger.Info("[AUTHENTICODE] Verifying Authenticode signature")

	// Read PE file
	peData, err := io.ReadAll(input)
	if err != nil {
		return &WrappedError{Msg: "failed to read PE file", Err: err}
	}

	// Parse PE structure
	pe, err := parsePE(peData)
	if err != nil {
		return &WrappedError{Msg: "failed to parse PE", Err: err}
	}

	// Extract signature
	signature, err := s.extractSignature(pe)
	if err != nil {
		return &WrappedError{Msg: "failed to extract signature", Err: err}
	}

	if len(signature) == 0 {
		return &MessageError{Msg: "PE file is not signed"}
	}

	// Verify PKCS#7 signature
	if err := s.verifyPKCS7Signature(pe, signature); err != nil {
		return &WrappedError{Msg: "signature verification failed", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Signature verified successfully")
	return nil
}

// VerifyFile verifies an Authenticode signature on a file
func (s *Signer) VerifyFile(path string) error {
	s.logger.Info("[AUTHENTICODE] Verifying file", "path", path)

	file, err := os.Open(path)
	if err != nil {
		return &WrappedError{Msg: "failed to open file", Err: err}
	}
	defer func() { _ = file.Close() }()

	return s.Verify(file)
}

// ExtractCertificate extracts the signing certificate from a signed PE file
func (s *Signer) ExtractCertificate(input io.Reader) (*x509.Certificate, error) {
	s.logger.Info("[AUTHENTICODE] Extracting certificate")

	peData, err := io.ReadAll(input)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read PE file", Err: err}
	}

	pe, err := parsePE(peData)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse PE", Err: err}
	}

	signature, err := s.extractSignature(pe)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract signature", Err: err}
	}

	if len(signature) == 0 {
		return nil, &MessageError{Msg: "PE file is not signed"}
	}

	// Parse PKCS#7 and extract certificate
	cert, err := s.extractCertificateFromPKCS7(signature)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract certificate", Err: err}
	}

	s.logger.Info("[AUTHENTICODE] Certificate extracted", "subject", cert.Subject.String())
	return cert, nil
}

// ExtractCertificateFile extracts the signing certificate from a file
func (s *Signer) ExtractCertificateFile(path string) (*x509.Certificate, error) {
	s.logger.Info("[AUTHENTICODE] Extracting certificate from file", "path", path)

	file, err := os.Open(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open file", Err: err}
	}
	defer func() { _ = file.Close() }()

	return s.ExtractCertificate(file)
}

// SigningTime returns the signing time from a signed PE file
func SigningTime(input io.Reader) (time.Time, error) {
	peData, err := io.ReadAll(input)
	if err != nil {
		return time.Time{}, &WrappedError{Msg: "failed to read PE file", Err: err}
	}

	pe, err := parsePE(peData)
	if err != nil {
		return time.Time{}, &WrappedError{Msg: "failed to parse PE", Err: err}
	}

	signer := &Signer{}
	signature, err := signer.extractSignature(pe)
	if err != nil {
		return time.Time{}, &WrappedError{Msg: "failed to extract signature", Err: err}
	}

	if len(signature) == 0 {
		return time.Time{}, &MessageError{Msg: "PE file is not signed"}
	}

	return extractSigningTime(signature)
}

// Public returns the public key associated with this signer
func (s *Signer) Public() crypto.PublicKey {
	return s.cert.PublicKey
}
