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

package image

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"net/http"
	"time"
)

// TimestampClient defines the interface for RFC3161 timestamp operations.
type TimestampClient interface {
	// Timestamp creates a timestamp for the given data.
	Timestamp(ctx context.Context, data []byte) ([]byte, error)

	// Verify verifies a timestamp token against the original data.
	Verify(ctx context.Context, token, data []byte) (*TimestampInfo, error)
}

// TimestampInfo contains information extracted from a timestamp token.
type TimestampInfo struct {
	// Time is the timestamp from the TSA.
	Time time.Time
	// SerialNumber is the TSA serial number.
	SerialNumber []byte
	// HashAlgorithm is the algorithm used for hashing.
	HashAlgorithm string
	// Accuracy is the accuracy of the timestamp.
	Accuracy time.Duration
	// TSAName is the name of the TSA.
	TSAName string
	// PolicyID is the TSA policy identifier.
	PolicyID string
	// Nonce is the nonce if one was used.
	Nonce []byte
	// MessageImprint is the hash of the timestamped data.
	MessageImprint []byte
}

// RFC3161Client implements the TimestampClient interface for RFC3161 TSAs.
type RFC3161Client struct {
	tsaURL      string
	httpClient  *http.Client
	hashAlgo    asn1.ObjectIdentifier
	trustedCAs  *x509.CertPool
	currentTime func() time.Time
}

// RFC3161ClientOption is a functional option for configuring RFC3161Client.
type RFC3161ClientOption func(*RFC3161Client)

// WithTrustedCAs sets the trusted CA certificates for TSA certificate verification.
func WithTrustedCAs(pool *x509.CertPool) RFC3161ClientOption {
	return func(c *RFC3161Client) {
		c.trustedCAs = pool
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) RFC3161ClientOption {
	return func(c *RFC3161Client) {
		c.httpClient = client
	}
}

// WithCurrentTime sets a custom time function for certificate validation.
func WithCurrentTime(fn func() time.Time) RFC3161ClientOption {
	return func(c *RFC3161Client) {
		c.currentTime = fn
	}
}

// OIDs for timestamp operations
var (
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidContentTypeTST  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// Attribute OIDs
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// hashAlgorithmNames maps OIDs to algorithm names.
var hashAlgorithmNames = map[string]string{
	oidSHA256.String(): "SHA256",
	oidSHA384.String(): "SHA384",
	oidSHA512.String(): "SHA512",
}

// TimestampRequest represents an RFC3161 TimeStampReq.
type TimestampRequest struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          []byte                `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []Extension           `asn1:"optional,tag:0"`
}

// MessageImprint represents the hash of the data to timestamp.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// AlgorithmIdentifier represents an algorithm identifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Extension represents an X.509 extension.
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional,default:false"`
	ExtnValue []byte
}

// TimestampResponse represents an RFC3161 TimeStampResp.
type TimestampResponse struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo represents the status of a timestamp response.
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// contentInfo represents PKCS#7 ContentInfo.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData represents PKCS#7 SignedData.
type signedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs                       []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo    `asn1:"set"`
}

// signerInfo represents PKCS#7 SignerInfo.
type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// issuerAndSerial contains the issuer name and serial number.
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// attribute represents a PKCS#7 attribute.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// TSTInfo represents the RFC3161 TSTInfo structure.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     []Extension   `asn1:"optional,tag:1"`
}

// Accuracy represents the accuracy of a timestamp.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// ToDuration converts Accuracy to time.Duration.
func (a Accuracy) ToDuration() time.Duration {
	return time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}

// NewRFC3161Client creates a new RFC3161 timestamp client.
func NewRFC3161Client(tsaURL string, opts ...RFC3161ClientOption) (*RFC3161Client, error) {
	if tsaURL == "" {
		return nil, ErrNilParameter{Parameter: "tsaURL"}
	}

	client := &RFC3161Client{
		tsaURL: tsaURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		hashAlgo:    oidSHA256,
		currentTime: time.Now,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Timestamp creates a timestamp for the given data.
func (c *RFC3161Client) Timestamp(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrNilParameter{Parameter: "data"}
	}

	// Hash the data
	digest := sha256.Sum256(data)

	// Create timestamp request
	req := TimestampRequest{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: c.hashAlgo,
			},
			HashedMessage: digest[:],
		},
		CertReq: true,
	}

	// Encode request
	reqBytes, err := asn1.Marshal(req)
	if err != nil {
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "failed to encode request", Err: err}
	}

	// Send request to TSA
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tsaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "failed to create HTTP request", Err: err}
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "HTTP request failed", Err: err}
	}
	defer func() {
		// Best-effort close; response body already consumed
		if cerr := resp.Body.Close(); cerr != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "TSA returned status " + resp.Status + ": " + string(body)}
	}

	// Read response
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "failed to read response", Err: err}
	}

	// Parse response
	var tsResp TimestampResponse
	_, err = asn1.Unmarshal(respBytes, &tsResp)
	if err != nil {
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: "failed to parse response", Err: err}
	}

	// Check status
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		reason := "unknown error"
		if len(tsResp.Status.StatusString) > 0 {
			reason = tsResp.Status.StatusString[0]
		}
		return nil, ErrTimestampFailed{TSAUrl: c.tsaURL, Reason: reason}
	}

	// Return the timestamp token
	return tsResp.TimeStampToken.FullBytes, nil
}

// Verify verifies a timestamp token against the original data.
// It performs full RFC3161 verification including:
// 1. Parsing the CMS/PKCS#7 SignedData structure
// 2. Extracting TSTInfo from the encapsulated content
// 3. Verifying the signature on the timestamp token
// 4. Verifying the TSA certificate chain (if trusted CAs are configured)
// 5. Comparing the message imprint with the original digest
func (c *RFC3161Client) Verify(ctx context.Context, token, data []byte) (*TimestampInfo, error) {
	if len(token) == 0 {
		return nil, ErrNilParameter{Parameter: "token"}
	}

	if len(data) == 0 {
		return nil, ErrNilParameter{Parameter: "data"}
	}

	// Parse the timestamp token (CMS/PKCS#7 ContentInfo)
	var ci contentInfo
	rest, err := asn1.Unmarshal(token, &ci)
	if err != nil {
		return nil, ErrInvalidTimestampToken{Reason: "failed to parse ContentInfo", Err: err}
	}
	if len(rest) > 0 {
		return nil, ErrInvalidTimestampToken{Reason: "trailing data after ContentInfo"}
	}

	// Verify content type is SignedData
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, ErrInvalidTimestampToken{Reason: "expected SignedData content type"}
	}

	// Parse SignedData
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, ErrInvalidTimestampToken{Reason: "failed to parse SignedData", Err: err}
	}

	// Verify we have at least one signer
	if len(sd.SignerInfos) == 0 {
		return nil, ErrInvalidTimestampToken{Reason: "no signer info in timestamp token"}
	}

	// Verify content type is TSTInfo
	if !sd.ContentInfo.ContentType.Equal(oidContentTypeTST) {
		return nil, ErrInvalidTimestampToken{Reason: "expected TSTInfo content type"}
	}

	// Extract and parse TSTInfo
	tstInfoBytes := sd.ContentInfo.Content.Bytes
	var tstInfo TSTInfo
	_, err = asn1.Unmarshal(tstInfoBytes, &tstInfo)
	if err != nil {
		return nil, ErrInvalidTimestampToken{Reason: "failed to parse TSTInfo", Err: err}
	}

	// Determine hash algorithm and compute digest of original data
	hashAlgo := tstInfo.MessageImprint.HashAlgorithm.Algorithm
	hashName := hashAlgorithmNames[hashAlgo.String()]
	if hashName == "" {
		return nil, ErrUnsupportedAlgorithm{
			Algorithm: hashAlgo.String(),
			Supported: []string{"SHA256", "SHA384", "SHA512"},
		}
	}

	var hasher hash.Hash
	switch {
	case hashAlgo.Equal(oidSHA256):
		hasher = sha256.New()
	case hashAlgo.Equal(oidSHA384):
		hasher = sha512.New384()
	case hashAlgo.Equal(oidSHA512):
		hasher = sha512.New()
	default:
		return nil, ErrUnsupportedAlgorithm{
			Algorithm: hashAlgo.String(),
			Supported: []string{"SHA256", "SHA384", "SHA512"},
		}
	}

	hasher.Write(data)
	expectedDigest := hasher.Sum(nil)

	// Compare message imprint with computed digest
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, expectedDigest) {
		return nil, ErrMessageImprintMismatch{
			Expected: hex.EncodeToString(expectedDigest),
			Actual:   hex.EncodeToString(tstInfo.MessageImprint.HashedMessage),
		}
	}

	// Extract certificates from SignedData
	certs, err := c.extractCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, ErrTimestampVerificationFailed{
			Step:   "certificate extraction",
			Reason: "failed to extract certificates",
			Err:    err,
		}
	}

	if len(certs) == 0 {
		return nil, ErrTimestampVerificationFailed{
			Step:   "certificate extraction",
			Reason: "no certificates in timestamp token",
		}
	}

	// Find the signing certificate
	signerInfo := sd.SignerInfos[0]
	signingCert, err := c.findSigningCertificate(certs, signerInfo)
	if err != nil {
		return nil, ErrTimestampVerificationFailed{
			Step:   "certificate lookup",
			Reason: "failed to find signing certificate",
			Err:    err,
		}
	}

	// Verify certificate chain if trusted CAs are configured
	if c.trustedCAs != nil {
		if err := c.verifyCertificateChain(signingCert, certs); err != nil {
			return nil, ErrTimestampVerificationFailed{
				Step:   "certificate chain verification",
				Reason: "certificate chain verification failed",
				Err:    err,
			}
		}
	}

	// Verify the cryptographic signature
	if err := c.verifySignature(signerInfo, signingCert, tstInfoBytes); err != nil {
		return nil, ErrTimestampVerificationFailed{
			Step:   "signature verification",
			Reason: "signature verification failed",
			Err:    err,
		}
	}

	// Build TimestampInfo result
	info := &TimestampInfo{
		Time:           tstInfo.GenTime,
		SerialNumber:   tstInfo.SerialNumber.Bytes(),
		HashAlgorithm:  hashName,
		Accuracy:       tstInfo.Accuracy.ToDuration(),
		PolicyID:       tstInfo.Policy.String(),
		MessageImprint: tstInfo.MessageImprint.HashedMessage,
	}

	// Extract TSA name if present
	if len(tstInfo.TSA.Bytes) > 0 {
		info.TSAName = c.extractTSAName(tstInfo.TSA)
	} else if signingCert != nil {
		info.TSAName = signingCert.Subject.CommonName
	}

	// Extract nonce if present
	if tstInfo.Nonce != nil {
		info.Nonce = tstInfo.Nonce.Bytes()
	}

	return info, nil
}

// extractCertificates extracts X.509 certificates from raw certificate bytes.
func (c *RFC3161Client) extractCertificates(certBytes []byte) ([]*x509.Certificate, error) {
	if len(certBytes) == 0 {
		return nil, nil
	}

	var certs []*x509.Certificate
	for len(certBytes) > 0 {
		// Each certificate is a SEQUENCE (tag 0x30)
		if certBytes[0] != 0x30 {
			break
		}

		// Calculate certificate length
		certLen, headerLen, err := parseASN1Length(certBytes)
		if err != nil {
			return nil, err
		}

		totalLen := headerLen + certLen
		if totalLen > len(certBytes) {
			return nil, ErrInvalidTimestampToken{Reason: "certificate length exceeds available data"}
		}

		cert, err := x509.ParseCertificate(certBytes[:totalLen])
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		certBytes = certBytes[totalLen:]
	}

	return certs, nil
}

// parseASN1Length parses the length field of an ASN.1 element.
// Returns the content length and header length (tag + length bytes).
func parseASN1Length(data []byte) (int, int, error) {
	if len(data) < 2 {
		return 0, 0, ErrInvalidTimestampToken{Reason: "data too short for ASN.1 length"}
	}

	if data[1] < 0x80 {
		// Short form
		return int(data[1]), 2, nil
	}

	numBytes := int(data[1] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, ErrInvalidTimestampToken{Reason: "invalid ASN.1 length encoding"}
	}

	if len(data) < 2+numBytes {
		return 0, 0, ErrInvalidTimestampToken{Reason: "data too short for long-form length"}
	}

	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[2+i])
	}

	return length, 2 + numBytes, nil
}

// findSigningCertificate finds the certificate that matches the signer info.
func (c *RFC3161Client) findSigningCertificate(certs []*x509.Certificate, si signerInfo) (*x509.Certificate, error) {
	for _, cert := range certs {
		// Match by serial number
		if cert.SerialNumber.Cmp(si.IssuerAndSerialNumber.SerialNumber) != 0 {
			continue
		}

		// Match by issuer
		if bytes.Equal(cert.RawIssuer, si.IssuerAndSerialNumber.IssuerName.FullBytes) ||
			bytes.Equal(cert.RawIssuer, si.IssuerAndSerialNumber.IssuerName.Bytes) {
			return cert, nil
		}
	}

	return nil, ErrTimestampVerificationFailed{
		Step:   "certificate lookup",
		Reason: "no certificate matches signer info",
	}
}

// verifyCertificateChain verifies the TSA certificate chain against trusted CAs.
func (c *RFC3161Client) verifyCertificateChain(signingCert *x509.Certificate, certs []*x509.Certificate) error {
	// Build intermediate pool from certificates in the token
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if !bytes.Equal(cert.Raw, signingCert.Raw) {
			intermediates.AddCert(cert)
		}
	}

	// Determine verification time
	verifyTime := c.currentTime()
	if c.currentTime == nil {
		verifyTime = time.Now()
	}

	opts := x509.VerifyOptions{
		Roots:         c.trustedCAs,
		Intermediates: intermediates,
		CurrentTime:   verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	_, err := signingCert.Verify(opts)
	return err
}

// verifySignature verifies the cryptographic signature on the timestamp token.
func (c *RFC3161Client) verifySignature(si signerInfo, cert *x509.Certificate, tstInfoBytes []byte) error {
	// Determine the hash algorithm from the signer info
	digestAlgo := si.DigestAlgorithm.Algorithm
	var hashFunc crypto.Hash
	var hasher hash.Hash

	switch {
	case digestAlgo.Equal(oidSHA256):
		hashFunc = crypto.SHA256
		hasher = sha256.New()
	case digestAlgo.Equal(oidSHA384):
		hashFunc = crypto.SHA384
		hasher = sha512.New384()
	case digestAlgo.Equal(oidSHA512):
		hashFunc = crypto.SHA512
		hasher = sha512.New()
	default:
		return ErrUnsupportedAlgorithm{
			Algorithm: digestAlgo.String(),
			Supported: []string{"SHA256", "SHA384", "SHA512"},
		}
	}

	// Compute the digest to verify
	var digestToVerify []byte

	if len(si.AuthenticatedAttributes) > 0 {
		// When authenticated attributes are present, the signature is over
		// the DER encoding of the authenticated attributes with SET tag
		attrBytes, err := c.encodeAuthenticatedAttributes(si.AuthenticatedAttributes)
		if err != nil {
			return err
		}

		// Verify messageDigest attribute matches TSTInfo content
		if err := c.verifyMessageDigest(si.AuthenticatedAttributes, tstInfoBytes, hasher); err != nil {
			return err
		}

		// Hash the attributes for signature verification
		attrHasher := hasher
		if len(si.AuthenticatedAttributes) > 0 {
			switch {
			case digestAlgo.Equal(oidSHA256):
				attrHasher = sha256.New()
			case digestAlgo.Equal(oidSHA384):
				attrHasher = sha512.New384()
			case digestAlgo.Equal(oidSHA512):
				attrHasher = sha512.New()
			}
		}
		attrHasher.Write(attrBytes)
		digestToVerify = attrHasher.Sum(nil)
	} else {
		// No authenticated attributes - signature is over the content directly
		hasher.Write(tstInfoBytes)
		digestToVerify = hasher.Sum(nil)
	}

	// Verify signature based on key type
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pubKey, hashFunc, digestToVerify, si.EncryptedDigest)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pubKey, digestToVerify, si.EncryptedDigest) {
			return ErrTimestampVerificationFailed{
				Step:   "signature verification",
				Reason: "ECDSA signature verification failed",
			}
		}
		return nil
	default:
		return ErrUnsupportedAlgorithm{
			Algorithm: "unknown public key type",
			Supported: []string{"RSA", "ECDSA"},
		}
	}
}

// encodeAuthenticatedAttributes encodes authenticated attributes for signature verification.
// The attributes must be re-encoded with explicit SET tag (0x31) for verification.
func (c *RFC3161Client) encodeAuthenticatedAttributes(attrs []attribute) ([]byte, error) {
	// Re-marshal each attribute
	var attrBytes []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
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

// verifyMessageDigest verifies that the messageDigest attribute matches the content.
func (c *RFC3161Client) verifyMessageDigest(attrs []attribute, content []byte, hasher hash.Hash) error {
	for _, attr := range attrs {
		if attr.Type.Equal(oidAttributeMessageDigest) {
			// Parse the SET containing the OCTET STRING
			var setWrapper asn1.RawValue
			_, err := asn1.Unmarshal(attr.Values.FullBytes, &setWrapper)
			if err != nil {
				// Try direct unmarshal if FullBytes is empty
				if len(attr.Values.Bytes) > 0 {
					_, err = asn1.Unmarshal(attr.Values.Bytes, &setWrapper)
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}

			var digest []byte
			_, err = asn1.Unmarshal(setWrapper.Bytes, &digest)
			if err != nil {
				return err
			}

			// Compute expected digest
			hasher.Reset()
			hasher.Write(content)
			expectedDigest := hasher.Sum(nil)

			if !bytes.Equal(digest, expectedDigest) {
				return ErrTimestampVerificationFailed{
					Step:   "messageDigest verification",
					Reason: "messageDigest attribute does not match content",
				}
			}

			return nil
		}
	}

	return ErrTimestampVerificationFailed{
		Step:   "messageDigest verification",
		Reason: "messageDigest attribute not found",
	}
}

// extractTSAName extracts the TSA name from the GeneralName structure.
func (c *RFC3161Client) extractTSAName(tsaRaw asn1.RawValue) string {
	// TSA is a GeneralName, which is a CHOICE type
	// Most commonly it's a directoryName [4]
	if tsaRaw.Tag == 4 && tsaRaw.Class == asn1.ClassContextSpecific {
		// directoryName - parse as RDNSequence
		var name pkixName
		if _, err := asn1.Unmarshal(tsaRaw.Bytes, &name); err == nil {
			return name.String()
		}
	}

	// Return hex encoding as fallback
	return hex.EncodeToString(tsaRaw.Bytes)
}

// pkixName represents a simplified X.500 distinguished name.
type pkixName struct {
	Country            []string `asn1:"optional,omitempty"`
	Organization       []string `asn1:"optional,omitempty"`
	OrganizationalUnit []string `asn1:"optional,omitempty"`
	Locality           []string `asn1:"optional,omitempty"`
	Province           []string `asn1:"optional,omitempty"`
	CommonName         string   `asn1:"optional,omitempty"`
}

func (n pkixName) String() string {
	if n.CommonName != "" {
		return n.CommonName
	}
	if len(n.Organization) > 0 {
		return n.Organization[0]
	}
	return ""
}

// NoOpTimestampClient is a timestamp client that does nothing.
type NoOpTimestampClient struct{}

// NewNoOpTimestampClient creates a no-op timestamp client.
func NewNoOpTimestampClient() *NoOpTimestampClient {
	return &NoOpTimestampClient{}
}

// Timestamp returns nil for no-op client.
func (c *NoOpTimestampClient) Timestamp(ctx context.Context, data []byte) ([]byte, error) {
	return nil, nil
}

// Verify returns nil for no-op client.
func (c *NoOpTimestampClient) Verify(ctx context.Context, token, data []byte) (*TimestampInfo, error) {
	return nil, nil
}
