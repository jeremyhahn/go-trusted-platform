package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/op/go-logging"
	"github.com/youmark/pkcs8"

	"github.com/jeremyhahn/go-trusted-platform/util"
)

const (
	KEY_STORE_PKCS8  = "PKCS8"
	KEY_STORE_PKCS11 = "PKCS11"

	KEY_ALGO_RSA = "RSA"
	KEY_ALGO_ECC = "ECC"

	RSA_SCHEME_RSAPSS   = "RSA_PSS"
	RSA_SCHEME_PKCS1v15 = "PKCS1v15"

	CURVE_P224 = "P256"
	CURVE_P256 = "P256"
	CURVE_P384 = "P386"
	CURVE_P521 = "P521"
)

var (
	ErrInvalidConfig                = errors.New("certificate-authority: invalid configuration")
	ErrCorruptWrite                 = errors.New("certificate-authority: corrupt write: bytes written does not match data length")
	ErrCertRevoked                  = errors.New("certificate-authority: certificate revoked")
	ErrCertNotFound                 = errors.New("certificate-authority: certificate not found")
	ErrCertFuture                   = errors.New("certificate-authority: certificate issued in the future")
	ErrCertExpired                  = errors.New("certificate-authority: certificate expired")
	ErrCertInvalid                  = errors.New("certificate-authority: certificate invalid")
	ErrTrustExists                  = errors.New("certificate-authority: certificate already trusted")
	ErrInvalidSignature             = errors.New("certificate-authority: invalid signature")
	ErrInvalidSignatureAlgorithm    = errors.New("certificate-authority: invalid signature algorithm")
	ErrCRLAlreadyExists             = errors.New("certificate-authority: revocation list already exists")
	ErrNoIssuingCA                  = errors.New("certificate-authority: no issuing CAs found in certificate")
	ErrCertNotSupported             = errors.New("certificate-authority: certificate contains unsupported configuration")
	ErrBlobNotFound                 = errors.New("certificate-authority: signed blob not found")
	ErrInvalidPublicKey             = errors.New("certificate-authority: invalid public key")
	ErrInvalidPrivateKey            = errors.New("certificate-authority: invalid private key")
	ErrInvalidPublicKeyRSA          = errors.New("certificate-authority: invalid RSA public key")
	ErrInvalidPrivateKeyRSA         = errors.New("certificate-authority: invalid RSA private key")
	ErrInvalidPublicKeyECC          = errors.New("certificate-authority: invalid ECC public key")
	ErrInvalidPrivateKeyECC         = errors.New("certificate-authority: invalid ECC private key")
	ErrInvalidEncodingPEM           = errors.New("certificate-authority: invalid PEM encoding")
	ErrInvalidCurve                 = errors.New("certificate-authority: invalid ECC Curve")
	ErrInvalidAlgorithm             = errors.New("certificate-authority: invalid algorithm")
	ErrPrivateKeyPasswordRequired   = errors.New("certificate-authority: private key password required")
	ErrPasswordComplexity           = errors.New("certificate-authority: private key password doesn't meet complexity requirements")
	ErrNotInitialized               = errors.New("certificate-authority: not initialized")
	ErrAlreadyInitialized           = errors.New("certificate-authority: already initialized")
	ErrInvalidIntermediateSelection = errors.New("certificate-authority: invalid intermediate certificate authority selection")
	ErrInvalidPassword              = errors.New("certificate-authority: invalid password")
	ErrUnsupportedSigningAlgorithm  = errors.New("certificate-authority: unsupported signing algorithm")
	ErrUnsupportedHashAlgorithm     = errors.New("certificate-authority: unsupported hashing algorithm")
	ErrUnsupportedRSAScheme         = errors.New("certificate-authority: unsupported RSA padding scheme")
	ErrInvalidAttestationBlobType   = errors.New("certificate-authority: invalid attestation blob type")
	ErrInvalidSignerOpts            = errors.New("certificate-authority: invalid signing options, ca.SigningOpts with password required")

	WarnNoSigningPassword = errors.New("certificate-authority: signing with an insecure private key")
)

type CertificateAuthority interface {
	AttestationEventLog(cn string) ([]byte, error)
	AttestationPCRs(cn string) (map[string][][]byte, error)
	AttestationQuote(cn string) ([]byte, error)
	AttestationSignature(cn, blobType string) ([]byte, error)
	Blob(key string) ([]byte, error)
	CABundle() ([]byte, error)
	CABundleCertPool() (*(x509.CertPool), error)
	CACertificate() *x509.Certificate
	CAPrivKey(password []byte) (crypto.PublicKey, error)
	CAPubKey() (crypto.PublicKey, error)
	Certificate(cn string) (*x509.Certificate, error)
	Checksum(key string) (bool, error)
	CreateCSR(email string, request CertificateRequest, password []byte) ([]byte, error)
	DecodeCSR(bytes []byte) (*x509.CertificateRequest, error)
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
	DecryptionKey(cn, keyName string, password []byte) (crypto.Decrypter, error)
	DecodePEM(bytes []byte) (*x509.Certificate, error)
	DecodeRSAPubKeyPEM(bytes []byte) (crypto.PublicKey, error)
	DefaultValidityPeriod() int
	DER(cn string) ([]byte, error)
	Digest(key string, hash crypto.Hash) (bool, error)
	EncodePEM(derCert []byte) ([]byte, error)
	EncodePubKey(pub crypto.PublicKey) ([]byte, error)
	EncodePubKeyPEM(cn string, derBytes []byte) ([]byte, error)
	EncodePrivKey(privateKey crypto.PrivateKey, password []byte) ([]byte, error)
	EncodePrivKeyPEM(der []byte, isEncrypted bool) ([]byte, error)
	EncryptionKey(cn, keyName string) (*rsa.PublicKey, error)
	EndorsementKeyCertificate() ([]byte, error)
	Hash() crypto.Hash
	HashFileExtension(hash crypto.Hash) string
	Init(
		parentPrivKey crypto.PrivateKey,
		parentCertifiate *x509.Certificate,
		password []byte,
		random io.Reader) (crypto.PrivateKey, *x509.Certificate, error)
	Identity() Identity
	IsAutoImportingIssuerCAs() bool
	IsInitialized() bool
	IssueCertificate(request CertificateRequest, caPassword, certPassword []byte) ([]byte, error)
	IssuedCertificates() ([]string, error)
	IssuePrivKey(cn string, privateKey crypto.PrivateKey, password []byte) error
	IssuePubKey(cn string, pub crypto.PublicKey) error
	Import(cer *x509.Certificate) error
	ImportAttestation(cn, blobType string, data, caPassword []byte) error
	ImportAttestationKeyCertificate(domain, service string, akDER []byte) error
	ImportAttestationEventLog(cn string, data, caPassword []byte) error
	ImportAttestationPCRs(cn string, pcrs map[string][][]byte, caPassword []byte) error
	ImportAttestationQuote(cn string, data, caPassword []byte) error
	ImportBlob(key string, data []byte) error
	ImportCN(cn string, cert *x509.Certificate) error
	ImportDER(cn string, derCert []byte) error
	ImportDistrbutionCRLs(cert *x509.Certificate) error
	ImportEndorsementKeyCertificate(ekCertPEM, caPassword []byte) error
	ImportPEM(cn string, pemBytes []byte) error
	ImportIssuingCAs(cert *x509.Certificate, leafCN *string, leaf *x509.Certificate) error
	ImportTrustedRoot(cn string, derCert []byte) error
	ImportTrustedIntermediate(cn string, derCert []byte) error
	ImportPubKey(cn string, pub crypto.PublicKey) error
	Load(password []byte) (crypto.PrivateKey, *x509.Certificate, error)
	NewECDSASigningKey(cn, keyName string, password []byte) (crypto.Signer, error)
	NewEncryptionKey(cn, keyName string, password, caPassword []byte) (*rsa.PrivateKey, error)
	NewPKCS1v15SigningKey(cn, keyName string, password []byte) (crypto.Signer, error)
	NewRSASigningKey(cn, keyName string, password []byte) (crypto.Signer, error)
	NewSigningKey(cn, keyName string, password []byte) (crypto.Signer, error)
	ParseCABundle(bundle []byte) ([]*x509.Certificate, error)
	ParsePrivateKey(bytes, password []byte) (crypto.PrivateKey, error)
	PEM(cn string) ([]byte, error)
	PrivKey(cn, name string, password []byte, partition Partition) (crypto.PublicKey, error)
	PrivKeyPEM(cn, name string, password []byte) ([]byte, error)
	Public() crypto.PublicKey
	PubKey(cn string) (crypto.PublicKey, error)
	PubKeyPEM(cn string) ([]byte, error)
	RSADecrypt(cn, keyName string, password, ciphertext []byte) ([]byte, error)
	RSAEncrypt(cn, keyName string, data []byte) ([]byte, error)
	Revoke(cn string, password []byte) error
	RootCertificate() (*x509.Certificate, error)
	RootCertForCA(cn string) (*x509.Certificate, error)
	SetPassword(password []byte)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Signature(key string) ([]byte, error)
	Signed(key string) (bool, error)
	SignedBlob(key string) ([]byte, error)
	SignCSR(csrBytes []byte, request CertificateRequest, password []byte) ([]byte, error)
	SigningKey(cn, keyName string, password []byte) (SigningKey, error)
	TLSConfig(cn, name string, password []byte, includeSystemRoot bool) (*tls.Config, error)
	TPMBlobKey(domain, cn string) string
	TrustStore() TrustStore
	TrustedRootCertificate(cn string) (*x509.Certificate, error)
	TrustedRootCertPool(includeSystemRoot bool) (*x509.CertPool, error)
	TrustedIntermediateCertificate(cn string) (*x509.Certificate, error)
	TrustedIntermediateCertPool() (*x509.CertPool, error)
	Verify(certificate *x509.Certificate, leafCN *string) (bool, error)
	VerifyAttestationEventLog(cn string, eventLog []byte) error
	VerifyAttestationPCRs(cn string, pcrs map[string][][]byte) error
	VerifyAttestationQuote(cn string, quote []byte) error
	VerifyPKCS1v15(digest, signature []byte, opts *VerifyOpts) error
	VerifySignature(digest []byte, signature []byte, opts *VerifyOpts) error
	X509KeyPair(cn, name string, password []byte) (tls.Certificate, error)
}

type VerifyOpts struct {
	PSSSaltLength      int
	KeyCN              *string
	KeyName            *string
	BlobKey            *string
	Hash               *crypto.Hash
	UseStoredSignature bool
}

type CAParams struct {
	Debug                bool
	DebugSecrets         bool
	Logger               *logging.Logger
	Config               *Config
	Password             []byte
	SelectedIntermediate int
	Random               io.Reader
}

type CA struct {
	params             CAParams
	caDir              string
	parentIdentity     *Identity
	parentCertificate  *x509.Certificate
	parentPubKey       crypto.PublicKey
	identity           Identity
	signatureAlgorithm x509.SignatureAlgorithm
	certificate        *x509.Certificate
	publicKey          crypto.PublicKey
	curve              elliptic.Curve
	trustStore         TrustStore
	certStore          CertificateStore
	commonName         string
	passwordPolicy     *regexp.Regexp
	decrypter          crypto.Decrypter
	CertificateAuthority
}

// This function creates new Root and Intermediate x509 Certifiate Authorities. First
// an attempt is made to load them from a pre-existing initilization. If the CA hasn't
// been initialized, (missing CA public/private keys from the certificate store), the
// Root and Intermediate CAs will be returned along with ErrNotInitalized.
//
// ErrNotInitialized signals that platform setup needs to run first. After the
// platform setup has completed, call Init() on the returned Root and Intermediate
// CA instances, passing in the platform password and desired Random Number Generator
// to be used during private key generation.
func NewCA(params CAParams) (CertificateAuthority, CertificateAuthority, error) {

	// Ensure the selected intermediate is not the Root or out of bounds
	if params.SelectedIntermediate == 0 || params.SelectedIntermediate > len(params.Config.Identity) {
		return nil, nil, ErrInvalidIntermediateSelection
	}

	// Root CA
	rootCA, err := NewRootCA(params)
	if err != nil {
		return nil, nil, err
	}

	// Selected Intermediate CA - config supports multiple CA configurations
	intermediateCA, err := NewIntermediateCA(
		params,
		rootCA)
	if err != nil {
		return nil, nil, err
	}

	// If the CA hasn't been initialized yet, return an error signaling
	// to run platform setup, including prompting for passwords to
	// protect the CA PKCS8 private keys.
	if !intermediateCA.IsInitialized() {
		return rootCA, intermediateCA, ErrNotInitialized
	}

	// Load the Intermediate CA's keys and certificate from the store
	if _, _, err := intermediateCA.Load(params.Password); err != nil {
		return rootCA, intermediateCA, err
	}

	// Return the CA ready for use
	return rootCA, intermediateCA, nil
}

// Creates a new x509 Root Certificate Authority
func NewRootCA(params CAParams) (CertificateAuthority, error) {

	if params.Config == nil {
		return nil, ErrInvalidConfig
	}

	if len(params.Config.Identity) < 2 {
		params.Logger.Error("certificate-authority: Root and at least 1 Intermediate CA required")
		return nil, ErrInvalidConfig
	}

	caDir := fmt.Sprintf("%s/%s",
		params.Config.Home, params.Config.Identity[0].Subject.CommonName)
	if err := os.MkdirAll(caDir, os.ModePerm); err != nil {
		params.Logger.Error(err)
		return nil, err
	}

	passwordPolicy, err := regexp.Compile(params.Config.PasswordPolicy)
	if err != nil {
		params.Logger.Fatal(err)
	}

	return &CA{
		params:         params,
		caDir:          caDir,
		passwordPolicy: passwordPolicy,
		identity:       params.Config.Identity[0],
		trustStore:     NewDebianTrustStore(params.Logger, caDir),
		commonName:     params.Config.Identity[0].Subject.CommonName}, nil
}

// Create a new x509 Intermediate Certificate Authority
func NewIntermediateCA(
	params CAParams,
	rootCA CertificateAuthority) (CertificateAuthority, error) {

	identity := params.Config.Identity[params.SelectedIntermediate]
	intermediateCN := identity.Subject.CommonName
	caDir := fmt.Sprintf("%s/%s", params.Config.Home, intermediateCN)
	if err := os.MkdirAll(caDir, os.ModePerm); err != nil {
		params.Logger.Error(err)
		return nil, err
	}

	passwordPolicy, err := regexp.Compile(params.Config.PasswordPolicy)
	if err != nil {
		params.Logger.Error(err)
		return nil, err
	}

	parentIdentity := rootCA.Identity()

	return &CA{
		params:            params,
		caDir:             caDir,
		passwordPolicy:    passwordPolicy,
		identity:          identity,
		parentIdentity:    &parentIdentity,
		parentCertificate: rootCA.CACertificate(),
		trustStore:        NewDebianTrustStore(params.Logger, caDir),
		commonName:        identity.Subject.CommonName}, nil
}

// Sets the CA private key password (PKCS #8). Used by platform
// setup to inject the password after instantiation.
func (ca *CA) SetPassword(password []byte) {
	ca.params.Password = password
}

// Implements crypto.PrivateKey
// Implements crypto.Decrypter
func (ca *CA) Public() crypto.PublicKey {
	return ca.publicKey
}

// Returns the CA's hash function
func (ca *CA) Hash() crypto.Hash {
	hashes := SupportedHashes()
	hash, ok := hashes[ca.params.Config.Hash]
	if !ok {
		ca.params.Logger.Fatalf("%s: %s",
			ErrUnsupportedHashAlgorithm, ca.params.Config.Hash)
	}
	return hash
}

// Returns true if the Certificate Authority is initialized and ready
// to start servicing requests. A successful response indicates the Load()
// method is ready to be called. An unsuccessful response should perform
// platform setup first, supplying the password to use to protect the CA
// PKCS8 private keys.
func (ca *CA) IsInitialized() bool {
	caCert := fmt.Sprintf("%s/%s%s", ca.caDir, ca.commonName, FSEXT_PUBLIC_PEM)
	if _, err := os.Stat(caCert); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		ca.params.Logger.Error(err)
		return false
	}
}

// Load CA public/private key and x509 signing certificate from the
// certificate store. Any errors during Load are treated as Fatal.
func (ca *CA) Load(password []byte) (crypto.PrivateKey, *x509.Certificate, error) {

	ca.params.Logger.Infof("Loading Certificate Authority: %s", ca.commonName)

	if ca.params.DebugSecrets {
		ca.params.Logger.Debugf("CA password: %s", password)
	}

	caCertFile := fmt.Sprintf("%s/%s%s", ca.caDir, ca.commonName, FSEXT_DER)
	ca.params.Logger.Debugf("Loading CA certificate: %s", caCertFile)

	// Set ECC curve if configured for ECC signing
	if err := ca.setCurve(); err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Load the CA DER form certificate
	caCertDer, err := os.ReadFile(caCertFile)
	if err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Parse the DER cert into x509.Certificate
	ca.certificate, err = x509.ParseCertificate(caCertDer)
	if err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Load the certificate store
	ca.certStore, err = NewFileSystemCertStore(ca.params.Logger,
		ca.caDir, ca.certificate, ca.params.Config.RetainRevokedCertificates)

	// Load the CA public key
	ca.publicKey, err = ca.CAPubKey()
	if err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Load the CA private key
	privKey, err := ca.CAPrivKey(password)
	if err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Set the CA decrypter
	ca.decrypter, err = ca.DecryptionKey(ca.commonName, ca.commonName, ca.params.Password)
	if err != nil {
		ca.params.Logger.Fatal(err)
	}

	// Set the CA signature algorithm
	signatureAlgorithms := SupportedSignatureAlgorithms()
	preferredAlgo, ok := signatureAlgorithms[ca.params.Config.SignatureAlgorithm]
	if !ok {
		return nil, nil, fmt.Errorf("%s: %s",
			ErrInvalidSignatureAlgorithm, ca.params.Config.SignatureAlgorithm)
	}
	ca.signatureAlgorithm = preferredAlgo

	// Print the CA bundle to the log if in debug mode
	bundle, err := ca.CABundle()
	if err != nil {
		ca.params.Logger.Fatal(err)
	}
	ca.params.Logger.Debug("Certificate Authority CA Bundle:")
	ca.params.Logger.Debugf("\n%s", string(bundle))

	// Return the CA private key signing certificate
	return privKey, ca.certificate, nil
}

// The first time the Certificate Authority is run, it needs to be instantiated. This
// process creates new Root and Intermediate CA RSA private / public key pairs and x509
// signing certificate and saves them to the certificate store.
//
// Subsequent calls to the CA should call Load and check the IsInitalized response
// to detect whether the CA needs to be initialized. Attempting to initalize the CA
// after it's already been initialized results in a load operation instead of
// initialization.
//
// Certificates are saved to the certificate store in DER, PEM, PKCS#1 and PKCS#8 formats.
func (ca *CA) Init(
	parentPrivKey crypto.PrivateKey,
	parentCertificate *x509.Certificate,
	password []byte,
	random io.Reader) (crypto.PrivateKey, *x509.Certificate, error) {

	var err error
	var privateKey crypto.PrivateKey
	ca.params.Random = random
	ca.parentCertificate = parentCertificate

	// Set ECC curve if configured for ECC signing
	if err := ca.setCurve(); err != nil {
		return nil, nil, err
	}

	if ca.IsInitialized() {
		return ca.Load(password)
	}

	ca.params.Logger.Debugf("Initializing Certificate Authority: %s", ca.commonName)

	// Get SANS IPs, DNS, and Emails from config
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(ca.identity.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, nil
	}

	// Create a new CA certificate serial number
	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, nil
	}

	signatureAlgorithms := SupportedSignatureAlgorithms()
	preferredAlgo, ok := signatureAlgorithms[ca.params.Config.SignatureAlgorithm]
	if !ok {
		return nil, nil, fmt.Errorf("%s: %s",
			ErrInvalidSignatureAlgorithm, ca.params.Config.SignatureAlgorithm)
	}
	ca.signatureAlgorithm = preferredAlgo

	// Generate RSA or ECC signing key for the CA
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		privateKeyRSA, err := rsa.GenerateKey(random, ca.identity.KeySize)
		if err != nil {
			ca.params.Logger.Error(err)
			return privateKey, nil, nil
		}
		privateKey = privateKeyRSA
		ca.publicKey = &privateKeyRSA.PublicKey

	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		privateKeyECC, err := ecdsa.GenerateKey(ca.curve, rand.Reader)
		if err != nil {
			ca.params.Logger.Error(err)
			return privateKey, nil, nil
		}
		privateKey = privateKeyECC
		ca.publicKey = &privateKeyECC.PublicKey
	} else {
		return nil, nil, fmt.Errorf("%s: %s", ErrInvalidAlgorithm, ca.params.Config.KeyAlgorithm)
	}

	// Create Subject Key ID
	subjectKeyID, err := ca.createSubjectKeyIdentifier()
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, nil
	}

	// PKIX subject
	subject := pkix.Name{
		CommonName:         ca.identity.Subject.CommonName,
		Organization:       []string{ca.identity.Subject.Organization},
		OrganizationalUnit: []string{ca.identity.Subject.OrganizationalUnit},
		Country:            []string{ca.identity.Subject.Country},
		Province:           []string{ca.identity.Subject.Province},
		Locality:           []string{ca.identity.Subject.Locality},
		StreetAddress:      []string{ca.identity.Subject.Address},
		PostalCode:         []string{ca.identity.Subject.PostalCode}}

	// x509 CA template
	template := &x509.Certificate{
		SignatureAlgorithm:    ca.signatureAlgorithm,
		PublicKeyAlgorithm:    x509.PublicKeyAlgorithm(ca.signatureAlgorithm),
		SerialNumber:          serialNumber,
		Issuer:                subject,
		Subject:               subject,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        subjectKeyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(ca.identity.Valid, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		EmailAddresses:        emailAddresses}

	// If this is an Intermediate Certificate Authority,
	// use the Root keys and certificate to sign, otherwise,
	// self-sign (as the Root).
	signingCert := template
	privKey := privateKey
	if parentPrivKey != nil {
		privKey = parentPrivKey
		signingCert = parentCertificate
		ca.parentPubKey = parentCertificate.PublicKey
	}

	// Create the new Root / Intermediate CA certificate
	caDerCert, err := x509.CreateCertificate(rand.Reader,
		template, signingCert, ca.publicKey, privKey)
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, nil
	}

	// Parse the generated DER and set it as the CA certificate
	ca.certificate, err = x509.ParseCertificate(caDerCert)
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, nil
	}

	// Create the backend certificate store
	ca.certStore, err = NewFileSystemCertStore(
		ca.params.Logger, ca.caDir, ca.certificate, ca.params.Config.RetainRevokedCertificates)
	if err != nil {
		ca.params.Logger.Error(err)
		return privateKey, nil, err
	}

	// Save the DER form to the certificate store
	err = ca.certStore.Save(
		ca.identity.Subject.CommonName, caDerCert, PARTITION_CA, FSEXT_DER)
	if err != nil {
		return privateKey, nil, err
	}

	// Encode the DER form to PEM form and save it to the certificate store
	pemBytes, err := ca.EncodePEM(caDerCert)
	if err != nil {
		return privateKey, nil, err
	}
	if err := ca.certStore.Save(
		ca.identity.Subject.CommonName, pemBytes, PARTITION_CA, FSEXT_PEM); err != nil {
		return privateKey, nil, err
	}

	// Import the private key in PKCS8 and PEM form
	if err = ca.issueCAPrivKey(ca.commonName, privateKey, password); err != nil {
		return privateKey, nil, err
	}

	// If this is an Intermediate Certificate Authority, import the
	// Root CA certificate into the trusted root certificate store
	// and create a CA bundle file for TLS clients to verify issued
	// certificates.
	if ca.parentIdentity != nil {
		if err := ca.importRootCA(); err != nil {
			return privateKey, nil, err
		}
		if err := ca.createCABundle(); err != nil {
			return privateKey, nil, err
		}
	}

	// Initialize the CRL by creating a dummy cert and revoking it
	if err := ca.initCRL(password); err != nil {
		return nil, nil, err
	}

	// Set the CA's crypto.Decrypter
	if ca.params.Config.KeyStore == KEY_STORE_PKCS8 {
		// Create a new CA encryption key
		privKey, err := ca.NewEncryptionKey(
			ca.commonName, ca.commonName, password, password)
		if err != nil {
			return nil, nil, err
		}
		ca.decrypter = NewPKCS8Decrypter(
			ca.params.Random,
			ca.Hash(),
			ca,
			privKey)
	}

	return privateKey, ca.certificate, nil
}

// Returns the Certificate Authority identity configuration
func (ca *CA) Identity() Identity {
	return ca.identity
}

// Returns the default number of days certificates issued by
// the CA are valid. If a CSR is submitted that is requesting
// "0 days", the CA default value is used instead of the 0 value.
func (ca *CA) DefaultValidityPeriod() int {
	return ca.params.Config.ValidDays
}

// Returns true if auto-importing of CA certificates are enabled
func (ca *CA) IsAutoImportingIssuerCAs() bool {
	return ca.params.Config.AutoImportIssuingCA
}

// Returns the operating system's CA trusted certificates store provider
func (ca *CA) TrustStore() TrustStore {
	return ca.trustStore
}

func (ca *CA) RootCertForCA(cn string) (*x509.Certificate, error) {
	return ca.certStore.RootCertForCA(cn)
}

// Returns the x509 certificate used as the identity and signing certificate
// for the Root Certificate Authority.
func (ca *CA) RootCertificate() (*x509.Certificate, error) {
	return ca.RootCertForCA(ca.identity.Subject.CommonName)
}

// Returns the x509 certificate used as the identity and signing certificate
// for the Certificate Authority.
func (ca *CA) CACertificate() *x509.Certificate {
	return ca.certificate
}

// Returns a trusted root certificate from the trust store
func (ca *CA) TrustedRootCertificate(cn string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error
	der, err := ca.certStore.TrustedRoot(cn)
	if err != nil {
		return nil, err
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		// Try to parse it as PEM
		return ca.DecodePEM(der)
	}
	return cert, err
}

// Returns a trusted root certificate from the trust store
func (ca *CA) TrustedIntermediateCertificate(cn string) (*x509.Certificate, error) {
	der, err := ca.certStore.TrustedIntermediate(cn)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (ca *CA) TrustedRootCertPool(includeSystemRoot bool) (*x509.CertPool, error) {
	return ca.certStore.TrustedRootCertPool(includeSystemRoot)
}

func (ca *CA) TrustedIntermediateCertPool() (*x509.CertPool, error) {
	return ca.certStore.TrustedIntermediateCertPool()
}

// Creates a new Certificate Signing Request (CSR)
func (ca *CA) CreateCSR(email string, request CertificateRequest, password []byte) ([]byte, error) {

	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	emailAddresses = append(emailAddresses, email)

	_subject := pkix.Name{
		CommonName:         request.Subject.CommonName,
		Organization:       []string{request.Subject.Organization},
		OrganizationalUnit: []string{request.Subject.OrganizationalUnit},
		Country:            []string{request.Subject.Country},
		Province:           []string{request.Subject.Province},
		Locality:           []string{request.Subject.Locality},
		StreetAddress:      []string{request.Subject.Address},
		PostalCode:         []string{request.Subject.PostalCode},
	}

	rawSubj := _subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: ca.signatureAlgorithm,
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(ca.signatureAlgorithm),
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		EmailAddresses:     emailAddresses,
	}

	dnsNames = append(dnsNames, request.Subject.CommonName)
	template.DNSNames = dnsNames

	caPrivateKey, err := ca.certStore.CAPrivKey(password)
	csrPEM := new(bytes.Buffer)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, caPrivateKey)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}

	if err := pem.Encode(csrPEM, csrBlock); err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	pemBytes := csrPEM.Bytes()
	err = ca.certStore.Save(
		request.Subject.CommonName,
		pemBytes,
		PARTITION_ISSUED,
		FSEXT_CSR)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	ca.params.Logger.Debug(string(pemBytes))

	return pemBytes, nil
}

// Signs a Certificate Signing Request (CSR) and stores it in the cert store
// in PEM format. This method returns the raw DER encoded []byte array as
// returned from x509.CreateCertificate.
func (ca *CA) SignCSR(csrBytes []byte, request CertificateRequest, password []byte) ([]byte, error) {

	csr, err := ca.DecodeCSR(csrBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	template := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       serialNumber,
		Issuer:             ca.certificate.Subject,
		Subject:            csr.Subject,
		AuthorityKeyId:     ca.certificate.SubjectKeyId,
		SubjectKeyId:       ca.certificate.SubjectKeyId,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, request.Valid),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:        csr.IPAddresses,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
	}
	template.DNSNames = csr.DNSNames

	caPrivateKey, err := ca.certStore.CAPrivKey(password)
	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, ca.certificate, template.PublicKey, caPrivateKey)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	// Import the DER and PEM forms
	if err := ca.ImportDER(csr.Subject.CommonName, derBytes); err != nil {
		return nil, err
	}

	// Import the public key
	err = ca.issuePubKey(
		request.Subject.CommonName, csr.PublicKey, PARTITION_ISSUED)
	if err != nil {
		return nil, err
	}

	return ca.EncodePEM(derBytes)
}

// Create a new private / public key pair and save it to the cert store
// in DER and PEM form. This method returns the raw DER encoded []byte
// as returned from x509.CreateCertificate.
func (ca *CA) IssueCertificate(request CertificateRequest, caPassword, certPassword []byte) ([]byte, error) {
	if request.Valid == 0 {
		request.Valid = ca.params.Config.ValidDays
	}
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	dnsNames = append(dnsNames, request.Subject.CommonName)
	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: ca.signatureAlgorithm,
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(ca.signatureAlgorithm),
		SerialNumber:       serialNumber,
		Issuer:             ca.certificate.Subject,
		Subject: pkix.Name{
			CommonName:    request.Subject.CommonName,
			Organization:  []string{request.Subject.Organization},
			Country:       []string{request.Subject.Country},
			Province:      []string{request.Subject.Province},
			Locality:      []string{request.Subject.Locality},
			StreetAddress: []string{request.Subject.Address},
			PostalCode:    []string{request.Subject.PostalCode},
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, request.Valid),
		AuthorityKeyId: ca.certificate.SubjectKeyId,
		SubjectKeyId:   ca.certificate.SubjectKeyId,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses}

	var certPrivKey crypto.PrivateKey
	var certPubKey crypto.PublicKey
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		privateKeyRSA, err := rsa.GenerateKey(ca.params.Random, ca.identity.KeySize)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}
		certPrivKey = privateKeyRSA
		certPubKey = &privateKeyRSA.PublicKey
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		privateKeyECC, err := ecdsa.GenerateKey(ca.curve, rand.Reader)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}
		certPrivKey = privateKeyECC
		certPubKey = &privateKeyECC.PublicKey
	} else {
		return nil, fmt.Errorf("%s: %s", ErrInvalidAlgorithm, ca.params.Config.KeyAlgorithm)
	}

	// Get the CA key to sign the certificate
	caPrivateKey, err := ca.certStore.CAPrivKey(caPassword)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create the x509 certificate
	certDerBytes, err := x509.CreateCertificate(
		rand.Reader, cert, ca.certificate, certPubKey, caPrivateKey)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	// Import the certificate in DER and PEM for, import public key
	if err := ca.ImportDER(request.Subject.CommonName, certDerBytes); err != nil {
		return nil, err
	}

	// Save the PKCS1 public key
	// err = ca.issuePubKey(
	// 	request.Subject.CommonName, certPubKey, PARTITION_ISSUED)
	// if err != nil {
	// 	return nil, err
	// }

	// Save the PKCS8 private key
	err = ca.issuePrivKey(
		request.Subject.CommonName, certPrivKey, certPassword, PARTITION_ISSUED)
	if err != nil {
		return nil, err
	}

	return certDerBytes, nil
}

// Revoke a certificate
func (ca *CA) Revoke(cn string, password []byte) error {

	// Check the certificate store to see if this certificate has
	// been added to the revocation list, and exists in the revoked
	// partition.
	revoked, err := ca.certStore.IsRevoked(cn, nil)
	if err != nil {
		return err
	}
	if revoked {
		return ErrCertRevoked
	}

	// Load the requested cert
	certPEM, err := ca.PEM(cn)
	if err != nil {
		return err
	}

	// Decode the PEM to a *x509.Certificate
	certificate, err := ca.DecodePEM(certPEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	return ca.certStore.Revoke(cn, certificate, password)
}

// Verify certificate is valid
func (ca *CA) Verify(certificate *x509.Certificate, leafCN *string) (bool, error) {

	// Make sure it's valid according to the timeframe it was issued
	if time.Now().Unix() < certificate.NotBefore.Unix() {
		ca.params.Logger.Error(ErrCertFuture)
		return false, ErrCertFuture
	}
	if time.Now().Unix() > certificate.NotAfter.Unix() {
		ca.params.Logger.Error(ErrCertExpired)
		return false, ErrCertExpired
	}

	// Check the local revocation list
	revoked, err := ca.certStore.IsRevoked(
		certificate.Subject.CommonName, certificate.SerialNumber)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, ErrCertRevoked
	}

	// Check the distribuition point CRLs
	revoked, err = ca.certStore.IsRevokedAtDistributionPoints(
		certificate.Subject.CommonName, certificate.SerialNumber)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, ErrCertRevoked
	}

	// Load the Certificate Authority Root CA certificate and any other
	// trusted root certificates that've been imported into the certificate store
	roots, err := ca.certStore.TrustedRootCertPool(ca.params.Config.AutoImportIssuingCA)
	if err != nil {
		return false, err
	}

	// Load the Certificate Authority Intermediate CA certificate and all
	// imported trusted intermediate certificates from the certificate store
	intermediates, err := ca.certStore.TrustedIntermediateCertPool()
	if err != nil {
		return false, err
	}

	// Set the verify options containing the trusted root and
	// intermediate CA certificates, verify hostname, and permitted
	// key usages.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       certificate.Subject.CommonName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// KeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Verify already checks the signatures
	// Try to locate a parent certificate to ensure the signatures match
	// parentCert, err := ca.ParentCertificateFor(certificate)
	// if err != nil {
	// 	ca.params.Logger.Error(err)
	// 	ca.params.Logger.Warningf("certificate-authority: unable to verify %s signature, no parent certificate found in certificate store",
	// 		certificate.Subject.CommonName)
	// } else {
	// 	ca.params.Logger.Debugf("certificate-authority: verifying parent and child certificate signatures match")
	// 	if err := certificate.CheckSignatureFrom(parentCert); err != nil {
	// 		ca.params.Logger.Error(err)
	// 		return false, err
	// 	}
	// }

	// Verify the certificate using the x509 runtime lib
	if _, err := certificate.Verify(opts); err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			// If the issuing authority is unknown and
			// auto-import is enabled, attempt to download
			// and import the CA certificate chain and verify
			// the leaf certificate again.
			if ca.params.Config.AutoImportIssuingCA {
				ca.params.Logger.Warningf("certificate-authority: UnknownAuthorityError: attempting to auto-import Issuer CA chain")
				if err := ca.ImportIssuingCAs(certificate, leafCN, certificate); err != nil {
					return false, err
				}
				// Attempt to verify the leaf certificate again
				// now that it's CA certs are imported.
				valid, err := ca.Verify(certificate, leafCN)
				if err != nil {
					return false, err
				}
				if !valid {
					return false, ErrCertInvalid
				}
			} else {
				return false, err
			}
		} else {
			return false, err
		}
	}

	return true, nil
}

// Retrives the parent certificate for the specified common name
func (ca *CA) ParentCertificateFor(cert *x509.Certificate) (*x509.Certificate, error) {

	var parent *x509.Certificate
	var err error

	// Check the current CA certificate first
	if ca.certificate.Subject.CommonName == cert.Issuer.CommonName {
		return ca.certificate, nil
	}

	// Check the trusted root and intermediate certificate store
	parent, err = ca.certStore.TrustedCertificateFor(cert)
	if err == nil {
		return parent, nil
	}
	if err != ErrCertNotFound {
		return nil, err
	}

	// // One last attempt to locate the parent by using the file name
	// // of an IssuingCertificateURL in the trusted root and intermediate
	// // certificate store.
	// parentCertFileName, err := ca.parseIssuerCommonName(cert)
	// if err != nil {
	// 	return nil, err
	// }
	// // Check the trusted root and intermediate certificate store
	// parent, err = ca.certStore.TrustedCertificateFor(parentCertFileName)
	// if err == nil {
	// 	return parent, nil
	// }
	// if err != ErrCertNotFound {
	// 	return nil, err
	// }

	return parent, nil
}

// Parses the Issuer common name from a child certificate
func (ca *CA) parseIssuerCommonName(cert *x509.Certificate) (string, error) {

	cn := cert.Subject.CommonName

	if len(cert.IssuingCertificateURL) == 0 {
		ca.params.Logger.Errorf("certificate-authority: no issuing CAs found in certificate")
		return "", ErrNoIssuingCA
	}

	if len(cert.IssuingCertificateURL) > 1 {
		ca.params.Logger.Error("certificate-authority: multiple issuing CAs not supported: %s", cn)
		return "", ErrCertNotSupported
	}

	if cn == "" {
		// Parse the certificate file name from the URL
		filePieces := strings.Split(cert.IssuingCertificateURL[0], "/")
		filename := filePieces[len(filePieces)-1]
		namePieces := strings.Split(filename, ".")
		cn = namePieces[0]
		// extension := ""
		// if len(namePieces) > 1  {
		// 	extension := namePieces[1]
		// }
		return cn, nil
	}

	return "", ErrCertNotSupported
}

// Download, verify and import all "CA Issuers" listed in the certificate
// and it's CRL into the Certificate Authority. The certificate(s) are added
// to the trusted certpool, but not installed to the operating system trust store.
func (ca *CA) ImportIssuingCAs(cert *x509.Certificate, leafCN *string, leaf *x509.Certificate) error {
	var err error
	for _, url := range cert.IssuingCertificateURL {
		cn := cert.Subject.CommonName
		if cn == "" {
			cn, err = ca.parseIssuerCommonName(cert)
			if err != nil {
				return err
			}
		}

		ca.params.Logger.Infof("certificate-authority: importing CA Issuer certificate from %s", url)

		// Download the certificate
		resp, err := http.Get(url)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		// Read the certificate into a memory buffer
		buf := new(bytes.Buffer)
		if _, err = io.Copy(buf, resp.Body); err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		bufBytes := buf.Bytes()

		// Parse the cert to see if there are any more parents
		// in the certificate chain.
		caCert, err := x509.ParseCertificate(bufBytes)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Verify the issuer certficate
		//
		// Disabling this for now because Intel TPM EK Platform key
		// (CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer) is throwing error:
		//
		// x509: certificate relies on legacy Common Name field, use SANs instead
		//
		// valid, err := ca.Verify(caCert, &caCert.Subject.CommonName)
		// if err != nil {
		// 	ca.params.Logger.Error(err)
		// 	return err
		// }
		// if !valid {
		// 	ca.params.Logger.Errorf("invalid certificate: %s", cn)
		// 	return err
		// }

		// Set the correct parition based on the certificate type
		var partition Partition = PARTITION_TRUSTED_INTERMEDIATE
		if caCert.IsCA && len(caCert.IssuingCertificateURL) == 0 {
			partition = PARTITION_TRUSTED_ROOT
		}

		// Stop the recursion loop and abort if the certificate already
		// exists in the certificate store.
		trustsCA, err := ca.certStore.TrustsCA(cn, partition)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		if trustsCA {
			ca.params.Logger.Errorf("certificate-authority: CA Issuer certificate already trusted: %s", cn)
			return ErrTrustExists
		}

		// Save the certificate to the Certificate Authority trust store in DER form
		err = ca.certStore.Save(cn, bufBytes, partition, FSEXT_DER)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Save the certificate to the Certificate Authority trust store in PEM form
		bufPEM, err := ca.EncodePEM(bufBytes)
		if err != nil {
			return err
		}
		err = ca.certStore.Save(cn, bufPEM, partition, FSEXT_PEM)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		ca.params.Logger.Infof("CA Issuer successfully imported: %s", cn)

		// If the certificate has parents, keep downloading
		// and importing all certificates in the chain until
		// the root certificate is reached.
		if len(caCert.IssuingCertificateURL) > 0 {
			// Found a parent cert, import it
			if err := ca.ImportIssuingCAs(caCert, leafCN, leaf); err != nil {
				ca.params.Logger.Error(err)
				return err
			}
		}
		// Done downloading cert chain
	}
	return nil
}

// Download, verify and import all "Distribution Point CRLs" listed in the certificate
// The CRL(s) are added to the Certificate Authority 3rd party CRL store and used during
// certificate verifications.
func (ca *CA) ImportDistrbutionCRLs(cert *x509.Certificate) error {
	for _, url := range cert.CRLDistributionPoints {
		cn := cert.Subject.CommonName

		exists, err := ca.certStore.HasCRL(cn)
		if err != nil {
			return err
		}
		if exists {
			ca.params.Logger.Error(ErrCRLAlreadyExists)
			return ErrCRLAlreadyExists
		}

		if cn == "" {
			cn, err = ca.parseIssuerCommonName(cert)
			if err != nil {
				return err
			}
		}

		ca.params.Logger.Infof("Importing Distribution Certificate Revocation List (CRL): %s", url)

		// Download the CRL
		resp, err := http.Get(url)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Read the CRL into a memory buffer
		buf := new(bytes.Buffer)
		if _, err = io.Copy(buf, resp.Body); err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		derBytes := buf.Bytes()

		// Parse the CRL to make sure its valid
		crl, err := x509.ParseRevocationList(derBytes)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Stop the recursion loop and abort if the CRL already
		// exists in the certificate store.
		hasCRL, err := ca.certStore.HasCRL(crl.Issuer.CommonName)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		if hasCRL {
			ca.params.Logger.Errorf("certificate-authority: CRL already imported: %s", cn)
			return ErrTrustExists
		}

		// Save the CRL to the Certificate Authority trust store in binary format
		err = ca.certStore.Save(cn, derBytes, PARTITION_CRL, FSEXT_CRL)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Save the CRL to the Certificate Authority trust store in PEM form
		// crlPEM, err := ca.EncodePEM(bufBytes)
		// if err != nil {
		// 	return err
		// }
		// err = ca.certStore.Save(cn, crlPEM, PARTITION_CRL, FSEXT_PEM)
		// if err != nil {
		// 	ca.params.Logger.Error(err)
		// 	return err
		// }

		ca.params.Logger.Infof("Distribution CRL successfully imported: %s", cn)
	}
	return nil
}

// Returns all certificates in the Certificate Authority certificate store.
func (ca *CA) IssuedCertificates() ([]string, error) {
	certs := make(map[string]bool, 0)
	files, err := os.ReadDir(ca.caDir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Name() == "ca.crl" {
			continue
		}
		certs[file.Name()] = true
	}
	names := make([]string, len(certs))
	i := 0
	for k := range certs {
		names[i] = k
		i++
	}
	sort.Strings(names)
	return names, nil
}

// Returns a validated x509 certificate from the "issued" certificate
// store partition.
func (ca *CA) Certificate(cn string) (*x509.Certificate, error) {
	der, err := ca.DER(cn)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Returns raw ASN.1 DER encoded certificate bytes from the certificate store
func (ca *CA) DER(cn string) ([]byte, error) {
	return ca.certStore.Get(cn, cn, PARTITION_ISSUED, FSEXT_DER)
}

// Returns a PEM certifcate from the cert store as []byte or
// ErrCertNotFound if the certificate does not exist.
func (ca *CA) PEM(cn string) ([]byte, error) {
	return ca.certStore.Get(cn, cn, PARTITION_ISSUED, FSEXT_PEM)
}

// Decodes CSR bytes to x509.CertificateRequest
func (ca *CA) DecodeCSR(bytes []byte) (*x509.CertificateRequest, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// Decodes PEM bytes to *x509.Certificate
func (ca *CA) DecodePEM(bytes []byte) (*x509.Certificate, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

// Encodes a raw ASN.1 DER bytes to PEM bytes
func (ca *CA) EncodePEM(derCert []byte) ([]byte, error) {
	return ca.certStore.EncodePEM(derCert)
}

// Encodes any public key (RSA/ECC) to ASN.1 DER form
func (ca *CA) EncodePubKey(pub crypto.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// Encodes a private key to ASN.1 DER PKCS8 form
func (ca *CA) EncodePrivKey(privateKey crypto.PrivateKey, password []byte) ([]byte, error) {
	pkcs8, err := pkcs8.MarshalPrivateKey(privateKey, password, nil)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return pkcs8, nil
}

// Encodes a private key to ASN.1 DER PKCS8 form
func (ca *CA) EncodePrivKeyPEM(der []byte, isEncrypted bool) ([]byte, error) {
	caPrivKeyPEM := new(bytes.Buffer)
	var keyType string

	if isEncrypted {
		keyType = "ENCRYPTED PRIVATE KEY"
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		keyType = "RSA PRIVATE KEY"
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		keyType = "EC PRIVATE KEY"
	} else {
		return nil, fmt.Errorf("%s: %s",
			ErrInvalidAlgorithm, ca.params.Config.KeyAlgorithm)
	}
	err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  keyType,
		Bytes: der,
	})
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return caPrivKeyPEM.Bytes(), nil
}

// Parses RSA private key bytes in ASN.1 DER form. This function
// supports PKCS1, PKCS8 and PKCS8 password protected private keys.
func (ca *CA) ParsePrivateKey(bytes, password []byte) (crypto.PrivateKey, error) {
	var err error
	var privKeyAny any
	// First, try parsing PKCS8 encrypted private key
	if password != nil {
		privKeyAny, err = pkcs8.ParsePKCS8PrivateKey(bytes, password)
		if err != nil {
			if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
				return nil, ErrInvalidPassword
			}
			if strings.Compare(err.Error(), "pkcs8: incorrect password") == 0 {
				return nil, ErrInvalidPassword
			}
			ca.params.Logger.Error(err)
			return nil, ErrInvalidPrivateKey
		}
		return privKeyAny, nil
	}
	// Next, raw DER PKCS8
	privKeyAny, err = x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		// ... finally, PKCS1
		privKeyAny, err = x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
				return nil, ErrInvalidPassword
			}
			ca.params.Logger.Error(err)
			return nil, ErrInvalidPrivateKey
		}
	}
	return privKeyAny.(crypto.PrivateKey), nil
}

// Returns a private key from the certificate store using the stored ASN.1
// DER PKCS8 key.
func (ca *CA) PrivateKey(cn string) (crypto.PrivateKey, error) {
	bytes, err := ca.certStore.Get(cn, cn, PARTITION_ISSUED, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Loads and parses a PKIX, ASN.1 DER RSA PKCS8 password protected
// private key from the certificate store
func (ca *CA) CAPrivKey(password []byte) (crypto.PublicKey, error) {
	return ca.certStore.CAPrivKey(password)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) CAPubKey() (crypto.PublicKey, error) {
	return ca.certStore.CAPubKey()
}

// Returns the requested PKCS8 private key from the certificate store
// "issued" partition.
func (ca *CA) PrivKey(
	cn, name string,
	password []byte,
	partition Partition) (crypto.PublicKey, error) {

	return ca.certStore.PrivKey(cn, name, password, partition)
}

// Returns the requested PKCS8 PEM private key from the certificate store
// "issued" partition
func (ca *CA) PrivKeyPEM(cn, name string, password []byte) ([]byte, error) {
	if password != nil {
		// Get the decrypted private key
		privKey, err := ca.certStore.PrivKey(cn, name, password, PARTITION_ISSUED)
		if err != nil {
			return nil, err
		}
		// Encode to (decrypted) DER form
		privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}
		// Encode to (decrypted) PEM form
		privKeyPEM, err := ca.EncodePrivKeyPEM(privKeyDER, false)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}
		return privKeyPEM, nil
	}
	// No password / encryption, return the key as-is
	return ca.certStore.Get(cn, name, PARTITION_ISSUED, FSEXT_PRIVATE_PEM)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) PubKey(cn string) (crypto.PublicKey, error) {
	return ca.certStore.PubKey(cn, cn, PARTITION_ISSUED)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
// and returns it in PEM form.
func (ca *CA) PubKeyPEM(cn string) ([]byte, error) {
	return ca.certStore.PubKeyPEM(cn, cn, PARTITION_ISSUED)
}

// Imports a new x509 certificate to the certificate store.
func (ca *CA) Import(cert *x509.Certificate) error {
	return ca.ImportDER(cert.Subject.CommonName, cert.Raw)
}

// Imports a new x509 certificate to the certificate store using
// the specified common name.
func (ca *CA) ImportCN(cn string, cert *x509.Certificate) error {
	return ca.ImportDER(cn, cert.Raw)
}

// Import a raw DER certificate and perform the following operations:
// 1. Parse to ensure it's valid
// 2. Verify the certificate (auto-import issuer CA's if enabled)
// 3. Format & save as PEM
// 4. Extract and save the public key
func (ca *CA) ImportDER(cn string, derCert []byte) error {

	// Parse the certificate to ensure it's valid
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Set the proper partition based on the certificate type
	var partition Partition = PARTITION_ISSUED
	if cert.IsCA {
		partition = PARTITION_CA
	}

	// Save the DER form to the certificate store
	err = ca.certStore.Save(cn, derCert, partition, FSEXT_DER)
	if err != nil {
		return err
	}

	// Encode the DER form to PEM form and save it to
	// the certificate store
	pemBytes, err := ca.EncodePEM(derCert)
	if err != nil {
		return err
	}
	if err := ca.certStore.Save(cn, pemBytes, partition, FSEXT_PEM); err != nil {
		return err
	}

	// Verify the certificate
	valid, err := ca.Verify(cert, &cn)
	if err != nil {
		ca.params.Logger.Warning(err)
	}
	if !valid && ca.params.Config.AutoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &cn, cert); err != nil {
			return err
		}
	}

	return nil
	//return ca.IssuePubKey(cn, cert.PublicKey)
}

// Import a PEM certificate to the certificate store. The certificate
// is parsed and verified prior to import to ensure it's valid.
func (ca *CA) ImportPEM(cn string, pemBytes []byte) error {

	// Parse the certificat to ensure it's valid
	cert, err := ca.DecodePEM(pemBytes)
	if err != nil {
		return err
	}

	// Import the intermediate and root certificates so the
	// cert can be validated, if not already in the store
	valid, err := ca.Verify(cert, &cn)
	if err != nil {
		ca.params.Logger.Warning(err)
	}
	if !valid && ca.params.Config.AutoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &cn, cert); err != nil {
			return err
		}
	}

	return ca.certStore.Save(cn, pemBytes, PARTITION_ISSUED, FSEXT_PEM)
}

// Saves a private key to the certificate store "issued" partition in ASN.1 DER
// PKCS8 and PEM (PCKS8) form
func (ca *CA) IssuePrivKey(cn string, privateKey crypto.PrivateKey, password []byte) error {
	return ca.issuePrivKey(cn, privateKey, password, PARTITION_ISSUED)
}

// Saves a CA private key to the certificate store in ASN.1 DER PKCS8 and PEM (PCKS8) form
func (ca *CA) issueCAPrivKey(cn string, privateKey crypto.PrivateKey, password []byte) error {
	return ca.issuePrivKey(cn, privateKey, password, PARTITION_CA)
}

// Extracts the public key from the private key and saves both to the certificate store
// in ASN.1 DER PKCS8 and PEM (PCKS8) form
func (ca *CA) issuePrivKey(
	cn string,
	privateKey crypto.PrivateKey,
	password []byte,
	partition Partition) error {

	isEncrypted := false

	// Ensure password meets configuration and complexity requirements
	if ca.params.Config.RequirePrivateKeyPassword {
		if password == nil {
			return ErrPrivateKeyPasswordRequired
		}
		if !ca.passwordPolicy.MatchString(string(password)) {
			return fmt.Errorf("%s: %s", ErrPasswordComplexity, ca.passwordPolicy)
		}
		isEncrypted = true
	}
	isEncrypted = password != nil
	// Encode the password to PKCS8
	pkcs8, err := ca.EncodePrivKey(privateKey, password)
	err = ca.certStore.Save(cn, pkcs8, partition, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Encode to PEM form
	pkcs8PEM, err := ca.EncodePrivKeyPEM(pkcs8, isEncrypted)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Save the private key to the requested partition
	err = ca.certStore.Save(cn, pkcs8PEM, partition, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		rsaPriv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivateKeyRSA
		}
		return ca.issuePubKey(cn, &rsaPriv.PublicKey, partition)
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		eccPriv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivateKeyECC
		}
		return ca.issuePubKey(cn, &eccPriv.PublicKey, partition)
	}
	return ErrInvalidAlgorithm
}

// Encodes a public key as PKIX, ASN.1 DER and PEM form and saves both to the
// certificate store "issued" partition
func (ca *CA) IssuePubKey(cn string, pub crypto.PublicKey) error {
	return ca.issuePubKey(cn, pub, PARTITION_ISSUED)
}

// Encodes a public key ASN.1 DER form public key to PEM form
func (ca *CA) EncodePubKeyPEM(cn string, derBytes []byte) ([]byte, error) {
	pubPEM := new(bytes.Buffer)
	err := pem.Encode(pubPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return pubPEM.Bytes(), err
}

// Decodes and returns an ASN.1 DER - PEM encoded - RSA Public Key
func (ca *CA) DecodeRSAPubKeyPEM(bytes []byte) (crypto.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return pubKey.(crypto.PublicKey), nil
}

// Imports any public key (RSA/ECC) to the certificate store in PEM form
func (ca *CA) ImportPubKey(cn string, pub crypto.PublicKey) error {
	pubDER, err := ca.EncodePubKey(pub)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	return ca.certStore.Save(cn, pubPEM, PARTITION_PUBLIC_KEYS, FSEXT_PUBLIC_PEM)
}

// Imports a root CA certificate into the trusted root store
func (ca *CA) ImportTrustedRoot(cn string, derCert []byte) error {
	return ca.importTrustedCert(cn, derCert, PARTITION_TRUSTED_ROOT)
}

// Imports an intermediate CA certificate into the trusted intermediate store
func (ca *CA) ImportTrustedIntermediate(cn string, derCert []byte) error {
	return ca.importTrustedCert(cn, derCert, PARTITION_TRUSTED_INTERMEDIATE)
}

// Generates a new certificate serial number
func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// Parses extended IP, DNS, and Email addresses SubjectAlternativeNames (SANS)
func parseSANS(sans *SubjectAlternativeNames) ([]net.IP, []string, []string, error) {
	var ipAddresses []net.IP
	var dnsNames []string
	var emailAddresses []string
	if sans != nil {
		ipAddresses = make([]net.IP, len(sans.IPs))
		for i, ip := range sans.IPs {
			ip, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip)) // ip, ipnet, err
			if err != nil {
				return nil, nil, nil, err
			}
			ipAddresses[i] = ip
		}
		dnsNames = make([]string, len(sans.DNS))
		copy(dnsNames, sans.DNS)
		emailAddresses = make([]string, len(sans.Email))
		copy(emailAddresses, sans.Email)
	}
	return ipAddresses, dnsNames, emailAddresses, nil
}

// Build Subject Key Identifier
func (ca *CA) createSubjectKeyIdentifier() ([]byte, error) {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	spkiASN1, err := x509.MarshalPKIXPublicKey(ca.publicKey)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
}

// Imports a CA certificate into the specified trust store partition
func (ca *CA) importTrustedCert(cn string, derCert []byte, partition Partition) error {
	err := ca.certStore.Save(cn, derCert, partition, FSEXT_DER)
	if err != nil {
		return err
	}
	pem, err := ca.EncodePEM(derCert)
	if err != nil {
		return err
	}
	return ca.certStore.Save(cn, pem, partition, FSEXT_PEM)
}

// Encodes a public key to PEM form and saves it to the certificate store
func (ca *CA) issuePubKey(cn string, pub crypto.PublicKey, partition Partition) error {
	// PKIX, ASN.1 DER form
	pubDER, err := ca.EncodePubKey(pub)
	if err != nil {
		return err
	}
	// Save the ASN.1 DER PKCS1 form
	if err := ca.certStore.Save(cn, pubDER, partition, FSEXT_PUBLIC_PKCS1); err != nil {
		return err
	}
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubDER)
	// pubPEM := new(bytes.Buffer)
	// err = pem.Encode(pubPEM, &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: privKeyDER,
	// })
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Save the PEM (PKCS1) form
	return ca.certStore.Save(cn, pubPEM, partition, FSEXT_PUBLIC_PEM)
}

// Imports the Root CA certificate into the trusted root store of an Intermediate
// Certificate Authority.
func (ca *CA) importRootCA() error {

	// Save DER certificate
	err := ca.certStore.Save(
		ca.parentCertificate.Subject.CommonName,
		ca.parentCertificate.Raw,
		PARTITION_TRUSTED_ROOT,
		FSEXT_DER)
	if err != nil {
		return err
	}

	// Save PEM certificate
	rootPEM, err := ca.EncodePEM(ca.parentCertificate.Raw)
	if err != nil {
		return nil
	}
	err = ca.certStore.Save(
		ca.parentCertificate.Subject.CommonName,
		rootPEM,
		PARTITION_TRUSTED_ROOT,
		FSEXT_PEM)
	if err != nil {
		return err
	}

	// Save RSA public key to the CA public keys partition
	err = ca.ImportPubKey(
		ca.parentCertificate.Subject.CommonName,
		ca.parentPubKey)
	if err != nil {
		return err
	}

	// Verify the Intermediate CA cert
	valid, err := ca.Verify(ca.certificate,
		&ca.certificate.Subject.CommonName)
	if err != nil {
		// return err
		ca.params.Logger.Warning(err)
	}
	if !valid {
		return ErrCertInvalid
	}

	return nil
}

func (ca *CA) createCABundle() error {

	if ca.parentCertificate == nil {
		return errors.New("certificate-authority: parent CA needed to create bundle")
	}

	certs := make([][]byte, 0)

	// Encode the CA certificate to PEM
	caPEM, err := ca.EncodePEM(ca.certificate.Raw)
	if err != nil {
		return err
	}
	err = ca.certStore.Save(
		ca.certificate.Subject.CommonName,
		caPEM,
		PARTITION_CA,
		FSEXT_CA_BUNDLE_PEM)
	if err != nil {
		return err
	}
	certs = append(certs, caPEM)

	// Encode the parent certificate to PEM
	parentPEM, err := ca.EncodePEM(ca.parentCertificate.Raw)
	if err != nil {
		return err
	}
	err = ca.certStore.Append(
		ca.certificate.Subject.CommonName,
		parentPEM,
		PARTITION_CA,
		FSEXT_CA_BUNDLE_PEM)
	if err != nil {
		return err
	}
	certs = append(certs, caPEM)

	// Append any other Issuing CAs
	for _, issuer := range ca.parentCertificate.IssuingCertificateURL {
		cn, _ := util.FileName(issuer)
		certPEM, err := ca.certStore.Get(cn, cn, PARTITION_CA, FSEXT_PEM)
		if err != nil {
			return err
		}
		err = ca.certStore.Append(
			ca.certificate.Subject.CommonName,
			certPEM,
			PARTITION_CA,
			FSEXT_CA_BUNDLE_PEM)
		certs = append(certs, caPEM)
	}

	// Walk the array backwards - CA bundle strats with the Leaf
	// and ends with the Root
	for i := len(certs) - 1; i >= 0; i-- {
		ca.params.Logger.Debug(string(certs[i]))
	}

	return nil
}

// Returns a CA "bundle" that contains all of the certificates
// in the chain up to the Root. This file is useful for clients
// who wish to verify a TLS connection to a server who was issued
// a certificate from this CA.
func (ca *CA) CABundle() ([]byte, error) {
	return ca.certStore.Get(
		ca.certificate.Subject.CommonName,
		ca.certificate.Subject.CommonName,
		PARTITION_CA,
		FSEXT_CA_BUNDLE_PEM)
}

// Returns a CA "bundle" that contains all of the certificates
// in the chain up to the Root. This file is useful for clients
// who wish to verify a TLS connection to a server who was issued
// a certificate from this CA.
func (ca *CA) CABundleCertPool() (*(x509.CertPool), error) {

	rootCAs := x509.NewCertPool()
	bundlePEM, err := ca.CABundle()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	if !rootCAs.AppendCertsFromPEM(bundlePEM) {
		ca.params.Logger.Error(err)
		return nil, ErrCertInvalid
	}

	return rootCAs, nil
}

// Parses a PEM encoded CA bundle with multiple certificates
// and returns and array of x509 certificates that can be used
// for verification or creating a CertPool.
func (ca *CA) ParseCABundle(bundle []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	// keys := make([]*rsa.PrivateKey, 0)
	for block, rest := pem.Decode(bundle); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ca.params.Logger.Error(err)
				return nil, err
			}
			certs = append(certs, cert)
		// case "PRIVATE KEY":
		// 	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		// 	if err != nil {
		// 		ca.params.Logger.Error(err)
		// 		return nil, err
		// 	}
		// 	keys = append(keys, key)
		default:
			ca.params.Logger.Error("certificate-authority: invalid certificate in bundle")
			return nil, ErrCertInvalid
		}
	}
	return certs, nil
}

// Returns an x509 certificate KeyPair suited for tls.Config
func (ca *CA) X509KeyPair(cn, name string, password []byte) (tls.Certificate, error) {

	privKeyPEM, err := ca.PrivKeyPEM(cn, name, password)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM, err := ca.PEM(cn)
	if err != nil {
		return tls.Certificate{}, err
	}

	ca.params.Logger.Debugf(
		"certificate-authority: Loading TLS KeyPair: cn: %s, name: %s", cn, name)

	ca.params.Logger.Debugf("\n%s", string(certPEM))

	if ca.params.DebugSecrets {
		ca.params.Logger.Debugf(
			"certificate-authority: TLS KeyPair password: %s", password)
		ca.params.Logger.Debugf("\n%s", string(privKeyPEM))
	}

	// Create the new x509 keypair using the public and private
	// key pair
	keypair, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Set the leaf certificate to reduce per-handshake processing
	cert, err := ca.Certificate(cn)
	if err != nil {
		return tls.Certificate{}, err
	}
	keypair.Leaf = cert

	return keypair, err
}

// Returns a tls.Config for the requested common name populated with the
// Certificate Authority Trusted Root certificates and leaf certifiate.
func (ca *CA) TLSConfig(cn, name string, password []byte, includeSystemRoot bool) (*tls.Config, error) {

	rootCAs, err := ca.TrustedRootCertPool(includeSystemRoot)
	if err != nil {
		return nil, err
	}

	cert, err := ca.X509KeyPair(cn, name, password)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// Returns the requested blob from the blob store
func (ca *CA) Blob(key string) ([]byte, error) {
	return ca.certStore.Blob(key)
}

// Saves a new blob to the blob store
func (ca *CA) ImportBlob(key string, data []byte) error {
	return ca.certStore.SaveBlob(key, data)
}

// Sets the Elliptical Curve Cryptography curve to use when
// generating ECC keys / certificates
func (ca *CA) setCurve() error {
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		switch ca.params.Config.EllipticalCurve {
		case "P224":
			ca.curve = elliptic.P224()
		case "P256":
			ca.curve = elliptic.P256()
		case "P384":
			ca.curve = elliptic.P384()
		case "P521":
			ca.curve = elliptic.P521()
		default:
			return fmt.Errorf("%s: %s", ErrInvalidCurve, ca.params.Config.EllipticalCurve)
		}
	}
	return nil
}

// Encodes a public key as PKIX, ASN.1 DER and PEM form and saves both to the
// certificate store CA partition
func (ca *CA) issueCAPubKey(cn string) error {
	return ca.issuePubKey(cn, ca.publicKey, PARTITION_CA)
}

// Create a dummy certificate and revoke it to initialize the CRL
func (ca *CA) initCRL(password []byte) error {
	ca.params.Logger.Info("Initializing Certificate Revocation List")
	cn := "dummy"
	dummyCert := CertificateRequest{
		Valid: 1,
		Subject: Subject{
			CommonName: cn,
		},
	}
	certPassword := []byte("$3cretP4s5")
	_, err := ca.IssueCertificate(dummyCert, password, certPassword)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	return ca.Revoke(cn, password)
}

// Ensures the specified password meets requirements and returns
// a boolean flag indicating if the key is encrypted.
//
// ErrPrivateKeyPasswordRequired is returned if a password is
// required but the specified password is nil
//
// ErrPasswordComplexity is returned if the password fails to meet
// password complexity requirements.
func (ca *CA) checkPassword(password []byte) (bool, error) {
	isEncrypted := false
	if ca.params.Config.RequirePrivateKeyPassword {
		if password == nil {
			return false, ErrPrivateKeyPasswordRequired
		}
		if !ca.passwordPolicy.MatchString(string(password)) {
			return false, ErrPasswordComplexity
		}
		isEncrypted = true
	}
	return isEncrypted, nil
}
