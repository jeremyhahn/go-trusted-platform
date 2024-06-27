package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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
	"sort"
	"strings"
	"time"

	"github.com/op/go-logging"

	"github.com/jeremyhahn/go-trusted-platform/util"
)

const (
	KEY_ALGO_RSA = "RSA"
	KEY_ALGO_ECC = "ECC"

	CURVE_P224 = "P256"
	CURVE_P256 = "P256"
	CURVE_P384 = "P386"
	CURVE_P521 = "P521"
)

var (
	ErrInvalidConfig        = errors.New("certificate-authority: invalid configuration")
	ErrCorruptWrite         = errors.New("certificate-authority: corrupt write: bytes written does not match data length")
	ErrCertRevoked          = errors.New("certificate-authority: certificate revoked")
	ErrCertNotFound         = errors.New("certificate-authority: certificate not found")
	ErrCertFuture           = errors.New("certificate-authority: certificate issued in the future")
	ErrCertExpired          = errors.New("certificate-authority: certificate expired")
	ErrCertInvalid          = errors.New("certificate-authority: certificate invalid")
	ErrTrustExists          = errors.New("certificate-authority: certificate already trusted")
	ErrInvalidSignature     = errors.New("certificate-authority: invalid signature")
	ErrCRLAlreadyExists     = errors.New("certificate-authority: revocation list already exists")
	ErrNoIssuingCA          = errors.New("certificate-authority: no issuing CAs found in certificate")
	ErrCertNotSupported     = errors.New("certificate-authority: certificate contains unsupported configuration")
	ErrBlobNotFound         = errors.New("certificate-authority: signed blob not found")
	ErrInvalidPublicKey     = errors.New("certificate-authority: invalid public key")
	ErrInvalidPrivateKey    = errors.New("certificate-authority: invalid private key")
	ErrInvalidPublicKeyRSA  = errors.New("certificate-authority: invalid RSA public key")
	ErrInvalidPrivateKeyRSA = errors.New("certificate-authority: invalid RSA private key")
	ErrInvalidPublicKeyECC  = errors.New("certificate-authority: invalid ECC public key")
	ErrInvalidPrivateKeyECC = errors.New("certificate-authority: invalid ECC private key")
	ErrInvalidEncodingPEM   = errors.New("certificate-authority: invalid PEM encoding")
	ErrInvalidCurve         = errors.New("certificate-authority: invalid ECC Curve")
	ErrInvalidAlgorithm     = errors.New("certificate-authority: invalid algorithm")
)

type CertificateAuthority interface {
	CABundle() ([]byte, error)
	CABundleCertPool() (*(x509.CertPool), error)
	CACertificate() *x509.Certificate
	CAPubKey() (crypto.PublicKey, error)
	Certificate(cn string) (*x509.Certificate, error)
	CertStore() CertificateStore
	CreateCSR(email string, request CertificateRequest) ([]byte, error)
	DecodeCSR(bytes []byte) (*x509.CertificateRequest, error)
	EncodePEM(derCert []byte) ([]byte, error)
	EncodePubKey(pub crypto.PublicKey) ([]byte, error)
	EncodePubKeyPEM(cn string, derBytes []byte) ([]byte, error)
	EncodePrivKey(privateKey crypto.PrivateKey) ([]byte, error)
	EncodePrivKeyPEM(der []byte) ([]byte, error)
	EncryptionKey(cn, keyName string) (*rsa.PublicKey, error)
	DecodePEM(bytes []byte) (*x509.Certificate, error)
	DecodeRSAPubKeyPEM(bytes []byte) (crypto.PublicKey, error)
	DER(cn string) ([]byte, error)
	Init(identity Identity, parentPrivKey crypto.PrivateKey, random io.Reader) error
	Identity() *x509.Certificate
	IsAutoImportingIssuerCAs() bool
	IsReady() bool
	IssueCertificate(request CertificateRequest) ([]byte, error)
	IssuedCertificates() ([]string, error)
	IssueCAPrivKey(cn string, privateKey crypto.PrivateKey) error
	IssueCAPubKey(cn string, pub crypto.PublicKey) error
	IssuePrivKey(cn string, privateKey crypto.PrivateKey) error
	IssuePubKey(cn string, pub crypto.PublicKey) error
	Import(cer *x509.Certificate) error
	ImportCN(cn string, cert *x509.Certificate) error
	ImportDER(cn string, derCert []byte) error
	ImportDistrbutionCRLs(cert *x509.Certificate) error
	ImportPEM(cn string, pemBytes []byte) error
	ImportIssuingCAs(cert *x509.Certificate, leafCN *string, leaf *x509.Certificate) error
	ImportTrustedRoot(cn string, derCert []byte) error
	ImportTrustedIntermediate(cn string, derCert []byte) error
	ImportPubKey(cn string, pub crypto.PublicKey) error
	NewEncryptionKey(cn, keyName string) (*rsa.PublicKey, error)
	ParseCABundle(bundle []byte) ([]*x509.Certificate, error)
	ParsePrivateKey([]byte) (crypto.PrivateKey, error)
	PEM(cn string) ([]byte, error)
	PersistentSign(key string, data []byte, saveData bool) error
	PersistentVerifySignature(cn string, data []byte) error
	PubKey(cn string) (crypto.PublicKey, error)
	RSADecrypt(cn, keyName string, ciphertext []byte) ([]byte, error)
	RSAEncrypt(cn, keyName string, data []byte) ([]byte, error)
	Revoke(cn string) error
	RootCertificate() (*x509.Certificate, error)
	RootCertForCA(cn string) (*x509.Certificate, error)
	Sign(key []byte) ([]byte, error)
	Signature(key string) ([]byte, error)
	Signed(key string) (bool, error)
	SignedData(key string) ([]byte, error)
	SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error)
	TrustStore() TrustStore
	TrustedRootCertificate(cn string) (*x509.Certificate, error)
	TrustedRootCertPool(includeSystemRoot bool) (*x509.CertPool, error)
	TrustedIntermediateCertificate(cn string) (*x509.Certificate, error)
	TrustedIntermediateCertPool() (*x509.CertPool, error)
	Verify(certificate *x509.Certificate, leafCN *string) (bool, error)
	VerifySignature(data []byte, signature []byte) error
	X509KeyPair(cn string) (tls.Certificate, error)
	TLSConfig(cn string, includeSystemRoot bool) (*tls.Config, error)
	DefaultValidityPeriod() int
}

type CA struct {
	logger              *logging.Logger
	config              *Config
	rootDir             string
	certDir             string
	parentIdentity      *Identity
	parentCertificate   *x509.Certificate
	parentPubKey        crypto.PublicKey
	identity            Identity
	signatureAlgorithm  x509.SignatureAlgorithm
	certificate         *x509.Certificate
	publicKey           crypto.PublicKey
	curve               elliptic.Curve
	trustStore          TrustStore
	certStore           CertificateStore
	commonName          string
	autoImportIssuingCA bool
	random              io.Reader
	CertificateAuthority
}

// Create x509 Root and Intermediate Certificate Authorities
func NewCA(
	logger *logging.Logger,
	rootDir string,
	config *Config,
	random io.Reader) (CertificateAuthority, map[string]CertificateAuthority, error) {

	// Root CA
	rootCA, err := NewRootCA(logger, rootDir, config)
	if err != nil {
		return nil, nil, err
	}
	if err := rootCA.Init(config.Identity[0], nil, random); err != nil {
		return nil, nil, err
	}
	rootPubKey, err := rootCA.CAPubKey()
	if err != nil {
		return nil, nil, err
	}

	// Intermediate CA's
	intermediates := make(map[string]CertificateAuthority, len(config.Identity)-1)
	intermediateIdentities := config.Identity[1:]
	for _, identity := range intermediateIdentities {
		intermediateCA, err := NewIntermediateCA(
			logger,
			rootDir,
			config,
			identity,
			config.Identity[0],
			rootCA.CACertificate(),
			rootPubKey,
			config.AutoImportIssuingCA)
		if err != nil {
			return nil, nil, err
		}
		caPrivKey, err := rootCA.CertStore().CAPrivKey()
		if err != nil {
			return nil, nil, err
		}
		if err := intermediateCA.Init(identity, caPrivKey, random); err != nil {
			return nil, nil, err
		}
		intermediates[identity.Subject.CommonName] = intermediateCA
	}

	return rootCA, intermediates, nil
}

// Creates a new x509 Root Certificate Authority
func NewRootCA(
	logger *logging.Logger,
	rootDir string,
	config *Config) (CertificateAuthority, error) {

	if config == nil {
		return nil, ErrInvalidConfig
	}

	if len(config.Identity) < 2 {
		logger.Error("certificate-authority: Root and at least 1 Intermediate CA required")
		return nil, ErrInvalidConfig
	}

	certDir := fmt.Sprintf("%s/%s",
		rootDir,
		config.Identity[0].Subject.CommonName)

	if err := os.MkdirAll(certDir, os.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}

	return &CA{
		logger:              logger,
		config:              config,
		rootDir:             rootDir,
		certDir:             certDir,
		identity:            config.Identity[0],
		trustStore:          NewDebianTrustStore(logger, certDir),
		commonName:          config.Identity[0].Subject.CommonName,
		autoImportIssuingCA: config.AutoImportIssuingCA}, nil
}

// Create a new x509 Intermediate Certificate Authority
func NewIntermediateCA(
	logger *logging.Logger,
	rootDir string,
	config *Config,
	identity Identity,
	parentIdentity Identity,
	parentCertificate *x509.Certificate,
	parentPubKey crypto.PublicKey,
	autoImportIssuingCA bool) (CertificateAuthority, error) {

	certDir := fmt.Sprintf("%s/%s",
		rootDir,
		identity.Subject.CommonName)

	if err := os.MkdirAll(rootDir, os.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}

	return &CA{
		logger:              logger,
		rootDir:             rootDir,
		config:              config,
		certDir:             certDir,
		identity:            identity,
		parentIdentity:      &parentIdentity,
		parentCertificate:   parentCertificate,
		parentPubKey:        parentPubKey,
		trustStore:          NewDebianTrustStore(logger, certDir),
		commonName:          identity.Subject.CommonName,
		autoImportIssuingCA: autoImportIssuingCA}, nil
}

// Sets the Elliptical Curve Cryptography Curve to use when
// generating ECC keys / certificates
func (ca *CA) setCurve() error {
	if ca.config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
		switch ca.config.EllipticalCurve {
		case "P224":
			ca.curve = elliptic.P224()
		case "P256":
			ca.curve = elliptic.P256()
		case "P384":
			ca.curve = elliptic.P384()
		case "P521":
			ca.curve = elliptic.P521()
		default:
			return fmt.Errorf("%s: %s", ErrInvalidCurve, ca.config.EllipticalCurve)
		}
		ca.signatureAlgorithm = x509.ECDSAWithSHA256
	}
	return nil
}

// Returns the default number of days certificates issued by
// the CA are valid. If a CSR is submitted that is requesting
// "0 days", the CA default value is used instead of the 0 value.
func (ca *CA) DefaultValidityPeriod() int {
	return ca.config.ValidDays
}

// Returns true if auto-importing of CA certificates are enabled
func (ca *CA) IsAutoImportingIssuerCAs() bool {
	return ca.config.AutoImportIssuingCA
}

// Returns the backend certificate store used to
func (ca *CA) CertStore() CertificateStore {
	return ca.certStore
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

// Returns true if the Certificate Authority is initialized and ready
// to start servicing requests.
func (ca *CA) IsReady() bool {
	caCert := fmt.Sprintf("%s/%s%s", ca.certDir, ca.commonName, FSEXT_PUBLIC_PEM)
	if _, err := os.Stat(caCert); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		ca.logger.Error(err)
		return false
	}
}

// The first time the Certificate Authority is instantiated, a new root and intermediate
// RSA private / public key pair and x509 signing certificate is generated and saved to
// the cert store. Subsequent initializations load the generated keys and certificates
// so the CA is ready to start servicing requests. Certificates are saved to the cert
// store in DER, PEM, PKCS#1 and PKCS#8 formats.
func (ca *CA) Init(identity Identity, parentPrivKey crypto.PrivateKey, random io.Reader) error {

	if err := ca.setCurve(); err != nil {
		return err
	}

	// Set the Random Number Generator and ECC curve
	// based on platform configuration.
	ca.random = random

	if ca.IsReady() {
		return ca.loadCA()
	}

	ca.logger.Debugf("Initializing Certificate Authority: %s", ca.commonName)

	var privateKey crypto.PrivateKey

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(identity.SANS)
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	if ca.config.DefaultKeyAlgorithm == KEY_ALGO_RSA {
		privateKeyRSA, err := rsa.GenerateKey(random, identity.KeySize)
		if err != nil {
			ca.logger.Error(err)
			return err
		}
		privateKey = privateKeyRSA
		ca.publicKey = &privateKeyRSA.PublicKey
		ca.signatureAlgorithm = x509.SHA256WithRSA
	} else if ca.config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
		privateKeyECC, err := ecdsa.GenerateKey(ca.curve, rand.Reader)
		if err != nil {
			ca.logger.Error(err)
			return err
		}
		privateKey = privateKeyECC
		ca.publicKey = &privateKeyECC.PublicKey
		// set in the call to setCurve
		// ca.signatureAlgorithm = x509.ECDSAWithSHA256
	} else {
		return fmt.Errorf("%s: %s", ErrInvalidAlgorithm, ca.config.DefaultKeyAlgorithm)
	}

	subjectKeyID, err := ca.createSubjectKeyIdentifier()
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	subject := pkix.Name{
		CommonName:         identity.Subject.CommonName,
		Organization:       []string{identity.Subject.Organization},
		OrganizationalUnit: []string{identity.Subject.OrganizationalUnit},
		Country:            []string{identity.Subject.Country},
		Province:           []string{identity.Subject.Province},
		Locality:           []string{identity.Subject.Locality},
		StreetAddress:      []string{identity.Subject.Address},
		PostalCode:         []string{identity.Subject.PostalCode}}

	template := &x509.Certificate{
		SignatureAlgorithm:    ca.signatureAlgorithm,
		PublicKeyAlgorithm:    x509.PublicKeyAlgorithm(ca.signatureAlgorithm),
		SerialNumber:          serialNumber,
		Issuer:                subject,
		Subject:               subject,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        subjectKeyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(identity.Valid, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		EmailAddresses:        emailAddresses}

	// If this is an Intermediate Certificate Authority,
	// use the root certificate to sign the certificate,
	// otherwise, self-sign.
	parentCertificate := ca.parentCertificate
	if parentCertificate == nil {
		parentCertificate = template
	}

	// If this an Intermediate Certificate Authority, use
	// the parent CA's private key to sign the Intermediate
	// Certificate Authority's certificate.
	usePrivKey := privateKey
	if parentPrivKey != nil {
		usePrivKey = parentPrivKey
	}

	// Create the new Root / Intermediate CA certificate
	caDerCert, err := x509.CreateCertificate(rand.Reader,
		template, parentCertificate, ca.publicKey, usePrivKey)
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	// Parse the generated DER and set it as the CA certificate
	ca.certificate, err = x509.ParseCertificate(caDerCert)
	if err != nil {
		ca.logger.Error(err)
		return nil
	}

	// Create the backend certificate store
	ca.certStore, err = NewFileSystemCertStore(ca.logger, ca.certDir, ca.certificate)
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	if err := ca.ImportDER(ca.commonName, caDerCert); err != nil {
		return nil
	}

	if err = ca.IssueCAPrivKey(ca.commonName, privateKey); err != nil {
		return err
	}

	// Install the CA certificate to the operating system trust store
	// (needs root to install: run CLI "ca" command as root instead of running the server as root?)
	// if err := ca.trustStore.Install(ca.commonName); err != nil {
	// 	ca.logger.Error(err)
	// 	return err
	// }

	// If this is an Intermediate Certificate Authority, import the
	// Root CA certificate into the trusted root certificate store
	// and create a CA bundle file for TLS clients to verify issued
	// certificates.
	if ca.parentIdentity != nil {
		ca.importRootCA()
		ca.createCABundle()
	}

	return nil
}

// Creates a new Certificate Signing Request (CSR)
func (ca *CA) CreateCSR(email string, request CertificateRequest) ([]byte, error) {

	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.logger.Error(err)
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

	caPrivateKey, err := ca.certStore.CAPrivKey()
	csrPEM := new(bytes.Buffer)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, caPrivateKey)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}

	if err := pem.Encode(csrPEM, csrBlock); err != nil {
		ca.logger.Error(err)
		return nil, err
	}

	pemBytes := csrPEM.Bytes()
	err = ca.certStore.Save(
		request.Subject.CommonName,
		pemBytes,
		PARTITION_ISSUED,
		FSEXT_CSR)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}

	ca.logger.Debug(string(pemBytes))

	return pemBytes, nil
}

// Signs a Certificate Signing Request (CSR) and stores it in the cert store
// in PEM format. This method returns the raw DER encoded []byte array as
// returned from x509.CreateCertificate.
func (ca *CA) SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error) {

	csr, err := ca.DecodeCSR(csrBytes)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}

	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.logger.Error(err)
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

	caPrivateKey, err := ca.certStore.CAPrivKey()
	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, ca.certificate, template.PublicKey, caPrivateKey)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	if err := ca.ImportDER(csr.Subject.CommonName, derBytes); err != nil {
		return nil, err
	}

	return ca.EncodePEM(derBytes)
}

// Create a new private / public key pair and save it to the cert store
// in DER and PEM form. This method returns the raw DER encoded []byte
// as returned from x509.CreateCertificate.
func (ca *CA) IssueCertificate(request CertificateRequest) ([]byte, error) {
	if request.Valid == 0 {
		request.Valid = ca.config.ValidDays
	}
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	dnsNames = append(dnsNames, request.Subject.CommonName)
	serialNumber, err := newSerialNumber()
	if err != nil {
		ca.logger.Error(err)
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

	var certPubKey crypto.PublicKey
	if ca.config.DefaultKeyAlgorithm == KEY_ALGO_RSA {
		privateKeyRSA, err := rsa.GenerateKey(ca.random, ca.identity.KeySize)
		if err != nil {
			ca.logger.Error(err)
			return nil, err
		}
		certPubKey = &privateKeyRSA.PublicKey
	} else if ca.config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
		privateKeyECC, err := ecdsa.GenerateKey(ca.curve, rand.Reader)
		if err != nil {
			ca.logger.Error(err)
			return nil, err
		}
		certPubKey = &privateKeyECC.PublicKey
	} else {
		return nil, fmt.Errorf("%s: %s", ErrInvalidAlgorithm, ca.config.DefaultKeyAlgorithm)
	}

	caPrivateKey, err := ca.certStore.CAPrivKey()
	certDerBytes, err := x509.CreateCertificate(
		rand.Reader, cert, ca.certificate, certPubKey, caPrivateKey)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	caPrivateKey = nil

	if err := ca.ImportDER(request.Subject.CommonName, certDerBytes); err != nil {
		return nil, err
	}

	return certDerBytes, nil
}

// Revoke a certificate
func (ca *CA) Revoke(cn string) error {

	// Load the requested cert
	certPEM, err := ca.PEM(cn)
	if err != nil {
		return err
	}

	// Decode the PEM to a *x509.Certificate
	certificate, err := ca.DecodePEM(certPEM)
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	// Check the certificate store to see if this certificate has
	// been added to the revocation list, and exists in the revoked
	// partition.
	revoked, err := ca.certStore.IsRevoked(cn, certificate.SerialNumber)
	if err != nil {
		return err
	}
	if revoked {
		return ErrCertRevoked
	}

	return ca.certStore.Revoke(cn, certificate)
}

// Verify certificate is valid
func (ca *CA) Verify(certificate *x509.Certificate, leafCN *string) (bool, error) {

	// Make sure it's valid according to the timeframe it was issued
	if time.Now().Unix() < certificate.NotBefore.Unix() {
		ca.logger.Error(ErrCertFuture)
		return false, ErrCertFuture
	}
	if time.Now().Unix() > certificate.NotAfter.Unix() {
		ca.logger.Error(ErrCertExpired)
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
	roots, err := ca.certStore.TrustedRootCertPool(ca.autoImportIssuingCA)
	if err != nil {
		return false, err
	}
	intermediates := x509.NewCertPool()

	if ca.parentCertificate != nil {
		// Load the Certificate Authority Intermediate CA certificate and all
		// imported trusted intermediate certificates from the certificate store
		intermediates, err = ca.certStore.TrustedIntermediateCertPool()
		if err != nil {
			return false, err
		}
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
	// 	ca.logger.Error(err)
	// 	ca.logger.Warningf("certificate-authority: unable to verify %s signature, no parent certificate found in certificate store",
	// 		certificate.Subject.CommonName)
	// } else {
	// 	ca.logger.Debugf("certificate-authority: verifying parent and child certificate signatures match")
	// 	if err := certificate.CheckSignatureFrom(parentCert); err != nil {
	// 		ca.logger.Error(err)
	// 		return false, err
	// 	}
	// }

	// Verify the certificate using the x509 runtime lib
	if _, err := certificate.Verify(opts); err != nil {
		if err != nil {
			if _, ok := err.(x509.UnknownAuthorityError); ok {
				// If the issuing authority is unknown and
				// auto-import is enabled, attempt to download
				// and import the CA certificate chain and verify
				// the leaf certificate again.
				if ca.autoImportIssuingCA {
					ca.logger.Warningf("certificate-authority: UnknownAuthorityError: attempting to auto-import Issuer CA chain")
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
		ca.logger.Errorf("certificate-authority: no issuing CAs found in certificate")
		return "", ErrNoIssuingCA
	}

	if len(cert.IssuingCertificateURL) > 1 {
		ca.logger.Error("certificate-authority: multiple issuing CAs not supported: %s", cn)
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

// Signs the requested data and returns the signature
func (ca *CA) Sign(data []byte) ([]byte, error) {
	privateKey, err := ca.certStore.CAPrivKey()
	if err != nil {
		return nil, err
	}
	var signature []byte
	hashed := sha256.Sum256(data)
	if ca.certificate.SignatureAlgorithm == x509.SHA256WithRSA {
		signature, err = rsa.SignPKCS1v15(
			rand.Reader,
			privateKey.(*rsa.PrivateKey),
			crypto.SHA256,
			hashed[:])
	} else if ca.certificate.SignatureAlgorithm == x509.ECDSAWithSHA256 {
		signature, err = ecdsa.SignASN1(
			rand.Reader,
			privateKey.(*ecdsa.PrivateKey),
			hashed[:])
	}
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	return signature, nil
}

// Verifies the signature of the requested data
func (ca *CA) VerifySignature(data []byte, signature []byte) error {
	hashed := sha256.Sum256(data)
	if ca.certificate.SignatureAlgorithm == x509.SHA256WithRSA {
		rsaPub, ok := ca.publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature); err != nil {
			return ErrInvalidSignature
		}
	} else if ca.certificate.SignatureAlgorithm == x509.ECDSAWithSHA256 {
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return err
		}
		eccPub, ok := ca.publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}
		if ok := ecdsa.VerifyASN1(eccPub, hashed[:], signature); !ok {
			return ErrInvalidSignature
		}
	}
	return nil
}

// Signs the requested data and saves the signature, and optionally the data,
// to the certificate store. If the blob key contains forward slashes, a
// directory hierarchy will be created to match the key. For example, the
// blob key /my/secret/blob.dat would get saved to cert-store/signed/my/secret/blob.dat
func (ca *CA) PersistentSign(key string, data []byte, saveData bool) error {
	signature, err := ca.Sign(data)
	if err != nil {
		return err
	}
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	if err := ca.certStore.SaveBlob(sigKey, signature); err != nil {
		return err
	}
	if saveData {
		if err := ca.certStore.SaveBlob(key, data); err != nil {
			return err
		}
	}
	return nil
}

// Verifies the signature of the requested data using a stored signature
func (ca *CA) PersistentVerifySignature(key string, data []byte) error {
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	signature, err := ca.certStore.Blob(sigKey)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(data)
	rsaPub, ok := ca.publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidPublicKeyRSA
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// Returns a stored signature from the signed blob store
func (ca *CA) Signature(key string) ([]byte, error) {
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	return ca.certStore.Blob(sigKey)
}

// Returns true if the specified common name has a stored signature
func (ca *CA) Signed(key string) (bool, error) {
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	if _, err := ca.certStore.Blob(sigKey); err != nil {
		return false, err
	}
	return true, nil
}

// Returns signed data from the signed blob store
func (ca *CA) SignedData(key string) ([]byte, error) {
	return ca.certStore.Blob(key)
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

		ca.logger.Infof("certificate-authority: importing CA Issuer certificate from %s", url)

		// Download the certificate
		resp, err := http.Get(url)
		if err != nil {
			ca.logger.Error(err)
			return err
		}
		// Read the certificate into a memory buffer
		buf := new(bytes.Buffer)
		if _, err = io.Copy(buf, resp.Body); err != nil {
			ca.logger.Error(err)
			return err
		}
		bufBytes := buf.Bytes()

		// Parse the cert to see if there are any more parents
		// in the certificate chain.
		caCert, err := x509.ParseCertificate(bufBytes)
		if err != nil {
			ca.logger.Error(err)
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
		// 	ca.logger.Error(err)
		// 	return err
		// }
		// if !valid {
		// 	ca.logger.Errorf("invalid certificate: %s", cn)
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
			ca.logger.Error(err)
			return err
		}
		if trustsCA {
			ca.logger.Errorf("certificate-authority: CA Issuer certificate already trusted: %s", cn)
			return ErrTrustExists
		}

		// Save the certificate to the Certificate Authority trust store in DER form
		//err = ca.certStore.SaveTrustedCA(cn, bufBytes, partition, FSEXT_DER)
		err = ca.certStore.Save(cn, bufBytes, partition, FSEXT_DER)
		if err != nil {
			ca.logger.Error(err)
			return err
		}

		// Save the certificate to the Certificate Authority trust store in PEM form
		bufPEM, err := ca.EncodePEM(bufBytes)
		if err != nil {
			return err
		}
		err = ca.certStore.Save(cn, bufPEM, partition, FSEXT_PEM)
		if err != nil {
			ca.logger.Error(err)
			return err
		}

		ca.logger.Infof("CA Issuer successfully imported: %s", cn)

		// If the certificate has parents, keep downloading
		// and importing all certificates in the chain until
		// the root certificate is reached.
		if len(caCert.IssuingCertificateURL) > 0 {
			// Found a parent cert, import it
			if err := ca.ImportIssuingCAs(caCert, leafCN, leaf); err != nil {
				ca.logger.Error(err)
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
			ca.logger.Error(ErrCRLAlreadyExists)
			return ErrCRLAlreadyExists
		}

		if cn == "" {
			cn, err = ca.parseIssuerCommonName(cert)
			if err != nil {
				return err
			}
		}

		ca.logger.Infof("Importing Distribution Certificate Revocation List (CRL): %s", url)

		// Download the CRL
		resp, err := http.Get(url)
		if err != nil {
			ca.logger.Error(err)
			return err
		}

		// Read the CRL into a memory buffer
		buf := new(bytes.Buffer)
		if _, err = io.Copy(buf, resp.Body); err != nil {
			ca.logger.Error(err)
			return err
		}
		derBytes := buf.Bytes()

		// Parse the CRL to make sure its valid
		crl, err := x509.ParseRevocationList(derBytes)
		if err != nil {
			ca.logger.Error(err)
			return err
		}

		// Stop the recursion loop and abort if the CRL already
		// exists in the certificate store.
		hasCRL, err := ca.certStore.HasCRL(crl.Issuer.CommonName)
		if err != nil {
			ca.logger.Error(err)
			return err
		}
		if hasCRL {
			ca.logger.Errorf("certificate-authority: CRL already imported: %s", cn)
			return ErrTrustExists
		}

		// Save the CRL to the Certificate Authority trust store in binary format
		err = ca.certStore.Save(cn, derBytes, PARTITION_CRL, FSEXT_CRL)
		if err != nil {
			ca.logger.Error(err)
			return err
		}

		// Save the CRL to the Certificate Authority trust store in PEM form
		// crlPEM, err := ca.EncodePEM(bufBytes)
		// if err != nil {
		// 	return err
		// }
		// err = ca.certStore.Save(cn, crlPEM, PARTITION_CRL, FSEXT_PEM)
		// if err != nil {
		// 	ca.logger.Error(err)
		// 	return err
		// }

		ca.logger.Infof("Distribution CRL successfully imported: %s", cn)
	}
	return nil
}

// Returns the all of the certificates in the Certificate Authority
// certificate store.
func (ca *CA) IssuedCertificates() ([]string, error) {
	certs := make(map[string]bool, 0)
	files, err := os.ReadDir(ca.certDir)
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
	return ca.certStore.Get(cn, PARTITION_ISSUED, FSEXT_DER)
}

// Returns a PEM certifcate from the cert store as []byte or
// ErrCertNotFound if the certificate does not exist.
func (ca *CA) PEM(cn string) ([]byte, error) {
	return ca.certStore.Get(cn, PARTITION_ISSUED, FSEXT_PEM)
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
func (ca *CA) EncodePrivKey(privateKey crypto.PrivateKey) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	return pkcs8, nil
}

// Encodes a private key to ASN.1 DER PKCS8 form
func (ca *CA) EncodePrivKeyPEM(der []byte) ([]byte, error) {
	caPrivKeyPEM := new(bytes.Buffer)
	var keyType string
	if ca.config.DefaultKeyAlgorithm == KEY_ALGO_RSA {
		keyType = "RSA PRIVATE KEY"
	} else if ca.config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
		keyType = "EC PRIVATE KEY"
	} else {
		return nil, fmt.Errorf("%s: %s",
			ErrInvalidAlgorithm, ca.config.DefaultKeyAlgorithm)
	}
	err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  keyType,
		Bytes: der,
	})
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	return caPrivKeyPEM.Bytes(), nil
}

// Parses RSA private key bytes in ASN.1 DER form
func (ca *CA) ParsePrivateKey(bytes []byte) (crypto.PrivateKey, error) {
	var err error
	var privKeyAny any
	// Try parsing as PKCS8 first, since thats what the CA prefers
	privKeyAny, err = x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		// ... try parsing as PKCS1
		privKeyAny, err = x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			ca.logger.Error(err)
			return nil, ErrInvalidPrivateKey
		}
	}
	return privKeyAny.(crypto.PrivateKey), nil
}

// Returns a private key from the certificate store using the stored ASN.1
// DER PKCS8 key.
func (ca *CA) PrivateKey(cn string) (crypto.PrivateKey, error) {
	bytes, err := ca.certStore.Get(cn, PARTITION_ISSUED, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) CAPubKey() (crypto.PublicKey, error) {
	return ca.certStore.CAPubKey()
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) PubKey(cn string) (crypto.PublicKey, error) {
	return ca.certStore.PubKey(cn)
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
		ca.logger.Error(err)
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

	// Import the intermediate and root certificates so the
	// cert can be validated
	valid, err := ca.Verify(cert, &cn)
	if err != nil {
		ca.logger.Warning(err)
	}
	if !valid && ca.autoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &cn, cert); err != nil {
			return err
		}
	}

	return ca.IssuePubKey(cn, cert.PublicKey)
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
		ca.logger.Warning(err)
	}
	if !valid && ca.autoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &cn, cert); err != nil {
			return err
		}
	}

	return ca.certStore.Save(cn, pemBytes, PARTITION_ISSUED, FSEXT_PEM)
}

// Saves a private key to the certificate store "issued" partition in ASN.1 DER
// PKCS8 and PEM (PCKS8) form
func (ca *CA) IssuePrivKey(cn string, privateKey crypto.PrivateKey) error {
	return ca.issuePrivKey(cn, privateKey, PARTITION_ISSUED)
}

// Saves a CA private key to the certificate store in ASN.1 DER PKCS8 and PEM (PCKS8) form
func (ca *CA) IssueCAPrivKey(cn string, privateKey crypto.PrivateKey) error {
	return ca.issuePrivKey(cn, privateKey, PARTITION_CA)
}

// Extracts the public key from the private key and saves both to the certificate store
// in ASN.1 DER PKCS8 and PEM (PCKS8) form
func (ca *CA) issuePrivKey(cn string, privateKey crypto.PrivateKey, partition Partition) error {
	pkcs8, err := ca.EncodePrivKey(privateKey)
	err = ca.certStore.Save(cn, pkcs8, partition, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		ca.logger.Error(err)
		return err
	}
	pkcs8PEM, err := ca.EncodePrivKeyPEM(pkcs8)
	if err != nil {
		ca.logger.Error(err)
		return err
	}
	err = ca.certStore.Save(cn, pkcs8PEM, partition, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.logger.Error(err)
		return err
	}
	if ca.config.DefaultKeyAlgorithm == KEY_ALGO_RSA {
		rsaPriv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivateKeyRSA
		}
		return ca.issuePubKey(cn, &rsaPriv.PublicKey, partition)
	} else if ca.config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
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

// Encodes a public key as PKIX, ASN.1 DER and PEM form and saves both to the
// certificate store CA partition
func (ca *CA) IssueCAPubKey(cn string, pub crypto.PublicKey) error {
	return ca.issuePubKey(cn, pub, PARTITION_CA)
}

// Encodes a public key ASN.1 DER form public key to PEM form
func (ca *CA) EncodePubKeyPEM(cn string, derBytes []byte) ([]byte, error) {
	pubPEM := new(bytes.Buffer)
	err := pem.Encode(pubPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})
	if err != nil {
		ca.logger.Error(err)
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
		ca.logger.Error(err)
		return nil, err
	}
	return pubKey.(crypto.PublicKey), nil
}

// Imports any public key (RSA/ECC) to the certificate store in PEM form
func (ca *CA) ImportPubKey(cn string, pub crypto.PublicKey) error {
	pubDER, err := ca.EncodePubKey(pub)
	if err != nil {
		ca.logger.Error(err)
		return err
	}
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubDER)
	if err != nil {
		ca.logger.Error(err)
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

// Creates a new RSA encryption key for the requested common name and
// returns the public half of the key. Private encryption keys are
// unable to be retrieved from the Certificate authority and stored in
// a separate partition / hierarchy to increase security and provide
// flexibility to rotate keyes without impacting other resources.
func (ca *CA) NewEncryptionKey(cn, keyName string) (*rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(ca.random, ca.identity.KeySize)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	// Private Key: Create
	pkcs8, err := ca.EncodePrivKey(privateKey)
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	// Private Key: Encode to PKCS8
	pkcs8PEM, err := ca.EncodePrivKeyPEM(pkcs8)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	// Private Key: Save PKCS8 PEM encoded key
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8PEM, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	// Public Key: Encode to PKIX, ASN.1 DER form
	privKeyDER, err := ca.EncodePubKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ca.certStore.SaveKeyed(
		cn, keyName, privKeyDER, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}
	// Public Key: Encdode to PEM form
	pubPEM, err := ca.EncodePubKeyPEM(cn, privKeyDER)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	// Public Key: Save PEM form
	err = ca.certStore.SaveKeyed(cn, keyName, pubPEM, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// Returns the RSA public key for the requested common name / key from the
// encryption keys partition
func (ca *CA) EncryptionKey(cn, keyName string) (*rsa.PublicKey, error) {
	pubPEM, err := ca.certStore.GetKeyed(
		cn, keyName, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		return nil, err
	}
	rsaPub, err := ca.DecodeRSAPubKeyPEM(pubPEM)
	if err != nil {
		return nil, err
	}
	return rsaPub.(*rsa.PublicKey), nil
}

// Encrypts the requested data using RSA Optimal Asymetric Encryption
// Padding (OAEP) provided by the common name's public key. OAEP is used
// to protect against Bleichenbacher ciphertext attacks described here:
// https://pkg.go.dev/crypto/rsa#DecryptPKCS1v15SessionKey
// https://www.rfc-editor.org/rfc/rfc3218.html#section-2.3.2
func (ca *CA) RSAEncrypt(cn, keyName string, data []byte) ([]byte, error) {
	pub, err := ca.EncryptionKey(cn, keyName)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), ca.random, pub, data, nil)
}

// Decrypts the requested data, expected in OAEP form, using the common
// name's RSA private key.
func (ca *CA) RSADecrypt(cn, keyName string, ciphertext []byte) ([]byte, error) {
	privDER, err := ca.certStore.GetKeyed(
		cn, keyName, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	priv, err := ca.ParsePrivateKey(privDER)
	if err != nil {
		return nil, err
	}
	privKey := priv.(*rsa.PrivateKey)
	return rsa.DecryptOAEP(sha256.New(), ca.random, privKey, ciphertext, nil)
}

// Load CA private and public keys from the cert store, decode the
// public key to x509 certificate and set it as the CA identity /
// signing certificate.
func (ca *CA) loadCA() error {

	ca.logger.Infof("Loading Certificate Authority: %s", ca.commonName)

	caCertFile := fmt.Sprintf("%s/%s%s", ca.certDir, ca.commonName, FSEXT_DER)

	caCertDer, err := os.ReadFile(caCertFile)
	if err != nil {
		return err
	}

	ca.certificate, err = x509.ParseCertificate(caCertDer)
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	ca.certStore, err = NewFileSystemCertStore(ca.logger,
		ca.certDir, ca.certificate)

	ca.publicKey, err = ca.CAPubKey()
	if err != nil {
		ca.logger.Error(err)
		return err
	}

	return nil
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
		ca.logger.Error(err)
		return nil, err
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		ca.logger.Error(err)
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
	privKeyDER, err := ca.EncodePubKey(pub)
	if err != nil {
		return err
	}
	// Save the ASN.1 DER PKCS1 form
	if err := ca.certStore.Save(cn, privKeyDER, partition, FSEXT_PUBLIC_PKCS1); err != nil {
		return err
	}
	pubPEM, err := ca.EncodePubKeyPEM(cn, privKeyDER)
	// pubPEM := new(bytes.Buffer)
	// err = pem.Encode(pubPEM, &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: privKeyDER,
	// })
	if err != nil {
		ca.logger.Error(err)
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
		ca.logger.Warning(err)
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

	// Save the current CA certificate to a bundle file
	caPEM, err := ca.EncodePEM(ca.certificate.Raw)
	if err != nil {
		return err
	}
	err = ca.certStore.Save(
		ca.certificate.Subject.CommonName,
		caPEM,
		PARTITION_CA,
		FSEXT_PEM_BUNDLE)
	if err != nil {
		return err
	}

	// Append the parent certificate
	parentPEM, err := ca.EncodePEM(ca.parentCertificate.Raw)
	if err != nil {
		return err
	}
	err = ca.certStore.Append(
		ca.certificate.Subject.CommonName,
		parentPEM,
		PARTITION_CA,
		FSEXT_PEM_BUNDLE)
	if err != nil {
		return err
	}

	// Append any other Issuing CAs
	for _, issuer := range ca.parentCertificate.IssuingCertificateURL {
		cn, _ := util.FileName(issuer)
		certPEM, err := ca.certStore.Get(cn, PARTITION_CA, FSEXT_PEM)
		if err != nil {
			return err
		}
		err = ca.certStore.Append(
			ca.certificate.Subject.CommonName,
			certPEM,
			PARTITION_CA,
			FSEXT_PEM_BUNDLE)
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
		PARTITION_CA,
		FSEXT_PEM_BUNDLE)
}

// Returns a CA "bundle" that contains all of the certificates
// in the chain up to the Root. This file is useful for clients
// who wish to verify a TLS connection to a server who was issued
// a certificate from this CA.
func (ca *CA) CABundleCertPool() (*(x509.CertPool), error) {

	rootCAs := x509.NewCertPool()
	bundlePEM, err := ca.CABundle()
	if err != nil {
		ca.logger.Error(err)
		return nil, err
	}

	if !rootCAs.AppendCertsFromPEM(bundlePEM) {
		ca.logger.Error(err)
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
				ca.logger.Error(err)
				return nil, err
			}
			certs = append(certs, cert)
		// case "PRIVATE KEY":
		// 	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		// 	if err != nil {
		// 		ca.logger.Error(err)
		// 		return nil, err
		// 	}
		// 	keys = append(keys, key)
		default:
			ca.logger.Error("certificate-authority: invalid certificate in bundle")
			return nil, ErrCertInvalid
		}
	}
	return certs, nil
}

// Returns an x509 certificate KeyPair suited for tls.Config
func (ca *CA) X509KeyPair(cn string) (tls.Certificate, error) {

	privKeyPEM, err := ca.certStore.PrivKeyPEM(cn)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM, err := ca.PEM(cn)
	if err != nil {
		return tls.Certificate{}, err
	}

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
func (ca *CA) TLSConfig(cn string, includeSystemRoot bool) (*tls.Config, error) {

	rootCAs, err := ca.TrustedRootCertPool(includeSystemRoot)
	if err != nil {
		return nil, err
	}

	cert, err := ca.X509KeyPair(cn)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cert},
	}, nil
}
