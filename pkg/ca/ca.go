package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/youmark/pkcs8"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

var (
	ErrInvalidConfig                = errors.New("certificate-authority: invalid configuration")
	ErrCertFuture                   = errors.New("certificate-authority: certificate issued in the future")
	ErrCertExpired                  = errors.New("certificate-authority: certificate expired")
	ErrTrustExists                  = errors.New("certificate-authority: certificate already trusted")
	ErrDistributionPointExists      = errors.New("certificate-authority: distribution point already exists")
	ErrInvalidSignature             = errors.New("certificate-authority: invalid signature")
	ErrInvalidSignatureAlgorithm    = errors.New("certificate-authority: invalid signature algorithm")
	ErrCRLAlreadyExists             = errors.New("certificate-authority: revocation list already exists")
	ErrNoIssuingCA                  = errors.New("certificate-authority: no issuing CAs found in certificate")
	ErrCertNotSupported             = errors.New("certificate-authority: certificate contains unsupported configuration")
	ErrInvalidPublicKey             = errors.New("certificate-authority: invalid public key")
	ErrInvalidCurve                 = errors.New("certificate-authority: invalid ECC Curve")
	ErrPrivateKeyPasswordRequired   = errors.New("certificate-authority: private key password required")
	ErrNotInitialized               = errors.New("certificate-authority: not initialized")
	ErrAlreadyInitialized           = errors.New("certificate-authority: already initialized")
	ErrInvalidIntermediateSelection = errors.New("certificate-authority: invalid intermediate certificate authority selection")
	ErrUnsupportedHashAlgorithm     = errors.New("certificate-authority: unsupported hashing algorithm")
	ErrUnsupportedRSAScheme         = errors.New("certificate-authority: unsupported RSA padding scheme")
	ErrInvalidAttestationBlobType   = errors.New("certificate-authority: invalid attestation blob type")
	ErrParentCertificatesNotFound   = errors.New("certificate-authority: parent CA certificates not found in certificate store")

	WarnNoSigningPassword = errors.New("certificate-authority: signing with an insecure private key")
)

type CertificateAuthority interface {
	AttestationEventLog(cn string) ([]byte, error)
	AttestationPCRs(cn string) (map[string][][]byte, error)
	AttestationQuote(cn string) ([]byte, error)
	AttestationSignature(cn, blobType string) ([]byte, error)
	Blob(key string) ([]byte, error)
	CABundle(algorithm *x509.PublicKeyAlgorithm) ([]byte, error)
	CABundleCertPool(algorithm *x509.PublicKeyAlgorithm) (*(x509.CertPool), error)
	CACertificate(algorithm *x509.PublicKeyAlgorithm) (*x509.Certificate, error)
	CACertificates() map[x509.PublicKeyAlgorithm]*x509.Certificate
	CAKeyAttributes(algo *x509.PublicKeyAlgorithm) keystore.KeyAttributes
	CAKeyAttributesList() map[x509.PublicKeyAlgorithm]keystore.KeyAttributes
	CASigner(algo *x509.PublicKeyAlgorithm) (crypto.Signer, error)
	Certificate(attrs keystore.KeyAttributes) (*x509.Certificate, error)
	Checksum(key string) (bool, error)
	CreateCSR(request CertificateRequest) ([]byte, error)
	DefaultKeyAlgorithm() x509.PublicKeyAlgorithm
	DefaultValidityPeriod() int
	DER(keystore.KeyAttributes) ([]byte, error)
	EndorsementKeyCertificate() ([]byte, error)
	Hash() crypto.Hash
	Init(parentCA CertificateAuthority) (CertificateAuthority, error)
	Identity() Identity
	IsAutoImportingIssuerCAs() bool
	IsInitialized() bool
	IssueCertificate(request CertificateRequest) ([]byte, error)
	IssuedCertificates() ([]string, error)
	Import(attrs keystore.KeyAttributes, cer *x509.Certificate) error
	ImportAttestation(keystore.KeyAttributes, string, []byte) error
	ImportAttestationKeyCertificate(attrs keystore.KeyAttributes, akDER []byte) error
	ImportAttestationEventLog(attestatomAttrs keystore.KeyAttributes, data []byte) error
	ImportAttestationPCRs(attestatomAttrs keystore.KeyAttributes, pcrs []byte) error
	ImportAttestationQuote(attestatomAttrs keystore.KeyAttributes, data []byte) error
	ImportBlob(key string, data []byte) error
	ImportCN(attrs keystore.KeyAttributes, cert *x509.Certificate) error
	ImportDER(attrs keystore.KeyAttributes, derCert []byte) error
	ImportDistrbutionCRLs(cert *x509.Certificate) error
	ImportEndorsementKeyCertificate(attrs keystore.KeyAttributes, ekCertPEM []byte) error
	ImportPEM(attrs keystore.KeyAttributes, pemBytes []byte) error
	ImportIssuingCAs(cert *x509.Certificate, leafCN *string, leaf *x509.Certificate) error
	ImportTrustedRoot(keystore.KeyAttributes, []byte) error
	ImportTrustedIntermediate(attrs keystore.KeyAttributes, derCert []byte) error
	IssuePubKey(keystore.KeyAttributes, crypto.PublicKey) error
	Load(parentCA CertificateAuthority) error
	Login(password []byte) error
	NewSigningKey(attrs keystore.KeyAttributes) (crypto.Signer, error)
	ParseCABundle(bundle []byte) ([]*x509.Certificate, error)
	ParsePrivateKey(bytes, password []byte) (crypto.PrivateKey, error)
	PEM(keystore.KeyAttributes) ([]byte, error)
	Public() crypto.PublicKey
	PubKey(attrs keystore.KeyAttributes) (crypto.PublicKey, error)
	PubKeyPEM(attrs keystore.KeyAttributes) ([]byte, error)
	Revoke(attrs keystore.KeyAttributes) error
	RootCertificate(algorithm x509.PublicKeyAlgorithm) (*x509.Certificate, error)
	RootCertForCA(attrs keystore.KeyAttributes) (*x509.Certificate, error)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Signature(key string) ([]byte, error)
	IsSigned(key string) (bool, error)
	SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error)
	Signer(attrs keystore.KeyAttributes) (crypto.Signer, error)
	SigningKey(attrs keystore.KeyAttributes) (crypto.Signer, error)
	TLSCertificate(attrs keystore.KeyAttributes) (tls.Certificate, error)
	TLSConfig(attrs keystore.KeyAttributes, includeSystemRoot bool) (*tls.Config, error)
	TPMBlobKey(attrs keystore.KeyAttributes) string
	TrustStore() OSTrustStore
	TrustedRootCertificate(
		attrs keystore.KeyAttributes, ext store.FSExtension) (*x509.Certificate, error)
	TrustedRootCertPool(
		algorithm x509.PublicKeyAlgorithm,
		includeSystemRoot bool) (*x509.CertPool, error)
	TrustedIntermediateCertificate(cn string) (*x509.Certificate, error)
	TrustedIntermediateCertPool(attrs keystore.KeyAttributes) (*x509.CertPool, error)
	Verify(certificate *x509.Certificate, leafCN *string) (bool, error)
	VerifyAttestationEventLog(signerAttrs keystore.KeyAttributes, eventLog []byte) error
	VerifyAttestationPCRs(signerAttrs keystore.KeyAttributes, pcrs []byte) error
	VerifyAttestationQuote(signerAttrs keystore.KeyAttributes, quote []byte) error
	VerifySignature(digest []byte, signature []byte, opts *keystore.VerifyOpts) error
}

type CA struct {
	backend                   store.Backend
	blobStore                 blobstore.BlobStorer
	caDir                     string
	certStore                 CertificateStorer
	commonName                string
	identity                  Identity
	keyStore                  keystore.KeyStorer
	passwordPolicy            *regexp.Regexp
	params                    CAParams
	trustStore                OSTrustStore
	keyAttributes             map[x509.PublicKeyAlgorithm]keystore.KeyAttributes
	certificates              map[x509.PublicKeyAlgorithm]*x509.Certificate
	parentCertificates        map[x509.PublicKeyAlgorithm]*x509.Certificate
	defaultKeyAlgorithm       x509.PublicKeyAlgorithm
	defaultKeyAttributes      keystore.KeyAttributes
	defaultSignatureAlgorithm x509.SignatureAlgorithm
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

	// Ensure at least 1 CA is configured
	if len(params.Config.Identity) == 0 {
		return nil, nil, ErrInvalidConfig
	}

	// Instantiate the parent CA
	params.Identity = params.Config.Identity[0]
	parentCA, err := NewParentCA(params)
	if err != nil {
		return nil, nil, err
	}

	// Return the Root CA if it's the only CA configured
	if len(params.Config.Identity) == 1 {
		if parentCA.IsInitialized() {
			if err := parentCA.Load(nil); err != nil {
				return nil, nil, err
			}
			return parentCA, nil, nil
		}
		return parentCA, nil, ErrNotInitialized
	}

	// Ensure the selected intermediate is not the Root or out of bounds
	if params.SelectedCA == 0 || params.SelectedCA > len(params.Config.Identity) {
		return nil, nil, ErrInvalidIntermediateSelection
	}

	// Use the selectedIntermediate index pointer to load the desired intermediate
	params.Identity = params.Config.Identity[params.SelectedCA]
	intermediateCA, err := NewIntermediateCA(params)
	if err != nil {
		return nil, nil, err
	}

	// If not initialized, return ErrNotInitialized signaling to run
	// platform setup. Return the parentCA so the Init() method can be
	// invoked after setup is complete.
	if !parentCA.IsInitialized() {
		return parentCA, intermediateCA, ErrNotInitialized
	} else {
		if err := parentCA.Load(nil); err != nil {
			return nil, nil, err
		}
	}

	// Return initialization error to run setup
	if !intermediateCA.IsInitialized() {
		return nil, nil, ErrNotInitialized
	} else {
		intermediateCA.Load(parentCA)
		if err := intermediateCA.Load(nil); err != nil {
			return nil, nil, err
		}
	}

	return parentCA, intermediateCA, nil
}

// Creates a new parent x509 Certificate Authority. This may be the
// Root or a subordinate Intermediate CA.
func NewParentCA(params CAParams) (CertificateAuthority, error) {

	if len(params.Config.Identity) < 2 {
		params.Logger.Error("certificate-authority: Root and at least 1 Intermediate CA required")
		return nil, ErrInvalidConfig
	}

	params = initStores(params)
	caCN := params.Identity.Subject.CommonName

	passwordPolicy, err := regexp.Compile(params.Config.PasswordPolicy)
	if err != nil {
		params.Logger.Error(err)
		return nil, err
	}

	defaultKeyAttributes, err := CAKeyAttributesFromParams(params)
	if err != nil {
		return nil, err
	}

	defaultKeyAlgorithm, ok := keystore.AvailableKeyAlgorithms()[params.Config.DefaultKeyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	defaultSignatureAlgorithm, ok := keystore.AvailableSignatureAlgorithms()[params.Config.SignatureAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	keyAttrs := make(map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, 0)
	certificates := make(map[x509.PublicKeyAlgorithm]*x509.Certificate, len(params.Config.KeyAlgorithms))
	parentCertificates := make(map[x509.PublicKeyAlgorithm]*x509.Certificate, len(params.Config.KeyAlgorithms))

	return &CA{
		params:                    params,
		backend:                   params.Backend,
		caDir:                     params.Config.Home,
		keyStore:                  params.KeyStore,
		certStore:                 params.CertStore,
		blobStore:                 params.BlobStore,
		passwordPolicy:            passwordPolicy,
		identity:                  params.Config.Identity[0],
		trustStore:                NewDebianTrustStore(params.Logger, params.Config.Home),
		commonName:                caCN,
		defaultKeyAttributes:      defaultKeyAttributes,
		defaultSignatureAlgorithm: defaultSignatureAlgorithm,
		defaultKeyAlgorithm:       defaultKeyAlgorithm,
		keyAttributes:             keyAttrs,
		certificates:              certificates,
		parentCertificates:        parentCertificates}, nil
}

// Create a new x509 Intermediate Certificate Authority. This
// Intermediate either be a child to a Root or the child of
// another Intermediate CA in a chain.
func NewIntermediateCA(params CAParams) (CertificateAuthority, error) {

	params = initStores(params)
	identity := params.Config.Identity[params.SelectedCA]

	passwordPolicy, err := regexp.Compile(params.Config.PasswordPolicy)
	if err != nil {
		params.Logger.Error(err)
		return nil, err
	}

	defaultKeyAttributes, err := CAKeyAttributesFromParams(params)
	if err != nil {
		return nil, err
	}

	defaultKeyAlgorithm, ok := keystore.AvailableKeyAlgorithms()[params.Config.DefaultKeyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	defaultSignatureAlgorithm, ok := keystore.AvailableSignatureAlgorithms()[params.Config.SignatureAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	keyAttrs := make(map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, 0)
	certificates := make(map[x509.PublicKeyAlgorithm]*x509.Certificate, len(params.Config.KeyAlgorithms))
	parentCertificates := make(map[x509.PublicKeyAlgorithm]*x509.Certificate, len(params.Config.KeyAlgorithms))

	return &CA{
		params:                    params,
		backend:                   params.Backend,
		caDir:                     params.Config.Home,
		keyStore:                  params.KeyStore,
		certStore:                 params.CertStore,
		blobStore:                 params.BlobStore,
		passwordPolicy:            passwordPolicy,
		identity:                  identity,
		trustStore:                NewDebianTrustStore(params.Logger, params.Config.Home),
		commonName:                identity.Subject.CommonName,
		defaultSignatureAlgorithm: defaultSignatureAlgorithm,
		defaultKeyAlgorithm:       defaultKeyAlgorithm,
		defaultKeyAttributes:      defaultKeyAttributes,
		keyAttributes:             keyAttrs,
		certificates:              certificates,
		parentCertificates:        parentCertificates}, nil
}

// Implements crypto.PrivateKey
// Implements crypto.Decrypter
func (ca *CA) Public() crypto.PublicKey {
	signer, err := ca.Signer(ca.defaultKeyAttributes)
	if err != nil {
		ca.params.Logger.Fatal(err)
	}
	return signer.Public()
}

// Returns the CA's default hash function
func (ca *CA) Hash() crypto.Hash {
	hashes := keystore.AvailableHashes()
	ca.params.Logger.Debugf("Supported Hashes\n%s", hashes)
	hash, ok := hashes[ca.params.Config.Hash]
	if !ok {
		ca.params.Logger.Fatalf("%s: %s",
			ErrUnsupportedHashAlgorithm, ca.params.Config.Hash)
	}
	return hash
}

// Returns the CA's default key algorithm
func (ca *CA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return ca.defaultKeyAlgorithm
}

// Returns the CA's default key algorithm
func (ca *CA) Login(password []byte) error {
	attrs := ca.defaultKeyAttributes
	attrs.Password = password
	_, err := ca.keyStore.Signer(attrs)
	if err != nil {
		return err
	}
	return nil
}

// Load CA public/private key and x509 signing certificate from the
// certificate store. Any errors during Load are treated as Fatal.
func (ca *CA) Load(parentCA CertificateAuthority) error {

	ca.params.Logger.Infof("Loading Certificate Authority: %s", ca.commonName)

	intermediatePassword := []byte(ca.params.Config.Identity[ca.params.SelectedCA].KeyPassword)
	var password []byte
	// var authPassword []byte
	if parentCA != nil {
		// authPassword = []byte(parentCA.Identity().KeyPassword)
		password = intermediatePassword
	} else {
		password = []byte(ca.identity.KeyPassword)
	}

	// Create an x509 key pair and certificate for each
	// key algorithm configured via platform configuration file
	availableKeyAlgorithms := keystore.AvailableKeyAlgorithms()
	for _, algo := range ca.params.Config.KeyAlgorithms {

		keyAlgo, ok := availableKeyAlgorithms[algo]
		if !ok {
			return keystore.ErrInvalidKeyAlgorithm
		}

		keyAlg, err := keystore.ParseKeyAlgorithm(algo)
		if err != nil {
			return err
		}

		caKeyAttrs, ok := keystore.Templates[keyAlgo]
		if !ok {
			return keystore.ErrInvalidKeyAlgorithm
		}
		caKeyAttrs.Domain = ca.commonName
		caKeyAttrs.CN = ca.commonName
		caKeyAttrs.KeyAlgorithm = keyAlg
		caKeyAttrs.KeyType = keystore.KEY_TYPE_CA
		caKeyAttrs.Password = password
		// caKeyAttrs.AuthPassword = authPassword

		// opaque, err := ca.keyStore.CreateKey(caKeyAttrs)
		// if err != nil {
		// 	return nil, err
		// }
		// publicKey := opaque.Public()
		ca.keyAttributes[keyAlg] = caKeyAttrs
		ca.params.Logger.Debugf("certificate-authority: loaded %s CA key attributes", algo)

		// Get the CA cert from the cert store
		cert, err := ca.Certificate(caKeyAttrs)
		if err != nil {
			return err
		}
		ca.certificates[keyAlg] = cert

		// Load parent certificates
		var parentCertificate *x509.Certificate
		if parentCA != nil {
			parentCertificate, ok = parentCA.CACertificates()[caKeyAttrs.KeyAlgorithm]
			if !ok {
				ca.params.Logger.Fatal(ErrParentCertificatesNotFound)
			}
			ca.parentCertificates[caKeyAttrs.KeyAlgorithm] = parentCertificate
		}

		// Set the key attributes and certificate
		ca.keyAttributes[caKeyAttrs.KeyAlgorithm] = caKeyAttrs
		ca.certificates[caKeyAttrs.KeyAlgorithm] = cert

		// Print the CA bundle to the log if in debug mode
		// bundle, err := ca.CABundle(&keyAlg)
		// if err != nil {
		// 	ca.params.Logger.Fatal(err)
		// }
		// ca.params.Logger.Debugf("Certificate Authority %s CA Bundle:", keyAlg)
		// ca.params.Logger.Debugf("\n%s", string(bundle))
	}

	return nil
}

// Returns true if the Certificate Authority is initialized and ready
// to start servicing requests. A successful response indicates the Load()
// method is ready to be called. An unsuccessful response should perform
// platform setup first, supplying the password to use to protect the CA
// PKCS8 private keys.
func (ca *CA) IsInitialized() bool {
	caCert := fmt.Sprintf("%s/%s/%s.%s%s",
		ca.caDir,
		ca.commonName,
		ca.commonName,
		strings.ToLower(ca.params.Config.DefaultKeyAlgorithm),
		store.FSEXT_PUBLIC_PEM)
	if _, err := os.Stat(caCert); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		ca.params.Logger.Error(err)
		return false
	}
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
func (ca *CA) Init(parentCA CertificateAuthority) (CertificateAuthority, error) {

	if ca.IsInitialized() {
		if err := ca.Load(parentCA); err != nil {
			return nil, err
		}
	}

	ca.params.Logger.Debugf("Initializing Certificate Authority: %s", ca.commonName)

	var err error
	var signer crypto.Signer

	// Get SANS IPs, DNS, and Emails from config
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(ca.identity.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create a new CA certificate serial number
	serialNumber, err := util.X509SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	intermediatePassword := []byte(ca.params.Config.Identity[ca.params.SelectedCA].KeyPassword)
	var password []byte
	var authPassword []byte
	if parentCA != nil {
		authPassword = []byte(parentCA.Identity().KeyPassword)
		password = intermediatePassword
	} else {
		password = []byte(ca.identity.KeyPassword)
	}

	// Create an x509 key pair and certificate for each
	// key algorithm configured via platform configuration file
	availableKeyAlgorithms := keystore.AvailableKeyAlgorithms()
	for _, algo := range ca.params.Config.KeyAlgorithms {

		keyAlgo, ok := availableKeyAlgorithms[algo]
		if !ok {
			return nil, keystore.ErrInvalidKeyAlgorithm
		}

		keyAlg, err := keystore.ParseKeyAlgorithm(algo)
		if err != nil {
			return nil, err
		}

		caKeyAttrs, ok := keystore.Templates[keyAlgo]
		if !ok {
			return nil, keystore.ErrInvalidKeyAlgorithm
		}
		caKeyAttrs.Domain = ca.commonName
		caKeyAttrs.CN = ca.commonName
		caKeyAttrs.KeyAlgorithm = keyAlg
		caKeyAttrs.KeyType = keystore.KEY_TYPE_CA
		caKeyAttrs.Password = password
		caKeyAttrs.AuthPassword = authPassword

		opaque, err := ca.keyStore.CreateKey(caKeyAttrs)
		if err != nil {
			return nil, err
		}
		publicKey := opaque.Public()
		ca.keyAttributes[keyAlg] = caKeyAttrs
		ca.params.Logger.Debugf("certificate-authority: created %s key", algo)

		// Look up the key from the store
		signer, err = ca.keyStore.Signer(caKeyAttrs)
		if err != nil {
			return nil, err
		}

		// Create Subject Key ID
		subjectKeyID, err := ca.createSubjectKeyIdentifier(publicKey)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
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
			SignatureAlgorithm:    caKeyAttrs.SignatureAlgorithm,
			PublicKeyAlgorithm:    caKeyAttrs.KeyAlgorithm,
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
		cert := template
		caSigner := signer

		var parentCertificate *x509.Certificate
		if parentCA != nil {
			parentCertificate, ok = parentCA.CACertificates()[caKeyAttrs.KeyAlgorithm]
			if !ok {
				return nil, ErrParentCertificatesNotFound
			}
			// Load parent CA and use it to sign this new intermediate
			parentAttrs := caKeyAttrs
			parentAttrs.Domain = parentCertificate.Subject.CommonName
			parentAttrs.CN = parentCertificate.Subject.CommonName
			parentAttrs.Password = caKeyAttrs.AuthPassword

			signer, err = parentCA.Signer(parentAttrs)
			if err != nil {
				return nil, err
			}
			caSigner = signer
			cert = parentCertificate
			publicKey = parentCertificate.PublicKey

			ca.parentCertificates[caKeyAttrs.KeyAlgorithm] = parentCertificate
		}

		// Create the new Root / Intermediate CA certificate
		caDerCert, err := x509.CreateCertificate(rand.Reader,
			template, cert, opaque.Public(), caSigner)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}
		// Done with the dynamic "cert" variable, now
		// use it to store the certificate for this CA.
		// Calling x509.ParseCertificate so the cert.Raw
		// bytes and other fields are fully populated instead
		// of having the partially populated template
		cert, err = x509.ParseCertificate(caDerCert)
		if err != nil {
			return nil, err
		}

		// Save the DER form to the certificate store
		err = ca.certStore.Save(caKeyAttrs, caDerCert, store.FSEXT_DER, nil)
		if err != nil {
			return nil, err
		}

		// Encode the DER form to PEM form and save it to the certificate store
		pemBytes, err := EncodePEM(caDerCert)
		if err != nil {
			return nil, err
		}
		if err := ca.certStore.Save(
			caKeyAttrs, pemBytes, store.FSEXT_PEM, nil); err != nil {

			return nil, err
		}

		// Set the key attributes and certificate
		ca.keyAttributes[caKeyAttrs.KeyAlgorithm] = caKeyAttrs
		ca.certificates[caKeyAttrs.KeyAlgorithm] = cert

		// If this is an Intermediate Certificate Authority, import the
		// Root CA certificate into the trusted root certificate store
		// and create a CA bundle file for TLS clients to verify issued
		// certificates.
		if parentCA != nil {
			if err := ca.importRootCA(
				caKeyAttrs.KeyAlgorithm, parentCertificate); err != nil {
				return nil, err
			}
			if err := ca.createCABundle(
				&caKeyAttrs.KeyAlgorithm, parentCertificate); err != nil {
				return nil, err
			}
		}

		// Initialize the CRL by creating a dummy cert and revoking it
		if err := ca.initCRL(caKeyAttrs); err != nil {
			return nil, err
		}
	}

	return ca, nil
}

// Returns a map containing all CA key algorithms
func (ca *CA) CAKeyAttributesList() map[x509.PublicKeyAlgorithm]keystore.KeyAttributes {
	return ca.keyAttributes
}

// Returns the CA key attributes for the requested algorithm
func (ca *CA) CAKeyAttributes(algo *x509.PublicKeyAlgorithm) keystore.KeyAttributes {
	if algo == nil {
		alg, err := keystore.ParseKeyAlgorithm(ca.params.Config.DefaultKeyAlgorithm)
		if err != nil {
			ca.params.Logger.Fatal(err)
		}
		algo = &alg
	}
	key, ok := ca.keyAttributes[*algo]
	if !ok {
		ca.params.Logger.Fatal(keystore.ErrInvalidKeyAlgorithm)
	}
	return key
}

// Returns the CA signing certificates
func (ca *CA) CACertificates() map[x509.PublicKeyAlgorithm]*x509.Certificate {
	return ca.certificates
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
func (ca *CA) OSTrustStore() OSTrustStore {
	return ca.trustStore
}

func (ca *CA) RootCertForCA(attrs keystore.KeyAttributes) (*x509.Certificate, error) {
	return ca.certStore.RootCertForCA(attrs)
}

// Returns the x509 certificate used as the identity and signing certificate
// for the Root Certificate Authority.
func (ca *CA) RootCertificate(algorithm x509.PublicKeyAlgorithm) (*x509.Certificate, error) {
	caAttrs, ok := ca.keyAttributes[algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	return ca.RootCertForCA(caAttrs)
}

// Returns the x509 certificate used as the identity and signing certificate
// for the Certificate Authority.
// func (ca *CA) CACertificate() *x509.Certificate {
// 	return ca.certificate
// }

// Returns a trusted root certificate from the trust store
func (ca *CA) TrustedRootCertificate(
	attrs keystore.KeyAttributes, ext store.FSExtension) (*x509.Certificate, error) {

	var cert *x509.Certificate
	var err error
	der, err := ca.certStore.TrustedRoot(attrs, ext)
	if err != nil {
		return nil, err
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		// Try to parse it as PEM
		return DecodePEM(der)
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

// Returns a cert pool initialized with all of the trusted root
// certificates in the certificate store. Pass a true value
// for includeSystemRoot to include the Operating System trusted
// root certificates.
func (ca *CA) TrustedRootCertPool(
	algorithm x509.PublicKeyAlgorithm,
	includeSystemRoot bool) (*x509.CertPool, error) {

	caKeyAttrs, ok := ca.keyAttributes[algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	return ca.certStore.TrustedRootCertPool(caKeyAttrs, includeSystemRoot)
}

// Returns a cert pool initialized with all of the trusted intermediate
// certificates in the certificate store.
func (ca *CA) TrustedIntermediateCertPool(
	attrs keystore.KeyAttributes) (*x509.CertPool, error) {

	return ca.certStore.TrustedIntermediateCertPool(attrs)
}

// Creates a new Certificate Signing Request (CSR)
func (ca *CA) CreateCSR(request CertificateRequest) ([]byte, error) {

	ca.params.Logger.Debug("Creating new Certificate Signing Request")

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	keystore.DebugKeyAttributes(ca.params.Logger, *request.KeyAttributes)

	signatureAlgorithm := request.KeyAttributes.SignatureAlgorithm
	keyAlgorithm := request.KeyAttributes.KeyAlgorithm

	// Get the key attributes for the requested algorithm
	caKeyAttributes, ok := ca.keyAttributes[keyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Parse ip, dns and email addresses
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// emailAddresses = append(emailAddresses, email)

	// Build PKIX subject
	subject := pkix.Name{
		CommonName:         request.Subject.CommonName,
		Organization:       []string{request.Subject.Organization},
		OrganizationalUnit: []string{request.Subject.OrganizationalUnit},
		Country:            []string{request.Subject.Country},
		Province:           []string{request.Subject.Province},
		Locality:           []string{request.Subject.Locality},
		StreetAddress:      []string{request.Subject.Address},
		PostalCode:         []string{request.Subject.PostalCode},
	}

	// Build email ASN sequence
	oidEmailAddress := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	asn1Subj, _ := asn1.Marshal(rawSubj)

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(signatureAlgorithm),
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		EmailAddresses:     emailAddresses,
	}

	// Set DNS names as SANS
	dnsNames = append(dnsNames, request.Subject.CommonName)
	template.DNSNames = dnsNames

	// Get the CA signer
	signer, err := ca.Signer(caKeyAttributes)
	if err != nil {
		return nil, err
	}

	// Create and sign the x509 certificate
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Encode CSR to PEM form
	csrPEM, err := EncodeCSR(csrBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Save the CSR in PEM form
	err = ca.certStore.Save(*request.KeyAttributes, csrPEM, store.FSEXT_CSR, nil)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	ca.params.Logger.Debug(string(csrPEM))

	return csrPEM, nil
}

// Signs a Certificate Signing Request (CSR) and stores it in the cert store
// in PEM format. This method returns the raw DER encoded []byte array as
// returned from x509.CreateCertificate.
func (ca *CA) SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error) {

	ca.params.Logger.Debug("Signing Certificate Signing Request")

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	keystore.DebugKeyAttributes(ca.params.Logger, *request.KeyAttributes)

	// Get the key attributes for the requested algorithm
	caKeyAttributes, ok := ca.keyAttributes[request.KeyAttributes.KeyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Revoke the certificate
	caCertificate, err := ca.CACertificate(&caKeyAttributes.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	csr, err := DecodeCSR(csrBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	serialNumber, err := util.X509SerialNumber()
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
		Issuer:             caCertificate.Subject,
		Subject:            csr.Subject,
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SubjectKeyId:       caCertificate.SubjectKeyId,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, request.Valid),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:        csr.IPAddresses,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
	}
	template.DNSNames = csr.DNSNames

	// Get the CA signer
	signer, err := ca.Signer(caKeyAttributes)
	if err != nil {
		return nil, err
	}

	// Create the x509 certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, caCertificate, template.PublicKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create certificate key attributes
	certKeyAttrs, err := keystore.Template(csr.PublicKeyAlgorithm)
	if err != nil {
		return nil, err
	}
	keyName := request.KeyAttributes.CN
	if keyName == "" {
		keyName = csr.Subject.CommonName
	}
	certKeyAttrs.Domain = request.KeyAttributes.Domain
	certKeyAttrs.CN = csr.Subject.CommonName
	certKeyAttrs.KeyAlgorithm = csr.PublicKeyAlgorithm
	certKeyAttrs.Password = request.KeyAttributes.Password

	// Import the DER and PEM forms
	if err := ca.ImportDER(certKeyAttrs, derBytes); err != nil {
		return nil, err
	}

	// Import the public key
	err = ca.issuePubKey(certKeyAttrs, csr.PublicKey, store.PARTITION_TLS)
	if err != nil {
		return nil, err
	}

	return EncodePEM(derBytes)
}

// Create a new private / public key pair and save it to the cert store
// in DER and PEM form. This method returns the raw DER encoded []byte
// as returned from x509.CreateCertificate.
func (ca *CA) IssueCertificate(request CertificateRequest) ([]byte, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	keystore.DebugKeyAttributes(ca.params.Logger, *request.KeyAttributes)

	signatureAlgorithm := request.KeyAttributes.SignatureAlgorithm
	keyAlgorithm := request.KeyAttributes.KeyAlgorithm

	// Get the key attributes for the requested algorithm
	caKeyAttributes, ok := ca.keyAttributes[request.KeyAttributes.KeyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	caCertificate, err := ca.CACertificate(&keyAlgorithm)
	if err != nil {
		return nil, err
	}

	if request.Valid == 0 {
		request.Valid = ca.params.Config.ValidDays
	}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	dnsNames = append(dnsNames, request.Subject.CommonName)

	serialNumber, err := util.X509SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create the new certificate
	template := &x509.Certificate{
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: keyAlgorithm,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
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
		AuthorityKeyId: caCertificate.SubjectKeyId,
		SubjectKeyId:   caCertificate.SubjectKeyId,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses}

	// Create a new key pair for the certificate
	opaque, err := ca.keyStore.CreateKey(*request.KeyAttributes)
	if err != nil {
		return nil, err
	}
	template.PublicKey = opaque.Public()

	// Get the CA signer
	signer, err := ca.Signer(caKeyAttributes)
	if err != nil {
		return nil, err
	}

	// Create the x509 certificate
	certDerBytes, err := x509.CreateCertificate(
		rand.Reader, template, caCertificate, opaque.Public(), signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// // Import the certificate in DER and PEM form; import public key
	// certKeyAttrs, err := keystore.Template(keyAlgorithm)
	// if err != nil {
	// 	return nil, err
	// }

	// If X509 certificate attributes set, use the CN from the
	// x509 attributes, otherwise use the CN that the signing
	// key belongs to.
	// cn := request.Subject.CommonName
	// if request.KeyAttributes.X509Attributes != nil {
	// 	cn = request.KeyAttributes.X509Attributes.CN
	// }

	// certKeyAttrs.CN = cn
	// certKeyAttrs.KeyName = request.Subject.CommonName
	// certKeyAttrs.KeyAlgorithm = keyAlgorithm
	// certKeyAttrs.Password = request.KeyAttributes.Password
	// if err := ca.ImportDER(certKeyAttrs, certDerBytes); err != nil {
	// 	return nil, err
	// }

	// // Ensure key type is set to TLS
	// request.KeyAttributes.KeyType = keystore.KEY_TYPE_TLS

	if err := ca.ImportDER(*request.KeyAttributes, certDerBytes); err != nil {
		return nil, err
	}

	return certDerBytes, nil
}

// Revoke a certificate
func (ca *CA) Revoke(attrs keystore.KeyAttributes) error {

	// Get the CA key for the provided algorithm
	caAttrs, ok := ca.keyAttributes[attrs.KeyAlgorithm]
	if !ok {
		return keystore.ErrInvalidKeyAlgorithm
	}

	// Check the certificate store to see if this certificate has
	// been added to the revocation list, and exists in the revoked
	// partition.
	revoked, err := ca.certStore.IsRevoked(attrs, nil)
	if err != nil {
		return err
	}
	if revoked {
		return ErrCertRevoked
	}

	// Load the requested cert
	certPEM, err := ca.PEM(attrs)
	if err != nil {
		return err
	}

	// Decode the PEM to a *x509.Certificate
	certificate, err := DecodePEM(certPEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Get the CA signer
	signer, err := ca.Signer(caAttrs)
	if err != nil {
		return err
	}

	// Get the CA certificate
	caCertificate, err := ca.Certificate(caAttrs)
	if err != nil {
		return err
	}

	return ca.certStore.Revoke(attrs, certificate, caCertificate, signer)
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

	// Create key attributes template
	caKeyAttrs, ok := ca.keyAttributes[certificate.PublicKeyAlgorithm]
	if !ok {
		return false, keystore.ErrInvalidKeyAlgorithm
	}

	// Create key attributes for certificate using
	// the CA key attributes as a tempalte
	certKeyAttrs := caKeyAttrs
	certKeyAttrs.Domain = certificate.Subject.CommonName
	certKeyAttrs.CN = certificate.Subject.CommonName

	// Check the local revocation list
	revoked, err := ca.certStore.IsRevoked(certKeyAttrs, certificate.SerialNumber)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, ErrCertRevoked
	}

	// Check the distribuition point CRLs
	revoked, err = ca.certStore.IsRevokedAtDistributionPoints(
		certKeyAttrs, certificate.SerialNumber)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, ErrCertRevoked
	}

	caKeyAttributes, ok := ca.keyAttributes[certificate.PublicKeyAlgorithm]
	if !ok {
		return false, keystore.ErrInvalidKeyAlgorithm
	}

	// Load the Certificate Authority Root CA certificate and any other
	// trusted root certificates that've been imported into the certificate store
	roots, err := ca.certStore.TrustedRootCertPool(
		caKeyAttributes,
		ca.params.Config.AutoImportIssuingCA)
	if err != nil {
		return false, err
	}

	// Load the Certificate Authority Intermediate CA certificate and all
	// imported trusted intermediate certificates from the certificate store
	intermediates, err := ca.certStore.TrustedIntermediateCertPool(caKeyAttributes)
	if err != nil {
		if err != store.ErrFileNotFound {
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
		} else if err != ErrTrustExists {
			return false, err
		}
	}

	return true, nil
}

// Parses the Issuer common name from a child certificate
func (ca *CA) parseIssuerURL(url string) (string, store.FSExtension, error) {
	// Parse the certificate file name from the URL
	pathPieces := strings.Split(url, "/")
	filename := pathPieces[len(pathPieces)-1]
	namePieces := strings.Split(filename, ".")
	if len(namePieces) != 2 {
		return "", "", ErrInvalidIssuingURL
	}
	cn := namePieces[0]
	ext := store.FSExtension(strings.ToLower("." + namePieces[1]))
	if ext != store.FSEXT_DER && ext != store.FSEXT_PEM {
		return "", "", ErrInvalidIssuingURL
	}
	return cn, ext, nil
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
	// var err error
	for _, url := range cert.IssuingCertificateURL {

		cn, ext, err := ca.parseIssuerURL(url)
		if err != nil {
			return err
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
		var partition store.Partition = store.PARTITION_TRUSTED_INTERMEDIATE
		if caCert.IsCA && len(caCert.IssuingCertificateURL) == 0 {
			partition = store.PARTITION_TRUSTED_ROOT
		}

		// Stop the recursion loop and abort if the certificate already
		// exists in the certificate store.
		template, err := keystore.Template(cert.PublicKeyAlgorithm)
		if err != nil {
			return err
		}
		template.Domain = cn
		template.CN = cn
		template.KeyType = keystore.KEY_TYPE_NULL

		err = ca.certStore.TrustsCA(template, partition)
		if err != nil {
			if err == ErrTrustExists {
				ca.params.Logger.Errorf("certificate-authority: CA Issuer certificate already trusted: %s", cn)
			}
			return err
		}

		// Save the certificate to the Certificate Authority trust store in PEM form
		// if ext == store.FSEXT_DER {
		// bufPEM, err := EncodePEM(bufBytes)
		// if err != nil {
		// 	return err
		// }
		// err = ca.certStore.Save(template, bufPEM, store.FSEXT_PEM, &partition)
		// if err != nil {
		// 	ca.params.Logger.Error(err)
		// 	return err
		// }
		// } else if ext == store.FSEXT_PEM {
		err = ca.certStore.Save(template, bufBytes, ext, &partition)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		// }

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
	}
	return nil
}

// Download, verify and import all "Distribution Point CRLs" listed in the certificate
// The CRL(s) are added to the Certificate Authority 3rd party CRL store and used during
// certificate verifications.
func (ca *CA) ImportDistrbutionCRLs(cert *x509.Certificate) error {
	for _, url := range cert.CRLDistributionPoints {

		cn := cert.Subject.CommonName
		template, err := keystore.Template(cert.PublicKeyAlgorithm)
		if err != nil {
			return err
		}
		template.Domain = cn
		template.CN = cn
		template.KeyType = keystore.KEY_TYPE_CA

		if hasCRL := ca.certStore.HasCRL(template); hasCRL {
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
		_, err = x509.ParseRevocationList(derBytes)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Stop the recursion loop and abort if the CRL already
		// exists in the certificate store.
		if hasCRL := ca.certStore.HasCRL(template); hasCRL {
			ca.params.Logger.Errorf("certificate-authority: CRL already imported: %s", cn)
			return ErrDistributionPointExists
		}

		// Save the CRL to the Certificate Authority trust store in binary format
		partition := store.PARTITION_CRL
		err = ca.certStore.Save(template, derBytes, store.FSEXT_CRL, &partition)
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

// Returns a validated x509 certificate from the certificate store
func (ca *CA) Certificate(attrs keystore.KeyAttributes) (*x509.Certificate, error) {
	der, err := ca.DER(attrs)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Returns raw ASN.1 DER encoded certificate bytes from the certificate store
func (ca *CA) DER(attrs keystore.KeyAttributes) ([]byte, error) {
	var err error
	var der []byte
	switch attrs.KeyType {
	case keystore.KEY_TYPE_CA:
		der, err = ca.certStore.Get(attrs, store.FSEXT_DER, nil)
	default:
		der, err = ca.certStore.Get(attrs, store.FSEXT_DER, nil)
	}
	if err != nil {
		return nil, err
	}
	return der, nil
}

// Returns a PEM certifcate from the cert store as []byte or
// ErrCertNotFound if the certificate does not exist.
func (ca *CA) PEM(attrs keystore.KeyAttributes) ([]byte, error) {
	var err error
	var pem []byte
	switch attrs.KeyType {
	case keystore.KEY_TYPE_CA:
		partition := store.PARTITION_CA
		pem, err = ca.certStore.Get(attrs, store.FSEXT_PEM, &partition)
	default:
		// partition := store.PARTITION_ISSUED/
		pem, err = ca.certStore.Get(attrs, store.FSEXT_PEM, nil)
	}
	if err != nil {
		return nil, err
	}
	return pem, nil
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
				return nil, store.ErrInvalidPassword
			}
			if strings.Compare(err.Error(), "pkcs8: incorrect password") == 0 {
				return nil, store.ErrInvalidPassword
			}
			ca.params.Logger.Error(err)
			return nil, keystore.ErrInvalidPrivateKey
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
				return nil, store.ErrInvalidPassword
			}
			ca.params.Logger.Error(err)
			return nil, keystore.ErrInvalidPrivateKey
		}
	}
	return privKeyAny.(crypto.PrivateKey), nil
}

// Returns a private key from the certificate store using the stored ASN.1
// DER PKCS8 key.
// func (ca *CA) PrivateKey(cn string) (crypto.PrivateKey, error) {
// 	bytes, err := ca.certStore.Get(cn, cn, PARTITION_ISSUED, FSEXT_PRIVATE_PKCS8)
// 	if err != nil {
// 		return nil, err
// 	}
// 	key, err := x509.ParsePKCS8PrivateKey(bytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return key, nil
// }

// Returns a crypto.Signer for an issued certificate
func (ca *CA) Signer(attrs keystore.KeyAttributes) (crypto.Signer, error) {
	return ca.keyStore.Signer(attrs)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) PubKey(attrs keystore.KeyAttributes) (crypto.PublicKey, error) {
	return ca.certStore.PubKey(attrs)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
// and returns it in PEM form.
func (ca *CA) PubKeyPEM(attrs keystore.KeyAttributes) ([]byte, error) {
	return ca.certStore.PubKeyPEM(attrs)
}

// Imports a new x509 certificate to the certificate store.
func (ca *CA) Import(attrs keystore.KeyAttributes, cert *x509.Certificate) error {
	return ca.ImportDER(attrs, cert.Raw)
}

// Imports a new x509 certificate to the certificate store using
// the specified common name.
func (ca *CA) ImportCN(attrs keystore.KeyAttributes, cert *x509.Certificate) error {
	return ca.ImportDER(attrs, cert.Raw)
}

// Import a raw DER certificate and perform the following operations:
// 1. Parse to ensure it's valid
// 2. Verify the certificate (auto-import issuer CA's if enabled)
// 3. Format & save as PEM
// 4. Extract and save the public key
func (ca *CA) ImportDER(attrs keystore.KeyAttributes, derCert []byte) error {

	// Parse the certificate to ensure it's valid
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Verify the certificate
	valid, err := ca.Verify(cert, &attrs.CN)
	if err != nil {
		ca.params.Logger.Warning(err)
	}
	if !valid && ca.params.Config.AutoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &attrs.CN, cert); err != nil {
			return err
		}
	}

	// Save the DER form to the certificate store
	err = ca.backend.Save(attrs, derCert, store.FSEXT_DER, nil)
	if err != nil {
		return err
	}

	// Encode the DER form to PEM form and save it to
	// the certificate store
	pemBytes, err := EncodePEM(derCert)
	if err != nil {
		return err
	}
	if err := ca.certStore.Save(
		attrs, pemBytes, store.FSEXT_PEM, nil); err != nil {
		return err
	}

	return nil
}

// Import a PEM certificate to the certificate store. The certificate
// is parsed and verified prior to import to ensure it's valid.
func (ca *CA) ImportPEM(attrs keystore.KeyAttributes, pemBytes []byte) error {

	// Parse the certificat to ensure it's valid
	cert, err := DecodePEM(pemBytes)
	if err != nil {
		return err
	}

	// Import the intermediate and root certificates so the
	// cert can be validated, if not already in the store
	valid, err := ca.Verify(cert, &attrs.CN)
	if err != nil {
		ca.params.Logger.Warning(err)
	}
	if !valid && ca.params.Config.AutoImportIssuingCA {
		if err := ca.ImportIssuingCAs(cert, &attrs.CN, cert); err != nil {
			return err
		}
	}

	partition := store.PARTITION_TLS
	return ca.certStore.Save(attrs, pemBytes, store.FSEXT_PEM, &partition)
}

// Encodes a public key as PKIX, ASN.1 DER and PEM form and saves both to the
// certificate store "issued" partition
func (ca *CA) IssuePubKey(attrs keystore.KeyAttributes, pub crypto.PublicKey) error {
	return ca.issuePubKey(attrs, pub, store.PARTITION_TLS)
}

// Imports a root CA certificate into the trusted root store
func (ca *CA) ImportTrustedRoot(attrs keystore.KeyAttributes, derCert []byte) error {
	return ca.importTrustedCert(attrs, derCert, store.PARTITION_TRUSTED_ROOT)
}

// Imports an intermediate CA certificate into the trusted intermediate store
func (ca *CA) ImportTrustedIntermediate(attrs keystore.KeyAttributes, derCert []byte) error {
	return ca.importTrustedCert(attrs, derCert, store.PARTITION_TRUSTED_INTERMEDIATE)
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
func (ca *CA) createSubjectKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
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
func (ca *CA) importTrustedCert(attrs keystore.KeyAttributes, derCert []byte, partition store.Partition) error {
	err := ca.certStore.Save(attrs, derCert, store.FSEXT_DER, &partition)
	if err != nil {
		return err
	}
	pem, err := EncodePEM(derCert)
	if err != nil {
		return err
	}
	return ca.certStore.Save(attrs, pem, store.FSEXT_PEM, &partition)
}

// Encodes a public key to PEM form and saves it to the certificate store
func (ca *CA) issuePubKey(
	attrs keystore.KeyAttributes,
	pub crypto.PublicKey,
	partition store.Partition) error {

	// PKIX, ASN.1 DER form
	pubDER, err := store.EncodePubKey(pub)
	if err != nil {
		return err
	}
	// Save the ASN.1 DER PKCS1 form
	if err := ca.certStore.Save(
		attrs, pubDER, store.FSEXT_PUBLIC_PKCS1, &partition); err != nil {
		return err
	}
	pubPEM, err := store.EncodePubKeyPEM(attrs.CN, pubDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Save the PEM (PKCS1) form
	return ca.certStore.Save(attrs, pubPEM, store.FSEXT_PUBLIC_PEM, &partition)
}

// Returns a CA crypto.Signer for the provided algorithm. If an algorithm
// is not provided, the default CA key algorithm is used.
func (ca *CA) CASigner(algorithm *x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	if algorithm == nil {
		algorithm = &ca.defaultKeyAlgorithm
	}
	key, ok := ca.keyAttributes[*algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	return ca.Signer(key)
}

// Retrieves the CA certificate for the provided key algorithm. If an algorithm
// is not provided, the default CA key algorithm is used.
func (ca *CA) CACertificate(algorithm *x509.PublicKeyAlgorithm) (*x509.Certificate, error) {
	if algorithm == nil {
		algorithm = &ca.defaultKeyAlgorithm
	}
	key, ok := ca.keyAttributes[*algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	certificate, err := ca.Certificate(key)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

// Imports the Root CA certificate into the trusted root
// store of an Intermediate Certificate Authority.
func (ca *CA) importRootCA(
	algorithm x509.PublicKeyAlgorithm,
	parentCertificate *x509.Certificate) error {

	template, err := keystore.Template(algorithm)
	if err != nil {
		return err
	}
	template.Domain = ca.identity.Subject.CommonName
	template.CN = parentCertificate.Subject.CommonName
	template.X509Attributes = &keystore.X509Attributes{
		CN:   parentCertificate.Subject.CommonName,
		Type: keystore.X509_TYPE_TRUSTED_ROOT,
	}

	// Save DER certificate
	err = ca.certStore.Save(
		template, parentCertificate.Raw, store.FSEXT_DER, nil)
	if err != nil {
		return err
	}

	// Get the current CA certificate
	caKeyAttrs, ok := ca.keyAttributes[algorithm]
	if !ok {
		return keystore.ErrInvalidKeyAlgorithm
	}
	caCert, err := ca.Certificate(caKeyAttrs)

	// Verify the Intermediate CA cert
	valid, err := ca.Verify(caCert, &caCert.Subject.CommonName)
	if err != nil {
		ca.params.Logger.Warning(err)
		// return err
	}
	if !valid {
		return ErrCertInvalid
	}

	return nil
}

func (ca *CA) createCABundle(
	algorithm *x509.PublicKeyAlgorithm,
	parentCertificate *x509.Certificate) error {

	if parentCertificate == nil {
		return errors.New("certificate-authority: parent CA needed to create bundle")
	}

	if algorithm == nil {
		algorithm = &ca.defaultKeyAlgorithm
	}

	template, err := keystore.Template(*algorithm)
	if err != nil {
		return err
	}
	template.Domain = ca.identity.Subject.CommonName
	template.KeyType = keystore.KEY_TYPE_CA

	certs := make([][]byte, 0)

	// Get the certificate for "this" Intermediate CA
	certificate, err := ca.CACertificate(algorithm)
	if err != nil {
		return err
	}
	template.CN = certificate.Subject.CommonName

	// Encode this CA certificate to PEM
	caPEM, err := EncodePEM(certificate.Raw)
	if err != nil {
		return err
	}

	partition := store.PARTITION_CA
	err = ca.certStore.Save(
		template,
		caPEM,
		store.FSEXT_CA_BUNDLE_PEM,
		&partition)
	if err != nil {
		return err
	}
	certs = append(certs, caPEM)

	// Encode the parent certificate to PEM
	parentPEM, err := EncodePEM(parentCertificate.Raw)
	if err != nil {
		return err
	}
	err = ca.certStore.Append(
		template,
		parentPEM,
		store.PARTITION_CA,
		store.FSEXT_CA_BUNDLE_PEM)
	if err != nil {
		return err
	}
	certs = append(certs, caPEM)

	// Append any other Issuing CAs
	for _, issuer := range parentCertificate.IssuingCertificateURL {
		cn, _ := util.FileName(issuer)
		issuerTemplate := template
		issuerTemplate.Domain = cn
		issuerTemplate.CN = cn
		partition = store.PARTITION_CA
		certPEM, err := ca.certStore.Get(issuerTemplate, store.FSEXT_PEM, &partition)
		if err != nil {
			return err
		}
		err = ca.certStore.Append(
			template,
			certPEM,
			store.PARTITION_CA,
			store.FSEXT_CA_BUNDLE_PEM)
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
// a certificate from this CA. If a key algorithm is not provided,
// the default CA key algorithm is used.
func (ca *CA) CABundle(algorithm *x509.PublicKeyAlgorithm) ([]byte, error) {
	if algorithm == nil {
		algorithm = &ca.defaultKeyAlgorithm
	}
	keyAttrs, ok := ca.keyAttributes[*algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	partition := store.PARTITION_CA
	return ca.certStore.Get(keyAttrs, store.FSEXT_CA_BUNDLE_PEM, &partition)
}

// Returns a x509.CertPool with the CA certificates bundled, If a
// key algorithm is not provided, the default CA key algorithm is used.
func (ca *CA) CABundleCertPool(algorithm *x509.PublicKeyAlgorithm) (*(x509.CertPool), error) {
	if algorithm == nil {
		algorithm = &ca.defaultKeyAlgorithm
	}
	rootCAs := x509.NewCertPool()
	bundlePEM, err := ca.CABundle(algorithm)
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
func (ca *CA) TLSCertificate(attrs keystore.KeyAttributes) (tls.Certificate, error) {

	ca.params.Logger.Debug("certificate-authority: building TLS certificate")
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	signer, err := ca.keyStore.Signer(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := ca.Certificate(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		PrivateKey:  signer,
		Leaf:        cert,
		Certificate: [][]byte{cert.Raw},
	}, nil
}

// Returns a tls.Config for the requested common name populated with the
// Certificate Authority Trusted Root certificates and leaf certifiate.
func (ca *CA) TLSConfig(attrs keystore.KeyAttributes, includeSystemRoot bool) (*tls.Config, error) {

	ca.params.Logger.Debug("certificate-authority: building TLS config")
	keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	rootCAs, err := ca.TrustedRootCertPool(attrs.KeyAlgorithm, includeSystemRoot)
	if err != nil {
		return nil, err
	}

	signer, err := ca.keyStore.Signer(attrs)
	if err != nil {
		return nil, err
	}

	leaf, err := ca.Certificate(attrs)
	if err != nil {
		return nil, err
	}

	certs := make([][]byte, 2)
	certs[0] = leaf.Raw
	certs[1] = ca.certificates[attrs.KeyAlgorithm].Raw

	return &tls.Config{
		RootCAs: rootCAs,
		Certificates: []tls.Certificate{
			{
				PrivateKey:  signer,
				Leaf:        leaf,
				Certificate: certs,
			},
		},
		// Force TLS 1.3 to protect against TLS downgrade attacks
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}, nil
}

// Returns the requested blob from the blob store
func (ca *CA) Blob(key string) ([]byte, error) {
	return ca.blobStore.Blob(key)
}

// Saves a new blob to the blob store
func (ca *CA) ImportBlob(key string, data []byte) error {
	return ca.blobStore.Save(key, data)
}

// Create a dummy certificate and revoke it to initialize the CRL
func (ca *CA) initCRL(caAttrs keystore.KeyAttributes) error {
	ca.params.Logger.Infof("Initializing %s Certificate Revocation List",
		caAttrs.KeyAlgorithm)
	// Create dummy certificate key attributes using the
	// CA attibutes as a tmplate
	attrs, err := keystore.Template(caAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	if err != nil {
		return err
	}
	attrs.Domain = "dummy"
	attrs.CN = "dummy"
	dummyCert := CertificateRequest{
		KeyAttributes: &attrs,
		Valid:         1,
		Subject: Subject{
			CommonName: attrs.CN,
		},
	}
	_, err = ca.IssueCertificate(dummyCert)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	return ca.Revoke(attrs)
}

// Ensures the specified password meets complexity requirements.
//
// ErrPrivateKeyPasswordRequired is returned if a password is
// required but the specified password is nil
//
// ErrPasswordComplexity is returned if the password fails to meet
// complexity requirements
func (ca *CA) checkPassword(password []byte) error {
	if ca.params.Config.RequirePrivateKeyPassword {
		if password == nil {
			return ErrPrivateKeyPasswordRequired
		}
		if !ca.passwordPolicy.MatchString(string(password)) {
			return common.ErrPasswordComplexity
		}
	}
	return nil
}
