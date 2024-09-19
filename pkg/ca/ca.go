package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

var (
	ErrInvalidConfig                = errors.New("certificate-authority: invalid configuration")
	ErrCertFuture                   = errors.New("certificate-authority: certificate issued in the future")
	ErrCertExpired                  = errors.New("certificate-authority: certificate expired")
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
	ErrUnknownCA                    = errors.New("certificate-authority: unknown certificate authority")
	ErrMissingIssuerURL             = errors.New("certificate-authority: missing Issuing CA URL in certificate")
	ErrInvalidIssuer                = errors.New("certificate-authority: invalid certificate issuer")

	WarnNoSigningPassword = errors.New("certificate-authority: signing with an insecure private key")
)

type CertificateAuthority interface {
	// AttestLocal(signerAttrs *keystore.KeyAttributes) error
	// AttestationEventLog(cn string) ([]byte, error)
	// AttestationPCRs(cn string) (map[string][][]byte, error)
	// AttestationQuote(cn string) ([]byte, error)
	// AttestationSignature(cn, blobType string) ([]byte, error)
	CABundle(storeType *keystore.StoreType, keyAlgorithm *x509.PublicKeyAlgorithm) ([]byte, error)
	CABundleCertPool(*keystore.StoreType, *x509.PublicKeyAlgorithm) (*x509.CertPool, error)
	CAKeyAttributes(
		storeType keystore.StoreType,
		keyAlgorithm x509.PublicKeyAlgorithm) (*keystore.KeyAttributes, error)
	CASigner(storeType *keystore.StoreType, algorithm *x509.PublicKeyAlgorithm) (crypto.Signer, error)
	Certificate(keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error)
	Checksum(key []byte) (bool, error)
	CreateCSR(request CertificateRequest) ([]byte, error)
	DefaultKeyAlgorithm() x509.PublicKeyAlgorithm
	DefaultValidityPeriod() int
	EndorsementKeyCertificate() ([]byte, error)
	Hash() crypto.Hash
	Identity() Identity
	Init(parentCA CertificateAuthority) error
	IsAutoImportingIssuerCAs() bool
	IsInitialized() (bool, error)
	ImportAttestation(attestatomAttrs *keystore.KeyAttributes, blobType string, data []byte, backend keystore.KeyBackend) error
	ImportAttestationKeyCertificate(attrs *keystore.KeyAttributes, akDER []byte) error
	ImportAttestationEventLog(attestatomAttrs *keystore.KeyAttributes, data []byte, backend keystore.KeyBackend) error
	ImportAttestationPCRs(attestatomAttrs *keystore.KeyAttributes, pcrs []byte, backend keystore.KeyBackend) error
	ImportAttestationQuote(attestatomAttrs *keystore.KeyAttributes, data []byte, backend keystore.KeyBackend) error
	ImportCertificate(certificate *x509.Certificate) error
	ImportDistrbutionCRLs(cert *x509.Certificate) error
	ImportEndorsementKeyCertificate(attrs *keystore.KeyAttributes, ekCertBytes []byte) error
	ImportLocalAttestation(keyAttrs *keystore.KeyAttributes, quote tpm2.Quote, backend keystore.KeyBackend) error
	ImportIssuingCAs(certificate *x509.Certificate) error
	IssueCertificate(request CertificateRequest) ([]byte, error)
	ImportCertificatePEM(attrs *keystore.KeyAttributes, pemBytes []byte) error
	IssueAKCertificate(request CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)
	IssueEKCertificate(request CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error)
	Load() error
	Key(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error)
	Keyring() *platform.Keyring
	ParseBundle(bundle []byte) ([]*x509.Certificate, error)
	PEM(attrs *keystore.KeyAttributes) ([]byte, error)
	Public() crypto.PublicKey
	Revoke(certificate *x509.Certificate) error
	RootCertificate(storeType keystore.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.Certificate, error)
	RootCertificateFor(certificate *x509.Certificate) (*x509.Certificate, error)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	SignedBlob(key []byte) ([]byte, error)
	Signature(key string) ([]byte, error)
	IsSigned(key string) (bool, error)
	SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error)
	SignedDigest(key string, hash crypto.Hash) (bool, error)
	Signer(attrs *keystore.KeyAttributes) (crypto.Signer, error)
	SignTCGCSRIDevID(
		cn string,
		tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
		request *CertificateRequest) ([]byte, error)
	TLSCertificate(attrs *keystore.KeyAttributes) (tls.Certificate, error)
	TLSBundle(attrs *keystore.KeyAttributes) ([][]byte, *x509.Certificate, error)
	TLSConfig(attrs *keystore.KeyAttributes) (*tls.Config, error)
	OSTrustStore() OSTrustStore
	TrustedRootCertPool(certificate *x509.Certificate) (*x509.CertPool, error)
	TrustedIntermediateCertPool(certificate *x509.Certificate) (*x509.CertPool, error)
	Verify(certificate *x509.Certificate) error
	VerifyAttestationEventLog(signerAttrs *keystore.KeyAttributes, eventLog []byte) error
	VerifyAttestationPCRs(signerAttrs *keystore.KeyAttributes, pcrs []byte) error
	VerifyAttestationQuote(signerAttrs *keystore.KeyAttributes, quote []byte) error
	VerifySignature(digest []byte, signature []byte, opts *keystore.VerifyOpts) error
	VerifyTCGCSRIDevID(
		tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
		signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error)
	VerifyQuote(keyAttrs *keystore.KeyAttributes, quote tpm2.Quote, nonce []byte) error
}

type CA struct {
	blobStore            blobstore.BlobStorer
	certStore            certstore.CertificateStorer
	commonName           string
	identity             Identity
	keyring              *platform.Keyring
	params               *CAParams
	trustStore           OSTrustStore
	keyAttributesMap     map[keystore.StoreType]map[x509.PublicKeyAlgorithm]keystore.KeyAttributes
	defaultKeyAttributes keystore.KeyAttributes
	CertificateAuthority
}

// This function creates new Root and Intermediate x509 Certifiate Authorities
// according to the platform configuration file. First, an attempt is made to
// load them from a pre-existing initilization. If the CA hasn't been initialized,
// (missing CA public/private keys from the key store(s)), the Root and Intermediate
// CAs will be returned along with ErrNotInitalized.
//
// ErrNotInitialized signals that Init needs to be called to initialize the CA key
// store(s). After initialization, subsequent invocations will load and return
// the CAs ready to use.
func NewCA(params *CAParams) (CertificateAuthority, CertificateAuthority, error) {

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

	// Return the parent CA if it's the only CA configured
	if len(params.Config.Identity) == 1 {
		if _, err := parentCA.IsInitialized(); err != nil {
			if err := parentCA.Load(); err != nil {
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

	// Use the selected Intermediate index pointer to load the desired intermediate
	params.Identity = params.Config.Identity[params.SelectedCA]
	intermediateCA, err := NewIntermediateCA(params)
	if err != nil {
		return nil, nil, err
	}

	// If not initialized, return ErrNotInitialized signaling to
	// initialize the key stores.
	if _, err := intermediateCA.IsInitialized(); err != nil {
		return nil, nil, err
	} else {
		if err := intermediateCA.Load(); err != nil {
			return nil, nil, err
		}
	}

	return parentCA, intermediateCA, nil
}

// Creates a new x509 Root or Parent x509 Certificate Authority
func NewParentCA(params *CAParams) (CertificateAuthority, error) {

	if len(params.Config.Identity) < 2 {
		params.Logger.Errorf("certificate-authority: Root and at least 1 Intermediate CA required")
		return nil, ErrInvalidConfig
	}

	caCN := params.Identity.Subject.CommonName

	storeLen := len(params.Keyring.Stores())
	keyAttributesMap := make(map[keystore.StoreType]map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, storeLen)
	for _, store := range params.Keyring.Stores() {
		keyAttributesMap[store.Type()] = make(map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, 0)
	}

	return &CA{
		params:           params,
		keyring:          params.Keyring,
		certStore:        params.CertStore,
		blobStore:        params.BlobStore,
		identity:         params.Config.Identity[0],
		trustStore:       NewDebianTrustStore(params.Logger, params.Fs, params.Home),
		commonName:       caCN,
		keyAttributesMap: keyAttributesMap,
	}, nil
}

// Create a new x509 Intermediate Certificate Authority.
func NewIntermediateCA(params *CAParams) (CertificateAuthority, error) {

	storeLen := len(params.Keyring.Stores())
	keyAttributesMap := make(map[keystore.StoreType]map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, storeLen)
	for _, store := range params.Keyring.Stores() {
		keyAttributesMap[store.Type()] = make(map[x509.PublicKeyAlgorithm]keystore.KeyAttributes, 0)
	}

	return &CA{
		params:           params,
		keyring:          params.Keyring,
		certStore:        params.CertStore,
		blobStore:        params.BlobStore,
		identity:         params.Identity,
		trustStore:       NewDebianTrustStore(params.Logger, params.Fs, params.Home),
		commonName:       params.Identity.Subject.CommonName,
		keyAttributesMap: keyAttributesMap,
	}, nil
}

// Returns the CA's default public key
// Implements crypto.PrivateKey
// Implements crypto.Decrypter
func (ca *CA) Public() crypto.PublicKey {
	signer, err := ca.Signer(&ca.defaultKeyAttributes)
	if err != nil {
		ca.params.Logger.FatalError(err)
	}
	return signer.Public()
}

// Returns the CA's default hash function
func (ca *CA) Hash() crypto.Hash {
	return ca.defaultKeyAttributes.Hash
}

// Returns the CA's default key algorithm
func (ca *CA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return ca.defaultKeyAttributes.KeyAlgorithm
}

// Load CA key attributes. Any errors during Load are treated as Fatal.
func (ca *CA) Load() error {

	ca.params.Logger.Infof("Loading Certificate Authority: %s", ca.commonName)

	for _, keyConfig := range ca.identity.Keys {

		if keyConfig == nil {
			continue
		}

		// Create key attributes from config
		caKeyAttrs, err := keystore.KeyAttributesFromConfig(keyConfig)
		if err != nil {
			return err
		}
		caKeyAttrs.CN = ca.commonName
		caKeyAttrs.KeyType = keystore.KEY_TYPE_CA

		// If this key is configured with the platform policy, set
		// the password to a PlatformPassword
		if caKeyAttrs.PlatformPolicy {
			password, err := ca.keyring.Password(caKeyAttrs)
			if err != nil {
				return err
			}
			caKeyAttrs.Password = password
		} else {
			// Prompt the user for the password to this key
			fmt.Println(caKeyAttrs)
			password := prompt.KeyPassword()
			caKeyAttrs.Password = keystore.NewClearPassword(password)
		}

		// Try to load the key using the password / auth policy
		if caKeyAttrs.StoreType != keystore.STORE_PKCS8 {
			if _, err = ca.keyring.Key(caKeyAttrs); err != nil {
				ca.params.Logger.Error(err)
				return err
			}
		}

		ca.keyAttributesMap[caKeyAttrs.StoreType][caKeyAttrs.KeyAlgorithm] = *caKeyAttrs

		if ca.defaultKeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			ca.defaultKeyAttributes = *caKeyAttrs
		}

		ca.params.Logger.Debugf(
			"certificate-authority: loaded %s CA key attributes",
			caKeyAttrs.KeyAlgorithm)

		// Print the CA bundle to the log if in debug mode
		bundle, err := ca.CABundle(&caKeyAttrs.StoreType, &caKeyAttrs.KeyAlgorithm)
		if err != nil {
			ca.params.Logger.FatalError(err)
		}
		ca.params.Logger.Debugf(
			"certificate-authority: %s bundle:",
			caKeyAttrs.KeyAlgorithm)
		ca.params.Logger.Debugf("\n%s", string(bundle))
	}

	return nil
}

// Returns true if the Certificate Authority's configured keys are available
// to start servicing requests. A successful response indicates the Load()
// method is ready to be called. An unsuccessful response intidates Init()
// must be called to initialize the key and certificate store(s).
func (ca *CA) IsInitialized() (bool, error) {
	if len(ca.identity.Keys) == 0 {
		return false, ErrInvalidConfig
	}
	for _, keyConfig := range ca.identity.Keys {
		if keyConfig == nil {
			continue
		}
		keyAttrs, err := keystore.KeyAttributesFromConfig(keyConfig)
		if err != nil {
			ca.params.Logger.FatalError(err)
		}
		keyAttrs.KeyType = keystore.KEY_TYPE_CA
		keyAttrs.CN = ca.commonName
		if err != nil {
			ca.params.Logger.Error(err)
			return false, nil
		}
		if keyAttrs.PlatformPolicy {
			password, err := ca.keyring.Password(keyAttrs)
			if err != nil {
				ca.params.Logger.Error(ErrUnsealFailure)
				keystore.DebugKeyAttributes(ca.params.Logger, keyAttrs)
				return false, nil
			}
			keyAttrs.Password = password
			if ca.params.DebugSecrets {
				if keyAttrs.StoreType == keystore.STORE_PKCS11 {
					// PKCS #11 doesn't support key level passwords
					continue
				}
				clearPass, err := password.String()
				if err != nil {
					// if err == keystore.ErrFileNotFound {
					// 	keyAttrs.Password = keystore.NewRequiredPassword()
					// 	return true
					// }
					keystore.DebugKeyAttributes(ca.params.Logger, keyAttrs)
					return false, err
				}
				ca.params.Logger.Debugf(
					"ca.IsInitialized: loaded CA %s key password %s:%s",
					keyAttrs.StoreType, keyAttrs.CN, clearPass)
			}
		} else {
			// if ca.params.Config.RequireKeyPassword {
			// 	return false, keystore.ErrPasswordRequired
			// }
			keyAttrs.Password = keystore.NewClearPassword([]byte(keyConfig.Password))
		}
		if _, err = ca.keyring.Key(keyAttrs); err != nil {
			ca.params.Logger.MaybeError(err)
			keystore.DebugKeyAttributes(ca.params.Logger, keyAttrs)
			return false, nil
		}
	}
	return true, nil
}

// The first time the Certificate Authority is run, it needs to be initialized. This
// process creates new Root and Intermediate CA(s) private / public key pairs and x509
// signing certificate and saves them to the certificate store.
//
// Subsequent calls to the CA can call Load(). The caller should check IsInitalized first
// to be certain the key and certificate store(s) are accessible and ready to service requests.
//
// Certificates are saved to the certificate store in DER form. Other formats can be exported
// from the stores after they've been saved.
func (ca *CA) Init(parentCA CertificateAuthority) error {

	initialized, err := ca.IsInitialized()
	if err != nil {
		if err != keystore.ErrFileNotFound {
			return err
		}
	}
	if initialized {
		return ca.Load()
		// return ErrAlreadyInitialized
	}

	ca.params.Logger.Infof(
		"Initializing Certificate Authority: %s", ca.commonName)

	// Ensure the parent CA is initialized so it can sign for this
	// new Intermediate.
	if parentCA != nil {
		initialized, err = parentCA.IsInitialized()
		if err != nil {
			return err
		}
		if !initialized {
			return ErrNotInitialized
		}
	}

	// Get SANS IPs, DNS, and Emails from config
	ipAddresses, dnsNames, emailAddresses, err := parseSANS(ca.identity.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	// Create an x509 key pair and certificate for each
	// key algorithm configured via platform configuration file
	// availableKeyAlgorithms := keystore.AvailableKeyAlgorithms()
	for _, keyConfig := range ca.identity.Keys {

		if keyConfig == nil {
			continue
		}

		// Create a new CA certificate serial number
		serialNumber, err := util.SerialNumber()
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		// Create key attributes from config
		caKeyAttrs, err := keystore.KeyAttributesFromConfig(keyConfig)
		if err != nil {
			return err
		}
		caKeyAttrs.CN = ca.commonName
		caKeyAttrs.KeyType = keystore.KEY_TYPE_CA

		// Generate new CA key
		opaque, err := ca.keyring.GenerateKey(caKeyAttrs)
		if err != nil {
			return err
		}
		publicKey := opaque.Public()

		// Create Subject Key ID
		subjectKeyID, err := ca.createSubjectKeyIdentifier(publicKey)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
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

		var parentCert *x509.Certificate
		issuer := subject
		if parentCA != nil {
			parentKeyAttrs, err := parentCA.CAKeyAttributes(
				caKeyAttrs.StoreType,
				caKeyAttrs.KeyAlgorithm)
			if err != nil {
				return err
			}
			parentCert, err = parentCA.Certificate(parentKeyAttrs)
			if err != nil {
				return err
			}
			issuer = parentCert.Subject

			// Set the opaque key to the parent CA
			opaque, err = parentCA.Key(parentKeyAttrs)
			if err != nil {
				return err
			}
		}

		// x509 CA template
		template := &x509.Certificate{
			SignatureAlgorithm:    caKeyAttrs.SignatureAlgorithm,
			PublicKeyAlgorithm:    caKeyAttrs.KeyAlgorithm,
			SerialNumber:          serialNumber,
			Issuer:                issuer,
			Subject:               subject,
			SubjectKeyId:          subjectKeyID,
			AuthorityKeyId:        subjectKeyID,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(ca.identity.Valid, 0, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			EmailAddresses:        emailAddresses,
			ExtraExtensions: []pkix.Extension{
				{
					Id:       common.OIDTPKeyStore,
					Value:    []byte(caKeyAttrs.StoreType),
					Critical: false,
				},
			}}

		signingCert := template
		if parentCA != nil {
			signingCert = parentCert
		}

		ca.params.Logger.Infof(
			"Generating %s certificate for %s with %s %s %s signing key",
			caKeyAttrs.KeyAlgorithm,
			caKeyAttrs.CN,
			caKeyAttrs.StoreType,
			caKeyAttrs.SignatureAlgorithm)

		// Create the new CA certificate
		caDerCert, err := x509.CreateCertificate(rand.Reader,
			template, signingCert, publicKey, opaque)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		cert, err := x509.ParseCertificate(caDerCert)
		if err != nil {
			return err
		}

		err = ca.certStore.ImportCertificate(cert)
		if err != nil {
			return err
		}

		ca.keyAttributesMap[caKeyAttrs.StoreType][caKeyAttrs.KeyAlgorithm] = *caKeyAttrs

		if ca.defaultKeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			ca.defaultKeyAttributes = *caKeyAttrs
		}

		// Import root certificate
		if parentCert != nil {
			if err := ca.certStore.ImportCertificate(parentCert); err != nil {
				return err
			}
		}

		// Initialize the CRL - create a dummy cert and revoke it
		if err := ca.initCRL(caKeyAttrs); err != nil {
			return err
		}
	}

	return nil
}

// Returns the Certificate Authority's key chain
func (ca *CA) Key(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	return ca.keyring.Key(attrs)
}

// Returns the CA key attributes for the requested algorithm
func (ca *CA) CAKeyAttributes(
	storeType keystore.StoreType,
	keyAlgorithm x509.PublicKeyAlgorithm) (*keystore.KeyAttributes, error) {

	storeMap, ok := ca.keyAttributesMap[storeType]
	if !ok {
		ca.params.Logger.Errorf("%s: %s",
			keystore.ErrInvalidKeyStore, storeType)
		return nil, keystore.ErrInvalidKeyStore
	}
	key, ok := storeMap[keyAlgorithm]
	if !ok {
		ca.params.Logger.Errorf("%s: %s",
			keystore.ErrInvalidKeyAttributes, keyAlgorithm)
		return nil, keystore.ErrInvalidKeyAttributes
	}
	return &key, nil
}

// Returns the Certificate Authority identity configuration
func (ca *CA) Keyring() *platform.Keyring {
	return ca.params.Keyring
}

// Returns the Certificate Authority identity configuration
func (ca *CA) Identity() Identity {
	return ca.identity
}

// Returns the default number of days certificates issued by
// the CA are valid.
func (ca *CA) DefaultValidityPeriod() int {
	return ca.params.Config.DefaultValidityPeriod
}

// Returns true if auto-importing of CA certificates are enabled
func (ca *CA) IsAutoImportingIssuerCAs() bool {
	return ca.params.Config.AutoImportIssuingCA
}

// Returns the operating system's CA trusted certificates store provider
func (ca *CA) OSTrustStore() OSTrustStore {
	return ca.trustStore
}

// Returns a cert pool initialized with the root certificate for the
// provided certificate.
func (ca *CA) TrustedRootCertPool(
	certificate *x509.Certificate) (*x509.CertPool, error) {

	pool := x509.NewCertPool()

	rootCert, err := ca.RootCertificateFor(certificate)
	if err != nil {
		return nil, err
	}

	pemBytes, err := EncodePEM(rootCert.Raw)
	if err != nil {
		return nil, err
	}

	ok := pool.AppendCertsFromPEM(pemBytes)
	if !ok {
		return nil, err
	}

	return pool, nil
}

// Returns a cert pool initialized with the root certificate for the
// provided certificate. TrustedRootFor
func (ca *CA) RootCertificateFor(
	certificate *x509.Certificate) (*x509.Certificate, error) {

	storeType, err := certstore.ParseKeyStoreType(certificate)
	if err == keystore.ErrInvalidKeyStore {
		storeType = ca.defaultKeyAttributes.StoreType
	}
	return ca.RootCertificate(storeType, certificate.PublicKeyAlgorithm)
}

// Returns a cert pool initialized with the root certificate for the
// provided certificate.
func (ca *CA) RootCertificate(
	storeType keystore.StoreType,
	keyAlgorithm x509.PublicKeyAlgorithm) (*x509.Certificate, error) {

	var rootCert *x509.Certificate

	caCert, err := ca.Certificate(&ca.defaultKeyAttributes)
	if err != nil {
		return nil, err
	}

	issuerCN := caCert.Issuer.CommonName
	for issuerCN != "" {
		parentAttrs, ok := ca.keyAttributesMap[storeType][keyAlgorithm]
		if !ok {
			return nil, keystore.ErrInvalidKeyAlgorithm
		}
		parentAttrs.CN = issuerCN
		rootCert, err = ca.Certificate(&parentAttrs)
		if err != nil {
			return nil, err
		}
		if rootCert.Issuer.CommonName == rootCert.Subject.CommonName {
			break
		}
		issuerCN = rootCert.Issuer.CommonName
	}
	if !rootCert.IsCA {
		return nil, ErrInvalidIssuer
	}

	return rootCert, nil
}

// Returns a cert pool initialized with the root certificate for the
// provided certificate.
func (ca *CA) TrustedIntermediateCertPool(
	certificate *x509.Certificate) (*x509.CertPool, error) {

	pool := x509.NewCertPool()

	parentAttrs, err := certstore.KeyAttributesFromCertificate(certificate)
	if err != nil {
		return nil, err
	}
	parentAttrs.Debug = ca.params.DebugSecrets
	parentAttrs.CN = certificate.Issuer.CommonName
	parentAttrs.KeyType = keystore.KEY_TYPE_CA
	parentAttrs.SignatureAlgorithm = certificate.SignatureAlgorithm

	for _, ext := range certificate.Extensions {
		if ext.Id.Equal(common.OIDTPIssuerKeyStore) {
			parentAttrs.StoreType = keystore.StoreType(ext.Value)
			break
		}
	}

	cert, err := ca.Certificate(parentAttrs)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, ErrInvalidIssuer
	}

	pemBytes, err := EncodePEM(cert.Raw)
	if err != nil {
		return nil, err
	}

	ok := pool.AppendCertsFromPEM(pemBytes)
	if !ok {
		return nil, err
	}

	return pool, nil
}

// Creates a new Certificate Signing Request (CSR)
func (ca *CA) CreateCSR(request CertificateRequest) ([]byte, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	if request.KeyAttributes.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	// keystore.DebugKeyAttributes(ca.params.Logger, request.KeyAttributes)

	caKeyAttrs, err := ca.matchingKeyOrDefault(request.KeyAttributes)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"creating %s Certificate Signing Request for %s",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName)

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
		SignatureAlgorithm: request.KeyAttributes.SignatureAlgorithm,
		PublicKeyAlgorithm: request.KeyAttributes.KeyAlgorithm,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		// EmailAddresses:     emailAddresses,
	}

	// Set DNS names as SANS
	dnsNames = append(dnsNames, request.Subject.CommonName)
	template.DNSNames = dnsNames

	// Get the CA signer
	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Creating %s CSR for %s with %s %s %s key",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	// Create and sign the x509 certificate request
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

	ca.params.Logger.Debug(string(csrPEM))

	return csrPEM, nil
}

// Signs a Certificate Signing Request (CSR) and save it to the cert store
// in DER and PEM form. This method returns the raw DER encoded []byte array
// as returned from x509.CreateCertificate.
func (ca *CA) SignCSR(csrBytes []byte, request CertificateRequest) ([]byte, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	if request.KeyAttributes.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	// keystore.DebugKeyAttributes(ca.params.Logger, request.KeyAttributes)

	caKeyAttrs, err := ca.matchingKeyOrDefault(request.KeyAttributes)
	if err != nil {
		return nil, err
	}

	// Decode the CSR
	csr, err := DecodeCSR(csrBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create new serial number
	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Get the CA certificate
	caCertificate, err := ca.Certificate(caKeyAttrs)
	if err != nil {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Create new x509 certificate template
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
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:        csr.IPAddresses,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       common.OIDTPIssuerKeyStore,
				Value:    []byte(caKeyAttrs.StoreType),
				Critical: false,
			},
			{
				Id:       common.OIDTPKeyStore,
				Value:    []byte(request.KeyAttributes.StoreType),
				Critical: false,
			},
		},
	}
	template.DNSNames = csr.DNSNames

	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Signing %s CSR for %s with %s %s %s key",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, caCertificate, template.PublicKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	if err := ca.ImportCertificate(certificate); err != nil {
		return nil, err
	}

	return derBytes, nil
}

// Verifies a TCG_CSR_IDEVID Certificate Signing Request (CSR) per TCG TPM 2.0
// Keys for Identity and Attestation - Section 6.1.2 - Procedure.
// The CA issues a challenge to the device to validate that the TPM has the
// EK matching the certificate in step 2b and that the IAK whose public area
// is included in 2c is loaded in the device’s TPM. The challenge data blob is
// created using the following procedure:
// a. Calculate the cryptographic Name of the IAK, by hashing its public area
// with its associated hash algorithm, prepended with the Algorithm ID of the
// hashing algorithm. Refer to TPM 2.0 Library Specification [2], Part 1,
// Section 16 (“Names”).
// b. Using the sequence described in TPM 2.0 Library Specification, Part 3,
// section 12.6.3 (“TPM2_MakeCredential Detailed Actions”), create the
// encrypted “credential” structure to be sent to the device. When building
// this encrypted structure, objectName is the Name of the IAK calculated in
// step ‘a’ and Certificate (which is the payload field) holds a nonce (whose
// size matches the Name hash). Retain the nonce for use in later steps.
// c. The CA sends the encrypted “credential” blob to the enrolling TPM device.
func (ca *CA) VerifyTCGCSRIDevID(
	tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {

	akAttrs, unpackedCSR, err := ca.params.TPM.VerifyCSR(
		tcgCSRIDevID, signatureAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	ekCert, err := x509.ParseCertificate(unpackedCSR.CsrContents.EkCert)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := ca.Verify(ekCert); err != nil {
		return nil, nil, nil, err
	}

	return ca.params.TPM.MakeCredential(akAttrs.TPMAttributes.Name, nil)
}

// Signs a TCG-CSR-IDEVID Certificate Signing Request (CSR) and imports it to
// the certificate store in DER form. This method returns the raw DER encoded
// []byte array as returned from x509.CreateCertificate.
//
// The TCG-CSR-IDEVID structure doesn't define a common name or any PKIX subject
// fields. If a nil CertificateRequest parameter is passed, the certificate
// generated from the TCG-CSR-IDEVID request uses the CA certificate PKIX subject
// configuration.
// The caller can use the StoreType parameter in the passed request parameter's
// key attributes to control which key store module the CA uses to sign the
// request. The CA must own a key in the requested key store, with a matching
// algorithm.
func (ca *CA) SignTCGCSRIDevID(
	cn string,
	tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
	request *CertificateRequest) ([]byte, error) {

	// Unpack the binary CSR
	unpackedCSR, err := tpm2.TransformIDevIDCSR(tcgCSRIDevID)
	if err != nil {
		return nil, err
	}

	// Parse the CSR signing public key from the TCG CSR contents
	idevidPubKey, err := ca.params.TPM.ParsePublicKey(
		unpackedCSR.CsrContents.SigningPub)
	if err != nil {
		return nil, err
	}

	var keyAlgo x509.PublicKeyAlgorithm
	switch idevidPubKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = x509.RSA
	case *ecdsa.PublicKey:
		keyAlgo = x509.ECDSA
	case ed25519.PublicKey:
		keyAlgo = x509.Ed25519
	default:
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Create new serial number
	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	algoMap, ok := ca.keyAttributesMap[keystore.STORE_TPM2]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	caKeyAttrs, ok := algoMap[keyAlgo]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Get the CA certificate
	caCertificate, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	caps, err := ca.params.TPM.FixedProperties()
	if err != nil {
		return nil, err
	}

	// TCG TPM 2.0 Keys for Device Identity and Attestation -
	// Section 8.1 - DevID Certificate Fields Summary.
	// Devices possessing an IDevID or IAK certificate are
	// expected to operate indefinitely into the future and
	// SHOULD use the value 99991231235959Z. Solutions verifying
	// an IDevID/IAK certificate are expected to accept this value
	// indefinitely. Any other value in a DevID notAfter field is
	// expected to be treated as specified in RFC-5280.
	notAfter, err := time.Parse("20060102150405Z", "99991231235959Z")
	if err != nil {
		return nil, err
	}

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

	// Create new x509 certificate template
	template := x509.Certificate{
		SignatureAlgorithm: caKeyAttrs.SignatureAlgorithm,
		PublicKeyAlgorithm: caKeyAttrs.KeyAlgorithm,
		PublicKey:          idevidPubKey,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
		Subject:            subject,
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SubjectKeyId:       caCertificate.SubjectKeyId,
		NotBefore:          time.Now(),
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       common.OIDTCGPermanentIdentifier,
				Value:    []byte(unpackedCSR.CsrContents.ProdSerial),
				Critical: false,
			},
			{
				Id:       common.OIDTCGManufacturer,
				Value:    []byte(caps.VendorID),
				Critical: false,
			},
			{
				Id:       common.OIDTCGModel,
				Value:    []byte(caps.VendorID),
				Critical: false,
			},
			{
				Id:       common.OIDTCGVersion,
				Value:    []byte(fmt.Sprintf("%d.%d", caps.FwMajor, caps.FwMinor)),
				Critical: false,
			},
			{
				Id:       common.OIDTCGHWType,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTCGSpecification,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTCGPlatformModel,
				Value:    []byte(unpackedCSR.CsrContents.ProdModel),
				Critical: false,
			},
			{
				Id:       common.OIDTCGPlatformSerial,
				Value:    []byte(unpackedCSR.CsrContents.ProdSerial),
				Critical: false,
			},
			{
				Id:       common.OIDTPIssuerKeyStore,
				Value:    []byte(caKeyAttrs.StoreType),
				Critical: false,
			},
			{
				Id:       common.OIDTPKeyStore,
				Value:    []byte(keystore.STORE_TPM2),
				Critical: false,
			},
		},
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			common.OIDTCGVerifiedTPMResidency,
			common.OIDTCGVerifiedTPMFixed,
		},
	}

	if request != nil {

		ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, err
		}

		dnsNames = append(dnsNames, request.Subject.CommonName)

		template.IPAddresses = ipAddresses
		template.DNSNames = dnsNames
		template.EmailAddresses = emailAddresses
	}

	signer, err := ca.Signer(&caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Signing %s TCG-CSR-IDEVID for %s with %s %s %s key",
		keyAlgo,
		cn,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, caCertificate, template.PublicKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	if err := ca.ImportCertificate(certificate); err != nil {
		return nil, err
	}

	return derBytes, nil
}

// Generate a new private / public key pair and x509 certificate and
// import it to the certificate store in DER form. This method returns
// the raw DER encoded []byte as returned from x509.CreateCertificate.
func (ca *CA) IssueCertificate(request CertificateRequest) ([]byte, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	if request.KeyAttributes.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	// keystore.DebugKeyAttributes(ca.params.Logger, request.KeyAttributes)

	caKeyAttrs, err := ca.matchingKeyOrDefault(request.KeyAttributes)
	if err != nil {
		return nil, err
	}

	caCertificate, err := ca.Certificate(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	if request.Valid == 0 {
		request.Valid = ca.params.Config.DefaultValidityPeriod
	}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	dnsNames = append(dnsNames, request.Subject.CommonName)

	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Create the new certificate
	template := &x509.Certificate{
		SignatureAlgorithm: caKeyAttrs.SignatureAlgorithm,
		PublicKeyAlgorithm: caKeyAttrs.KeyAlgorithm,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
		Subject: pkix.Name{
			CommonName:         request.Subject.CommonName,
			Organization:       []string{request.Subject.Organization},
			OrganizationalUnit: []string{request.Subject.OrganizationalUnit},
			Country:            []string{request.Subject.Country},
			Province:           []string{request.Subject.Province},
			Locality:           []string{request.Subject.Locality},
			StreetAddress:      []string{request.Subject.Address},
			PostalCode:         []string{request.Subject.PostalCode},
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, request.Valid),
		AuthorityKeyId: caCertificate.SubjectKeyId,
		SubjectKeyId:   caCertificate.SubjectKeyId,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       common.OIDTPIssuerKeyStore,
				Value:    []byte(caKeyAttrs.StoreType),
				Critical: false,
			},
			{
				Id:       common.OIDTPKeyStore,
				Value:    []byte(request.KeyAttributes.StoreType),
				Critical: false,
			},
		},
	}

	opaque, err := ca.keyring.GenerateKey(request.KeyAttributes)
	if err != nil {
		return nil, err
	}
	template.PublicKey = opaque.Public()

	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Issuing %s certificate for %s with %s %s %s key",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	certDerBytes, err := x509.CreateCertificate(
		rand.Reader, template, caCertificate, opaque.Public(), signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certDerBytes)
	if err != nil {
		return nil, err
	}

	if err := ca.ImportCertificate(certificate); err != nil {
		return nil, err
	}

	return certDerBytes, nil
}

// Creates a new private / public key pair for the purposes of a TPM Endorsement
// Certificate (EK Credential Profile), in DER form. This method returns the raw
// DER encoded []byte as returned from x509.CreateCertificate.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf
func (ca *CA) IssueEKCertificate(
	request CertificateRequest,
	ekPubKey crypto.PublicKey) (*x509.Certificate, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// request.KeyAttributes.SignatureAlgorithm = ca.defaultKeyAttributes.SignatureAlgorithm

	caKeyAttrs, err := ca.matchingKeyOrDefault(request.KeyAttributes)
	if err != nil {
		return nil, err
	}

	caCertificate, err := ca.Certificate(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	if request.Valid == 0 {
		request.Valid = ca.params.Config.DefaultValidityPeriod
	}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	dnsNames = append(dnsNames, request.Subject.CommonName)

	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	caps, err := ca.params.TPM.FixedProperties()
	if err != nil {
		return nil, err
	}

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

	template := &x509.Certificate{
		Subject:            subject,
		SignatureAlgorithm: caKeyAttrs.SignatureAlgorithm,
		PublicKeyAlgorithm: request.KeyAttributes.KeyAlgorithm,
		PublicKey:          ekPubKey,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, request.Valid),
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SubjectKeyId:       caCertificate.SubjectKeyId,
		KeyUsage:           x509.KeyUsageDataEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       common.OIDTCGManufacturer,
				Value:    []byte(caps.VendorID),
				Critical: false,
			},
			{
				Id:       common.OIDTCGModel,
				Value:    []byte(caps.VendorID),
				Critical: false,
			},
			{
				Id:       common.OIDTCGVersion,
				Value:    []byte(fmt.Sprintf("%d.%d", caps.FwMajor, caps.FwMinor)),
				Critical: false,
			},
			{
				Id:       common.OIDTCGHWType,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTCGEKCertificate,
				Value:    []byte{},
				Critical: false,
			},
			{
				Id:       common.OIDTCGSpecification,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTPIssuerKeyStore,
				Value:    []byte(caKeyAttrs.StoreType),
				Critical: false,
			},
			{
				Id:       common.OIDTPKeyStore,
				Value:    []byte(request.KeyAttributes.StoreType),
				Critical: false,
			},
		},
		EmailAddresses: emailAddresses}

	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Signing %s EK Certificate for %s with %s %s %s key",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	certDerBytes, err := x509.CreateCertificate(
		rand.Reader, template, caCertificate, ekPubKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certDerBytes)
	if err != nil {
		return nil, err
	}

	if err := ca.ImportCertificate(certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

// Creates a new private / public key pair for the purposes of an Attestation
// Key Certificate (AK Credential Profile), in DER form. This method returns
// the raw DER encoded []byte as returned from x509.CreateCertificate.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf
func (ca *CA) IssueAKCertificate(
	request CertificateRequest,
	pubKey crypto.PublicKey) (*x509.Certificate, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	if request.KeyAttributes.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return nil, keystore.ErrInvalidSignatureAlgorithm
	}

	// ca.params.Logger.Infof(
	// 	"Issuing AK Certificate for %s", request.Subject.CommonName)

	// keystore.DebugKeyAttributes(ca.params.Logger, request.KeyAttributes)

	// storeType := request.KeyAttributes.StoreType
	// keyAlgorithm := request.KeyAttributes.KeyAlgorithm
	// signatureAlgorithm := request.KeyAttributes.SignatureAlgorithm

	// // Get the key attributes for the requested store and algorithm
	// caKeyAttributes, ok := ca.keyAttributesMap[storeType][keyAlgorithm]
	// if !ok {
	// 	return nil, keystore.ErrInvalidKeyAttributes
	// }

	// var caKeyAttributes keystore.KeyAttributes
	// var ok bool

	// switch pubKey.(type) {
	// case *rsa.PublicKey:
	// 	caKeyAttributes, ok = ca.keyAttributesMap[storeType][x509.RSA]
	// 	keyAlgorithm = x509.RSA
	// case *ecdsa.PublicKey:
	// 	caKeyAttributes, ok = ca.keyAttributesMap[storeType][x509.ECDSA]
	// 	keyAlgorithm = x509.ECDSA
	// case ed25519.PublicKey:
	// 	caKeyAttributes, ok = ca.keyAttributesMap[storeType][x509.Ed25519]
	// 	keyAlgorithm = x509.Ed25519
	// default:
	// 	return nil, keystore.ErrInvalidKeyAlgorithm
	// }
	// if !ok {
	// 	return nil, keystore.ErrInvalidKeyAlgorithm
	// }

	// if signatureAlgorithm == x509.UnknownSignatureAlgorithm {
	// 	signatureAlgorithm = caKeyAttributes.SignatureAlgorithm
	// 	request.KeyAttributes.SignatureAlgorithm = signatureAlgorithm
	// }

	caKeyAttrs, err := ca.matchingKeyOrDefault(request.KeyAttributes)
	if err != nil {
		return nil, err
	}

	// Create new serial number
	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// Get the CA certificate
	caCertificate, err := ca.Certificate(caKeyAttrs)
	if err != nil {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	caps, err := ca.params.TPM.FixedProperties()
	if err != nil {
		return nil, err
	}

	// TCG TPM 2.0 Keys for Device Identity and Attestation -
	// Section 8.1 - DevID Certificate Fields Summary.
	// Devices possessing an IDevID or IAK certificate are
	// expected to operate indefinitely into the future and
	// SHOULD use the value 99991231235959Z. Solutions verifying
	// an IDevID/IAK certificate are expected to accept this value
	// indefinitely. Any other value in a DevID notAfter field is
	// expected to be treated as specified in RFC-5280.
	notAfter, err := time.Parse("20060102150405Z", "99991231235959Z")
	if err != nil {
		return nil, err
	}

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

	// Create new x509 certificate template
	template := x509.Certificate{
		SignatureAlgorithm: request.KeyAttributes.SignatureAlgorithm,
		PublicKeyAlgorithm: request.KeyAttributes.KeyAlgorithm,
		PublicKey:          pubKey,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
		Subject:            subject,
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SubjectKeyId:       caCertificate.SubjectKeyId,
		NotBefore:          time.Now(),
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			// {
			// 	Id:       common.OIDTCGPermanentIdentifier,
			// 	Value:    []byte(request.PermanentID),
			// 	Critical: false,
			// },
			// {
			// 	Id:       common.OIDTCGPlatformModel,
			// 	Value:    []byte(request.ProdModel),
			// 	Critical: false,
			// },
			// {
			// 	Id:       common.OIDTCGPlatformSerial,
			// 	Value:    []byte(request.ProdSerial),
			// 	Critical: false,
			// },
			{
				Id:       common.OIDTCGManufacturer,
				Value:    []byte(caps.VendorID),
				Critical: false,
			},
			{
				Id:       common.OIDTCGModel,
				Value:    []byte(caps.Manufacturer),
				Critical: false,
			},
			{
				Id:       common.OIDTCGVersion,
				Value:    []byte(fmt.Sprintf("%d.%d", caps.FwMajor, caps.FwMinor)),
				Critical: false,
			},
			{
				Id:       common.OIDTCGHWType,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTCGSpecification,
				Value:    []byte(caps.Family),
				Critical: false,
			},
			{
				Id:       common.OIDTPIssuerKeyStore,
				Value:    []byte(caKeyAttrs.StoreType),
				Critical: false,
			},
			{
				Id:       common.OIDTPKeyStore,
				Value:    []byte(request.KeyAttributes.StoreType),
				Critical: false,
			},
		},
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			common.OIDTCGVerifiedTPMResidency,
			common.OIDTCGVerifiedTPMFixed,
		},
	}

	ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	dnsNames = append(dnsNames, request.Subject.CommonName)

	template.IPAddresses = ipAddresses
	template.DNSNames = dnsNames
	template.EmailAddresses = emailAddresses

	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, caCertificate, pubKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	if err := ca.ImportCertificate(certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

// Revoke a certificate
func (ca *CA) Revoke(certificate *x509.Certificate) error {

	ca.params.Logger.Infof("Revoking certificate: %s",
		certificate.Subject.CommonName)

	keyAttrs, err := certstore.KeyAttributesFromCertificate(certificate)
	if err != nil {
		return err
	}

	caKeyAttrs, ok := ca.keyAttributesMap[keyAttrs.StoreType][certificate.PublicKeyAlgorithm]
	if !ok {
		return keystore.ErrInvalidKeyAlgorithm
	}

	caCert, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return err
	}

	caSigner, err := ca.Signer(&caKeyAttrs)
	if err != nil {
		return err
	}

	err = ca.certStore.Revoke(certificate, caCert, caSigner)
	if err != nil {
		if err != certstore.ErrCRLNotFound {
			return err
		}
	}

	return ca.keyring.Delete(keyAttrs)
}

// Verifies a certificate by checking the CA revocation list
// and loading it's issuer certificates from the private trusted
// root and intermediate certificate store if they exist. Issuer
// certificates will be automatically downloaded and installed to
// the appropriate certificate store partition if auto-import is
// enabled in the platform configuration file.
func (ca *CA) Verify(certificate *x509.Certificate) error {

	var caKeyAttrs keystore.KeyAttributes
	var storeMap map[x509.PublicKeyAlgorithm]keystore.KeyAttributes
	var keyAlgo x509.PublicKeyAlgorithm
	var ok bool

	// If the CA has a matching key algorithm and store type,
	// check the CRL for an entry for this certificate. Don't
	// return any errors if the CA doesn't have a matching key,
	// since this could be any kind of certificate, issued from
	// any CA. This verification is only concerned with certificate
	// chain, end entity certificate, and revocation list validity.
	certAttrs, _ := certstore.KeyAttributesFromCertificate(certificate)
	keyAlgo, _ = keystore.KeyAlgorithmFromSignatureAlgorithm(certAttrs.SignatureAlgorithm)
	storeMap, _ = ca.keyAttributesMap[certAttrs.StoreType]

	caKeyAttrs, ok = storeMap[keyAlgo]
	if ok {
		// Get the CA certificate
		caCert, err := ca.certStore.Get(&caKeyAttrs)
		if err != nil {
			return err
		}

		// Check to see if it's revoked
		if err := ca.certStore.IsRevoked(certificate, caCert); err != nil {
			return err
		}

		// Check the distribuition point CRLs
		if err = ca.certStore.IsRevokedAtDistributionPoints(certificate); err != nil {
			return err
		}
	}

	// Load the Certificate Authority Root CA certificate and any other
	// trusted root certificates that've been imported into the certificate store
	roots, err := ca.TrustedRootCertPool(certificate)
	if err != nil {
		return err
	}

	// Load the Certificate Authority Intermediate CA certificate and all
	// imported trusted intermediate certificates from the certificate store
	intermediates, err := ca.TrustedIntermediateCertPool(certificate)
	if err != nil {
		if err != certstore.ErrCertNotFound {
			return err
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
		// KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Verify the certificate using the x509 runtime lib
	if _, err := certificate.Verify(opts); err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			// If the issuing authority is unknown and
			// auto-import is enabled, attempt to download
			// and import the CA certificate chain and verify
			// the leaf certificate again.
			if ca.params.Config.AutoImportIssuingCA {
				ca.params.Logger.Warnf(
					"certificate-authority: UnknownAuthorityError: %s with %s key store",
					certAttrs.CN, certAttrs.StoreType)
				ca.params.Logger.Warnf(
					"certificate-authority: attempting auto-import of Issuer CA chain")
				if err := ca.ImportIssuingCAs(certificate); err != nil {
					return err
				}
				// Attempt to verify the leaf certificate again
				// now that it's CA certs are imported.
				if err := ca.Verify(certificate); err != nil {
					return err
				}
			} else {
				return err
			}
		} else if err != certstore.ErrTrustExists {
			return err
		}
	}

	return nil
}

// Parses the Issuer common name from a child certificate
func (ca *CA) parseIssuerURL(url string) (string, certstore.FSExtension, error) {
	// Parse the certificate file name from the URL
	pathPieces := strings.Split(url, "/")
	filename := pathPieces[len(pathPieces)-1]
	namePieces := strings.Split(filename, ".")
	if len(namePieces) != 2 {
		return "", "", ErrInvalidIssuingURL
	}
	cn := namePieces[0]
	ext := certstore.FSExtension(strings.ToLower("." + namePieces[1]))
	if ext != certstore.FSEXT_DER && ext != certstore.FSEXT_PEM {
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
		ca.params.Logger.Errorf("certificate-authority: multiple issuing CAs not supported: %s", cn)
		return "", ErrCertNotSupported
	}

	if cn == "" {
		// Parse the certificate file name from the URL
		filePieces := strings.Split(cert.IssuingCertificateURL[0], "/")
		filename := filePieces[len(filePieces)-1]
		namePieces := strings.Split(filename, ".")
		cn = namePieces[0]
		return cn, nil
	}

	return "", ErrCertNotSupported
}

// Download, verify and import all "CA Issuers" listed in the certificate
// and it's CRL into the Certificate Authority. The certificate(s) are added
// to the trusted certpool, but not installed to the operating system trust store.
func (ca *CA) ImportIssuingCAs(cert *x509.Certificate) error {

	if len(cert.IssuingCertificateURL) == 0 {
		ca.params.Logger.Error(ErrMissingIssuerURL)
		return ErrMissingIssuerURL
	}

	for _, url := range cert.IssuingCertificateURL {

		cn := cert.Subject.CommonName

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
		issuerCert, err := x509.ParseCertificate(bufBytes)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		cn = issuerCert.Subject.CommonName

		keyAttrs, err := certstore.KeyAttributesFromCertificate(issuerCert)
		if err != nil {
			return err
		}
		if _, err := ca.certStore.Get(keyAttrs); err == nil {
			return certstore.ErrTrustExists
		}

		if err := ca.certStore.ImportCertificate(issuerCert); err != nil {
			return err
		}

		ca.params.Logger.Infof("Issuer successfully imported: %s", cn)

		// If the certificate has parents, keep downloading
		// and importing all certificates in the chain until
		// the root certificate is reached.
		if len(issuerCert.IssuingCertificateURL) > 0 {
			// Found a parent cert, import it
			if err := ca.ImportIssuingCAs(issuerCert); err != nil {
				ca.params.Logger.Error(err)
				return err
			}
		}
	}
	return nil
}

// Download, verify and import all Distribution Point CRLs listed in the certificate
// The CRL(s) are added to the Certificate Authority 3rd party CRL store and used during
// certificate verifications.
func (ca *CA) ImportDistrbutionCRLs(certificate *x509.Certificate) error {

	for _, url := range certificate.CRLDistributionPoints {

		cn := certificate.Subject.CommonName

		if _, err := ca.certStore.CRLs(certificate); err != nil {
			if err != certstore.ErrCRLNotFound {
				ca.params.Logger.Errorf("%s: %s", ErrDistributionPointExists, cn)
				return ErrCRLAlreadyExists
			}
		}

		ca.params.Logger.Infof(
			"Importing Distribution Certificate Revocation List (CRL): %s",
			url)

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

		// Save the CRL to the Certificate Authority trust store in DER form
		err = ca.certStore.Save(certificate, certstore.PARTITION_CRL)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		ca.params.Logger.Infof("Distribution CRL successfully imported: %s", cn)
	}
	return nil
}

// Returns a validated x509 certificate from the certificate store
func (ca *CA) Certificate(keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error) {
	return ca.certStore.Get(keyAttrs)
}

// Returns a PEM certifcate from the cert store as []byte or
// ErrCertNotFound if the certificate does not exist.
func (ca *CA) PEM(attrs *keystore.KeyAttributes) ([]byte, error) {
	certificate, err := ca.certStore.Get(attrs)
	if err != nil {
		return nil, err
	}
	return certstore.EncodePEM(certificate.Raw)
}

// Returns a crypto.Signer for an issued certificate
func (ca *CA) Signer(attrs *keystore.KeyAttributes) (crypto.Signer, error) {
	return ca.keyring.Signer(attrs)
}

// Loads and parses a PKIX, ASN.1 DER RSA public key from the certificate store
func (ca *CA) PubKey(attrs *keystore.KeyAttributes) (crypto.PublicKey, error) {
	signer, err := ca.keyring.Signer(attrs)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// Import a x509 certificate and save it to the certificate store
func (ca *CA) ImportCertificate(certificate *x509.Certificate) error {
	// if _, err := ca.Verify(certificate); err != nil {
	// 	return err
	// }
	err := ca.certStore.ImportCertificate(certificate)
	if err != nil {
		return err
	}
	return nil
}

// Import a PEM certificate to the certificate store. The certificate
// is parsed and verified prior to import to ensure it's valid.
func (ca *CA) ImportCertificatePEM(attrs *keystore.KeyAttributes, pemBytes []byte) error {
	cert, err := DecodePEM(pemBytes)
	if err != nil {
		return err
	}
	// err = ca.Verify(cert)
	// if err != nil {
	// 	return err
	// }
	err = ca.certStore.ImportCertificate(cert)
	if err != nil {
		return err
	}
	return nil
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

// Returns a CA crypto.Signer for the provided algorithm. If an algorithm
// is not provided, the default CA key algorithm is used.
func (ca *CA) CASigner(
	storeType *keystore.StoreType,
	algorithm *x509.PublicKeyAlgorithm) (crypto.Signer, error) {

	if storeType == nil {
		storeType = &ca.defaultKeyAttributes.StoreType
	}
	if algorithm == nil {
		algorithm = &ca.defaultKeyAttributes.KeyAlgorithm
	}
	key, ok := ca.keyAttributesMap[*storeType][*algorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	return ca.Signer(&key)
}

// Returns the CA bundle for an Intermediate Certificate Authority
func (ca *CA) CABundle(
	storeType *keystore.StoreType,
	keyAlgorithm *x509.PublicKeyAlgorithm) ([]byte, error) {

	if storeType == nil {
		storeType = &ca.defaultKeyAttributes.StoreType
	}
	if keyAlgorithm == nil {
		keyAlgorithm = &ca.defaultKeyAttributes.KeyAlgorithm
	}
	// Retrieve the CA cert
	caKeyAttrs, ok := ca.keyAttributesMap[*storeType][*keyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	caCert, err := ca.certStore.Get(&caKeyAttrs)
	if err != nil {
		return nil, err
	}

	if caCert.Issuer.CommonName == "" {
		return nil, ErrInvalidIssuer
	}

	// Retrieve the parent cert
	parentKeyAttrs := caKeyAttrs
	parentKeyAttrs.CN = caCert.Issuer.CommonName
	parentCert, err := ca.certStore.Get(&parentKeyAttrs)

	// Convert both DER certs to PEM
	caPEM, err := certstore.EncodePEM(caCert.Raw)
	if err != nil {
		return nil, err
	}
	parentPEM, err := certstore.EncodePEM(parentCert.Raw)
	if err != nil {
		return nil, err
	}

	// Concatenate the certs
	bytes := caPEM
	bytes = append(bytes, parentPEM...)

	return bytes, nil
}

// Returns a x509.CertPool with the CA certificates bundled, If a
// key algorithm is not provided, the default CA key algorithm is used.
func (ca *CA) CABundleCertPool(
	storeType *keystore.StoreType,
	keyAlgorithm *x509.PublicKeyAlgorithm) (*(x509.CertPool), error) {

	if storeType == nil {
		storeType = &ca.defaultKeyAttributes.StoreType
	}
	if keyAlgorithm == nil {
		keyAlgorithm = &ca.defaultKeyAttributes.KeyAlgorithm
	}
	rootCAs := x509.NewCertPool()
	bundlePEM, err := ca.CABundle(storeType, keyAlgorithm)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	if !rootCAs.AppendCertsFromPEM(bundlePEM) {
		ca.params.Logger.Error(err)
		return nil, certstore.ErrCertInvalid
	}
	return rootCAs, nil
}

// Parses a PEM encoded CA bundle with multiple certificates
// and returns and array of x509 certificates that can be used
// for verification or creating a CertPool.
func (ca *CA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
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
			ca.params.Logger.Errorf("certificate-authority: invalid certificate in bundle")
			return nil, certstore.ErrCertInvalid
		}
	}
	return certs, nil
}

// Returns an x509 certificate KeyPair suited for tls.Config
func (ca *CA) TLSCertificate(attrs *keystore.KeyAttributes) (tls.Certificate, error) {

	ca.params.Logger.Debugf("certificate-authority: building TLS certificate")
	// keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	signer, err := ca.keyring.Signer(attrs)
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
// Certificate Authority, cross-signed intermediates if any, and
// the end entity leaf certificate.
func (ca *CA) TLSConfig(attrs *keystore.KeyAttributes) (*tls.Config, error) {

	ca.params.Logger.Debugf(
		"certificate-authority: building %s TLS config", attrs.CN)

	// keystore.DebugKeyAttributes(ca.params.Logger, attrs)

	certs, leaf, err := ca.TLSBundle(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := ca.keyring.Signer(attrs)
	if err != nil {
		return nil, err
	}

	caCert, err := ca.certStore.Get(attrs)
	if err != nil {
		return nil, err
	}

	rootCAs, err := ca.TrustedRootCertPool(caCert)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs: rootCAs,
		Certificates: []tls.Certificate{{
			PrivateKey:  signer,
			Leaf:        leaf,
			Certificate: certs,
		}},
		// Force TLS 1.3 to protect against TLS downgrade attacks
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}, nil
}

// Creates a TLS "bundle" containing the requested leaf certificate,
// the Certificate Authority's certificate, and any cross-signed
// certificates in ASN.1 DER form, and returns the certificate bundle
// and leaf.
func (ca *CA) TLSBundle(attrs *keystore.KeyAttributes) ([][]byte, *x509.Certificate, error) {

	// Retrieve the leaf cert
	leaf, err := ca.Certificate(attrs)
	if err != nil {
		return nil, nil, err
	}

	// TODO: load cross-signed certificates
	crossSignedCerts := make([][]byte, 0)

	// Get the CA certificate
	caKeyAttrs, ok := ca.keyAttributesMap[attrs.StoreType][attrs.KeyAlgorithm]
	if !ok {
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}
	caCertificate, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return nil, nil, err
	}

	// rootCert, err := ca.TrustedRootCertficate(caCertificate)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// Start concatenating a list of DER encoded certs
	certs := make([][]byte, len(crossSignedCerts)+2)
	certs[0] = leaf.Raw
	certs[1] = caCertificate.Raw
	// certs[2] = rootCert.Raw

	// Copy cross signed certs to cert buffer
	for i, csc := range crossSignedCerts {
		copy(csc, certs[i+2])
	}

	return certs, leaf, nil
}

// Returns the requested blob from the blob store
func (ca *CA) Blob(key []byte) ([]byte, error) {
	return ca.blobStore.Get(key)
}

// Saves a new blob to the blob store
func (ca *CA) ImportBlob(key, data []byte) error {
	return ca.blobStore.Save(key, data)
}

// Create a dummy certificate and revoke it to initialize the CRL
func (ca *CA) initCRL(caAttrs *keystore.KeyAttributes) error {
	ca.params.Logger.Infof("Initializing %s %s Certificate Revocation List",
		caAttrs.StoreType,
		caAttrs.KeyAlgorithm)
	// Create dummy certificate key attributes using the
	// CA attibutes as a tmplate
	keyAttrs := *caAttrs
	keyAttrs.CN = "dummy"
	keyAttrs.KeyType = keystore.KEY_TYPE_TLS
	keyAttrs.Password = nil
	keyAttrs.Secret = nil
	dummyCertReq := CertificateRequest{
		KeyAttributes: &keyAttrs,
		Valid:         1,
		Subject: Subject{
			CommonName: keyAttrs.CN,
		},
	}
	der, err := ca.IssueCertificate(dummyCertReq)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}

	err = ca.Revoke(certificate)

	return err
}

// Return the CA key attributes that match the provided key attribute's
// algorithm and store type, or return the default CA key attributes if
// the CA doesn't have a matching key.
func (ca *CA) matchingKeyOrDefault(
	keyAttrs *keystore.KeyAttributes) (*keystore.KeyAttributes, error) {

	storeMap, ok := ca.keyAttributesMap[keyAttrs.StoreType]
	if !ok {
		ca.params.Logger.Debugf("%s: %s", InfoUsingDefaultCAKey, keyAttrs.CN)
		return &ca.defaultKeyAttributes, nil
	}

	attrs, ok := storeMap[keyAttrs.KeyAlgorithm]
	if !ok {
		ca.params.Logger.Debugf("%s: %s", InfoUsingDefaultCAKey, keyAttrs.CN)
		return &ca.defaultKeyAttributes, nil
	}

	return &attrs, nil
}
