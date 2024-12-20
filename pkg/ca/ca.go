package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"log/slog"
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
	ErrEncodingPEM                  = errors.New("certificate-authority: error encoding to PEM")
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
	CertificateStore() certstore.CertificateStorer
	Checksum(key []byte) (bool, error)
	CreateCSR(request CertificateRequest) ([]byte, error)
	CrossSignedPEM(attrs *keystore.KeyAttributes) ([]byte, error)
	DefaultKeyAlgorithm() x509.PublicKeyAlgorithm
	DefaultSignatureAlgorithm() x509.SignatureAlgorithm
	DefaultValidityPeriod() int
	EndorsementKeyCertificate() ([]byte, error)
	Exists(cn string, algorithm x509.PublicKeyAlgorithm) bool
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
	ImportXSignedCertificate(issuerCN string, certificate *x509.Certificate) error
	ImportDistrbutionCRLs(cert *x509.Certificate) error
	ImportEndorsementKeyCertificate(attrs *keystore.KeyAttributes, ekCertBytes []byte) error
	ImportLocalAttestation(keyAttrs *keystore.KeyAttributes, quote tpm2.Quote, backend keystore.KeyBackend) error
	ImportIssuingCAs(certificate *x509.Certificate) error
	IssueCertificate(request CertificateRequest) ([]byte, error)
	Issued(cn string) bool
	ImportCertificatePEM(attrs *keystore.KeyAttributes, pemBytes []byte) error
	IssueAKCertificate(request CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)
	IssueEKCertificate(request CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error)
	Load() error
	Key(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error)
	Keyring() *platform.Keyring
	ParseBundle(bundle []byte) ([]*x509.Certificate, error)
	PEM(attrs *keystore.KeyAttributes) ([]byte, error)
	Public() crypto.PublicKey
	Revoke(certificate *x509.Certificate, deleteKeys bool) error
	RootCertificate(child *x509.Certificate) (*x509.Certificate, error)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	SignedBlob(key []byte) ([]byte, error)
	Signature(key string) ([]byte, error)
	IsSigned(key string) (bool, error)
	SignCSR(csrPEM []byte, request *CertificateRequest) (*x509.Certificate, error)
	SignedDigest(key string, hash crypto.Hash) (bool, error)
	Signer(attrs *keystore.KeyAttributes) (crypto.Signer, error)

	SignTCGCSRIDevID(
		tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
		request *CertificateRequest) (iakDER []byte, idevidDER []byte, err error)
	SignTCGCSRIDevIDBytes(
		tcgCSRIDevIDBytes []byte,
		request *CertificateRequest) (iakDER []byte, idevidDER []byte, err error)

	TLSCertificate(attrs *keystore.KeyAttributes) (tls.Certificate, error)
	TLSBundle(attrs *keystore.KeyAttributes) ([][]byte, *x509.Certificate, error)
	TLSConfig(attrs *keystore.KeyAttributes) (*tls.Config, error)
	TLSConfigWithXSigner(attrs *keystore.KeyAttributes, issuerCN string) (*tls.Config, error)
	OSTrustStore() OSTrustStore
	TrustedRootCertPool(certificate *x509.Certificate, xsignerCN *string) (*x509.CertPool, error)
	TrustedIntermediateCertPool(certificate *x509.Certificate, xsignerCN *string) (*x509.CertPool, error)
	Verify(certificate *x509.Certificate, xsignerCN *string) error
	VerifyAttestationEventLog(signerAttrs *keystore.KeyAttributes, eventLog []byte) error
	VerifyAttestationPCRs(signerAttrs *keystore.KeyAttributes, pcrs []byte) error
	VerifyAttestationQuote(signerAttrs *keystore.KeyAttributes, quote []byte) error
	VerifySignature(digest []byte, signature []byte, opts *keystore.VerifyOpts) error
	VerifyTCG_CSR_IDevID(
		tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
		signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error)
	VerifyTCG_CSR_IDevIDBytes(
		tcgCSRIDevIDBytes []byte,
		signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error)
	VerifyQuote(keyAttrs *keystore.KeyAttributes, quote tpm2.Quote, nonce []byte) error
	XSignedIntermediateCertificates(issuerCN string, cert *x509.Certificate) ([]*x509.Certificate, error)
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

// Returns the CA's default signature algorithm
func (ca *CA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return ca.defaultKeyAttributes.SignatureAlgorithm
}

// Returns the CA's x509 certificate store
func (ca *CA) CertificateStore() certstore.CertificateStorer {
	return ca.certStore
}

// Returns true if the provided common name can be located in
// the certificate store.
func (ca *CA) Exists(cn string, algorithm x509.PublicKeyAlgorithm) bool {
	for _, store := range ca.Keyring().Stores() {
		keyAttrs := &keystore.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: algorithm,
			StoreType:    store.Type(),
		}
		cert, err := ca.certStore.Get(keyAttrs)
		if err == nil && cert != nil {
			return true
		}
	}
	return false
}

// Returns true if the provided common name has an issued certificate
func (ca *CA) Issued(cn string) bool {
	return ca.certStore.Issued(cn)
}

// Load CA key attributes.
func (ca *CA) Load() error {

	ca.params.Logger.Info("Loading Certificate Authority",
		slog.String("commonName", ca.commonName))

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

		ca.params.Logger.Debug(
			"certificate-authority: loaded CA key",
			slog.Any("attributes", caKeyAttrs.KeyAlgorithm))

		// Load / parse the CA bundle
		bundle, err := ca.CABundle(&caKeyAttrs.StoreType, &caKeyAttrs.KeyAlgorithm)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		ca.params.Logger.Debug(
			"certificate-authority: loaded CA bundle",
			slog.String("keyAlgorithm", caKeyAttrs.KeyAlgorithm.String()),
			slog.String("storeType", caKeyAttrs.StoreType.String()),
			slog.String("bundle", string(bundle)))
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
			Version:               3,
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
		certDER, err := x509.CreateCertificate(ca.params.Random,
			template, signingCert, publicKey, opaque)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}

		if ca.params.Config.QuantumSafe {
			// Add quantum safe extensions
			extensions := quantumSafeExtentions(keystore.QUANTUM_ALGORITHM_DILITHIUM2, certDER)
			template.ExtraExtensions = append(template.ExtraExtensions, extensions...)
		}

		cert, err := x509.ParseCertificate(certDER)
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
// provided certificate. An optional cross signing CA may be provided
// to include that CA's root certificate in the returned CertPool.
func (ca *CA) TrustedRootCertPool(
	certificate *x509.Certificate, xsignerCN *string) (*x509.CertPool, error) {

	pool := x509.NewCertPool()

	rootCert, err := ca.RootCertificate(certificate)
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

	// cross-signed root certificates should be in the OS / browser trust store
	// if xsignerCN != nil {
	// 	xsignedRoot, err := ca.XSignedRootCertificate(*xsignerCN, certificate)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	xsignedPEM, err := certstore.EncodePEM(xsignedRoot.Raw)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ok := pool.AppendCertsFromPEM(xsignedPEM)
	// 	if !ok {
	// 		return nil, err
	// 	}
	// }

	return pool, nil
}

// Retrieves the root certificate for a cross signing CA
func (ca *CA) XSignedRootCertificate(issuerCN string, cert *x509.Certificate) (*x509.Certificate, error) {
	parent, err := ca.certStore.GetXSigned(issuerCN, &keystore.KeyAttributes{
		CN:           cert.Issuer.CommonName,
		KeyAlgorithm: cert.PublicKeyAlgorithm,
		StoreType:    keystore.STORE_UNKNOWN,
	})
	if err != nil {
		if err == blobstore.ErrBlobNotFound {
			// It's impossible to know which key algorithm
			// was used by the parent CA, so try all supported
			// key algorithms to see if it can be found using
			// a different algorithm
			supportedAlgs := []x509.PublicKeyAlgorithm{
				x509.RSA,
				x509.ECDSA,
				x509.Ed25519}
			for _, alg := range supportedAlgs {
				if alg == cert.PublicKeyAlgorithm {
					continue
				}
				parent, err = ca.certStore.GetXSigned(issuerCN, &keystore.KeyAttributes{
					CN:           cert.Issuer.CommonName,
					KeyAlgorithm: alg,
					StoreType:    keystore.STORE_UNKNOWN,
				})
				if err != nil {
					continue
				}
				err = nil
				break
			}
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if cert.IsCA && parent.Issuer.CommonName == parent.Subject.CommonName {
		return cert, nil
	}
	return ca.XSignedRootCertificate(issuerCN, parent)
}

// Returns a cert pool initialized with the root certificate for the
// provided certificate.
func (ca *CA) RootCertificate(cert *x509.Certificate) (*x509.Certificate, error) {

	var rootCert *x509.Certificate

	// Parse the key store type  from the certificate
	storeType, err := certstore.ParseKeyStoreType(cert)
	if err == keystore.ErrInvalidKeyStore {
		// No key store OID found, use the CA default store type
		storeType = ca.defaultKeyAttributes.StoreType
	}

	// If the store type is unknown, this is likely a cross-signed or otherwise
	// imported certificate. Attempt to locate the issuer certificate using
	// only the common name.
	if storeType == keystore.STORE_UNKNOWN {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	// Get the local CA key attributes for the child's public key algorithm
	caKeyAttrs, ok := ca.keyAttributesMap[storeType][cert.PublicKeyAlgorithm]
	if !ok {
		caKeyAttrs, ok = ca.keyAttributesMap[storeType][ca.DefaultKeyAlgorithm()]
		if !ok {
			return nil, keystore.ErrInvalidKeyAttributes
		}
	}

	// Set the caKeyAttrs CN to the actual issuer CN in the child cert
	// to ensure the correct root certificate is returned. This could be
	// a certificate that was issued by a different CA.
	caKeyAttrs.CN = cert.Issuer.CommonName

	// Get the matching certificate for this parent's key attributes
	caCert, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return nil, err
	}

	// Walk the certificate chain to the root
	issuerCN := caCert.Issuer.CommonName
	for issuerCN != "" {

		// Build a new set of key attributes for the parent
		parentAttrs, ok := ca.keyAttributesMap[storeType][cert.PublicKeyAlgorithm]
		if !ok {
			return nil, keystore.ErrInvalidKeyAlgorithm
		}
		parentAttrs.CN = issuerCN

		// Get the matching certificate for this parent's key attributes
		rootCert, err = ca.Certificate(&parentAttrs)
		if err != nil {
			return nil, err
		}

		// If the issuer is the subject, we've reached the root
		if rootCert.Issuer.CommonName == rootCert.Subject.CommonName {
			break
		}

		// Set the issuer CN to the next certificate in the chain
		issuerCN = rootCert.Issuer.CommonName
	}

	// Ensure the root certificate is a CA certificate
	if !rootCert.IsCA {
		return nil, ErrInvalidIssuer
	}

	return rootCert, nil
}

// Retrieves all intermediate CA certificates for the provided cross signing
// issuer's common name and leaf certificate.
func (ca *CA) XSignedIntermediateCertificates(
	issuerCN string, cert *x509.Certificate) ([]*x509.Certificate, error) {

	intermediates := make([]*x509.Certificate, 0)
	var parent *x509.Certificate
	var err error
	for err == nil {
		keyAttrs := &keystore.KeyAttributes{
			CN:           cert.Issuer.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm,
			StoreType:    keystore.STORE_UNKNOWN,
		}
		parent, err = ca.Certificate(keyAttrs)
		if err != nil {
			if err == blobstore.ErrBlobNotFound || err == certstore.ErrCertNotFound {
				// It's impossible to know which key algorithm
				// was used by the parent CA, so try all supported
				// key algorithms to see if it can be found using
				// a different algorithm
				supportedAlgs := []x509.PublicKeyAlgorithm{
					x509.RSA,
					x509.ECDSA,
					x509.Ed25519}
				for _, alg := range supportedAlgs {
					if alg == cert.PublicKeyAlgorithm {
						continue
					}
					keyAttrs.KeyAlgorithm = alg
					parent, err = ca.Certificate(keyAttrs)
					if err != nil {
						continue
					}
					err = nil
					break
				}
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
		if cert.IsCA && parent.Issuer.CommonName == parent.Subject.CommonName {
			// This is the root cert
			return intermediates, nil
		}
		intermediates = append(intermediates, parent)
		cert = parent
	}
	return nil, err
}

// Returns a cert pool initialized with the intermediate certificate for the
// provided leaf certificate. An optional cross-signing CA may be provided to
// include it's intermediate certificates in the returned CertPool.
func (ca *CA) TrustedIntermediateCertPool(
	certificate *x509.Certificate, xsignerCN *string) (*x509.CertPool, error) {

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

	if xsignerCN != nil {
		intermediates, err := ca.XSignedIntermediateCertificates(*xsignerCN, certificate)
		if err != nil {
			return nil, err
		}
		for _, intermediate := range intermediates {
			pem, err := certstore.EncodePEM(intermediate.Raw)
			if err != nil {
				return nil, err
			}
			ok := pool.AppendCertsFromPEM(pem)
			if !ok {
				return nil, err
			}
		}
	}

	return pool, nil
}

// Creates a new Certificate Signing Request (CSR) and return it in ASN.1 DER form.
func (ca *CA) CreateCSR(request CertificateRequest) ([]byte, error) {

	if request.KeyAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if request.KeyAttributes.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	var publicKey crypto.PublicKey
	var err error
	if request.KeyAttributes.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		if request.KeyAttributes.TPMAttributes != nil &&
			request.KeyAttributes.KeyType == keystore.KEY_TYPE_ENDORSEMENT {

			request.KeyAttributes.SignatureAlgorithm = ca.DefaultSignatureAlgorithm()
			publicKey, err = ca.params.TPM.ParsePublicKey(request.KeyAttributes.TPMAttributes.BPublic.Bytes())
			if err != nil {
				return nil, err
			}
		} else {
			return nil, keystore.ErrInvalidSignatureAlgorithm
		}
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

	extraExtensions := []pkix.Extension{
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
	}

	// Retrieve TPM fixed properties and build TCG / Platform Software
	// specific OIDs if the request contains a Permanent ID.
	if request.PermanentID != "" {
		if request.KeyAttributes.StoreType == keystore.STORE_TPM2 {
			props, err := ca.params.TPM.FixedProperties()
			if err != nil {
				return nil, err
			}
			extraExtensions = ca.tpmDeviceCertificateExtensions(
				request, caKeyAttrs.StoreType, props)
		} else {
			extraExtensions = ca.deviceCertificateExtensions(request, caKeyAttrs.StoreType)
		}
	}

	template := x509.CertificateRequest{
		Version:            3,
		RawSubject:         asn1Subj,
		SignatureAlgorithm: request.KeyAttributes.SignatureAlgorithm,
		PublicKeyAlgorithm: request.KeyAttributes.KeyAlgorithm,
		PublicKey:          publicKey,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		// EmailAddresses:     emailAddresses,
		ExtraExtensions: extraExtensions,
	}

	// Set DNS names as SANS
	dnsNames = append(dnsNames, request.Subject.CommonName)
	template.DNSNames = dnsNames

	// Get the key's signer
	var signer crypto.Signer
	if request.KeyAttributes.KeyType == keystore.KEY_TYPE_ENDORSEMENT {
		// TPM Endorsement Key is a restricted key that doesn't have the
		// ability to perform signing operations; use the CA key instead.
		signer, err = ca.Signer(caKeyAttrs)
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = ca.Signer(request.KeyAttributes)
		if err != nil {
			return nil, err
		}
	}

	ca.params.Logger.Infof(
		"Creating %s CSR for %s with %s %s %s key",
		request.KeyAttributes.KeyAlgorithm,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	// Create and sign the x509 certificate request
	csrBytes, err := x509.CreateCertificateRequest(ca.params.Random, &template, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	return csrBytes, nil
}

// Signs a Certificate Signing Request (CSR) and save it to the cert store
// in DER and PEM form. This method returns the raw DER encoded []byte array
// as returned from x509.CreateCertificate.
func (ca *CA) SignCSR(csrPEM []byte, request *CertificateRequest) (*x509.Certificate, error) {

	var caKeyAttrs *keystore.KeyAttributes
	var extensions []pkix.Extension
	var err error

	var valid int
	if request == nil {
		valid = ca.DefaultValidityPeriod()
	} else {
		valid = request.Valid
	}

	// Decode the CSR
	csr, err := DecodeCSR(csrPEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	if request != nil {
		caKeyAttrs, err = ca.matchingKeyOrDefault(request.KeyAttributes)
		if err != nil {
			return nil, err
		}
		valid = request.Valid
		extensions = []pkix.Extension{
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
		}

	} else {
		storeType := keystore.STORE_PKCS8
		if _storeType, err := certstore.ParseCertificateRequestKeyStoreType(csr); err == nil {
			ca.params.Logger.Warn("Unable to locate key store type in CSR, defaulting signer to PKCS #8 key")
			storeType = _storeType
		}
		_caKeyAttrs, ok := ca.keyAttributesMap[storeType][csr.PublicKeyAlgorithm]
		if !ok {
			ca.params.Logger.Errorf("%s: %s",
				keystore.ErrInvalidKeyAlgorithm, csr.PublicKeyAlgorithm)
			return nil, keystore.ErrInvalidKeyAlgorithm
		}
		caKeyAttrs = &_caKeyAttrs
		// caKeyAttrs, err = ca.preferredKeyOrDefault(csr.PublicKeyAlgorithm)
		// if err != nil {
		// 	return nil, err
		// }
		valid = ca.params.Config.DefaultValidityPeriod

		permID, err := certstore.ParseCertificateRequestPermanentIdentifier(csr)
		if err != nil {
			// This is a standard x509 certificate request without any Trusted Computing
			// or Platform Software (this software) specific OIDs.
			extensions = []pkix.Extension{
				{
					Id:       common.OIDTPIssuerKeyStore,
					Value:    []byte(caKeyAttrs.StoreType),
					Critical: false,
				},
				{
					Id:       common.OIDTPKeyStore,
					Value:    []byte(storeType),
					Critical: false,
				},
			}
		} else {
			// The CSR contains Trusted Computing Group and/or Platform Software
			// specific OIDs.
			model, _ := certstore.ParseCertificateRequestPlatformModel(csr)
			serial, _ := certstore.ParseCertificateRequestPlatformSerial(csr)
			manufacturer, _ := certstore.ParseCertificateRequestTPMManufacturer(csr)
			vendorID, _ := certstore.ParseCertificateRequestTPMModel(csr)
			family, _ := certstore.ParseCertificateRequestTPMVersion(csr)
			fwVersion, _ := certstore.ParseCertificateRequestTPMFirmwareVersion(csr)
			fips1402, _ := certstore.ParseCertificateRequestTPMFIPS1402(csr)
			parsedVersion, err := tpm2.VersionStringToInt64(fwVersion)
			if err != nil {
				if model == "" && serial == "" {
					// This is hacky and needs to be cleaned up later -
					// In this case, the CSR was generated by a device-attest-01
					// challenge using a permanennt-identifer authorization type
					// for a TLS certificate request.
					// Since TLS certificates are public certificates (non-device),
					// the permanent-identifier or other device specific identifers
					// are omitted from the signed certificate for privacy. Only
					// Trusted Platform OIDs indicating the CA and End Entity certificate
					// store types are included in TLS certificates.
					extensions = []pkix.Extension{
						{
							Id:       common.OIDTPIssuerKeyStore,
							Value:    []byte(caKeyAttrs.StoreType),
							Critical: false,
						},
						{
							Id:       common.OIDTPKeyStore,
							Value:    []byte(storeType),
							Critical: false,
						},
					}
				} else {
					// This is a permanent-identifier for a key stored in something
					// other than a TPM.
					extensions = ca.deviceCertificateExtensions(
						CertificateRequest{
							PermanentID: permID,
							ProdModel:   model,
							ProdSerial:  serial,
							KeyAttributes: &keystore.KeyAttributes{
								StoreType: storeType,
							},
						}, caKeyAttrs.StoreType)
				}

			} else {
				// This is a TPM permanent-identifier
				fwMajor, fwMinor, err := tpm2.Int64ToVersionComponents(parsedVersion)
				if err != nil {
					ca.params.Logger.Error(err)
					return nil, err
				}
				props := &tpm2.PropertiesFixed{
					Manufacturer: manufacturer,
					VendorID:     vendorID,
					Family:       family,
					FwMajor:      fwMajor,
					FwMinor:      fwMinor,
					Fips1402:     fips1402,
				}
				extensions = ca.tpmDeviceCertificateExtensions(
					CertificateRequest{
						PermanentID: permID,
						ProdModel:   model,
						ProdSerial:  serial,
						KeyAttributes: &keystore.KeyAttributes{
							StoreType: storeType,
						},
					}, caKeyAttrs.StoreType, props)
			}
		}
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
		Version:            3,
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
		NotAfter:           time.Now().AddDate(0, 0, valid),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:        csr.IPAddresses,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		ExtraExtensions:    extensions,
	}
	template.DNSNames = csr.DNSNames

	signer, err := ca.Signer(caKeyAttrs)
	if err != nil {
		return nil, err
	}

	ca.params.Logger.Infof(
		"Signing %s CSR for %s with %s %s %s key",
		csr.PublicKeyAlgorithm,
		csr.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	derBytes, err := x509.CreateCertificate(
		ca.params.Random, &template, caCertificate, template.PublicKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// if err := ca.ImportCertificate(certificate); err != nil {
	// 	return nil, err
	// }

	return certificate, nil
}

// Verifies a TCG_CSR_IDEVID Certificate Signing Request (CSR) per TCG TPM 2.0
// Keys for Identity and Attestation - Section 6 - Identity Provisioning, using
// one of the supported strategies.
// The CA issues a challenge to the device to validate that the TPM has the
// EK matching the certificate in step 2b and that the IAK whose public area
// is included in 2c is loaded in the deviceâ€s TPM. The challenge data blob is
// created using the following procedure:
// a. Calculate the cryptographic Name of the IAK, by hashing its public area
// with its associated hash algorithm, prepended with the Algorithm ID of the
// hashing algorithm. Refer to TPM 2.0 Library Specification [2], Part 1,
// Section 16 (â€Namesâ€).
// b. Using the sequence described in TPM 2.0 Library Specification, Part 3,
// section 12.6.3 (â€TPM2_MakeCredential Detailed Actionsâ€), create the
// encrypted â€credentialâ€ structure to be sent to the device. When building
// this encrypted structure, objectName is the Name of the IAK calculated in
// step â€aâ€ and Certificate (which is the payload field) holds a nonce (whose
// size matches the Name hash). Retain the nonce for use in later steps.
// c. The CA sends the encrypted â€credentialâ€ blob to the enrolling TPM device.
func (ca *CA) VerifyTCG_CSR_IDevID(
	tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {

	akAttrs, unpackedCSR, err := ca.params.TPM.VerifyTCGCSR(
		tcgCSRIDevID, signatureAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	ekCert, err := x509.ParseCertificate(unpackedCSR.CsrContents.EkCert)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := ca.Verify(ekCert, nil); err != nil {
		return nil, nil, nil, err
	}

	return ca.params.TPM.MakeCredential(akAttrs.TPMAttributes.Name, nil)
}

func (ca *CA) VerifyTCG_CSR_IDevIDBytes(
	tcgCSRIDevIDBytes []byte,
	signatureAlgorithm x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {

	tcgCSRIDevID, err := tpm2.UnmarshalIDevIDCSR(tcgCSRIDevIDBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	akAttrs, unpackedCSR, err := ca.params.TPM.VerifyTCG_CSR_IDevID(
		tcgCSRIDevID, signatureAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	ekCert, err := x509.ParseCertificate(unpackedCSR.CsrContents.EkCert)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := ca.Verify(ekCert, nil); err != nil {
		return nil, nil, nil, err
	}

	return ca.params.TPM.MakeCredential(akAttrs.TPMAttributes.Name, nil)
}

func (ca *CA) SignTCGCSRIDevIDBytes(
	tcgCSRIDevIDBytes []byte,
	request *CertificateRequest) (iakDER []byte, idevidDER []byte, err error) {

	// Unpack the binary CSR
	tcgCSRIDevID, err := tpm2.UnmarshalIDevIDCSR(tcgCSRIDevIDBytes)
	if err != nil {
		return nil, nil, err
	}

	return ca.SignTCGCSRIDevID(tcgCSRIDevID, request)
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
	tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
	request *CertificateRequest) (iakDER []byte, idevidDER []byte, err error) {

	// Unpack the binary CSR
	unpackedCSR, err := tpm2.UnpackIDevIDCSR(tcgCSRIDevID)
	if err != nil {
		return nil, nil, err
	}

	// Parse the IAK public key from the TCG CSR
	iakPubKey, err := ca.params.TPM.ParsePublicKey(
		unpackedCSR.CsrContents.AttestPub)
	if err != nil {
		return nil, nil, err
	}

	var iakKeyAlgo x509.PublicKeyAlgorithm
	switch iakPubKey.(type) {
	case *rsa.PublicKey:
		iakKeyAlgo = x509.RSA
	case *ecdsa.PublicKey:
		iakKeyAlgo = x509.ECDSA
	case ed25519.PublicKey:
		iakKeyAlgo = x509.Ed25519
	default:
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Parse the IDevID public key from the TCG CSR
	idevidPubKey, err := ca.params.TPM.ParsePublicKey(
		unpackedCSR.CsrContents.SigningPub)
	if err != nil {
		return nil, nil, err
	}

	var idevidKeyAlgo x509.PublicKeyAlgorithm
	switch idevidPubKey.(type) {
	case *rsa.PublicKey:
		idevidKeyAlgo = x509.RSA
	case *ecdsa.PublicKey:
		idevidKeyAlgo = x509.ECDSA
	case ed25519.PublicKey:
		idevidKeyAlgo = x509.Ed25519
	default:
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Create new serial number
	serialNumber, err := util.SerialNumber()
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, nil, err
	}

	algoMap, ok := ca.keyAttributesMap[keystore.STORE_TPM2]
	if !ok {
		return nil, nil, keystore.ErrInvalidKeyStore
	}
	caKeyAttrs, ok := algoMap[idevidKeyAlgo]
	if !ok {
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Get the CA certificate
	caCertificate, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}

	caps, err := ca.params.TPM.FixedProperties()
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
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

	// Set the store type for commonDeviceCertificateExtensions
	if request.KeyAttributes == nil {
		request.KeyAttributes = &keystore.KeyAttributes{
			StoreType: keystore.STORE_TPM2,
		}
	}

	// Create new x509 certificate template
	template := x509.Certificate{
		Version:            3,
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
		ExtraExtensions:    ca.tpmDeviceCertificateExtensions(*request, caKeyAttrs.StoreType, caps),
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			common.OIDTCGVerifiedTPMResidency,
			common.OIDTCGVerifiedTPMFixed,
		},
	}

	if request != nil {

		ipAddresses, dnsNames, emailAddresses, err := parseSANS(request.SANS)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, nil, err
		}

		dnsNames = append(dnsNames, request.Subject.CommonName)

		template.IPAddresses = ipAddresses
		template.DNSNames = dnsNames
		template.EmailAddresses = emailAddresses
	}

	signer, err := ca.Signer(&caKeyAttrs)
	if err != nil {
		return nil, nil, err
	}

	ca.params.Logger.Infof(
		"Signing %s TCG-CSR-IDEVID for %s with %s %s %s key",
		idevidKeyAlgo,
		request.Subject.CommonName,
		caKeyAttrs.StoreType,
		caKeyAttrs.KeyAlgorithm,
		caKeyAttrs.SignatureAlgorithm)

	// Create IAK certificate
	iakCertName := fmt.Sprintf("ak-%s-%s",
		unpackedCSR.CsrContents.ProdModel,
		unpackedCSR.CsrContents.ProdSerial)

	if request.KeyAttributes == nil {
		request.KeyAttributes = &keystore.KeyAttributes{
			CN:                 iakCertName,
			KeyAlgorithm:       iakKeyAlgo,
			SignatureAlgorithm: ca.defaultKeyAttributes.SignatureAlgorithm,
			StoreType:          keystore.STORE_TPM2,
		}
	}
	request.Subject.CommonName = iakCertName
	iakCert, err := ca.IssueAKCertificate(*request, iakPubKey)
	if err != nil {
		return nil, nil, err
	}

	// Create IDevID certificate
	idevidDER, err = x509.CreateCertificate(
		ca.params.Random, &template, caCertificate, idevidPubKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, nil, err
	}

	// certificate, err := x509.ParseCertificate(derBytes)
	// if err != nil {
	// 	ca.params.Logger.Error(err)
	// 	return nil, nil, err
	// }

	// if err := ca.ImportCertificate(certificate); err != nil {
	// 	return nil, nil, err
	// }

	return iakCert.Raw, idevidDER, nil
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
		Version:            3,
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
		ca.params.Random, template, caCertificate, opaque.Public(), signer)
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

	notAfter, err := time.Parse("20060102150405Z", "99991231235959Z")
	if err != nil {
		return nil, err
	}

	extraExtensions := ca.tpmDeviceCertificateExtensions(request, caKeyAttrs.StoreType, caps)
	ekExtensions := []pkix.Extension{
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
	}
	extraExtensions = append(extraExtensions, ekExtensions...)

	template := &x509.Certificate{
		Version:            3,
		Subject:            subject,
		SignatureAlgorithm: caKeyAttrs.SignatureAlgorithm,
		PublicKeyAlgorithm: request.KeyAttributes.KeyAlgorithm,
		PublicKey:          ekPubKey,
		SerialNumber:       serialNumber,
		Issuer:             caCertificate.Subject,
		NotBefore:          time.Now(),
		NotAfter:           notAfter,
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SubjectKeyId:       caCertificate.SubjectKeyId,
		KeyUsage:           x509.KeyUsageDataEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		ExtraExtensions:    extraExtensions,
		EmailAddresses:     emailAddresses}

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
		ca.params.Random, template, caCertificate, ekPubKey, signer)
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

	var keyAlgorithm x509.PublicKeyAlgorithm

	switch pubKey.(type) {
	case *rsa.PublicKey:
		keyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		keyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		keyAlgorithm = x509.Ed25519
	default:
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	if request.KeyAttributes == nil {
		request.KeyAttributes = &keystore.KeyAttributes{
			CN:                 "ak",
			KeyAlgorithm:       keyAlgorithm,
			SignatureAlgorithm: ca.defaultKeyAttributes.SignatureAlgorithm,
			StoreType:          keystore.STORE_TPM2,
		}
	}

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

	// Add tcg-kp-AIKCertificate OID
	// This TCG extension is part of the TPM Family 1.2 specs, however, is included here to support
	// the WebAuthn; 8.3.1. TPM Attestation Statement Certificate Requirements
	extraExtensions := ca.tpmDeviceCertificateExtensions(request, caKeyAttrs.StoreType, caps)
	extraExtensions = append(extraExtensions, pkix.Extension{
		Id:    common.OIDTCGAIKCertificate,
		Value: []byte{},
	})

	// Create new x509 certificate template
	template := x509.Certificate{
		Version:            3,
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
		ExtraExtensions:    extraExtensions,
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
		ca.params.Random, &template, caCertificate, pubKey, signer)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}

	// if err := ca.ImportCertificate(certificate); err != nil {
	// 	return nil, err
	// }

	return certificate, nil
}

// Revoke a certificate
func (ca *CA) Revoke(certificate *x509.Certificate, deleteKeys bool) error {

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

	if deleteKeys {
		if err := ca.keyring.Delete(keyAttrs); err != nil {
			return err
		}
	}

	return nil
}

// Verifies a certificate by checking the CA revocation list
// and loading it's issuer certificates from the private trusted
// root and intermediate certificate store if they exist. Issuer
// certificates will be automatically downloaded and installed to
// the appropriate certificate store partition if auto-import is
// enabled in the platform configuration file. An optional cross
// signer common name may be provided to include that external CA's
// root and intermediate certificates in the CertPool used to validate
// the provided certificate.
func (ca *CA) Verify(certificate *x509.Certificate, xsignerCN *string) error {

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
	roots, err := ca.TrustedRootCertPool(certificate, xsignerCN)
	if err != nil {
		return err
	}

	// Load the Certificate Authority Intermediate CA certificate and all
	// imported trusted intermediate certificates from the certificate store
	intermediates, err := ca.TrustedIntermediateCertPool(certificate, xsignerCN)
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
				if err := ca.Verify(certificate, xsignerCN); err != nil {
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

		ca.params.Logger.Info("certificate-authority: importing CA Issuer",
			slog.String("cn", cn),
			slog.String("utl", url))

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

// Returns a cross-signed certificate from the certificate store
func (ca *CA) XSignedCertificate(issuerCN string, keyAttrs *keystore.KeyAttributes) (*x509.Certificate, error) {
	return ca.certStore.GetXSigned(issuerCN, keyAttrs)
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

// Returns a PEM certificate signed / issued by an external CA in conjunction
// with the local CA.
func (ca *CA) CrossSignedPEM(attrs *keystore.KeyAttributes) ([]byte, error) {
	return nil, nil
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

// Import a x509 certificate to the certificate store
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

// Import a cross-signed certificae to the certificate store
func (ca *CA) ImportXSignedCertificate(issuerCN string, certificate *x509.Certificate) error {
	if err := ca.ImportIssuingCAs(certificate); err != nil {
		return err
	}
	// if err := ca.Verify(certificate); err != nil {
	// 	return err
	// }
	if err := ca.certStore.ImportXSignedCertificate(issuerCN, certificate); err != nil {
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
// the end entity leaf certificate, defaulting to a hybrid, quantum-safe
// X25519 / Kyber768 key exchange.
func (ca *CA) QuantumSafeTLSConfig(attrs *keystore.KeyAttributes) (*tls.Config, error) {
	tlsConfig, err := ca.TLSConfig(attrs)
	if err != nil {
		return nil, err
	}
	// TODO: Need to support hybrid certs
	tlsConfig.CurvePreferences = nil
	return tlsConfig, nil
}

// Returns a tls.Config for the requested common name populated with the
// Certificate Authority, cross-signed intermediates if any, and
// the end entity leaf certificate.
func (ca *CA) TLSConfig(attrs *keystore.KeyAttributes) (*tls.Config, error) {
	return ca.TLSConfigWithXSigner(attrs, "")
}

// Returns a tls.Config for the requested common name populated with the
// Certificate Authority, cross-signed intermediates if any, and
// the end entity leaf certificate.
func (ca *CA) TLSConfigWithXSigner(
	attrs *keystore.KeyAttributes, issuerCN string) (*tls.Config, error) {

	ca.params.Logger.Debug(
		"certificate-authority: building TLS config",
		slog.String("cn", attrs.CN),
		slog.String("issuer", issuerCN))

	certs, leaf, err := ca.TLSBundleWithCrossSigner(attrs, issuerCN)
	if err != nil {
		return nil, err
	}

	signer, err := ca.keyring.Signer(attrs)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			PrivateKey:  signer,
			Leaf:        leaf,
			Certificate: certs,
		}},
		CurvePreferences: []tls.CurveID{},
		// Force TLS 1.3 to protect against TLS downgrade attacks
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	// Get the CA certificate
	caKeyAttrs, ok := ca.keyAttributesMap[attrs.StoreType][attrs.KeyAlgorithm]
	if !ok {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}
	caCert, err := ca.certStore.Get(&caKeyAttrs)
	if err != nil {
		return nil, err
	}

	// Build a root cert cool
	rootCAs := x509.NewCertPool()

	if caCert.Subject.CommonName != leaf.Issuer.CommonName {

		// This certificate was issueed by a different CA,
		// attempt to load that CA's certificate bundle
		issuerKeyAttrs := &keystore.KeyAttributes{
			CN:                 leaf.Issuer.CommonName,
			KeyAlgorithm:       leaf.PublicKeyAlgorithm,
			SignatureAlgorithm: leaf.SignatureAlgorithm,
			StoreType:          attrs.StoreType,
		}

		caCert, err = ca.certStore.Get(issuerKeyAttrs)
		if err != nil {
			// Can't find the issuer cert - probably issued from an external CA
			// whose certificate chain couldn't be imported into the cert
			// store.Simply return the leaf certificate. If the client doesn't
			// have the required intermediate certificates to build a trust chain
			// back to the root, the TLS connection will fail.
			return tlsConfig, nil
		}

		rootCAs, err = ca.TrustedRootCertPool(caCert, &issuerCN)
		if err != nil {
			return nil, err
		}

	} else {

		// Load this CA's root and intermediate certificates
		rootCAs, err = ca.TrustedRootCertPool(caCert, &issuerCN)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig.RootCAs = rootCAs

	return tlsConfig, nil
}

// Creates a TLS "bundle" containing the requested leaf certificate,
// the Certificate Authority's certificate, and any cross-signed
// certificates in ASN.1 DER form, and returns the certificate bundle
// and leaf.
func (ca *CA) TLSBundle(attrs *keystore.KeyAttributes) ([][]byte, *x509.Certificate, error) {
	return ca.TLSBundleWithCrossSigner(attrs, "")
}

// Creates a TLS "bundle" containing the requested leaf certificate,
// the Certificate Authority's certificate, and any cross-signed
// certificates in ASN.1 DER form, and returns the certificate bundle
// and leaf.
func (ca *CA) TLSBundleWithCrossSigner(
	attrs *keystore.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {

	// Retrieve the leaf cert
	leaf, err := ca.Certificate(attrs)
	if err != nil {
		return nil, nil, err
	}

	// Get the CA certificate
	caKeyAttrs, ok := ca.keyAttributesMap[attrs.StoreType][attrs.KeyAlgorithm]
	if !ok {
		return nil, nil, keystore.ErrInvalidKeyAlgorithm
	}

	// Fetch the local CA certificate with the matching store type and key algorithm
	caCertificate, err := ca.Certificate(&caKeyAttrs)
	if err != nil {
		return nil, nil, err
	}

	// This certificate was issueed by a different CA, attempt to load the CA bundle
	// instead of load CA root and intermediate certificates
	if caCertificate.Subject.CommonName != leaf.Issuer.CommonName {
		issuerKeyAttrs := &keystore.KeyAttributes{
			CN:                 leaf.Issuer.CommonName,
			KeyAlgorithm:       leaf.PublicKeyAlgorithm,
			SignatureAlgorithm: leaf.SignatureAlgorithm,
			StoreType:          attrs.StoreType,
		}
		caCertificate, err = ca.certStore.Get(issuerKeyAttrs)
		if err != nil {
			// Can't find the issuer cert - probably issued from an external CA
			// whose certificate chain couldn't be imported into the cert
			// store. Log a warning message and return only th leaf certificate.
			ca.params.Logger.Warn("CA certificate not found in key store",
				slog.String("cn", leaf.Issuer.CommonName),
				slog.String("storeType", attrs.StoreType.String()))
			certs := make([][]byte, 1)
			certs[0] = leaf.Raw
			return certs, leaf, nil
		}
	}

	// Load cross-signed certs
	var crossSignedCerts [][]byte
	xsignedLeaf, err := ca.certStore.GetXSigned(issuerCN, attrs)
	if err == nil {
		xsignedIntermediates, err := ca.XSignedIntermediateCertificates(issuerCN, xsignedLeaf)
		if err != nil {
			return nil, nil, err
		}
		crossSignedCerts = make([][]byte, len(xsignedIntermediates)+1)
		crossSignedCerts[0] = xsignedLeaf.Raw
		for i := 0; i < len(xsignedIntermediates); i++ {
			crossSignedCerts[i+1] = xsignedIntermediates[i].Raw
		}
	}

	// Start concatenating a list of DER encoded certs
	// numCrossSigned := len(crossSignedCerts)
	// certs := make([][]byte, numCrossSigned+2)
	// certs[0] = leaf.Raw
	// certs[1] = caCertificate.Raw

	// for i, csc := range crossSignedCerts {
	// 	certs[i+2] = csc
	// }

	// Start concatenating a list of DER encoded certs
	numCrossSigned := len(crossSignedCerts)
	certs := make([][]byte, numCrossSigned+2)

	copy(certs, crossSignedCerts)
	certs[numCrossSigned] = leaf.Raw
	certs[numCrossSigned+1] = caCertificate.Raw

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
	return ca.Revoke(certificate, true)
}

// Return the CA key attributes that match the provided key attribute's
// algorithm and store type, or return the default CA key attributes if
// the CA doesn't have a matching key.
func (ca *CA) matchingKeyOrDefault(
	keyAttrs *keystore.KeyAttributes) (*keystore.KeyAttributes, error) {

	if keyAttrs == nil {
		return &ca.defaultKeyAttributes, nil
	}

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

// Return the CA key attributes in order of preference starting with PKCS #11,
// then TPM 2.0, and finally PKCS #8, or return the default CA key attributes.
func (ca *CA) preferredKeyOrDefault(algorithm x509.PublicKeyAlgorithm) (*keystore.KeyAttributes, error) {

	var storeMap map[x509.PublicKeyAlgorithm]keystore.KeyAttributes
	var ok bool

	storeMap, ok = ca.keyAttributesMap[keystore.STORE_PKCS11]
	if !ok {
		storeMap, ok = ca.keyAttributesMap[keystore.STORE_TPM2]
		if !ok {
			storeMap, ok = ca.keyAttributesMap[keystore.STORE_PKCS8]
			return &ca.defaultKeyAttributes, nil
		}
	}

	attrs, ok := storeMap[algorithm]
	if !ok {
		ca.params.Logger.Debugf("%s: %s", InfoUsingDefaultCAKey, algorithm.String())
		return &ca.defaultKeyAttributes, nil
	}

	return &attrs, nil
}

func (ca *CA) tpmCertificateExtensions(
	caKeyStore keystore.StoreType,
	leafKeyStore keystore.StoreType,
	props *tpm2.PropertiesFixed) []pkix.Extension {

	return []pkix.Extension{
		{
			Id:       common.OIDTCGTPMManufacturer,
			Value:    []byte(props.Manufacturer),
			Critical: false,
		},
		{
			Id:       common.OIDTCGTPMModel,
			Value:    []byte(props.VendorID),
			Critical: false,
		},
		{
			Id:       common.OIDTCGTPMVersion,
			Value:    []byte(props.Family),
			Critical: false,
		},
		{
			Id:       common.OIDTCGHWType,
			Value:    []byte{},
			Critical: false,
		},
		{
			Id:       common.OIDTCGTPMFirmwareVersion,
			Value:    []byte(fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)),
			Critical: false,
		},
		{
			Id:       common.OIDTPFIPS140,
			Value:    []byte(fmt.Sprintf("%t", props.Fips1402)),
			Critical: false,
		},
	}
}

func (ca *CA) deviceCertificateExtensions(
	request CertificateRequest, caKeyStore keystore.StoreType) []pkix.Extension {

	return []pkix.Extension{
		{
			Id:       common.OIDTCGPermanentIdentifier,
			Value:    []byte(request.PermanentID),
			Critical: false,
		},
		{
			Id:       common.OIDTCGPlatformModel,
			Value:    []byte(request.ProdModel),
			Critical: false,
		},
		{
			Id:       common.OIDTCGPlatformSerial,
			Value:    []byte(request.ProdSerial),
			Critical: false,
		},
		{
			Id:       common.OIDTPIssuerKeyStore,
			Value:    []byte(caKeyStore),
			Critical: false,
		},
		{
			Id:       common.OIDTPKeyStore,
			Value:    []byte(request.KeyAttributes.StoreType),
			Critical: false,
		},
	}
}

func (ca *CA) tpmDeviceCertificateExtensions(
	request CertificateRequest,
	caStoreType keystore.StoreType,
	props *tpm2.PropertiesFixed) []pkix.Extension {

	common := ca.tpmCertificateExtensions(
		caStoreType,
		request.KeyAttributes.StoreType,
		props)

	return append(common, ca.deviceCertificateExtensions(request, caStoreType)...)
}
