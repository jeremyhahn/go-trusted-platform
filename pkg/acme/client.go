package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/deviceattest01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/dns01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/endorse01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/enroll01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/http01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"golang.org/x/crypto/acme"

	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

var (
	ErrAccountNotFound           = errors.New("ACME account not found")
	ErrRegistrationFailed        = errors.New("ACME registration failed")
	ErrOrderCreationFailed       = errors.New("ACME order creation failed")
	ErrChallengeResolution       = errors.New("ACME challenge resolution failed")
	ErrChallengeFinalization     = errors.New("ACME challenge finalization failed")
	ErrAuthorizationFailed       = errors.New("ACME authorization failed")
	ErrCABundleDownloadFailed    = errors.New("ACME server certificate bundle download failed")
	ErrInvalidCACertificate      = errors.New("invalid CA certificate")
	ErrInvalidCrossSignerAuthzID = errors.New("invalid cross-signer authorization type, only 'dns' supported")

	mailTo = "mailto:"
)

type Client struct {
	accountKeyAttrs    *keystore.KeyAttributes
	ca                 ca.CertificateAuthority
	client             *acme.Client
	config             ClientConfig
	datastore          dao.Factory
	dnsService         *dns.Service
	isCrossSigner      bool
	mutex              sync.RWMutex
	logger             *logging.Logger
	platformKS         tpm2ks.PlatformKeyStorer
	serializer         keystore.KeySerializer
	tpm                tpm2.TrustedPlatformModule
	webServiceHTTPPort int
}

// Creates a new ACME client
func NewClient(
	config ClientConfig,
	ca ca.CertificateAuthority,
	datastore dao.Factory,
	dnsService *dns.Service,
	webServiceHTTPPort int,
	logger *logging.Logger,
	platformKS tpm2ks.PlatformKeyStorer,
	tpm tpm2.TrustedPlatformModule) (*Client, error) {

	accountKeyAttrs, err := keystore.KeyAttributesFromConfig(config.Account.Key)
	if err != nil {
		return nil, err
	}

	serializer, err := keystore.NewSerializer(datastore.SerializerType())
	if err != nil {
		return nil, err
	}

	ac := &Client{
		accountKeyAttrs:    accountKeyAttrs,
		ca:                 ca,
		config:             config,
		datastore:          datastore,
		dnsService:         dnsService,
		mutex:              sync.RWMutex{},
		logger:             logger,
		platformKS:         platformKS,
		serializer:         serializer,
		tpm:                tpm,
		webServiceHTTPPort: webServiceHTTPPort,
	}

	acmeClient, err := createClient(ac)
	if err != nil {
		return nil, err
	}

	ac.client = acmeClient
	return ac, nil
}

func NewCrossSigner(
	config ClientConfig,
	ca ca.CertificateAuthority,
	datastore dao.Factory,
	dnsService *dns.Service,
	webServiceHTTPPort int,
	logger *logging.Logger,
	platformKS tpm2ks.PlatformKeyStorer,
	tpm tpm2.TrustedPlatformModule) (*Client, error) {

	// if config.Server != nil {
	// 	if config.Server.DirectoryURL == config.Client.DirectoryURL {

	// 		if app.WebServiceConfig.Certificate.ACME != nil &&
	// 			app.WebServiceConfig.Certificate.ACME.CrossSigner != nil {

	// 			if app.WebServiceConfig.Certificate.ACME.CrossSigner.DirectoryURL == config.Client.DirectoryURL {
	// 				return ErrCrossSignerSameDirectoryURL
	// 			}
	// 		}

	// 	}
	// }

	accountKeyAttrs, err := keystore.KeyAttributesFromConfig(config.Account.Key)
	if err != nil {
		return nil, err
	}

	serializer, err := keystore.NewSerializer(datastore.SerializerType())
	if err != nil {
		return nil, err
	}

	ac := &Client{
		accountKeyAttrs:    accountKeyAttrs,
		ca:                 ca,
		config:             config,
		datastore:          datastore,
		dnsService:         dnsService,
		isCrossSigner:      true,
		mutex:              sync.RWMutex{},
		logger:             logger,
		platformKS:         platformKS,
		serializer:         serializer,
		tpm:                tpm,
		webServiceHTTPPort: webServiceHTTPPort,
	}

	acmeClient, err := createClient(ac)
	if err != nil {
		return nil, err
	}

	ac.client = acmeClient
	return ac, nil
}

// NewCrossSigningClient creates a new ACME client used to cross-sign a certificate
// request.
func (ac *Client) CrossSignerFromClient(crossSigner *CrossSign) (*Client, error) {

	clientConfig := ac.config
	clientConfig.DirectoryURL = crossSigner.DirectoryURL

	// Only RFC 8555 compliant cross-signing CAs supported
	clientConfig.RequestServerBundle = false

	csClient, err := NewClient(
		clientConfig,
		ac.ca,
		ac.datastore,
		ac.dnsService,
		ac.webServiceHTTPPort,
		ac.logger,
		ac.platformKS,
		ac.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create Let's Encrypt client: %v", err)
	}

	return csClient, nil
}

// Creates a new ACME client from the golang/crypto/acme library
func createClient(ac *Client) (*acme.Client, error) {

	tpmConfig := ac.tpm.Config()
	if ac.config.Account.Key == nil && tpmConfig.IDevID != nil {
		// TODO: Add support for key ids
		ac.config.Account.Key = &keystore.KeyConfig{
			Debug:              tpmConfig.IDevID.Debug,
			ECCConfig:          tpmConfig.IDevID.ECCConfig,
			CN:                 tpmConfig.IDevID.CN,
			Hash:               tpmConfig.IDevID.Hash,
			KeyAlgorithm:       tpmConfig.IDevID.KeyAlgorithm,
			Password:           tpmConfig.IDevID.Password,
			RSAConfig:          tpmConfig.IDevID.RSAConfig,
			PlatformPolicy:     tpmConfig.IDevID.PlatformPolicy,
			SignatureAlgorithm: tpmConfig.IDevID.SignatureAlgorithm,
			StoreType:          keystore.STORE_TPM2.String(),
		}
	}

	store, err := ac.ca.Keyring().Store(ac.accountKeyAttrs.StoreType.String())
	if err != nil {
		return nil, err
	}
	signer, err := store.Signer(ac.accountKeyAttrs)
	if err != nil {
		if err == keystore.ErrFileNotFound {
			signer, err = store.GenerateKey(ac.accountKeyAttrs)
			if err != nil {
				return nil, err
			}
		} else if err == keystore.ErrInvalidPassword && ac.isDefaultPasswordWithPolicy() {
			// This is a bit kludgy -
			// When the ACME client is instantiated, the ACME key attributes are retrieved
			// via keystore.KeyAttributesFromConfig(config.Account.Key) which reads the plain
			// text password defined in the config. When the key is generated the first time,
			// the password is replaced with the PlatformPassword object that retrieves it from
			// the TPM for all subsequent calls going forward.
			//
			// When the client is instantiated again during cross-signing, the account key
			// attributes are again instantiated from the config with the plain text password,
			// resulting in an incorrect password when auto-generated passwords are in use with
			// the default 123456. This is a workaround to replace the default plain-text password
			// with the PlatformPassword so it's properly retrieved from the TPM during cross-signing
			// operations.
			ac.accountKeyAttrs.Password = tpm2.NewPlatformPassword(
				ac.logger, ac.tpm, ac.accountKeyAttrs, ac.platformKS.Backend())

			signer, err = store.Signer(ac.accountKeyAttrs)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	httpClient, err := ac.createHTTPClient(ac.config.DirectoryURL)
	if err != nil {
		return nil, err
	}
	acmeClient := &acme.Client{
		DirectoryURL: ac.config.DirectoryURL,
		Key:          signer,
		HTTPClient:   httpClient,
	}

	return acmeClient, err
}

// Returns true if the ACME account key attributes is enabled
// with the platform-policy flag with the password configured.
func (ac *Client) isDefaultPasswordWithPolicy() bool {
	if !ac.accountKeyAttrs.PlatformPolicy {
		return false
	}
	password, err := ac.accountKeyAttrs.Password.String()
	if err != nil {
		return false
	}
	if password == keystore.DEFAULT_PASSWORD {
		return true
	}
	return false
}

// Fetches the ACME server CA bundle using a custom, insecure, non RFC compliant
// endpoint provided by the Trusted Platform ACME service. The returned certificates
// are used to create a new secure transport for the ACME client, and the secure client
// is returned.
func (ac *Client) createHTTPClient(directoryURL string) (*http.Client, error) {

	defer ac.mutex.Unlock()
	ac.mutex.Lock()

	// Create x509 root CA certificate pool using the OS trusted root CA store
	rootCAs, err := ac.createCACertPool(directoryURL, nil, nil)
	if err != nil {
		return nil, err
	}

	// Create a secure transport using the ACME server CA bundle
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// Fetches the ACME server CA bundle using a custom, insecure, non RFC compliant
// endpoint provided by the Trusted Platform ACME service. The certificates
// returned from the ACME server are parsed and a new x509 trusted root
// certificate pool is returned to the caller.
func (ac *Client) createCACertPool(
	directoryURL string,
	storeType *keystore.StoreType,
	keyAlgo *x509.PublicKeyAlgorithm) (*x509.CertPool, error) {

	// Create x509 root CA certificate pool using the OS trusted root CA store
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system root CAs: %v", err)
	}

	// If the ACME client config does not have the request-server-bundle
	// flag set, return the system root CA certificate pool. The CA bundle
	// request is not RFC 8555 compliant.
	if !ac.config.RequestServerBundle {
		return rootCAs, nil
	}

	// Add the ACME server CA bundle to the x509 root CA certificate pool
	_, bytes, err := ac.caBundleCerts(directoryURL, storeType, keyAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME server CA bundle: %v", err)
	}

	// Add the downloaded ACME server CA bundle to the ACME client trusted
	// root certificate pool
	if ok := rootCAs.AppendCertsFromPEM(bytes); !ok {
		return nil, ErrInvalidCACertificate
	}

	return rootCAs, nil
}

// Fetches the ACME server CA bundle using a custom, insecure, non RFC compliant
func (ac *Client) caBundleCerts(
	directoryURL string,
	storeType *keystore.StoreType,
	keyAlgo *x509.PublicKeyAlgorithm) ([]*x509.Certificate, []byte, error) {

	var caBundle bytes.Buffer

	// Create the ca-bundle ACME server endpoint
	parsedURL, err := url.Parse(directoryURL)
	if err != nil {
		return nil, nil, err
	}
	dir := path.Dir(parsedURL.Path)
	newPath := path.Join(dir, "ca-bundle")
	parsedURL.Path = newPath

	var sStoreType, sKeyAlgo string
	if storeType != nil {
		sStoreType = storeType.String()
	}
	if keyAlgo != nil {
		sKeyAlgo = keyAlgo.String()
	}

	caBundleEndpoint := fmt.Sprintf("%s/%s/%s",
		parsedURL.String(), sStoreType, sKeyAlgo)

	// Retrieve the CA bundle from the ACME server over an insecure connection
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Disable certificate verification
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	resp, err := httpClient.Get(caBundleEndpoint)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		ac.logger.Error(ErrCABundleDownloadFailed, slog.Int("status", resp.StatusCode))
		return nil, nil, err
	}

	// Copy the response body
	_, err = io.Copy(&caBundle, resp.Body)
	if err != nil {
		return nil, nil, err
	}

	caBundleBytes := caBundle.Bytes()

	// Parse the CA bundle and import the certificates into the CA certificate store
	certs, err := ac.ca.ParseBundle(caBundleBytes)
	if err != nil {
		return nil, nil, err
	}
	for _, cert := range certs {
		if !ac.ca.Exists(cert.Subject.CommonName, cert.PublicKeyAlgorithm) {
			if err := ac.ca.ImportCertificate(cert); err != nil {
				return nil, nil, err
			}
		}
	}

	return certs, caBundleBytes, nil
}

// Returns the ACME account key attributes
func (ac *Client) AccountKeyAttributes() *keystore.KeyAttributes {
	return ac.accountKeyAttrs
}

// Returns the ACME account key signer
func (ac *Client) AccountSigner() crypto.Signer {
	return ac.client.Key
}

// Returns the ACME account ID
func (ac *Client) AccountID() uint64 {
	return keystore.PublicKeyID(ac.client.Key.Public(), ac.serializer.Type())
}

// Returns the ACME account associated with the account email provided by the
// platform configuration file
func (ac *Client) Account() (*acme.Account, error) {
	defer ac.mutex.RUnlock()
	ac.mutex.RLock()
	if ac.config.Account == nil {
		return nil, ErrAccountNotFound
	}
	acmeAccount, err := ac.client.GetReg(context.Background(), "")
	if err != nil {
		return nil, err
	}
	return acmeAccount, nil
}

// Returns the ACME account associated with the provided email address
func (ac *Client) AccountFromEmail(email string) (*acme.Account, error) {
	defer ac.mutex.RUnlock()
	ac.mutex.RLock()
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, email)},
	}
	accountDAO, err := ac.datastore.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	accountDAO.Save(&entities.ACMEAccount{
		Contact: account.Contact,
	})
	return nil, ErrAccountNotFound
}

// Registers a new account with the ACME server using the account email
// provided by the platform configuration file
func (ac *Client) RegisterAccount() (*acme.Account, error) {
	defer ac.mutex.RUnlock()
	ac.mutex.RLock()
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, ac.config.Account.Email)},
	}
	newAccount, err := ac.client.Register(context.Background(), account, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}
	accountDAO, err := ac.datastore.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	keyBytes, err := ac.serializer.Serialize(ac.client.Key.Public())
	if err != nil {
		return nil, err
	}
	accountDAO.Save(&entities.ACMEAccount{
		ID:      keystore.PublicKeyID(ac.client.Key.Public(), ac.serializer.Type()),
		Contact: newAccount.Contact,
		Key:     string(keyBytes),
	})
	return newAccount, nil
}

// Registers a new account with the ACME server using the provided email address
func (ac *Client) RegisterAccountWithEmail(email string) (*acme.Account, error) {
	defer ac.mutex.RUnlock()
	ac.mutex.RLock()
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, email)},
	}
	newAccount, err := ac.client.Register(context.Background(), account, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}
	accountDAO, err := ac.datastore.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	keyBytes, err := ac.serializer.Serialize(ac.client.Key.Public())
	if err != nil {
		return nil, err
	}
	accountDAO.Save(&entities.ACMEAccount{
		Contact: newAccount.Contact,
		Key:     string(keyBytes),
	})
	return newAccount, nil
}

// Requests a new TPM Endorsement Key (EK) Certificate. This operation supports use cases where a TPM
// Manufacturer failed to pre-install an Endorsement Key Certificate in the TPM during manufacturing
// per TGC specifications, TPM simulators without an EK Cert, or any case that replaces the EK Cert
// with an OEM, Administrator or User generated EK Cert.
//
// NOTE: There is no way for the ACME server to prove or guarantee the EK provided in this request is a
// real EK in a genuine TPM. The endorse-01 challenge and subsequent EK Certificate issuance is
// provided as an OEM provisioning feature that places trust in the ACME server endpoint security and
// permissions granted to the user making this request.
func (ac *Client) RequestEndorsementKeyCertificate(
	certRequest ca.CertificateRequest) (*x509.Certificate, error) {

	defer ac.mutex.RUnlock()
	ac.mutex.RLock()

	var cert *x509.Certificate
	var csr []byte

	operation := func() error {

		ek := ac.tpm.EK()
		serializedEKPub, err := ac.serializer.Serialize(ek)
		if err != nil {
			return err
		}

		order, err := ac.client.AuthorizeOrder(context.Background(), []acme.AuthzID{{
			Type:  AuthzTypePermanentIdentifier.String(),
			Value: string(serializedEKPub),
		}})
		if err != nil {
			return fmt.Errorf("failed to authorize order: %v", err)
		}

		for _, authzURL := range order.AuthzURLs {

			authz, err := ac.client.GetAuthorization(context.Background(), authzURL)
			if err != nil {
				return fmt.Errorf("failed to get authorization: %v", err)
			}

			var acceptedChallenge *acme.Challenge

			for _, challenge := range authz.Challenges {

				// endorse-01
				if challenge.Type == ChallengeTypeEndorse01.String() {

					fmt.Println("Performing endorse-01 challenge")
					csr, err = endorse01.Setup(challenge.Token, ac.ca, ac.tpm)
					if err != nil {
						return fmt.Errorf("failed to generate attestation statement: %v", err)
					}
					challenge.Token = string(csr)
					acceptedChallenge = challenge
					break
				}
			}

			if acceptedChallenge == nil {
				return fmt.Errorf("server failed to offer %s challenge", ChallengeTypeEndorse01)
			}

			// Notify the ACME server that the challenge is ready to be validated
			_, err = ac.client.Accept(context.Background(), acceptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to accept challenge: %v", err)
			}

			// Wait for the ACME server to validate the challenge
			authz, err = ac.client.WaitAuthorization(context.Background(), authz.URI)
			if err != nil {
				return fmt.Errorf("failed to wait for authorization: %v", err)
			}

			// Ensure the authorization status is valid
			if authz.Status != acme.StatusValid {
				return fmt.Errorf("authorization status is not valid: %v", authz.Status)
			}
		}

		orderCertChain, _, err := ac.client.CreateOrderCert(context.Background(), order.FinalizeURL, csr, true)
		if err != nil {
			return fmt.Errorf("failed to finalize order: %v", err)
		}

		cert, err = x509.ParseCertificate(orderCertChain[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		// if cert.Subject.CommonName != subject.CommonName {
		// 	return fmt.Errorf("certificate common name does not match domain: %s", cert.Subject.CommonName)
		// }

		return nil
	}

	// exponentialBackOff := backoff.NewExponentialBackOff()
	// err = backoff.Retry(operation, exponentialBackOff)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	// }

	if err := operation(); err != nil {
		return nil, err
	}

	ekAttrs, err := ac.tpm.EKAttributes()
	if err != nil {
		return nil, err
	}
	// // Import the EK into the CA certificate store
	// if err := ac.ca.ImportCertificate(cert); err != nil {
	// 	return nil, err
	// }
	err = ac.ca.ImportEndorsementKeyCertificate(ekAttrs, cert.Raw)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Creates a new ACME order for Initial Attestation Key (IAK) and Initial Device Identifier
// (IDevID) certificates. The EK certificate serial number is used as the "permanent-identifier"
// authorization value to return a custom "device-01" challenge. In response to the challenge,
// a TCG-CSR-IDevID Certificate Signing Request is created as specified in Section 13.1 of the
// TPM 2.0 Keys for Device Identity and Attestation documentation, and the challenge is accepted.
// Upon notifying the ACME server the challenge is ready to be validated, the ACME server will
// provide the TCG-CSR-IDEVD using the methods described in the "device-01" challenge type. Upon
// successful validation, the ACME server fulfills the order and returns the IAK and IDevID certificates
// in that specific order.
//
// This operation is intended for use by an OEM or Enterprise to enable automated device enrollment
// via the ACME protocol.
func (ac *Client) EnrollDevice(
	certRequest ca.CertificateRequest) (*x509.Certificate, error) {

	defer ac.mutex.RUnlock()
	ac.mutex.RLock()

	if ac.config.Enrollment == nil {
		return nil, ErrMissingEnrollmentConfig
	}

	var csr []byte
	var certificates [][]byte

	operation := func() error {

		ipAddress := ac.config.Enrollment.IPAddress

		// Expand macros if present
		if len(ipAddress) >= 2 && ipAddress[0] == '$' && ipAddress[1] == '{' {
			ipAddress = dns.ExpandVar(ipAddress)
		}

		// Define the IP address for the IP authorization
		if ipAddress == "" {
			// No IP address, default to the IP address traffic is traversing
			// on this host.
			ipAddress = util.PreferredIPv4().String()
		}

		// Validate the IP address
		if parsedIP := net.ParseIP(ipAddress); parsedIP == nil {
			return fmt.Errorf("invalid %s IP address: %s",
				ac.config.Enrollment.Challenge,
				ac.config.Enrollment.IPAddress)
		}

		// Authorize the order using the IP address
		order, err := ac.client.AuthorizeOrder(context.Background(), []acme.AuthzID{{
			Type:  AuthzTypeIP.String(),
			Value: ipAddress,
		}})
		if err != nil {
			return fmt.Errorf("failed to authorize order: %v", err)
		}

		for _, authzURL := range order.AuthzURLs {

			authz, err := ac.client.GetAuthorization(context.Background(), authzURL)
			if err != nil {
				return fmt.Errorf("failed to get authorization: %v", err)
			}

			var acceptedChallenge *acme.Challenge

			for _, challenge := range authz.Challenges {

				if challenge.Type == ac.config.Enrollment.Challenge {
					_, port, err := ParseChallengeAsDynamicPortAssignment(challenge.Type)
					if err != nil {
						return err
					}

					keyAuth, err := ac.client.HTTP01ChallengeResponse(challenge.Token)
					if err != nil {
						return fmt.Errorf("failed to generate key authorization: %v", err)
					}

					csr, err = enroll01.Setup(port, keyAuth, ac.ca, ac.tpm)
					if err != nil {
						return fmt.Errorf("failed to generate attestation statement: %v", err)
					}
					acceptedChallenge = challenge
					break
				}
			}

			if acceptedChallenge == nil {
				return fmt.Errorf("server failed to offer %s challenge", ac.config.Enrollment.Challenge)
			}

			// Notify the ACME server that the challenge is ready to be validated
			_, err = ac.client.Accept(context.Background(), acceptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to accept challenge: %v", err)
			}

			// Wait for the ACME server to validate the challenge
			authz, err = ac.client.WaitAuthorization(context.Background(), authz.URI)
			if err != nil {
				return fmt.Errorf("failed to wait for authorization: %v", err)
			}

			// Ensure the authorization status is valid
			if authz.Status != acme.StatusValid {
				return fmt.Errorf("authorization status is not valid: %v", authz.Status)
			}
		}

		orderCertChain, _, err := ac.client.CreateOrderCert(context.Background(), order.FinalizeURL, csr, true)
		if err != nil {
			return fmt.Errorf("failed to finalize order: %v", err)
		}

		if len(orderCertChain) != 2 {
			return fmt.Errorf("unexpected number of certificates returned from ACME server: %d", len(orderCertChain))
		}

		certificates = orderCertChain

		return nil
	}

	// exponentialBackOff := backoff.NewExponentialBackOff()
	// err = backoff.Retry(operation, exponentialBackOff)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	// }

	if err := operation(); err != nil {
		return nil, err
	}

	iakCert, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return nil, err
	}
	if err := ac.ca.ImportCertificate(iakCert); err != nil {
		return nil, err
	}

	idevidCert, err := x509.ParseCertificate(certificates[1])
	if err != nil {
		return nil, err
	}
	if err := ac.ca.ImportCertificate(idevidCert); err != nil {
		return nil, err
	}

	return idevidCert, nil
}

// Creates a new ACME TLS certificate order using the provided authorization and challenge
// types. Upon successful authorization and challenge resolution, the requested certificate
// is returned in ASN.1 DER form.
func (ac *Client) RequestCertificate(
	acmeCertRequest CertificateRequest,
	createKey bool) (cert *x509.Certificate, xsignedCert *x509.Certificate, err error) {

	defer ac.mutex.RUnlock()
	ac.mutex.RLock()

	var challengePort int
	var primaryOrder, xsignedOrder *acme.Order
	var orderID uint64
	var certificateURL string
	var xsignedOrderEntity *entities.ACMEOrder
	var certDER []byte

	if acmeCertRequest.AuthzID == nil {

		// Attempt to parse the authorization type and value from the challenge type
		authzType, err := ParseAuthzTypeFromChallengeType(acmeCertRequest.ChallengeType)
		if err != nil {
			return nil, nil, err
		}
		// If this is acme-device-attest, build the appropriate authorization ID
		if acmeCertRequest.ChallengeType == ChallengeTypeDeviceAttest01.String() {
			ekCert, err := ac.tpm.EKCertificate()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get EK certificate: %v", err)
			}
			authzType := authzType.String()
			acmeCertRequest.PermanentID = ekCert.SerialNumber.String()
			acmeCertRequest.AuthzID = &AuthzID{
				Type:  &authzType,
				Value: &acmeCertRequest.PermanentID,
			}
		} else {
			// Default to the parsed authorization type with the web server's
			// common name as the value
			authtzType := authzType.String()
			acmeCertRequest.AuthzID = &AuthzID{
				Type:  &authtzType,
				Value: &acmeCertRequest.Subject.CommonName,
			}
		}
	}

	// Default to http-01 if an ACME challenge type is not provided in the certificate request
	if acmeCertRequest.ChallengeType == "" {
		acmeCertRequest.ChallengeType = ChallengeTypeHTTP01.String()
	}

	// Parse dynamic port assignment for the challenge type if present
	if acmeCertRequest.ChallengeType == ChallengeTypeHTTP01.String() {
		challengePort = ac.webServiceHTTPPort
	} else {
		_, port, err := ParseChallengeAsDynamicPortAssignment(acmeCertRequest.ChallengeType)
		if err != nil {
			return nil, nil, err
		}
		cport, err := strconv.ParseInt(port, 10, 64)
		if err != nil {
			return nil, nil, err
		}
		challengePort = int(cport)
	}

	// Generate an ACME client order ID from the authorization
	orderID = GenerateOrderID(acme.AuthzID{
		Type:  *acmeCertRequest.AuthzID.Type,
		Value: *acmeCertRequest.AuthzID.Value,
	})

	operation := func() error {

		primaryOrder, err = ac.client.AuthorizeOrder(context.Background(), []acme.AuthzID{
			{
				Type:  *acmeCertRequest.AuthzID.Type,
				Value: *acmeCertRequest.AuthzID.Value,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to authorize order: %v", err)
		}

		for _, authzURL := range primaryOrder.AuthzURLs {

			authz, err := ac.client.GetAuthorization(context.Background(), authzURL)
			if err != nil {
				return fmt.Errorf("failed to get authorization: %v", err)
			}

			var acceptedChallenge *acme.Challenge

			for _, challenge := range authz.Challenges {

				keyAuth, err := ac.client.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return fmt.Errorf("failed to generate key authorization: %v", err)
				}

				if challenge.Type == acmeCertRequest.ChallengeType {

					ac.logger.Info("Performing %s challenge",
						slog.String("challenge", challenge.Type))

					// http-01
					if IsHTTPxChallenge(challenge.Type) {
						http01.Setup(strconv.Itoa(challengePort), keyAuth)
						acceptedChallenge = challenge
						break
					}

					// dns-01
					if challenge.Type == ChallengeTypeDNS01.String() {
						if challenge.Type == ChallengeTypeDNS01.String() {
							fmt.Println("Performing dns-01 challenge")
							dns01.DNSService = ac.dnsService
							if err := dns01.Setup(challenge.Token, *acmeCertRequest.AuthzID.Value); err != nil {
								return fmt.Errorf("failed to setup DNS challenge: %v", err)
							}
							acceptedChallenge = challenge
							break
						}
					}

					// device-attest-01
					if challenge.Type == ChallengeTypeDeviceAttest01.String() {

						fmt.Println("Performing device-attest-01 challenge")

						akAttrs, err := ac.tpm.IAKAttributes()
						if err != nil {
							return fmt.Errorf("failed to get IAK attributes: %v", err)
						}

						payload, err := deviceattest01.Setup(keyAuth, akAttrs, deviceattest01.FormatTPM, ac.tpm)
						if err != nil {
							return fmt.Errorf("failed to generate attestation statement: %v", err)
						}

						ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
						defer cancel()

						if _, err = ac.client.AcceptWithPayload(ctx, challenge, payload); err != nil {
							return fmt.Errorf("failed to accept challenge: %v", err)
						}
						acceptedChallenge = challenge
						break
					}
				}

				// continue to the next challenge offered by the ACME server for this authorization type
			}

			if acceptedChallenge == nil {
				return fmt.Errorf(
					"failed to accept %s authorization for %s with %s challenge",
					*acmeCertRequest.AuthzID.Type,
					*acmeCertRequest.AuthzID.Value,
					acmeCertRequest.ChallengeType)
			}

			// Notify the ACME server that the challenge is ready to be validated
			_, err = ac.client.Accept(context.Background(), acceptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to accept challenge: %v", err)
			}

			// Wait for the ACME server to validate the challenge
			authz, err = ac.client.WaitAuthorization(context.Background(), authz.URI)
			if err != nil {
				return fmt.Errorf("failed to wait for authorization: %v", err)
			}

			if authz.Status != acme.StatusValid {
				return fmt.Errorf("authorization status is not valid: %v", authz.Status)
			}

			// Shutdown the web server if the challenge type is http-01
			if IsHTTPxChallenge(acceptedChallenge.Type) {
				http01.Shutdown()
			}
		}

		if createKey {
			store, err := ac.ca.Keyring().Store(acmeCertRequest.KeyAttributes.StoreType.String())
			if err != nil {
				return err
			}
			_, err = store.GenerateKey(acmeCertRequest.KeyAttributes)
			if err != nil {
				return err
			}
		}

		caCertRequest := ca.CertificateRequest{
			PermanentID:   acmeCertRequest.PermanentID,
			Subject:       acmeCertRequest.Subject,
			ProdModel:     acmeCertRequest.ProdModel,
			ProdSerial:    acmeCertRequest.ProdSerial,
			SANS:          acmeCertRequest.SANS,
			KeyAttributes: acmeCertRequest.KeyAttributes,
		}

		csrDER, err := ac.ca.CreateCSR(caCertRequest)
		if err != nil {
			return fmt.Errorf("failed to create CSR: %v", err)
		}

		orderCertChain, certURL, err := ac.client.CreateOrderCert(context.Background(), primaryOrder.FinalizeURL, csrDER, true)
		if err != nil {
			return fmt.Errorf("failed to finalize order: %v", err)
		}

		cert, err = x509.ParseCertificate(orderCertChain[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		if cert.Subject.CommonName != acmeCertRequest.Subject.CommonName {
			return fmt.Errorf(
				"certificate common name does not match requested common name: %s",
				cert.Subject.CommonName)
		}

		certificateURL = certURL

		// Cross-sign the certificate if this is the a main ACME client with a cross-signer
		// configured. If this is a cross-signer only instance, ignore the cross-signing operation
		// as the certificate that was just requested is the cross-signed certificate.
		if acmeCertRequest.CrossSigner != nil && !ac.isCrossSigner {

			if acmeCertRequest.CrossSigner.DirectoryURL == ac.client.DirectoryURL {
				// The cross-signer has the same directory URL. Invalid use case.
				return ErrCrossSignerSameDirectoryURL
			}

			// Use the same authorization as the primary signer

			xsignedOrder, certDER, certURL, err = ac.crossSignCertificate(acmeCertRequest, csrDER)
			if err != nil {
				return fmt.Errorf("failed to cross-sign certificate: %v", err)
			}

			xsignedCert, err = x509.ParseCertificate(certDER)
			if err != nil {
				return fmt.Errorf("failed to parse cross-signed certificate: %v", err)
			}

			identifierEntities := make([]entities.ACMEIdentifier, len(xsignedOrder.Identifiers))
			for i, identifier := range xsignedOrder.Identifiers {
				identifierEntities[i] = entities.ACMEIdentifier{
					Type:  identifier.Type,
					Value: identifier.Value,
				}
			}

			xsignedPEM, err := certstore.EncodePEM(xsignedCert.Raw)
			if err != nil {
				return fmt.Errorf("failed to encode cross-signed certificate: %v", err)
			}

			xsignedOrderEntity = &entities.ACMEOrder{
				ID:             orderID,
				Status:         acme.StatusValid,
				Expires:        xsignedOrder.Expires.String(),
				Identifiers:    identifierEntities,
				NotBefore:      xsignedOrder.NotBefore.String(),
				NotAfter:       xsignedOrder.NotAfter.String(),
				Authorizations: xsignedOrder.AuthzURLs,
				Finalize:       xsignedOrder.FinalizeURL,
				Certificate:    string(xsignedPEM),
				CertificateURL: certURL,
				AccountID:      ac.AccountID(),
				URL:            xsignedOrder.URI,
			}

			issuerCN, err := util.ParseFQDN(acmeCertRequest.CrossSigner.DirectoryURL)
			if err != nil {
				return err
			}
			// Import the new cross-signed certificate into the CA certificate store
			if err := ac.ca.ImportXSignedCertificate(issuerCN, xsignedCert); err != nil {
				return err
			}
		}

		return nil
	}

	// exponentialBackOff := backoff.NewExponentialBackOff()
	// err = backoff.Retry(operation, exponentialBackOff)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	// }

	if err := operation(); err != nil {
		return nil, nil, err
	}

	accountID := ac.AccountID()

	// Save the order to the datastore
	orderDAO, err := ac.datastore.ACMEOrderDAO(accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve order DAO: %v", err)
	}

	certPEM, err := certstore.EncodePEM(cert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate: %v", err)
	}

	identifierEntities := make([]entities.ACMEIdentifier, len(primaryOrder.Identifiers))
	for i, identifier := range primaryOrder.Identifiers {
		identifierEntities[i] = entities.ACMEIdentifier{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	orderEntity := &entities.ACMEOrder{
		ID:             orderID,
		Status:         acme.StatusValid,
		Expires:        primaryOrder.Expires.String(),
		Identifiers:    identifierEntities,
		NotBefore:      primaryOrder.NotBefore.String(),
		NotAfter:       primaryOrder.NotAfter.String(),
		Authorizations: primaryOrder.AuthzURLs,
		Finalize:       primaryOrder.FinalizeURL,
		Certificate:    string(certPEM),
		CertificateURL: certificateURL,
		AccountID:      ac.AccountID(),
		URL:            primaryOrder.URI,
		XSignedOrder:   xsignedOrderEntity,
	}

	// Save the order to the datastore
	if err := orderDAO.Save(orderEntity); err != nil {
		return nil, nil, fmt.Errorf("failed to save order: %v", err)
	}

	// Import the new certificate into the CA certificate store
	if err := ac.ca.ImportCertificate(cert); err != nil {
		return nil, nil, err
	}

	// Import the Enterprise / Privacy CA bundle into the certificate
	// store if it doesn't exist
	if !ac.ca.Exists(cert.Issuer.CommonName, cert.PublicKeyAlgorithm) {

		// Parse the key store type from the certificate
		storeType, err := certstore.ParseKeyStoreType(cert)
		if err != nil {
			return nil, nil, err
		}

		// Download the CA bundle from the ACME server and import them
		// into the local CA certificate store if they don't yet exist
		if ac.config.RequestServerBundle {
			if _, _, err := ac.caBundleCerts(ac.client.DirectoryURL, &storeType, &cert.PublicKeyAlgorithm); err != nil {
				return nil, nil, err
			}
		}
	}

	return cert, xsignedCert, nil
}

// Cross-signs a certificate using the client instantiated with the cross-signer
// DirecotryURL.
func (ac *Client) CrossSign(
	csrDER []byte,
	certDER []byte,
	acmeCertRequest CertificateRequest) (*x509.Certificate, error) {

	order, xsignedCertDER, xsignedCertURL, err := ac.crossSignCertificate(acmeCertRequest, csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to cross-sign certificate: %v", err)
	}

	xsignedCert, err := x509.ParseCertificate(xsignedCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-signed certificate: %v", err)
	}

	// exponentialBackOff := backoff.NewExponentialBackOff()
	// err = backoff.Retry(operation, exponentialBackOff)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	// }

	accountID := ac.AccountID()

	// Save the order to the datastore
	orderDAO, err := ac.datastore.ACMEOrderDAO(accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve order DAO: %v", err)
	}

	certPEM, err := certstore.EncodePEM(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %v", err)
	}

	identifierEntities := make([]entities.ACMEIdentifier, len(order.Identifiers))
	for i, identifier := range order.Identifiers {
		identifierEntities[i] = entities.ACMEIdentifier{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	orderID := GenerateOrderID(acme.AuthzID{
		Type:  *acmeCertRequest.AuthzID.Type,
		Value: *acmeCertRequest.AuthzID.Value,
	})

	orderEntity := &entities.ACMEOrder{
		ID:             orderID,
		Status:         acme.StatusValid,
		Expires:        order.Expires.String(),
		Identifiers:    identifierEntities,
		NotBefore:      order.NotBefore.String(),
		NotAfter:       order.NotAfter.String(),
		Authorizations: order.AuthzURLs,
		Finalize:       order.FinalizeURL,
		Certificate:    string(certPEM),
		CertificateURL: xsignedCertURL,
		AccountID:      ac.AccountID(),
		URL:            order.URI,
	}

	// Save the order to the datastore
	if err := orderDAO.Save(orderEntity); err != nil {
		return nil, fmt.Errorf("failed to save order: %v", err)
	}

	issuerCN, err := util.ParseFQDN(acmeCertRequest.CrossSigner.DirectoryURL)
	if err != nil {
		return nil, err
	}
	// Import the new cross-signed certificate into the CA certificate store
	if err := ac.ca.ImportXSignedCertificate(issuerCN, xsignedCert); err != nil {
		return nil, err
	}

	return xsignedCert, nil
}

// Perform an ACME key-change operation
func (ac *Client) KeyChange() error {

	// Retrieve the current account
	account, err := ac.Account()
	if err != nil {
		return fmt.Errorf("failed to retrieve account: %w", err)
	}

	accountDAO, err := ac.datastore.ACMEAccountDAO()
	if err != nil {
		return fmt.Errorf("failed to retrieve account DAO: %w", err)
	}

	newKey, err := rsa.GenerateKey(ac.tpm, 2049)
	if err != nil {
		return fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	// defer ac.mutex.RUnlock()
	// ac.mutex.RLock()

	// Perform the key rollover using the ACME library method
	ctx := context.Background()
	err = ac.client.AccountKeyRollover(ctx, newKey)
	if err != nil {
		return fmt.Errorf("failed to perform account key rollover: %w", err)
	}

	// Serialize the key
	keyBytes, err := ac.serializer.Serialize(newKey.Public())
	if err != nil {
		return fmt.Errorf("failed to serialize new public key: %w", err)
	}

	// Update the datastore with the new key information
	if err := accountDAO.Save(&entities.ACMEAccount{
		Contact: account.Contact,
		Key:     string(keyBytes),
	}); err != nil {
		return fmt.Errorf("failed to save updated account information: %w", err)
	}

	return nil
}

// Downloads the latest certificate from the ACME server, If the certificate is
// cross-signed, the cross-signed certificate is also downloaded and returned.
func (ac *Client) DownloadCertificates(
	challengeType string,
	keyAttrs *keystore.KeyAttributes,
	includeBundle bool,
	crossSigner *CrossSign) ([]*x509.Certificate, error) {

	accountID := ac.AccountID()

	var certs []*x509.Certificate

	// Parse the authorization type from the challenge type
	authzType, err := ParseAuthzTypeFromChallengeType(challengeType)
	if err != nil {
		return nil, err
	}

	authzID := acme.AuthzID{
		Type:  authzType.String(),
		Value: keyAttrs.CN,
	}

	orderDAO, err := ac.datastore.ACMEOrderDAO(accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve order DAO: %v", err)
	}

	orderID := GenerateOrderID(authzID)
	orderEntity, err := orderDAO.Get(orderID, ac.datastore.ConsistencyLevel())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve order: %v", err)
	}

	certChain, err := ac.client.FetchCert(context.Background(), orderEntity.CertificateURL, includeBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate: %v", err)
	}

	for _, _cert := range certChain {
		cert, err := x509.ParseCertificates(_cert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert...)
	}

	if orderEntity.XSignedOrder != nil {
		xsigner, err := ac.CrossSignerFromClient(crossSigner)
		if err != nil {
			return nil, fmt.Errorf("failed to create cross-signing client: %v", err)
		}
		xcertChain, err := xsigner.client.FetchCert(
			context.Background(), orderEntity.XSignedOrder.CertificateURL, includeBundle)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch cross-signed certificate: %v", err)
		}
		for _, _cert := range xcertChain {
			cert, err := x509.ParseCertificates(_cert)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cross-signed certificate: %v", err)
			}
			certs = append(certs, cert...)
		}

	}

	return certs, nil
}

// Returns the latest certificates from the local datastore. This includes the
// any cross-signed certificates if they exist.
func (ac *Client) Certificates(
	authzID acme.AuthzID,
	keyAttrs *keystore.KeyAttributes,
	includeBundle bool,
	crossSigner *CrossSign) ([]*x509.Certificate, error) {

	accountID := ac.AccountID()

	var certs []*x509.Certificate

	orderDAO, err := ac.datastore.ACMEOrderDAO(accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve order DAO: %v", err)
	}

	orderID := GenerateOrderID(authzID)
	orderEntity, err := orderDAO.Get(orderID, ac.datastore.ConsistencyLevel())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve order: %v", err)
	}

	certChain, err := ac.client.FetchCert(context.Background(), orderEntity.CertificateURL, includeBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate: %v", err)
	}

	for _, _cert := range certChain {
		cert, err := x509.ParseCertificates(_cert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert...)
	}

	if orderEntity.XSignedOrder != nil {
		xsigner, err := ac.CrossSignerFromClient(crossSigner)
		if err != nil {
			return nil, fmt.Errorf("failed to create cross-signing client: %v", err)
		}
		xcertChain, err := xsigner.client.FetchCert(
			context.Background(), orderEntity.XSignedOrder.CertificateURL, includeBundle)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch cross-signed certificate: %v", err)
		}
		for _, _cert := range xcertChain {
			cert, err := x509.ParseCertificates(_cert)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cross-signed certificate: %v", err)
			}
			certs = append(certs, cert...)
		}

	}

	return certs, nil
}

// crossSignCertificate cross-signs the provided certificate using Let's Encrypt or other cross-sign CA.
func (ac *Client) crossSignCertificate(
	acmeCertRequest CertificateRequest, csrDER []byte) (*acme.Order, []byte, string, error) {

	var certDER []byte
	var certURL string

	xsigner, err := ac.CrossSignerFromClient(acmeCertRequest.CrossSigner)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create cross-signing client: %v", err)
	}

	authzID, err := ParseAuthzIDFromChallengeType(acmeCertRequest.CrossSigner.ChallengeType)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse authorization ID: %v", err)
	}
	authzID.Value = acmeCertRequest.Subject.CommonName

	order, err := xsigner.client.AuthorizeOrder(context.Background(), []acme.AuthzID{authzID})
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to authorize cross-sign order: %v", err)
	}

	operation := func() error {

		// Authorize the order using the provided authorization type and value
		order, err = xsigner.client.AuthorizeOrder(context.Background(), []acme.AuthzID{
			authzID,
		})
		if err != nil {
			return fmt.Errorf("failed to authorize order: %v", err)
		}

		for _, authzURL := range order.AuthzURLs {

			authz, err := xsigner.client.GetAuthorization(context.Background(), authzURL)
			if err != nil {
				return fmt.Errorf("failed to get authorization: %v", err)
			}

			var acceptedChallenge *acme.Challenge

			for _, challenge := range authz.Challenges {

				keyAuth, err := xsigner.client.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return fmt.Errorf("failed to generate key authorization: %v", err)
				}

				if challenge.Type == acmeCertRequest.CrossSigner.ChallengeType {

					// http-01
					if challenge.Type == ChallengeTypeHTTP01.String() {
						http01.Setup(strconv.Itoa(xsigner.webServiceHTTPPort), keyAuth)
						acceptedChallenge = challenge
						break
					}

					// dns-01
					if challenge.Type == ChallengeTypeDNS01.String() {
						if challenge.Type == ChallengeTypeDNS01.String() {
							fmt.Println("Performing dns-01 challenge")
							dns01.DNSService = xsigner.dnsService
							if err := dns01.Setup(challenge.Token, *acmeCertRequest.AuthzID.Value); err != nil {
								return fmt.Errorf("failed to setup DNS challenge: %v", err)
							}
							acceptedChallenge = challenge
							break
						}
					}

				}

				// continue to the next challenge offered by the ACME server for this authorization type
			}

			if acceptedChallenge == nil {
				return fmt.Errorf(
					"failed to accept %s authorization for %s with %s challenge",
					*acmeCertRequest.AuthzID.Type,
					*acmeCertRequest.AuthzID.Value,
					acmeCertRequest.ChallengeType)
			}

			_, err = xsigner.client.Accept(context.Background(), acceptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to accept challenge: %v", err)
			}

			// Save the authz url to avoid nil pointer in the infinite loop
			// when an error is encountered and an authz url is not returned,
			// causing the URI to be lost.
			authzURI := authz.URI

			// Wait for the ACME server to validate the challenge
			authz, err = xsigner.client.WaitAuthorization(context.Background(), authz.URI)
			for err != nil {
				if strings.Contains(err.Error(), "too many requests") {
					break
				}
				xsigner.logger.Errorf(err.Error())
				xsigner.logger.Errorf("Retrying authorization in 1 minute...")
				time.Sleep(time.Minute)
				authz, err = xsigner.client.WaitAuthorization(context.Background(), authzURI)
				if err == nil {
					break
				}
				// return fmt.Errorf("failed to wait for authorization: %v", err)
			}

			if authz.Status != acme.StatusValid {
				return fmt.Errorf("authorization status is not valid: %v", authz.Status)
			}

			// Shutdown the web server if the challenge type is http-01
			if IsHTTPxChallenge(acceptedChallenge.Type) {
				http01.Shutdown()
			}
		}

		caCertRequest := ca.CertificateRequest{
			PermanentID:   acmeCertRequest.PermanentID,
			Subject:       acmeCertRequest.Subject,
			ProdModel:     acmeCertRequest.ProdModel,
			ProdSerial:    acmeCertRequest.ProdSerial,
			SANS:          acmeCertRequest.SANS,
			KeyAttributes: acmeCertRequest.KeyAttributes,
		}

		csrDER, err := xsigner.ca.CreateCSR(caCertRequest)
		if err != nil {
			return fmt.Errorf("failed to create CSR: %v", err)
		}

		orderCertChain, url, err := xsigner.client.CreateOrderCert(context.Background(), order.FinalizeURL, csrDER, true)
		if err != nil {
			return fmt.Errorf("failed to finalize order: %v", err)
		}

		cert, err := x509.ParseCertificate(orderCertChain[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		if cert.Subject.CommonName != acmeCertRequest.Subject.CommonName {
			return fmt.Errorf(
				"certificate common name does not match requested common name: %s",
				cert.Subject.CommonName)
		}

		certURL = url
		certDER = cert.Raw

		return nil
	}

	// exponentialBackOff := backoff.NewExponentialBackOff()
	// err = backoff.Retry(operation, exponentialBackOff)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	// }

	if err := operation(); err != nil {
		return nil, nil, "", err
	}

	return order, certDER, certURL, nil
}

// // CreateJWS creates and signs a JWS for a given payload using the appropriate key
// func (ac *Client) createJWS(payload, nonce []byte, url string, useKID bool) ([]byte, error) {

// 	var alg jose.SignatureAlgorithm

// 	alg, err := parseJOSEAlgorithm(ac.accountKeyAttrs.SignatureAlgorithm.String())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse JOSE signature algorithm: %v", err)
// 	}

// 	keyring := ac.ca.Keyring()

// 	store, err := keyring.Store(ac.accountKeyAttrs.StoreType.String())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}

// 	opaqueKey, err := store.Key(ac.accountKeyAttrs)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}

// 	opaqueSigner := NewSigner(ac.tpm.RandomSource(), opaqueKey)

// 	signerOptions := jose.SignerOptions{}
// 	signerOptions.NonceSource = NewNonce(nonce)
// 	signerOptions = *signerOptions.WithHeader("nonce", nonce)
// 	signerOptions = *signerOptions.WithHeader("url", url)

// 	if useKID {
// 		acctURL := ac.client.KID
// 		if acctURL == "" {
// 			return nil, fmt.Errorf("account URL (KID) is empty")
// 		}
// 		signerOptions = *signerOptions.WithHeader("kid", acctURL)
// 		// signerOptions.EmbedJWK = useKID == false
// 	} else {
// 		signerOptions.EmbedJWK = true
// 	}

// 	// signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaqueSigner}, &signerOptions)
// 	// if err != nil {
// 	// 	return nil, fmt.Errorf("failed to create signer: %v", err)
// 	// }

// 	// jws, err := signer.Sign(payload)
// 	// if err != nil {
// 	// 	return nil, fmt.Errorf("failed to sign JWS: %v", err)
// 	// }

// 	jws, err := opaqueSigner.SignPayload(payload, alg)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign JWS: %v", err)
// 	}

// 	// compactJWS, err := jws.CompactSerialize()
// 	// if err != nil {
// 	// 	return nil, fmt.Errorf("failed to serialize JWS: %v", err)
// 	// }

// 	// return []byte(compactJWS), nil

// 	return jws, nil
// }

// func (ac *Client) getNonce(ctx context.Context) (string, error) {

// 	directory, err := ac.client.Discover(context.Background())
// 	if err != nil {
// 		return "", err
// 	}

// 	req, err := http.NewRequestWithContext(ctx, http.MethodHead, directory.NonceURL, nil)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to create nonce request: %v", err)
// 	}

// 	resp, err := ac.client.HTTPClient.Do(req)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get nonce: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	nonce := resp.Header.Get("Replay-Nonce")
// 	if nonce == "" {
// 		return "", fmt.Errorf("no Replay-Nonce in response")
// 	}
// 	return nonce, nil
// }

// func (ac *Client) acceptWithPayload(ctx context.Context, challenge *acme.Challenge, payload []byte) error {

// 	// Marshal the payload to JSON
// 	payloadBytes, err := json.Marshal(payload)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal payload: %v", err)
// 	}

// 	// Get a fresh nonce from the ACME server
// 	nonce, err := ac.getNonce(ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to get nonce: %v", err)
// 	}

// 	// Determine whether to use KID (Key ID)
// 	useKID := ac.client.KID != ""

// 	// Create the JWS using your createJWS method
// 	jwsBytes, err := ac.createJWS(payloadBytes, []byte(nonce), challenge.URI, useKID)
// 	if err != nil {
// 		return fmt.Errorf("failed to create JWS: %v", err)
// 	}

// 	// Create the HTTP request
// 	req, err := http.NewRequestWithContext(ctx, http.MethodPost, challenge.URI, bytes.NewReader(jwsBytes))
// 	if err != nil {
// 		return fmt.Errorf("failed to create HTTP request: %v", err)
// 	}
// 	req.Header.Set("Content-Type", "application/jose+json")

// 	// Send the request
// 	resp, err := ac.client.HTTPClient.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("HTTP request failed: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	// Check for successful status codes (200 OK or 202 Accepted)
// 	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
// 		// Read the response body for error details
// 		bodyBytes, _ := io.ReadAll(resp.Body)
// 		return fmt.Errorf("ACME server returned an error: %s", string(bodyBytes))
// 	}

// 	// Optionally, parse the response body if needed

// 	// Read and print the response body
// 	bodyBytes, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return fmt.Errorf("failed to read response body: %v", err)
// 	}
// 	fmt.Println("Response Body:", string(bodyBytes))

// 	return nil
// }
