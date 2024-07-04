package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/util"
	"github.com/op/go-logging"

	pb "github.com/jeremyhahn/go-trusted-platform/attestation/proto"
)

const (
	TLS_DEADLINE = time.Minute
	akBlobName   = "ak"
)

var (
	ErrInvalidCACertificate    = errors.New("verifier: failed to add CA certificate to x509 certificate pool")
	ErrConnectionFailed        = errors.New("verifier: connection failed")
	ErrImportEKCert            = errors.New("verifier: failed to import Endorsement Key (EK) certificate")
	ErrCertKeyMismatch         = errors.New("verifier: certificate and attestation public key modulus mismatch")
	ErrInvalidPublicKey        = errors.New("verifier: invalid public key")
	ErrInvalidCredential       = errors.New("verifier: attestor failed credential challenge")
	ErrInvalidNonce            = errors.New("verifier: invalid nonce")
	ErrUnexpectedEventLogState = errors.New("verifier: unexpected event log state")
	ErrUnexpectedPCRState      = errors.New("verifier: unexpected PCR state")

	// CLI options when invoked directly
	attestorHostname = flag.String("attestor", "localhost", "The Attestor hostname / FQDN / IP")
	caPassword       = flag.String("ca-password", "", "The Certificate Authority private key password")
	serverPassword   = flag.String("server-password", "", "The gRPC server TLS private key password")
	akCertPassword   = flag.String("ak-password", "", "An optional password for the generated AK Certificate private key")
)

type AttestationKey struct {
	Name           []byte
	CreationHash   []byte
	CreationData   []byte
	CreationTicket []byte
}

type makeCredentialResponse struct {
	ak                tpm2.DerivedKey
	secret            []byte
	activationRequest *pb.ActivateCredentialRequest
}

type Verifier interface {
	Attest() error
	EKCert() (*x509.Certificate, error)
	AKProfile(ekCert *x509.Certificate) (tpm2.Key, tpm2.DerivedKey, error)
	MakeCredential(ek tpm2.Key, ak tpm2.DerivedKey) (makeCredentialResponse, error)
	ActivateCredential(makeCredentialResponse makeCredentialResponse) (tpm2.DerivedKey, error)
	IssueCertificate(ak tpm2.DerivedKey, certDER []byte) error
	Quote(ak tpm2.DerivedKey) (tpm2.Quote, []byte, error)
	Verify(quote tpm2.Quote, nonce []byte) error
	Close() error
}

type Verification struct {
	app            *app.App
	logger         *logging.Logger
	config         config.Attestation
	domain         string
	ca             ca.CertificateAuthority
	tpm            tpm2.TrustedPlatformModule2
	caPassword     []byte
	serverPassword []byte
	akCertPassword []byte
	grpcConn       *grpc.ClientConn
	secureAttestor pb.TLSAttestorClient
	clientCertPool *x509.CertPool
	attestor       string
	Verifier
}

func main() {
	flag.Parse()
	app := app.NewApp().Init(nil)
	verifier, err := NewVerifier(app,
		*attestorHostname, []byte(*caPassword), []byte(*serverPassword), []byte(*akCertPassword))
	if err != nil {
		app.Logger.Fatal(err)
	}
	if err := verifier.Attest(); err != nil {
		app.Logger.Fatal(err)
	}
}

// Creates a new Remote Attestation Verifier
func NewVerifier(app *app.App, attestor string, caPassword, serverPassword, akCertPassword []byte) (Verifier, error) {

	clientCertPool := x509.NewCertPool()
	secureConn, err := newTLSGRPCClient(
		app.Logger,
		app.AttestationConfig,
		serverPassword,
		app.Domain,
		attestor,
		app.CA)
	if err != nil {
		return nil, err
	}

	if err := app.TPM.Open(); err != nil {
		app.Logger.Error(err)
		return nil, err
	}

	return &Verification{
		app:            app,
		logger:         app.Logger,
		config:         app.AttestationConfig,
		ca:             app.CA,
		tpm:            app.TPM,
		domain:         app.Domain,
		secureAttestor: pb.NewTLSAttestorClient(secureConn),
		clientCertPool: clientCertPool,
		attestor:       attestor,
		caPassword:     caPassword,
		serverPassword: serverPassword,
		akCertPassword: akCertPassword,
	}, nil
}

// Creates a new insecure GRPC client
func newInsecureGRPCClient(config config.Attestation, attestor string) (*grpc.ClientConn, error) {
	socket := fmt.Sprintf("%s:%d", attestor, config.InsecurePort)
	return grpc.NewClient(
		socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// Creates a new mTLS encrypted GRPC client
func newTLSGRPCClient(
	logger *logging.Logger,
	config config.Attestation,
	serverPassword []byte,
	domain, attestor string,
	ca ca.CertificateAuthority) (*grpc.ClientConn, error) {

	socket := fmt.Sprintf("%s:%d", attestor, config.TLSPort)

	if config.InsecureSkipVerify {
		logger.Warning("verifier: InsecureSkipVerify is enabled, allowing man-in-the-middle attacks!")
	}

	rootCAs, err := buildRootCertPool(logger, config, ca, attestor)
	if err != nil {
		return nil, err
	}

	clientCert, err := ca.X509KeyPair(domain, domain, serverPassword)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       []tls.Certificate{clientCert},
		ServerName:         attestor,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	ce := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(ce))
	if err != nil {
		logger.Errorf("%s: %s", ErrConnectionFailed, err)
		return nil, ErrConnectionFailed
	}

	return conn, nil
}

// Creates Trusted Root CA CertPool to verify the Attestor's
// gRPC TLS server certificate.
func buildRootCertPool(
	logger *logging.Logger,
	config config.Attestation,
	ca ca.CertificateAuthority,
	attestor string) (*x509.CertPool, error) {

	if config.ClientCACert != "" {
		// Load client CA certs from location specified in config
		caPEM, err := os.ReadFile(config.ClientCACert)
		if err != nil {
			logger.Error(err)
			return nil, err
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caPEM) {
			return nil, ErrInvalidCACertificate
		}
		return rootCAs, nil
	}

	if config.AllowAttestorSelfCA {
		// Connect to the Attestor on insecure gRPC port and
		// exchange CA bundles to prepare an mTLS connection
		pool, err := ca.TrustedRootCertPool(false)
		if err != nil {
			return nil, err
		}
		bundle, err := getAttestorCABundle(logger, config, ca, attestor)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(bundle) {
			return nil, ErrInvalidCACertificate
		}
		return pool, nil
	}

	// Set up the mTLS connection using the Operating System
	// trusted root store and the Verifier / Service Provider
	// Certificate Authority Trusted Root and Intermediate
	// certificate store. This requires the client's gRPC TLS
	// server use either a certificate issued from a public
	// trusted CA whose root certificates are installed in the
	// Operating System trusted root store or a certificate issued
	// from the Verifier / Service Provider's Certificate Authority.
	return ca.TrustedRootCertPool(true)
}

// Retrieves the CA certificate(s) used to sign the Attestor's
// gRPC server TLS certificate. This is used to automatically
// configure the verifiers TLS client so the certificate can
// be verified.
func getAttestorCABundle(
	logger *logging.Logger,
	config config.Attestation,
	ca ca.CertificateAuthority,
	attestor string) ([]byte, error) {

	// Get the verifiers CA bundle
	bundle, err := ca.CABundle()
	if err != nil {
		return nil, err
	}

	conn, err := newInsecureGRPCClient(config, attestor)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	insecureAttestor := pb.NewInsecureAttestorClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Send the Attestor our CA certs and receive theirs in return
	response, err := insecureAttestor.GetCABundle(
		ctx,
		&pb.CABundleRequest{Bundle: bundle})
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Debugf("verifier: GetAttestorCABundle:\n%s", response.Bundle)
	return response.Bundle, nil
}

// Get the Attestor's Endorsement Key (EK) and import to CA
func (verifier *Verification) EKCert() (*x509.Certificate, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.GetEKCert(ctx, &pb.Null{})
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}

	cert, err := verifier.tpm.ImportDER(
		verifier.attestor, verifier.attestor, response.Certificate, true)
	if err != nil {
		return nil, ErrImportEKCert
	}

	verifier.logger.Infof("Endorsement Key (EK) Certificate\n%s",
		string(response.Certificate))

	return cert, nil
}

// Get the Attestor's Endorsement Key (EK) and Attestation Key (AK)
// RSA/ECC Public Key, compare their modulus with the EK certificate obtained
// from the TPM, Manufactuter website, or local file (during the EKCert call),
// and return them so they can be passed to CredentialChallenge to
// send the Attestor an encrypted secret using the provided AK. If the Attestor
// is able to decrypt the challenge and send it back in clear text form, they
// have proven their keys belong to an authentic TPM issued by a manufacturer
// that the Verifier (our) CA trusts.
func (verifier *Verification) AKProfile(ekCert *x509.Certificate) (tpm2.Key, tpm2.DerivedKey, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.GetAK(ctx, &pb.Null{})
	if err != nil {
		verifier.logger.Error(err)
		return tpm2.Key{}, tpm2.DerivedKey{}, err
	}

	verifier.debugAK(response)

	_, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		verifier.logger.Error("verifier: EK certificate")
		return tpm2.Key{}, tpm2.DerivedKey{}, err
	}

	verifier.logger.Infof("Endorsement Key (EK) Public Key PEM\n%s",
		string(response.EkPublicPEM))

	verifier.logger.Infof("Attestation Key (AK) Public Key PEM\n%s",
		string(response.EkPublicPEM))

	verifier.logger.Infof("Attestation Key (AK) Name: 0x%x", verifier.tpm.Encode(response.AkName))

	ek := tpm2.Key{
		PublicKeyPEM: response.EkPublicPEM,
		BPublicBytes: response.EkBPublicBytes,
	}

	ak := tpm2.DerivedKey{}
	ak.PublicKeyBytes = response.AkPublicKeyByes
	ak.BPublicBytes = response.AkBPublicBytes
	ak.PublicKeyPEM = response.AkPublicPEM

	return ek, ak, err
}

// Call TPM2_MakeCredential to generate the encrypted secret and privacy
// data to send to the Attestor for activation.
//
// Generate the encrypted-user-chosen-data and the wrapped-secret-data-encryption-key
// for the privacy-sensitive credentialing process of a TPM object:
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md
func (verifier *Verification) MakeCredential(ek tpm2.Key, ak tpm2.DerivedKey) (makeCredentialResponse, error) {

	verifier.logger.Info("Making Credential challenge")

	// Generate a secret using the TPM if enabled for entropy, or
	// the runtime random reader if disabled.
	secret, err := verifier.tpm.Random()
	if err != nil {
		verifier.logger.Error(err)
		return makeCredentialResponse{}, err
	}

	response, secret, err := verifier.tpm.MakeCredential(ek, ak, secret)
	if err != nil {
		verifier.logger.Error(err)
		return makeCredentialResponse{}, err
	}

	// Print some helpful information if secret debugging is enabled
	if verifier.app.DebugSecretsFlag {

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential Attestation Key Name (raw): %s",
			ak.Name)

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential Attestation Key Name (hex): %s",
			verifier.tpm.Encode(ak.Name))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential credential blob (raw): %s",
			response.CredentialBlob.Buffer)

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential credential blob (hex): 0x%x",
			verifier.tpm.Encode(response.CredentialBlob.Buffer))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential secret (raw): %s",
			verifier.tpm.Encode(response.Secret.Buffer))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential secret (hex): 0x%x",
			verifier.tpm.Encode(response.Secret.Buffer))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential encrypted secret (raw): %s",
			verifier.tpm.Encode(response.Secret.Buffer))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential encrypted secret (hex): 0x%x",
			verifier.tpm.Encode(response.Secret.Buffer))
	}

	return makeCredentialResponse{
		ak:     ak,
		secret: secret,
		activationRequest: &pb.ActivateCredentialRequest{
			CredentialBlob:  response.CredentialBlob.Buffer,
			EncryptedSecret: response.Secret.Buffer,
		}}, nil
}

// Send an encrypted secret to the Attestor to decrypt and return. The Attestor
// proves they are in posession of both the EK and AK by loading both keys into
// the TPM and using the EK to decrypt the secret.
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_activatecredential.1.md
func (verifier *Verification) ActivateCredential(
	makeCredentialResponse makeCredentialResponse) (tpm2.DerivedKey, error) {

	verifier.logger.Info("Activating Credential")

	// Send the ciphertext to the Attestor to decrypt and return to prove
	// possession of the private keys stored in an authentic TPM with an
	// EK certifiate issued by a manufacturer that is trusted by our CA.
	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.ActivateCredential(
		ctx, makeCredentialResponse.activationRequest)
	if err != nil {
		verifier.logger.Error(err)
		return tpm2.DerivedKey{}, err
	}

	// Compare the Attestor and Verifier secret
	if bytes.Compare(response.Secret, makeCredentialResponse.secret) != 0 {
		verifier.logger.Error("verifier: attestor failed to activate credential")
		return tpm2.DerivedKey{}, ErrInvalidCredential
	}

	verifier.logger.Info("Credential activation successful")

	return makeCredentialResponse.ak, nil
}

// Requests a TPM PCR quote from the Attestor that includes current TPM
// PCR values, EventLog, and Secure Boot state. If Open Enrollment is enabled,
// the state is signed and saved to the CA's signed blob storage, the Attestation
// Key's Public Key is imported into the key store, and an x509 certificate is
// issued and provided to the Attestor.
func (verifier *Verification) Quote(ak tpm2.DerivedKey) (tpm2.Quote, []byte, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	nonce, err := verifier.tpm.Random()
	if err != nil {
		return tpm2.Quote{}, nil, err
	}

	// Request a quote using PCRs specified in config
	quoteRequest := &pb.QuoteRequest{
		Nonce: nonce,
		Pcrs:  verifier.app.AttestationConfig.QuotePCRs,
	}

	// Request a quote from the Attestor
	response, err := verifier.secureAttestor.Quote(ctx, quoteRequest)
	if err != nil {
		verifier.logger.Error(err)
		return tpm2.Quote{}, nil, err
	}

	// De-gob the quote
	var quote tpm2.Quote
	buf := bytes.NewBuffer(response.Quote)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&quote); err != nil {
		return tpm2.Quote{}, nil, err
	}

	verifier.logger.Info("Quote received")

	if verifier.config.AllowOpenEnrollment {

		verifier.logger.Info("Beginning Open Enrollment")

		// Sign data using the CA's public key and save
		// to signed blob storage

		// Sign and store the quote
		err = verifier.ca.ImportAttestationQuote(verifier.attestor, response.Quote)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Sign and store the quote
		err = verifier.ca.ImportAttestationEventLog(verifier.attestor, quote.EventLog)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Sign and store the PCR state
		err = verifier.ca.ImportAttestationPCRs(verifier.attestor, quote.PCRs)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Parse the public key
		// TODO: Support ECC keys
		var rsaPub *rsa.PublicKey
		publicKey, err := x509.ParsePKIXPublicKey(quote.PublicKeyBytes)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}
		rsaPub = publicKey.(*rsa.PublicKey)

		// Import the public key to the CA public key store
		if err := verifier.ca.ImportPubKey(verifier.attestor, rsaPub); err != nil {
			return tpm2.Quote{}, nil, err
		}
	}

	return quote, nonce, nil
}

// Verifies a TPM 2.0 quote.
// Rather than parsing and replaying the event log, a more simplistic
// approach is taken, which compares the current event log and secure
// boot state blob with the state stored in the CA signed blob store
// captured during device enrollment. This may change in the future.
// The rationale for this is partly due to the event log not being
// a reliable source for integrity checking to begin with:
// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
func (verifier *Verification) Verify(quote tpm2.Quote, nonce []byte) error {

	// Make sure the returned nonce matches the nonce
	// that was sent in the quote request.
	if !bytes.Equal(quote.Nonce, nonce) {
		return ErrInvalidNonce
	}

	// Parse the public key
	var rsaPub *rsa.PublicKey
	publicKey, err := x509.ParsePKIXPublicKey(quote.PublicKeyBytes)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}
	rsaPub = publicKey.(*rsa.PublicKey)

	// Verify the quote signature
	digest := sha256.Sum256(quote.Quoted)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], quote.Signature); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	// Verify the event log
	err = verifier.ca.VerifyAttestationEventLog(verifier.attestor, quote.EventLog)
	if err != nil {
		return err
	}

	// Verify PCR state
	err = verifier.ca.VerifyAttestationPCRs(verifier.attestor, quote.PCRs)
	if err != nil {
		return err
	}

	return nil
}

// Imports the Attestation Key into the signed blob store
func (verifier *Verification) importAndSignAK(ak tpm2.DerivedKey) error {
	_ak := AttestationKey{
		Name:           ak.Name,
		CreationHash:   ak.CreationHash,
		CreationData:   ak.CreationData,
		CreationTicket: ak.CreationTicket,
	}

	akNameBlobKey := verifier.akBlobKey()

	// Encode the cert to a blob
	akBuffer := &bytes.Buffer{}
	encoder := gob.NewEncoder(akBuffer)
	if err := encoder.Encode(_ak); err != nil {
		verifier.logger.Error(err)
		return err
	}

	// Create new signing key
	key, err := verifier.ca.NewSigningKey(
		verifier.domain, akNameBlobKey, verifier.caPassword)
	if err != nil {
		return err
	}

	// Create signing options that contain the AK PEM cert
	// and blob storage parameters
	sigOpts, err := ca.NewSigningOpts(crypto.SHA256, akBuffer.Bytes())
	sigOpts.BlobKey = &akNameBlobKey
	sigOpts.BlobData = akBuffer.Bytes()
	sigOpts.StoreSignature = true
	if _, err = key.Sign(verifier.tpm.RandomReader(), sigOpts.Digest(), sigOpts); err != nil {
		return err
	}
	return nil
}

// Sends the issued x509 platform certifiate to the Attestor
func (verifier *Verification) IssueCertificate(ak tpm2.DerivedKey, certDER []byte) error {

	verifier.logger.Info("Issuing Attestation Key x509 certificate")

	// If only a Root CA is configured, use that, otherwuse default
	// to the first Intermediate CA.
	idx := 0
	if len(verifier.app.CAConfig.Identity) > 1 {
		idx = 1
	}

	// Generate the certificate request
	certReq := ca.CertificateRequest{
		Valid: verifier.ca.DefaultValidityPeriod(), // days
		Subject: ca.Subject{
			CommonName:   verifier.attestor,
			Organization: verifier.app.CAConfig.Identity[idx].Subject.CommonName,
			Country:      verifier.app.CAConfig.Identity[idx].Subject.Country,
			Locality:     verifier.app.CAConfig.Identity[idx].Subject.Locality,
			Address:      verifier.app.CAConfig.Identity[idx].Subject.Address,
			PostalCode:   verifier.app.CAConfig.Identity[idx].Subject.PostalCode,
		},
		SANS: &ca.SubjectAlternativeNames{
			DNS: []string{
				verifier.attestor,
			},
			IPs: []string{},
			Email: []string{
				verifier.app.Hostmaster,
			},
		},
	}

	// Include localhost SANS names -
	// TODO: Refactor this to take an option provided by
	// the attestor during enrollment
	if verifier.app.CAConfig.IncludeLocalhostInSANS {
		ips, err := util.LocalAddresses()
		if err != nil {
			verifier.logger.Error(err)
			return err
		}
		certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost")
		certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost.localdomain")
		certReq.SANS.Email = append(certReq.SANS.Email, "root@localhost")
		certReq.SANS.IPs = append(certReq.SANS.IPs, ips...)
	}

	// Issue the cert
	certDER, err := verifier.ca.IssueCertificate(
		certReq, verifier.caPassword, verifier.akCertPassword)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	// Sign and import the AK into the signed blob store
	if err := verifier.importAndSignAK(ak); err != nil {
		return err
	}

	// Send the Attestor the cert
	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	certRequest := &pb.AcceptCertificateResquest{Certificate: certDER}
	_, err = verifier.secureAttestor.AcceptCertificate(ctx, certRequest)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	return nil
}

// Cleans up the session:
// 1. Removing the Verifier's CA bundle from memory
// 2. Delete verifier session from SecureServer
// 3. Close the TPM
func (verifier *Verification) Close() error {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	if _, err := verifier.secureAttestor.Close(ctx, &pb.Null{}); err != nil {
		verifier.logger.Error(err)
		return err
	}

	return nil
}

// Provisions a new device key using the steps outlined in Key Provisioning:
// https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html
func (verifier *Verification) Attest() error {

	defer verifier.Close()

	verifier.logger.Info("Requesting Endorsement Key (EK) certificate")
	ekCert, err := verifier.EKCert()
	if err != nil {
		return err
	}

	verifier.logger.Info("Requesting Endorsement Key (EK) / Attestation Key (AK) profile")
	ek, ak, err := verifier.AKProfile(ekCert)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Creating Credential Challenge")
	makeCredentialResponse, err := verifier.MakeCredential(ek, ak)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Requesting credential activation")
	activatedAK, err := verifier.ActivateCredential(makeCredentialResponse)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Requesting Quote (PCRs & Event Log)")
	quote, nonce, err := verifier.Quote(activatedAK)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	var certDER []byte
	verifier.logger.Info("Verifying Quote")
	if err := verifier.Verify(quote, nonce); err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Issuing Attestor x509 device certificate")
	if err := verifier.IssueCertificate(activatedAK, certDER); err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Remote Attestation complete: success")
	verifier.logger.Info("")

	return nil
}

func (verifier *Verification) debugAK(ak *pb.AKReply) {
	verifier.logger.Debugf("Endorsement Key PEM:\n%s", string(ak.GetEkPublicPEM()))
	verifier.logger.Debugf("Attestation Key PEM:\n%s", string(ak.GetAkPublicPEM()))
	verifier.logger.Debugf("Attestation Key Name: 0x%x", verifier.tpm.Encode(ak.GetAkName()))
}

func (verifier *Verification) akBlobKey() string {
	return fmt.Sprintf("tpm/%s/%s.bin", verifier.attestor, akBlobName)
}
