package verifier

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
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
)

var (
	ErrInvalidCACertificate = errors.New("verifier: failed to add CA certificate to x509 certificate pool")
	ErrConnectionFailed     = errors.New("verifier: connection failed")
	ErrImportEKCert         = errors.New("verifier: failed to import Endorsement Key (EK) certificate")
	ErrCertKeyMismatch      = errors.New("verifier: certificate / attestation public key modulus mismatch")
	ErrInvalidPublicKey     = errors.New("verifier: invalid public key")
	ErrInvalidCredential    = errors.New("verifier: attestor failed credential challenge")

	// CLI option when invoked directly
	attestorHostname = flag.String("attestor", "localhost", "The Attestor hostname / FQDN / IP")
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
	Provision() error
	EKCert() (*x509.Certificate, error)
	AKProfile(ekCert *x509.Certificate) (tpm2.Key, tpm2.DerivedKey, error)
	MakeCredential(ek tpm2.Key, ak tpm2.DerivedKey) (makeCredentialResponse, error)
	ActivateCredential(makeCredentialResponse makeCredentialResponse) ([]byte, error)
	IssueCertificate(certDER []byte) error
	Quote(ak tpm2.DerivedKey) (*pb.QuoteResponse, error)
	Close() error
}

type Verification struct {
	app            *app.App
	logger         *logging.Logger
	config         config.Attestation
	domain         string
	ca             ca.CertificateAuthority
	tpm            tpm2.TrustedPlatformModule2
	srkAuth        []byte
	grpcConn       *grpc.ClientConn
	secureAttestor pb.TLSAttestorClient
	clientCertPool *x509.CertPool
	attestor       string
	Verifier
}

func main() {
	flag.Parse()
	app := app.NewApp().Init(nil)
	verifier, err := NewVerifier(app, *attestorHostname)
	if err != nil {
		app.Logger.Fatal(err)
	}
	if err := verifier.Provision(); err != nil {
		app.Logger.Fatal(err)
	}
}

// Creates a new Remote Attestation Verifier
func NewVerifier(app *app.App, attestor string) (Verifier, error) {

	clientCertPool := x509.NewCertPool()
	secureConn, err := newTLSGRPCClient(
		app.Logger,
		app.AttestationConfig,
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

	clientCert, err := ca.X509KeyPair(domain)
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

	// // Decode EK RSA public key
	// ekPubRSA, err := verifier.ca.DecodeRSAPubKeyPEM(response.EkPublicPEM)
	// if err != nil {
	// 	verifier.logger.Error(err)
	// 	return tpm2.Key{}, tpm2.DerivedKey{}, err
	// }

	// // Decode AK RSA public key
	// akPubRSA, err := verifier.ca.DecodeRSAPubKeyPEM(response.AkPublicPEM)
	// if err != nil {
	// 	verifier.logger.Error(err)
	// 	return tpm2.Key{}, tpm2.DerivedKey{}, err
	// }

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
// proves they are in posession of the both the EK and AK by loading both keys into
// their TPM and using the EK to decrypt the secret.
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_activatecredential.1.md
func (verifier *Verification) ActivateCredential(
	makeCredentialResponse makeCredentialResponse) ([]byte, error) {

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
		return nil, err
	}

	// Compare the Attestor and Verifier secret
	if bytes.Compare(response.Secret, makeCredentialResponse.secret) != 0 {
		verifier.logger.Error("verifier: attestor failed to activate credential")
		return nil, ErrInvalidCredential
	}

	verifier.logger.Error("verifier: Credential activation successful")

	var certDER []byte
	if verifier.config.AllowOpenEnrollment {
		certDER, err = verifier.enrollAttestor(makeCredentialResponse.ak)
		if err != nil {
			verifier.logger.Error(err)
			return nil, err
		}
	} else {
		// look up the policy and perform Quote / Verify
	}

	return certDER, nil
}

// Requests a TPM PCR quote from the Attestor
func (verifier *Verification) Quote(ak tpm2.DerivedKey) (*pb.QuoteResponse, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	quoteRequest := &pb.QuoteRequest{
		Nonce: []byte("test"),
		//Pcrs: []int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, },
		Pcrs: verifier.app.AttestationConfig.QuotePCRs,
	}

	quote, err := verifier.secureAttestor.Quote(ctx, quoteRequest)
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}

	return quote, nil
}

// Performs enrollment by requesting a Quote from the Attestor that includes current TPM
// PCR values, EventLog, and Secure Boot state, signing and storing them in the CA's signed
// blob storage, creating an attestation policy, and issuing and disseminating an x509
// Attestation Key certificate.
func (verifier *Verification) enrollAttestor(ak tpm2.DerivedKey) ([]byte, error) {

	verifier.logger.Info("Enrolling Attestor")

	quote, err := verifier.Quote(ak)
	if err != nil {
		return nil, err
	}

	verifier.logger.Debugf("%+v", quote)

	// Generate a platform x509 certifiate request for the Attestor
	certReq := ca.CertificateRequest{
		Valid: verifier.ca.DefaultValidityPeriod(), // days
		Subject: ca.Subject{
			CommonName:   verifier.attestor,
			Organization: verifier.app.WebService.Certificate.Subject.Organization,
			Country:      verifier.app.WebService.Certificate.Subject.Country,
			Locality:     verifier.app.WebService.Certificate.Subject.Locality,
			Address:      verifier.app.WebService.Certificate.Subject.Address,
			PostalCode:   verifier.app.WebService.Certificate.Subject.PostalCode,
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

	if verifier.app.CAConfig.IncludeLocalhostInSANS {
		ips, err := util.LocalAddresses()
		if err != nil {
			verifier.logger.Error(err)
			return nil, err
		}
		certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost")
		certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost.localdomain")
		certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost.localdomain")
		certReq.SANS.Email = append(certReq.SANS.Email, "root@localhost")
		certReq.SANS.IPs = append(certReq.SANS.IPs, ips...)
	}

	// Issue an x509 platform certificate to the Attestor
	certDER, err := verifier.ca.IssueCertificate(certReq, verifier.tpm.RandomReader())
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}

	// Sign and import the AK into the signed blob store
	if err := verifier.importAndSignAK(ak); err != nil {
		return nil, err
	}

	return certDER, nil
}

// Imports the Attestation Key into the signed blob store
func (verifier *Verification) importAndSignAK(ak tpm2.DerivedKey) error {
	_ak := AttestationKey{
		Name:           ak.Name,
		CreationHash:   ak.CreationHash,
		CreationData:   ak.CreationData,
		CreationTicket: ak.CreationTicket,
	}
	akNameBlobKey := fmt.Sprintf("tpm/%s/attestation-key.bin", verifier.attestor)
	akBuffer := &bytes.Buffer{}
	encoder := gob.NewEncoder(akBuffer)
	if err := encoder.Encode(_ak); err != nil {
		verifier.logger.Error(err)
		return err
	}
	err := verifier.ca.PersistentSign(akNameBlobKey, akBuffer.Bytes(), true)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}
	return nil
}

// Sends the issued x509 platform certifiate to the Attestor
func (verifier *Verification) IssueCertificate(certDER []byte) error {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	certRequest := &pb.AcceptCertificateResquest{Certificate: certDER}
	_, err := verifier.secureAttestor.AcceptCertificate(ctx, certRequest)
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
func (verifier *Verification) Provision() error {

	defer verifier.Close()

	verifier.logger.Info("Requesting Endorsement Key (EK) certificate")
	ekCert, err := verifier.EKCert()
	if err != nil {
		verifier.logger.Error(err)
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
	certDER, err := verifier.ActivateCredential(makeCredentialResponse)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Issuing Attestor x509 device certificate")
	if err := verifier.IssueCertificate(certDER); err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Remote Attestation Key Provisioning complete")
	verifier.logger.Info("")

	return nil
}

func (verifier *Verification) debugAK(ak *pb.AKReply) {
	verifier.logger.Debugf("Endorsement Key PEM:\n%s", string(ak.GetEkPublicPEM()))
	verifier.logger.Debugf("Attestation Key PEM:\n%s", string(ak.GetAkPublicPEM()))
	verifier.logger.Debugf("Attestation Key Name: 0x%x", verifier.tpm.Encode(ak.GetAkName()))
}
