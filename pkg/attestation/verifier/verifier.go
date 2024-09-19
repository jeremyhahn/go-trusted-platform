package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/proto"

	libtpm2 "github.com/google/go-tpm/tpm2"
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
	ErrUnexpectedEventLogState = errors.New("verifier: unexpected event log state")
	ErrUnexpectedPCRState      = errors.New("verifier: unexpected PCR state")

	// CLI options when invoked directly - flag names must be unique and
	// not conflict with those used in Cobra cmd package
	attestorHostname = flag.String("attestor", "localhost", "The Attestor hostname / FQDN / IP")
	caPassword       = flag.String("platform-password", "", "The Certificate Authority private key password")
	serverPassword   = flag.String("tls-password", "", "The gRPC server TLS private key password")
)

type AttestationKey struct {
	Name           []byte
	CreationHash   []byte
	CreationData   []byte
	CreationTicket []byte
}

type makeCredentialResponse struct {
	akAttrs           *keystore.KeyAttributes
	secret            []byte
	activationRequest *pb.ActivateCredentialRequest
}

type Verifier interface {
	Attest() error
	EKCert() (*x509.Certificate, error)
	AKProfile(ekCert *x509.Certificate) (*keystore.KeyAttributes, tpm2.AKProfile, error)
	MakeCredential(akName libtpm2.TPM2BName) (makeCredentialResponse, error)
	ActivateCredential(makeCredentialResponse makeCredentialResponse) error
	IssueCertificate(keyAttrs *keystore.KeyAttributes, akPubBytes []byte) error
	Quote(akAttrs *keystore.KeyAttributes, akPubBytes []byte) (tpm2.Quote, []byte, error)
	VerifyQuote(
		akAttrs *keystore.KeyAttributes,
		akProfile tpm2.AKProfile,
		quote tpm2.Quote,
		nonce []byte) error
	Close() error
}

type Verification struct {
	app            *app.App
	logger         *logging.Logger
	config         config.Attestation
	domain         string
	ca             ca.CertificateAuthority
	tpm            tpm2.TrustedPlatformModule
	grpcConn       *grpc.ClientConn
	secureAttestor pb.TLSAttestorClient
	clientCertPool *x509.CertPool
	attestorCN     string
	Verifier
}

func main() {
	flag.Parse()
	app, err := app.NewApp().Init(nil)
	if err != nil {
		app.Logger.FatalError(err)
	}
	verifier, err := NewVerifier(app, *attestorHostname)
	if err != nil {
		app.Logger.FatalError(err)
	}
	if err := verifier.Attest(); err != nil {
		app.Logger.FatalError(err)
	}
}

// Creates a new Remote Attestation Verifier
func NewVerifier(app *app.App, attestorCN string) (Verifier, error) {

	clientCertPool := x509.NewCertPool()
	secureConn, err := newTLSGRPCClient(
		app.Logger,
		app.AttestationConfig,
		app.ServerKeyAttributes,
		attestorCN,
		app.CA)
	if err != nil {
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
		attestorCN:     attestorCN,
	}, nil
}

// Creates a new insecure GRPC client
func newInsecureGRPCClient(config config.Attestation, attestorCN string) (*grpc.ClientConn, error) {
	socket := fmt.Sprintf("%s:%d", attestorCN, config.InsecurePort)
	return grpc.NewClient(
		socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// Creates a new mTLS encrypted GRPC client
func newTLSGRPCClient(
	logger *logging.Logger,
	config config.Attestation,
	serverKeyAttrs *keystore.KeyAttributes,
	attestorCN string,
	ca ca.CertificateAuthority) (*grpc.ClientConn, error) {

	socket := fmt.Sprintf("%s:%d", attestorCN, config.TLSPort)

	logger.Debugf("verifier: gRPC client socket: %s", socket)

	if config.InsecureSkipVerify {
		logger.Errorf("verifier: InsecureSkipVerify is enabled, allowing man-in-the-middle attacks!")
	}

	rootCAs := x509.NewCertPool()

	// Start concatenating a list of DER encoded certs
	if config.AllowAttestorSelfCA {
		// Connect to the Attestor on insecure gRPC port and
		// exchange CA bundles to prepare an mTLS connection
		bundle, err := getAttestorCABundle(
			logger, config, ca, attestorCN, serverKeyAttrs)
		if err != nil {
			return nil, err
		}
		certs, err := ca.ParseBundle(bundle)
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			if err := ca.ImportCertificate(cert); err != nil {
				return nil, err
			}
			pem, err := certstore.EncodePEM(cert.Raw)
			if err != nil {
				return nil, err
			}
			if !rootCAs.AppendCertsFromPEM(pem) {
				return nil, ErrInvalidCACertificate
			}
		}
	} else {
		serverCert, err := ca.Certificate(serverKeyAttrs)
		if err != nil {
			return nil, err
		}
		rootCAs, err = ca.TrustedRootCertPool(serverCert)
	}

	tlsCert, err := ca.TLSCertificate(serverKeyAttrs)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{tlsCert},
	}

	ce := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(ce))
	if err != nil {
		logger.Errorf("%s: %s", ErrConnectionFailed, err)
		return nil, ErrConnectionFailed
	}

	return conn, nil
}

// Retrieves the CA certificate(s) used to sign the Attestor's
// gRPC server TLS certificate. This is used to automatically
// configure the verifiers TLS client so the certificate can
// be verified.
func getAttestorCABundle(
	logger *logging.Logger,
	config config.Attestation,
	ca ca.CertificateAuthority,
	attestorCN string,
	serverKeyAttrs *keystore.KeyAttributes) ([]byte, error) {

	// Get the CA root and intermediate bundle
	bundle, err := ca.CABundle(&serverKeyAttrs.StoreType, &serverKeyAttrs.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	conn, err := newInsecureGRPCClient(config, attestorCN)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	insecureAttestor := pb.NewInsecureAttestorClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Exchange CA bundle w/ attestor
	response, err := insecureAttestor.GetCABundle(
		ctx,
		&pb.CABundleRequest{Bundle: bundle})
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Debugf("verifier: attestor CA bundle:\n%s", response.Bundle)
	return response.Bundle, nil
}

// Get the Attestor's Endorsement Key (EK) and import into the CA
func (verifier *Verification) EKCert() (*x509.Certificate, error) {

	verifier.logger.Info("Requesting Endorsement Key (EK) certificate")

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.GetEKCert(ctx, &pb.Null{})
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(response.Certificate)
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}

	err = verifier.ca.ImportCertificate(cert)
	if err != nil {
		return nil, ErrImportEKCert
	}

	verifier.logger.Info(
		"Endorsement Key (EK) Certificate successfully imported")

	return cert, nil
}

// Get the EK pub, AK pub, AK name and signature algorithm and
// create key attributes for the AK.
func (verifier *Verification) AKProfile(
	ekCert *x509.Certificate) (*keystore.KeyAttributes, tpm2.AKProfile, error) {

	verifier.logger.Info("Requesting Endorsement Key (EK) & Attestation Key (AK) profile")

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	akProfilePB, err := verifier.secureAttestor.GetAK(ctx, &pb.Null{})
	if err != nil {
		verifier.logger.Error(err)
		return nil, tpm2.AKProfile{}, err
	}

	_, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		verifier.logger.Errorf("verifier: EK certificate")
		return nil, tpm2.AKProfile{}, err
	}

	verifier.logger.Infof(
		"Attestation Key (AK) Name: 0x%x",
		tpm2.Encode(akProfilePB.AKName))

	if verifier.app.DebugFlag {
		akPEM, err := certstore.EncodePEM(akProfilePB.AKPub)
		if err != nil {
			return nil, tpm2.AKProfile{}, err
		}
		ekPEM, err := certstore.EncodePEM(akProfilePB.EKPub)
		if err != nil {
			return nil, tpm2.AKProfile{}, err
		}
		verifier.logger.Debugf(
			"EK Certificate (PEM)\n%s",
			ekPEM)
		verifier.logger.Debugf(
			"AK Certificate (PEM)\n%s",
			akPEM)
	}

	akName := libtpm2.TPM2BName{Buffer: akProfilePB.AKName}

	akProfile := tpm2.AKProfile{
		AKName:             akName,
		AKPub:              akProfilePB.AKPub,
		EKPub:              akProfilePB.EKPub,
		SignatureAlgorithm: x509.SignatureAlgorithm(akProfilePB.SignatureAlgorithm),
	}

	akAttrs, err := verifier.akAttributesFromProfile(akProfile)
	if err != nil {
		return nil, tpm2.AKProfile{}, err
	}

	keystore.DebugKeyAttributes(verifier.logger, akAttrs)

	return akAttrs, akProfile, nil
}

// Call TPM2_MakeCredential to generate the encrypted secret and privacy
// data to send to the Attestor for activation.
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md
func (verifier *Verification) MakeCredential(
	akName libtpm2.TPM2BName) (makeCredentialResponse, error) {

	verifier.logger.Info("Making Credential challenge (TPM2_MakeCredential)")

	credentialBlob, encryptedSecret, secret,
		err := verifier.tpm.MakeCredential(akName, nil)
	if err != nil {
		verifier.logger.Error(err)
		return makeCredentialResponse{}, err
	}

	verifier.logger.Debugf(
		"verifier: TPM2_MakeCredential Attestation Key Name: %s",
		tpm2.Encode(akName.Buffer))

	// Print some helpful information if secret debugging is enabled
	if verifier.app.DebugSecretsFlag {

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential credential blob (raw): %s",
			credentialBlob)

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential credential blob (hex): 0x%x",
			tpm2.Encode(credentialBlob))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential secret (raw): %s",
			tpm2.Encode(secret))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential secret (hex): 0x%x",
			tpm2.Encode(secret))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential encrypted secret (raw): %s",
			tpm2.Encode(encryptedSecret))

		verifier.logger.Debugf(
			"verifier: TPM2_MakeCredential encrypted secret (hex): 0x%x",
			tpm2.Encode(encryptedSecret))
	}

	return makeCredentialResponse{
		secret: secret,
		activationRequest: &pb.ActivateCredentialRequest{
			CredentialBlob:  credentialBlob,
			EncryptedSecret: encryptedSecret,
		}}, nil
}

// Enables the association of a credential with an object in a way that ensures
// that the TPM has validated the parameters of the credentialed object. In an
// attestation scheme , this guarantees the registrar that the attestation key
// belongs to the TPM with a qualified parent key in the TPM.
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_activatecredential.1.md
func (verifier *Verification) ActivateCredential(
	makeCredentialResponse makeCredentialResponse) error {

	verifier.logger.Info("Activating Credential (TPM2_ActivateCredential)")

	// Send the ciphertext to the Attestor to decrypt and return to prove
	// possession of the private keys stored in an authentic TPM with an
	// EK certifiate issued by a manufacturer that is trusted by our CA.
	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.ActivateCredential(
		ctx, makeCredentialResponse.activationRequest)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	// Compare the Attestor and Verifier secret
	if bytes.Compare(response.Secret, makeCredentialResponse.secret) != 0 {
		verifier.logger.Errorf("verifier: attestor failed to activate credential")
		return ErrInvalidCredential
	}

	verifier.logger.Info("Credential activation successful")

	return nil
}

// Requests a TPM PCR quote from the Attestor that includes current TPM
// PCR values, EventLog, and Secure Boot state. If Open Enrollment is enabled,
// the state is signed and saved to the CA's signed blob storage, an Attestation
// Certificate is created, imported to the certificate store, and provided to
// the Attestor.
func (verifier *Verification) Quote(
	akAttrs *keystore.KeyAttributes,
	akPub []byte) (tpm2.Quote, []byte, error) {

	verifier.logger.Info("Requesting Quote (PCRs & Event Log)")

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

	quote, err := tpm2.DecodeQuote(response.Quote)
	if err != nil {
		verifier.logger.Error(err)
		return tpm2.Quote{}, nil, err
	}

	verifier.logger.Info("Quote received")

	if verifier.config.AllowOpenEnrollment {

		verifier.logger.Info("Beginning Open Enrollment")

		// Sign and store the quote using the CA's private key
		err = verifier.ca.ImportAttestationQuote(akAttrs, response.Quote, nil)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Sign and store the quote using the CA's private key
		err = verifier.ca.ImportAttestationEventLog(akAttrs, quote.EventLog, nil)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Sign and store the PCR state using the CA's private key
		err = verifier.ca.ImportAttestationPCRs(akAttrs, quote.PCRs, nil)
		if err != nil {
			verifier.logger.Error(err)
			return tpm2.Quote{}, nil, err
		}

		// Issue the AK certificate -- not the restricted key used to sign the quote!
		if err := verifier.IssueCertificate(akAttrs, akPub); err != nil {
			return tpm2.Quote{}, nil, err
		}
	}

	return quote, nonce, nil
}

// Generate and send new x509 platform certifiate to the Attestor
func (verifier *Verification) IssueCertificate(
	akAttrs *keystore.KeyAttributes, akPubBytes []byte) error {

	verifier.logger.Info("Issuing Attestation Key x509 certificate")

	// If only a Root CA is configured, use that, otherwise default
	// to the first Intermediate CA.
	idx := 0
	if len(verifier.app.CAConfig.Identity) > 1 {
		idx = 1
	}

	// Generate the certificate request
	certReq := ca.CertificateRequest{}
	certReq.KeyAttributes = akAttrs
	certReq.Subject = ca.Subject{
		CommonName:   verifier.attestorCN,
		Organization: verifier.app.CAConfig.Identity[idx].Subject.CommonName,
		Country:      verifier.app.CAConfig.Identity[idx].Subject.Country,
		Locality:     verifier.app.CAConfig.Identity[idx].Subject.Locality,
		Address:      verifier.app.CAConfig.Identity[idx].Subject.Address,
		PostalCode:   verifier.app.CAConfig.Identity[idx].Subject.PostalCode,
	}
	certReq.SANS = &ca.SubjectAlternativeNames{
		DNS: []string{
			verifier.attestorCN,
		},
		IPs: []string{},
		Email: []string{
			verifier.app.Hostmaster,
		},
	}

	// Include localhost SANS names if configured to do so
	if verifier.app.CAConfig.IncludeLocalhostSANS {
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

	// Parse the public key bytes to crypto.PublicKey
	akPub, err := x509.ParsePKIXPublicKey(akPubBytes)
	if err != nil {
		return err
	}

	// Issue the new AK certificate
	cert, err := verifier.ca.IssueAKCertificate(certReq, akPub)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	// Set public bytes for importAndSignAK
	akAttrs.TPMAttributes = &keystore.TPMAttributes{
		PublicKeyBytes: akPubBytes,
	}

	// Sign and import the AK into the signed blob store
	if err := verifier.importAndSignAK(akAttrs); err != nil {
		return err
	}

	// Send the Attestor the cert
	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	certRequest := &pb.AcceptCertificateResquest{Certificate: cert.Raw}
	_, err = verifier.secureAttestor.AcceptCertificate(ctx, certRequest)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	return nil
}

// Sign the Attestation Key using the Certificate Authority private key. The
// signed public key is saved to blob storage
func (verifier *Verification) importAndSignAK(akAttrs *keystore.KeyAttributes) error {

	// Sign the AK DER cert bytes with the CA's private key
	// and save it to blob storage with digest and checksum
	caKeyAttrs, err := verifier.ca.CAKeyAttributes(
		akAttrs.StoreType, akAttrs.KeyAlgorithm)
	if err != nil {
		verifier.logger.Error(err)
		return nil
	}

	sigOpts := keystore.NewSignerOpts(
		caKeyAttrs, akAttrs.TPMAttributes.PublicKeyBytes)

	digest, err := sigOpts.Digest()
	if err != nil {
		return err
	}

	sigOpts.BlobCN = verifier.akBlobKey()
	sigOpts.BlobData = akAttrs.TPMAttributes.PublicKeyBytes
	if _, err := verifier.ca.Sign(
		verifier.tpm, digest, sigOpts); err != nil {
		return err
	}
	return nil
}

// Removing the Verifier's CA bundle from memory
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

	ekCert, err := verifier.EKCert()
	if err != nil {
		return err
	}

	akAttrs, akProfile, err := verifier.AKProfile(ekCert)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	makeCredentialResponse, err := verifier.MakeCredential(akProfile.AKName)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	err = verifier.ActivateCredential(makeCredentialResponse)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	quote, nonce, err := verifier.Quote(akAttrs, akProfile.AKPub)
	if err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Verifying Quote")
	if err := verifier.ca.VerifyQuote(akAttrs, quote, nonce); err != nil {
		verifier.logger.Error(err)
		return err
	}

	verifier.logger.Info("Remote Attestation complete: success")
	verifier.logger.Info("")

	return nil
}

func (verifier *Verification) akBlobKey() []byte {
	return []byte(fmt.Sprintf("tpm/%s/%s%s",
		verifier.attestorCN, akBlobName, certstore.FSEXT_DER))
}

// This function returns the AK attributes, hard-coding the
// key and hash function algorithms. This is because the
// tpm2-software.github.io flow doessn't provide any structures
// or mechanisms to obtain them.
//
// The Trusted Platform enrollment protocol will use ACME with the
// device-attest extension.
// https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03
func (verifier *Verification) akAttributesFromProfile(
	akProfile tpm2.AKProfile) (*keystore.KeyAttributes, error) {

	keyAttrs, err := keystore.Template(x509.RSA)
	if err != nil {
		return nil, err
	}
	keyAttrs.CN = verifier.attestorCN
	keyAttrs.Debug = verifier.app.DebugFlag
	keyAttrs.KeyType = keystore.KEY_TYPE_ATTESTATION
	keyAttrs.Hash = crypto.SHA256
	keyAttrs.StoreType = keystore.STORE_TPM2

	return keyAttrs, nil
}
