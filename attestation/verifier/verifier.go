package verifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/jeremyhahn/go-trusted-platform/pki/tpm2"
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
)

type Verifier interface {
	Verify() error
	EKCert() ([]byte, error)
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
	attestor := "localhost"
	app := app.NewApp().Init(nil)
	verifier, err := NewVerifier(app, attestor)
	if err != nil {
		app.Logger.Fatal(err)
	}
	if err := verifier.Verify(); err != nil {
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
		//ServerName:         config.Service,
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

	logger.Debugf("verifier: GetAttestorCABundle: %s", response.Bundle)
	return response.Bundle, nil
}

// Initiates Full Remote Attestation with an Attestor
func (verifier *Verification) Verify() error {

	defer verifier.Close()

	verifier.logger.Info("Requesting Endorsement Key (EK) certificate")
	ekDER, err := verifier.EKCert()
	if err != nil {
		verifier.logger.Error(err)
		return err
	}
	verifier.logger.Info(string(ekDER))

	// Import the Attestor EK cert into the Verifier CA
	_, err = verifier.tpm.ImportDER(verifier.attestor, verifier.attestor, ekDER, true)
	if err != nil {
		return ErrImportEKCert
	}
	return nil
}

// Get the Attestor's Endorsement Key (EK)
func (verifier *Verification) EKCert() ([]byte, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	response, err := verifier.secureAttestor.GetEKCert(ctx, &pb.Null{})
	if err != nil {
		verifier.logger.Error(err)
		return nil, err
	}
	return response.Certificate, nil
}

// Cleans up the session:
// 1. Removing the Verifier's CA bundle from memory
func (verifier *Verification) Close() error {

	ctx, cancel := context.WithTimeout(context.Background(), TLS_DEADLINE)
	defer cancel()

	if _, err := verifier.secureAttestor.Close(ctx, &pb.Null{}); err != nil {
		verifier.logger.Error(err)
		return err
	}
	return nil
}
