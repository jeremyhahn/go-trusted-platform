package attestor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/jeremyhahn/go-trusted-platform/pki/tpm2"
	"github.com/op/go-logging"

	pb "github.com/jeremyhahn/go-trusted-platform/attestation/proto"
)

var (
	ErrInvalidCACertificate  = errors.New("attestor: failed to add CA certificate to x509 certificate pool")
	ErrConnectionFailed      = errors.New("attestor: connection failed")
	ErrUnknownVerifier       = errors.New("attestor: unknown attestation verifier")
	ErrInvalidClientCertPool = errors.New("attestor: invalid verifier certificate pool")
	attestor                 Attestor
)

type Attestor interface {
	Run() error
	CA() ca.CertificateAuthority
	TPM() tpm2.TrustedPlatformModule2
	Logger() *logging.Logger
	ClientCertPool(cn string) (*x509.CertPool, error)
	AddVerifierCABundle(verifier string, bundle []byte) error
	RemoveVerifierCABundle(verifier string)
}

type Attest struct {
	logger               *logging.Logger
	config               config.Attestation
	domain               string
	ca                   ca.CertificateAuthority
	tpm                  tpm2.TrustedPlatformModule2
	srkAuth              []byte
	secureServer         *grpc.Server
	secureServerStopChan chan bool
	verifierCertPool     *x509.CertPool
	verifierCerts        map[string][]byte
	verifierCertPools    map[string]*x509.CertPool
	verifierCertsMutex   sync.RWMutex
	Attestor
}

func main() {
	app := app.NewApp().Init(nil)
	srkAuth := []byte(app.AttestationConfig.SRKAuth)
	if _, err := NewAttestor(app, srkAuth); err != nil {
		app.Logger.Fatal(err)
	}
	// Run forever
}

// Creates a new Attestor (client role)
func NewAttestor(app *app.App, srkAuth []byte) (Attestor, error) {

	var wg sync.WaitGroup
	secureServerStopChan := make(chan bool)

	verifierCerts := make(map[string][]byte, 0)
	verifierCertPools := make(map[string](*x509.CertPool), 0)

	attestor := &Attest{
		logger:               app.Logger,
		config:               app.AttestationConfig,
		ca:                   app.CA,
		tpm:                  app.TPM,
		domain:               app.Domain,
		srkAuth:              srkAuth,
		verifierCerts:        verifierCerts,
		verifierCertPools:    verifierCertPools,
		verifierCertsMutex:   sync.RWMutex{},
		secureServerStopChan: secureServerStopChan}

	insecureService := &InsecureServer{
		attestor: attestor,
		config:   app.AttestationConfig,
		logger:   app.Logger,
		ca:       app.CA}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := newInsecureGRPCServer(
			app.AttestationConfig,
			insecureService)
		if err != nil {
			app.Logger.Fatal(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		secureService := &SecureServer{
			attestor: attestor,
			config:   app.AttestationConfig,
			logger:   app.Logger,
			ca:       app.CA,
			tpm:      app.TPM,
			srkAuth:  srkAuth,
		}
		if err := attestor.newTLSGRPCServer(secureService); err != nil {
			app.Logger.Fatal(err)
		}
	}()

	wg.Wait()

	return attestor, nil
}

// Creates a new gRPC server TLS connection using Root CA trusted
// certificate pool. The returned connection must be closed after use.
func (attestor *Attest) newTLSGRPCServer(secureService *SecureServer) error {

	socket := fmt.Sprintf("localhost:%d", attestor.config.TLSPort)

	attestor.logger.Infof("Starting TLS gRPC services on port: %s", socket)

	rootCAs, err := attestor.ca.CABundleCertPool()
	if err != nil {
		attestor.logger.Error(err)
		return err
	}

	serverCert, err := attestor.ca.PEM(attestor.domain)
	if err != nil {
		return err
	}

	serverKey, err := attestor.ca.CertStore().PrivKeyPEM(attestor.domain)
	if err != nil {
		return err
	}

	serverKeyPair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		attestor.logger.Fatalf(
			"Failed to read Server Certificate files %s  %s: %v",
			serverCert,
			serverKey,
			err)
	}

	tlsTemplate := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{serverKeyPair},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Build mTLS config that contains the Attestor (our) Certificate Authority
	// bundle and a custom config builder for the  Verifier (client) CA server certs
	// that uses the verifierCertPools populated by the insecure gRPC server used
	// to exchange CA bundles in preparation for this mTLS connection.
	tlsConfig := tlsTemplate
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		// The Verifier (client) CA certificates are retrieved from
		// the verifierCertPools which are populated on the insecure
		// gRPC server when the Verifier sends their CA bundle to
		// prepare for a connection on the secure mTLS port.
		attestor.verifierCertsMutex.RLock()
		defer attestor.verifierCertsMutex.RUnlock()

		verifierIP := parseVerifierIP(info.Conn.RemoteAddr())
		pool, ok := attestor.verifierCertPools[verifierIP]
		if !ok {
			attestor.logger.Errorf(
				"attestor: client CA certifiates not found for verifier: %s", verifierIP)
			return tlsTemplate, nil
		}

		attestor.logger.Debugf("attestor: loading %s client CA certificates", verifierIP)

		clientTLS := tlsTemplate
		clientTLS.ClientAuth = tls.RequireAndVerifyClientCert
		clientTLS.ClientCAs = pool
		return clientTLS, nil
	}

	// Set up gRPC TLS listener
	creds := credentials.NewTLS(tlsConfig)
	listener, err := net.Listen("tcp", socket)
	if err != nil {
		attestor.logger.Fatalf("failed to listen: %v", err)
	}

	// statsHandler := &handler{
	// 	logger:   attestor.logger,
	// 	attestor: attestor,
	// }
	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts, grpc.Creds(creds), grpc.UnaryInterceptor(authUnaryInterceptor))
	// sopts = append(sopts, grpc.StatsHandler(statsHandler))
	attestor.secureServer = grpc.NewServer(sopts...)

	// verifier.RegisterVerifierServer(s, &server{})
	// healthpb.RegisterHealthServer(s, &hserver{
	// 	statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	// })

	pb.RegisterTLSAttestorServer(attestor.secureServer, secureService)

	go func() {
		// Run forever
		if err := attestor.secureServer.Serve(listener); err != nil {
			attestor.logger.Fatal(err)
		}
	}()

	// Block until a shutdown signal is received
	<-attestor.secureServerStopChan
	attestor.secureServer.GracefulStop()
	attestor.secureServer = nil
	return nil
}

// Starts a new insecure web service, used to provide the Verifier with
// the CA certificate(s) needed to verify the client-side TLS connection
func newInsecureGRPCServer(
	config config.Attestation,
	insecureService *InsecureServer) (*grpc.Server, error) {

	socket := fmt.Sprintf("localhost:%d", config.InsecurePort)

	insecureService.logger.Infof(
		"Starting insecure gRPC service on port %d", config.InsecurePort)

	lis, err := net.Listen("tcp", socket)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterInsecureAttestorServer(s, insecureService)
	insecureService.logger.Debugf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	return s, nil
}

// gRPC middleware which validates the OIDC token sent in every request.
// This check verifies the id token is valid and then extracts the google specific annotations.
func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Printf(">> authUnaryInterceptor inbound request\n")
	// optionally check for metadata or custom headers
	// md, ok := metadata.FromIncomingContext(ctx)
	// if !ok {
	// 	return nil, status.Errorf(codes.Unauthenticated, "could not recall RPC metadata")
	// }
	// newCtx := context.WithValue(ctx, contextKey("someKey"), "someValue")
	// return handler(newCtx, req)

	return handler(ctx, req)
	//return nil, status.Errorf(codes.Unauthenticated, "Authorization header not provided")
}

// Adds a verifier / service provider's CA bundle to the trusted
// client certificate pool.
func (attestor *Attest) AddVerifierCABundle(verifier string, bundle []byte) error {

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return ErrInvalidCACertificate
	}

	attestor.verifierCertsMutex.Lock()
	defer attestor.verifierCertsMutex.Unlock()

	if _, ok := attestor.verifierCertPools[verifier]; ok {
		return nil
	}

	attestor.verifierCertPools[verifier] = pool
	return nil
}

// Removes a verifier / service provider's CA bundle from
// the trusted client certificate pool.
func (attestor *Attest) RemoveVerifierCABundle(verifier string) {

	attestor.logger.Info("Discarding Verifier's CA bundle")

	attestor.verifierCertsMutex.Lock()
	defer attestor.verifierCertsMutex.Unlock()

	//delete(a.verifierCerts, verifier)
	delete(attestor.verifierCertPools, verifier)
}

// // Returns the Certificate Authority
// func (a *Attest) CA() ca.CertificateAuthority {
// 	return a.ca
// }

// // Returns the Trusted Platform module
// func (a *Attest) TPM() tpm2.TrustedPlatformModule2 {
// 	return a.tpm
// }

// // Get the Intermediate CA certificate
// func (s *service) CACert() []byte {
// 	return attestor.ca.CACertificate().Raw
// }

// // Get the local TPM Endorsement key
// func (s *service) EKCert() (*x509.Certificate, error) {
// 	return attestor.tpm.EKCert(attestor.srkAuth)
// }

// // Get the local TPM Endorsement key
// func (s *service) GetEK() error {
// 	_, _, _, err := attestor.tpm.RSAEK()
// 	if err != nil {
// 		return nil
// 	}
// 	return nil
// }
