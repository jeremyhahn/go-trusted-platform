package attestor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/op/go-logging"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/proto"
)

var (
	ErrInvalidCACertificate  = errors.New("attestor: failed to add CA certificate to x509 certificate pool")
	ErrConnectionFailed      = errors.New("attestor: connection failed")
	ErrUnknownVerifier       = errors.New("attestor: unknown attestation verifier")
	ErrInvalidClientCertPool = errors.New("attestor: invalid verifier certificate pool")

	fListenAddress = flag.String("listen", "", "The IP address or hostname to listen on for incoming requests")
)

type Attestor interface {
	Run() error
	AddVerifierCABundle(verifier string, bundle []byte) error
	RemoveVerifierCABundle(verifier string)
	KeyAttributes() *keystore.KeyAttributes
}

type Attest struct {
	ca                   ca.CertificateAuthority
	config               config.Attestation
	domain               string
	debug                bool
	debugSecrets         bool
	logger               *logging.Logger
	keyAttrs             *keystore.KeyAttributes
	secureGRPCServer     *grpc.Server
	secureServerStopChan chan bool
	tlsAlgorithm         x509.PublicKeyAlgorithm
	tlsCommonName        string
	verifierCertPool     *x509.CertPool
	verifierCertPools    map[string]*x509.CertPool
	verifierCertsMutex   sync.RWMutex
	Attestor
}

// Entry-point when invoked directly
func main() {

	initParams := app.AppInitParams{}
	initParams.ListenAddress = *fListenAddress

	app := app.NewApp().Init(&initParams)

	if _, err := NewAttestor(app); err != nil {
		app.Logger.Fatal(err)
	}
	// Run forever
}

// Creates a new Attestor (client role)
func NewAttestor(app *app.App) (Attestor, error) {

	var wg sync.WaitGroup
	secureServerStopChan := make(chan bool)
	verifierCertPools := make(map[string](*x509.CertPool), 0)

	attestor := &Attest{
		logger:               app.Logger,
		config:               app.AttestationConfig,
		ca:                   app.CA,
		domain:               app.Domain,
		debug:                app.DebugFlag,
		debugSecrets:         app.DebugSecretsFlag,
		keyAttrs:             app.ServerKeyAttributes,
		verifierCertPools:    verifierCertPools,
		verifierCertsMutex:   sync.RWMutex{},
		secureServerStopChan: secureServerStopChan,
		tlsAlgorithm:         app.ServerKeyAttributes.KeyAlgorithm,
		tlsCommonName:        app.WebService.Certificate.Subject.CommonName}

	insecureService := &InsecureAttestor{
		attestor: attestor,
		config:   app.AttestationConfig,
		logger:   app.Logger,
		ca:       app.CA}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := newInsecureGRPCServer(
			app.AttestationConfig,
			insecureService,
			app.ListenAddress)
		if err != nil {
			app.Logger.Fatal(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		secureService := NewSecureAttestor(attestor, app)
		if err := attestor.newTLSGRPCServer(
			app.ServerKeyAttributes,
			secureService,
			app.ListenAddress); err != nil {
			app.Logger.Fatal(err)
		}
	}()

	wg.Wait()

	return attestor, nil
}

// Creates a new gRPC server TLS connection using Root CA trusted
// certificate pool. The returned connection must be closed after use.
func (attestor *Attest) newTLSGRPCServer(
	keyAttrs *keystore.KeyAttributes,
	secureService *SecureAttestor,
	listenAddress string) error {

	socket := fmt.Sprintf("%s:%d", listenAddress, attestor.config.TLSPort)

	// Get a TLS config from the CA
	tlsConfig, err := attestor.ca.TLSConfig(keyAttrs)
	if err != nil {
		attestor.logger.Error(err)
		return err
	}

	// Build mTLS config that contains the Attestor (our) Certificate Authority
	// bundle and a custom config builder for the  Verifier (client) CA server certs
	// that uses the verifierCertPools populated by the insecure gRPC server used
	// to exchange CA bundles in preparation for this mTLS connection.
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
			return tlsConfig, nil
		}

		attestor.logger.Debugf("attestor: loading %s client CA certificates", verifierIP)

		clientTLS := tlsConfig
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

	statsHandler := &handler{
		logger:        attestor.logger,
		attestor:      attestor,
		secureService: secureService,
	}
	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts, grpc.Creds(creds), grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts, grpc.StatsHandler(statsHandler))
	attestor.secureGRPCServer = grpc.NewServer(sopts...)

	// verifier.RegisterVerifierServer(s, &server{})
	// healthpb.RegisterHealthServer(s, &hserver{
	// 	statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	// })

	pb.RegisterTLSAttestorServer(attestor.secureGRPCServer, secureService)

	attestor.logger.Infof("TLS gRPC service listening on: %s", socket)

	go func() {
		// Run forever
		if err := attestor.secureGRPCServer.Serve(listener); err != nil {
			attestor.logger.Fatal(err)
		}
	}()

	// Block until a shutdown signal is received
	<-attestor.secureServerStopChan
	attestor.secureGRPCServer.GracefulStop()
	attestor.secureGRPCServer = nil
	return nil
}

// Starts a new insecure web service, used to provide the Verifier with
// the CA certificate(s) needed to verify the client-side TLS connection
func newInsecureGRPCServer(
	config config.Attestation,
	insecureService *InsecureAttestor,
	listenAddress string) (*grpc.Server, error) {

	socket := fmt.Sprintf("%s:%d", listenAddress, config.InsecurePort)

	insecureService.logger.Infof(
		"Insecure gRPC service listening on %s", socket)

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
// the in-memory trusted client certificate pool.
func (attestor *Attest) RemoveVerifierCABundle(verifier string) {

	attestor.logger.Info("Discarding Verifier's CA bundle")

	attestor.verifierCertsMutex.Lock()
	defer attestor.verifierCertsMutex.Unlock()

	delete(attestor.verifierCertPools, verifier)
}

// Returns the Attestor's key algorithm
func (attestor *Attest) KeyAttributes() *keystore.KeyAttributes {
	return attestor.keyAttrs
}
