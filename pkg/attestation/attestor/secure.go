package attestor

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	pb "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/op/go-logging"
	"google.golang.org/grpc/peer"
)

var (
	ErrInternalServerError = errors.New("grpc-secure-server: internal server error")
)

// Secure TLS encrypted gRPC web service
type SecureAttestor struct {
	app      *app.App
	attestor Attestor
	config   config.Attestation
	keyAttrs *keystore.KeyAttributes
	logger   *logging.Logger
	pb.TLSAttestorClient
	pb.UnimplementedTLSAttestorServer
	sessionMutex sync.RWMutex
}

func NewSecureAttestor(
	attestor Attestor,
	app *app.App) *SecureAttestor {

	return &SecureAttestor{
		logger:       app.Logger,
		app:          app,
		config:       app.AttestationConfig,
		attestor:     attestor,
		keyAttrs:     app.ServerKeyAttributes,
		sessionMutex: sync.RWMutex{}}
}

// Opens a new connection to the TPM if a connection is not already connected
func (s *SecureAttestor) OnConnect() {
}

// Cleans up the session by removing the Verifier's CA bundle from memory
func (s *SecureAttestor) Close(ctx context.Context, in *pb.Null) (*pb.Null, error) {
	verifier := s.parseVerifierIP(ctx)

	s.logger.Debugf("Received connection from: %v", verifier)
	s.logger.Debugf("secure-server/Close: deleting verifier session: %s", verifier)
	s.attestor.RemoveVerifierCABundle(verifier)

	return nil, nil
}

// Returns the Attestor TPM Endorsement Key x509 Certificate in
// raw ASN.1 DER form
func (s *SecureAttestor) GetEKCert(ctx context.Context, in *pb.Null) (*pb.EKCertReply, error) {

	s.logConnection(ctx, "GetEK")

	// Get the EK cert as x509.Certificate
	cert, err := s.app.TPM.EKCertificate()
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Return the raw ASN.1 DER encoded certificate
	return &pb.EKCertReply{Certificate: cert.Raw}, nil
}

// Returns the Attestation Key (AK) from the TPM. The AK is generated
// from the EK.
func (s *SecureAttestor) GetAK(ctx context.Context, in *pb.Null) (*pb.AKReply, error) {

	s.logConnection(ctx, "GetAK")

	// Retrieve the AK Profile (EK pub, AK pub, AK name)
	profile, err := s.app.TPM.AKProfile()
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return &pb.AKReply{
		AKName:             profile.AKName.Buffer,
		AKPub:              profile.AKPub,
		EKPub:              profile.EKPub,
		SignatureAlgorithm: int32(profile.SignatureAlgorithm),
	}, nil
}

// Performs TPM2_ActivateCredential, loading the EK and AK into the TPM with an
// authorization policy that will only release the AK to decrypt the credential
// challenge to the salted HMAC session that created the session during the
// call to create the Attestation Key. The authorization policy is also salted
// with a TPM generated nonce to protect against replay attacks. If encryption
// is enabled, the bus between the TPM <-> CPU will be encrypted with AES 128.
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_activatecredential.1.md
func (s *SecureAttestor) ActivateCredential(
	ctx context.Context,
	in *pb.ActivateCredentialRequest) (*pb.ActivateCredentialResponse, error) {

	s.logConnection(ctx, "ActivateCredential")

	secret, err := s.app.TPM.ActivateCredential(
		in.CredentialBlob,
		in.EncryptedSecret)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return &pb.ActivateCredentialResponse{Secret: secret}, nil
}

// Accepts an issued Attestation Key (device) certificate from the Verifier
func (s *SecureAttestor) AcceptCertificate(
	ctx context.Context,
	in *pb.AcceptCertificateResquest) (*pb.Null, error) {

	s.logConnection(ctx, "AcceptCertificate")

	// Parse the certificate to make sure its valid
	cert, err := x509.ParseCertificate(in.Certificate)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Save the certificate to the platform certificate store
	if err := s.app.PlatformCertStore.ImportCertificate(cert); err != nil {
		return nil, err
	}

	return nil, nil
}

// Performs a TPM_Quote using the requested PCRs and nonce
func (s *SecureAttestor) Quote(
	ctx context.Context,
	in *pb.QuoteRequest) (*pb.QuoteResponse, error) {

	s.logConnection(ctx, "Quote")

	uints := make([]uint, len(in.Pcrs))
	for i, pcr := range in.Pcrs {
		uints[i] = uint(pcr)
	}

	quote, err := s.app.TPM.Quote(uints, in.Nonce)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	encoded, err := tpm2.EncodeQuote(quote)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return &pb.QuoteResponse{
		Quote: encoded,
	}, nil
}

// Create a log entry with the client IP and requested method name
func (s *SecureAttestor) logConnection(ctx context.Context, method string) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		s.logger.Warning("secure-server: unable to parse peer from context")
		s.logger.Debugf("%+v")
		return
	}
	s.logger.Debugf("secure-server/%s: Received connection from: %v",
		method, p.Addr.String())
}

// Parse the verifier IP from the context
func (s *SecureAttestor) parseVerifierIP(ctx context.Context) string {
	p, _ := peer.FromContext(ctx)
	return parseVerifierIP(p.Addr)
}
