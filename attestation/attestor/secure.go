package attestor

import (
	"context"
	"errors"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/app"
	pb "github.com/jeremyhahn/go-trusted-platform/attestation/proto"
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/tpm2"
	"github.com/op/go-logging"
	"google.golang.org/grpc/peer"
)

var (
	ErrInternalServerError = errors.New("grpc-secure-server: internal server error")
)

type Session struct {
	ek tpm2.Key
	ak tpm2.DerivedKey
}

// Secure TLS encrypted gRPC web service
type SecureAttestor struct {
	logger   *logging.Logger
	config   config.Attestation
	domain   string
	ca       ca.CertificateAuthority
	tpm      tpm2.TrustedPlatformModule2
	srkAuth  []byte
	attestor Attestor
	pb.TLSAttestorClient
	pb.UnimplementedTLSAttestorServer
	sessions     map[string]Session
	sessionMutex sync.RWMutex
}

func NewSecureAttestor(attestor Attestor, app *app.App, srkAuth []byte) *SecureAttestor {
	return &SecureAttestor{
		attestor:     attestor,
		config:       app.AttestationConfig,
		logger:       app.Logger,
		ca:           app.CA,
		tpm:          app.TPM,
		srkAuth:      srkAuth,
		sessions:     make(map[string]Session, 0),
		sessionMutex: sync.RWMutex{}}
}

func (s *SecureAttestor) setSession(verifier string, session Session) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.sessions[verifier] = session
}

func (s *SecureAttestor) deleteSession(verifier string) error {
	if _, ok := s.sessions[verifier]; !ok {
		s.logger.Errorf("missing expected session for %s", verifier)
		return ErrInternalServerError
	}
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	delete(s.sessions, verifier)
	return nil
}

func (s *SecureAttestor) session(verifier string) (Session, error) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	session, ok := s.sessions[verifier]
	if !ok {
		return Session{}, nil
	}
	return session, nil
}

// Returns the Attestor TPM Endorsement Key x509 Certificate in
// raw ASN.1 DER form
func (s *SecureAttestor) GetEKCert(ctx context.Context, in *pb.Null) (*pb.EKCertReply, error) {

	s.logConnection(ctx, "GetEK")

	// if err := s.tpm.Open(); err != nil {
	// 	return nil, err
	// }
	// defer s.tpm.Close()

	// Get the EK cert as x509.Certificate
	cert, err := s.tpm.EKCert(nil, s.srkAuth)
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

	verifier := s.parseVerifierIP(ctx)

	// if err := s.tpm.Open(); err != nil {
	// 	s.logger.Error(err)
	// 	return nil, err
	// }
	// defer s.tpm.Close()

	// Create EK and AK
	ek, ak, err := s.tpm.RSAAK()
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Create a new session to store the EK and AK
	// to reference in subsequent calls during the
	// remote attestation flow.
	session, err := s.session(verifier)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}
	session.ek = ek
	session.ak = ak
	s.setSession(verifier, session)
	s.logger.Debugf("secure-server/GetAK: creating session for verifier: %s", verifier)

	return &pb.AKReply{
		EkPublicPEM:    ek.PublicKeyPEM,
		EkBPublicBytes: ek.BPublicBytes,
		AkPublicPEM:    ak.PublicKeyPEM,
		AkBPublicBytes: ak.BPublicBytes,
		AkName:         ak.Name,
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

	verifier := s.parseVerifierIP(ctx)
	session, err := s.session(verifier)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// if err := s.tpm.Open(); err != nil {
	// 	s.logger.Error(err)
	// 	return nil, err
	// }
	// defer s.tpm.Close()

	secret, err := s.tpm.ActivateCredential(session.ak, tpm2.Credential{
		CredentialBlob:  in.CredentialBlob,
		EncryptedSecret: in.EncryptedSecret,
	})
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

	if err := s.ca.ImportDER(s.domain, in.Certificate); err != nil {
		s.logger.Error(err)
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
	quote, err := s.tpm.Quote(uints, in.Nonce)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return &pb.QuoteResponse{
		Nonce:  quote.Nonce,
		Quoted: quote.Quoted,
	}, nil
}

// Cleans up the session by removing the Verifier's CA bundle from memory
func (s *SecureAttestor) Close(ctx context.Context, in *pb.Null) (*pb.Null, error) {
	p, _ := peer.FromContext(ctx)
	s.logger.Debugf("Received connection from: %v", p.Addr.String())
	verifier := parseVerifierIP(p.Addr)
	s.attestor.RemoveVerifierCABundle(verifier)

	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	s.logger.Debugf("secure-server/Close: deleting verifier session: %s", verifier)
	delete(s.sessions, verifier)

	s.tpm.Close()
	return nil, nil
}

// Create a log entry with the client IP and requested method name
func (s *SecureAttestor) logConnection(ctx context.Context, method string) {
	p, _ := peer.FromContext(ctx)
	s.logger.Debugf("secure-server/%s: Received connection from: %v",
		method, p.Addr.String())
}

// Create a log entry with the client IP and requested method name
func (s *SecureAttestor) parseVerifierIP(ctx context.Context) string {
	p, _ := peer.FromContext(ctx)
	return p.Addr.String()
}
