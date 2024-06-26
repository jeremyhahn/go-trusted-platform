package attestor

import (
	"context"

	pb "github.com/jeremyhahn/go-trusted-platform/attestation/proto"
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/op/go-logging"
	"google.golang.org/grpc/peer"
)

// Insecure non TLS encrypted gRPC web service
type InsecureAttestor struct {
	attestor Attestor
	logger   *logging.Logger
	config   config.Attestation
	ca       ca.CertificateAuthority
	pb.InsecureAttestorServer
}

func (a *InsecureAttestor) SetAttestor(attestor Attestor) {
	a.attestor = attestor
}

// Provide the Verifier our CA certificate bundle over an insecure
// connection. This allows the Verifier to add the bundle to their
// CertPool to verify the certificate used by our gRPC TLS service,
// effectively "upgrading" to a secure mTLS encrypted gRPC connection.
// The verifier must be explicitly set in the "allowed-verifiers"
// configuration variable to be allowed to connect and retrieve
// the certificate bundle (and perform remote attestation).
func (s *InsecureAttestor) GetCABundle(
	ctx context.Context,
	in *pb.CABundleRequest) (*pb.CABundleReply, error) {

	p, _ := peer.FromContext(ctx)
	s.logger.Debugf("Received connection from: %v", p.Addr.String())
	s.logger.Debugf("Verifier's CA bundle: \n%s", in.Bundle)

	// Parse the received certificate to get the issued common name
	// and compare it against the allowed list of verifiers in the
	// config.
	// verifier := ""
	allowed := false
	// Parse the CA bundle into an array of x509 certs
	certs, err := s.ca.ParseCABundle(in.Bundle)
	if err != nil {
		return nil, err
	}
BREAK:
	for _, cert := range certs {
		for _, _verifier := range s.config.AllowedVerifiers {
			// Check the common name for an allow list match
			if _verifier == cert.Subject.CommonName {
				allowed = true
				// verifier = _verifier
				break BREAK
			}
			// Check the SANS for an allow list match
			for _, name := range cert.DNSNames {
				if name == _verifier {
					allowed = true
					// verifier = name
					break BREAK
				}
			}
		}
	}
	// Refuse the request with ErrUnknownVerifier if not on
	// the allow list.
	if !allowed {
		s.logger.Errorf("attestor: error: %s", ErrUnknownVerifier)
		return nil, ErrUnknownVerifier
	}

	// Add the Verifier / Service Provider's certificates to the
	// trusted client certificate pool
	verifierIP := parseVerifierIP(p.Addr)
	if err := s.attestor.AddVerifierCABundle(verifierIP, in.Bundle); err != nil {
		return nil, err
	}

	// Send our CA certs to the Verifier so they can terminate
	// the insecure connection and establish a new mTLS connection
	attestorBundle, err := s.ca.CABundle()
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Return our CA bundle to the Verifier / Service Provider
	return &pb.CABundleReply{Bundle: attestorBundle}, nil
}
