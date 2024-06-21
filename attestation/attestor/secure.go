package attestor

import (
	"context"

	pb "github.com/jeremyhahn/go-trusted-platform/attestation/proto"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/jeremyhahn/go-trusted-platform/pki/tpm2"
	"github.com/op/go-logging"
	"google.golang.org/grpc/peer"
)

// Secure TLS encrypted gRPC web service
type SecureServer struct {
	logger   *logging.Logger
	config   config.Attestation
	domain   string
	ca       ca.CertificateAuthority
	tpm      tpm2.TrustedPlatformModule2
	srkAuth  []byte
	attestor Attestor
	pb.TLSAttestorClient
	pb.UnimplementedTLSAttestorServer
}

func handleDisconnected() {
	// Remove the client cert from the attestors client cert pool
}

// Returns the attestor TPM Endorsement Key
func (s *SecureServer) GetEKCert(ctx context.Context, in *pb.Null) (*pb.EKCertReply, error) {

	p, _ := peer.FromContext(ctx)
	s.logger.Debugf("Received connection from: %v", p.Addr.String())

	if err := s.tpm.Open(); err != nil {
		return nil, err
	}
	defer s.tpm.Close()

	// Get the EK cert as x509.Certificate
	cert, err := s.tpm.EKCert(nil, s.srkAuth)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Return the raw ASN.1 DER encoded certificate
	return &pb.EKCertReply{Certificate: cert.Raw}, nil
}

// Cleans up the session by removing the Verifier's CA bundle from memory
func (s *SecureServer) Close(ctx context.Context, in *pb.Null) (*pb.Null, error) {
	p, _ := peer.FromContext(ctx)
	s.logger.Debugf("Received connection from: %v", p.Addr.String())
	verifierIP := parseVerifierIP(p.Addr)
	s.attestor.RemoveVerifierCABundle(verifierIP)
	return nil, nil
}
