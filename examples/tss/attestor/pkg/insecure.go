package main

import (
	"context"
	"crypto/x509"

	pb "github.com/jeremyhahn/go-trusted-platform/examples/tss/attestor/pkg/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

// Provide the Verifier the CA certificate bundle over an insecure
// connection. This allows the Verifier to add the bundle to their
// CertPool to verify the certificate used by this gRPC TLS service,
// thereby "upgrading" to a secure mTLS encrypted gRPC connection.
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

	var storeType keystore.StoreType

	certs, err := s.ca.ParseBundle(in.Bundle)
	if err != nil {
		return nil, err
	}
	var keyAlgorithm x509.PublicKeyAlgorithm
BREAK:
	for _, cert := range certs {

		s.logger.Debugf(
			"attestor: checking allowed verifiers list for common name: %s",
			cert.Subject.CommonName)

		for _, _verifier := range s.config.AllowedVerifiers {
			// Check the common name for an allow list match
			if _verifier == cert.Subject.CommonName {
				allowed = true
				keyAlgorithm = cert.PublicKeyAlgorithm
				storeType, err = certstore.ParseKeyStoreType(cert)
				if err != nil {
					s.logger.MaybeError(err)
				}
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
		s.logger.Errorf("error: %s", ErrUnknownVerifier)
		return nil, ErrUnknownVerifier
	}

	// Add the Verifier / Service Provider's certificates to the
	// trusted client certificate pool
	verifierIP := parseVerifierIP(p.Addr)
	if err := s.attestor.AddVerifierCABundle(verifierIP, in.Bundle); err != nil {
		return nil, err
	}

	// Send the local Root CA certificate to the Verifier so a new
	// mTLS connection can be established
	bundle, err := s.ca.CABundle(&storeType, &keyAlgorithm)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return &pb.CABundleReply{Bundle: bundle}, nil
}
