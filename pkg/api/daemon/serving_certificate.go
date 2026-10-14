package daemon

import (
	"crypto/tls"
	"sync/atomic"
)

// ServingCertificate holds the certificate the daemon's TLS listeners present
// and lets it be replaced while they run (#36). Every listener built from a
// Config carrying one reads it through GetCertificate, so the next handshake
// after Store presents the new certificate: no listener restarts, and
// in-flight connections keep the certificate they negotiated.
//
// The handshake path is a single atomic load; there is no lock.
type ServingCertificate struct {
	current atomic.Pointer[tls.Certificate]
}

// NewServingCertificate returns a ServingCertificate already serving cert.
// It fails with ErrUnusableServingCertificate when cert cannot complete a
// handshake.
func NewServingCertificate(cert tls.Certificate) (*ServingCertificate, error) {
	serving := &ServingCertificate{}
	if err := serving.Store(cert); err != nil {
		return nil, err
	}
	return serving, nil
}

// Store makes cert the certificate presented on every new handshake. An
// unusable certificate is refused with ErrUnusableServingCertificate and the
// certificate already stored keeps serving.
func (s *ServingCertificate) Store(cert tls.Certificate) error {
	if !tlsCertificateUsable(&cert) {
		return ErrUnusableServingCertificate{}
	}
	s.current.Store(&cert)
	return nil
}

// Current returns the certificate being served, or nil when there is none.
// Callers must not modify it. A nil receiver returns nil.
func (s *ServingCertificate) Current() *tls.Certificate {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// GetCertificate is the tls.Config.GetCertificate hook. It fails the
// handshake with ErrNoServingCertificate when nothing is stored.
func (s *ServingCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.Current()
	if cert == nil {
		return nil, ErrNoServingCertificate{}
	}
	return cert, nil
}
