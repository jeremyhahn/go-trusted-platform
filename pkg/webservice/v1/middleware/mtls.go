// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package middleware

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// ContextKeyDeviceSerial is the context key for the device serial.
const ContextKeyDeviceSerial = contextKey("device_serial")

// MTLSMiddleware verifies client certificates for mTLS
type MTLSMiddleware interface {
	Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc)
}

type mtlsMiddleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	trustedRoots   *x509.CertPool
}

func NewMTLSMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	trustedRoots *x509.CertPool,
) MTLSMiddleware {
	return &mtlsMiddleware{
		logger:         logger,
		responseWriter: responseWriter,
		trustedRoots:   trustedRoots,
	}
}

func (m *mtlsMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Check TLS connection
	if r.TLS == nil {
		m.responseWriter.Error401(w, r, ErrTLSRequired)
		return
	}

	// Check for peer certificates
	if len(r.TLS.PeerCertificates) == 0 {
		m.responseWriter.Error401(w, r, ErrClientCertRequired)
		return
	}

	clientCert := r.TLS.PeerCertificates[0]

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         m.trustedRoots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Add intermediate certs
	for _, cert := range r.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := clientCert.Verify(opts); err != nil {
		m.logger.Errorf("Client certificate verification failed: %v", err)
		m.responseWriter.Error401(w, r, ErrCertVerifyFailed)
		return
	}

	// An installer certificate carries clientAuth beside tp-pxeInstaller, so
	// the chain check above admits it, and its CN can name a device serial.
	// It holds only pxe:complete, never a device identity, so it is refused
	// before the serial is derived.
	if issuance.HasInstallerMarker(clientCert) {
		err := ErrInstallerNotDevice{CommonName: clientCert.Subject.CommonName}
		m.logger.Warn(err.Error())
		m.responseWriter.Error403(w, r, err, nil)
		return
	}

	// Extract serial number from certificate CN or SAN
	serial := DeviceSerialFromCert(clientCert)
	if serial == "" {
		m.responseWriter.Error401(w, r, ErrNoDeviceSerial)
		return
	}

	// Add serial to context for handlers
	ctx := context.WithValue(r.Context(), ContextKeyDeviceSerial, serial)

	next(w, r.WithContext(ctx))
}

func DeviceSerialFromCert(cert *x509.Certificate) string {
	// First check Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Check DNS SANs
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	// Check Serial Number field
	if cert.Subject.SerialNumber != "" {
		return cert.Subject.SerialNumber
	}

	return ""
}

var (
	ErrTLSRequired        = errors.New("TLS connection required")
	ErrClientCertRequired = errors.New("client certificate required")
	ErrCertVerifyFailed   = &MessageError{Msg: "client certificate verification failed"}
	ErrNoDeviceSerial     = errors.New("no device serial in certificate")
)

// ErrInstallerNotDevice signals that the verified client certificate
// carries the tp-pxeInstaller marker. An installer is never an enrolled
// device, whatever its Common Name says.
type ErrInstallerNotDevice struct {
	// CommonName is the Common Name of the installer certificate.
	CommonName string
}

func (e ErrInstallerNotDevice) Error() string {
	return "mtls: certificate " + strconv.Quote(e.CommonName) +
		" is an installer certificate (tp-pxeInstaller) and is not a device identity"
}

// Is matches any ErrInstallerNotDevice, whatever its Common Name.
func (e ErrInstallerNotDevice) Is(target error) bool {
	_, ok := target.(ErrInstallerNotDevice)
	return ok
}
