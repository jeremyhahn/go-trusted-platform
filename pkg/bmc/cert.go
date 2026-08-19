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

package bmc

import (
	"context"
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// CertBackend identifies which transport implements TLS certificate
// management against the BMC.
type CertBackend string

const (
	// CertBackendAuto probes Redfish CertificateService first and falls
	// back to vendor-specific paths (e.g. Supermicro CGI). The chosen
	// path is logged at INFO level so operators can audit selection.
	CertBackendAuto CertBackend = "auto"

	// CertBackendRedfish forces use of the Redfish CertificateService.
	// Suitable for X11+/iDRAC9+ generation hardware.
	CertBackendRedfish CertBackend = "redfish"

	// CertBackendSMCCGI forces the Supermicro ATEN CGI cert upload path.
	// Required for X10-era ATEN BMC firmware where Redfish
	// CertificateService is missing or broken.
	CertBackendSMCCGI CertBackend = "smc-cgi"
)

// validCertBackends is a map-based lookup for valid backend values.
var validCertBackends = map[CertBackend]struct{}{
	CertBackendAuto:    {},
	CertBackendRedfish: {},
	CertBackendSMCCGI:  {},
}

// IsValid reports whether b is a recognized backend.
func (b CertBackend) IsValid() bool {
	_, ok := validCertBackends[b]
	return ok
}

// CertificateManager exposes BMC web-server TLS certificate operations.
//
// The replacement contract requires both the certificate (PEM, possibly a
// chain) and the private key (PEM) to be supplied. The private key is
// passed via *memguard.MemoryEnclave so it stays in locked memory until the
// implementation hands it to the BMC transport. Implementations must
// scrub any in-process copies of the key bytes on return.
//
// After a successful ReplaceWebCertificate, most BMCs require a manager
// reset to activate the new certificate. Implementations are responsible
// for performing the reset and waiting for the BMC to come back online.
type CertificateManager interface {
	// GetWebCertificate returns the parsed certificate currently presented
	// by the BMC's HTTPS interface. The returned certificate is the leaf;
	// any chain elements are not returned by this call.
	GetWebCertificate(ctx context.Context) (*x509.Certificate, error)

	// ReplaceWebCertificate uploads certPEM (leaf, optionally followed by
	// intermediates) and keyPEM, then restarts the BMC web server so the
	// new certificate takes effect. Returns when the BMC responds again
	// on its HTTPS interface, or on context cancellation.
	ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.MemoryEnclave) error

	// Backend reports which CertBackend implementation is in use. For
	// auto-mode clients this reflects the resolved choice after probing.
	Backend() CertBackend
}
