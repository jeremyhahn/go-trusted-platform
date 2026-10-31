// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gateway

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tlspeer"
)

// gatewayPrincipal derives the calling gateway's authenticated identity
// from the TLS client certificate presented on the connection.
//
// # The binding field is the certificate Subject Common Name
//
// A gateway's control-plane identity is its client certificate's CN, and
// nothing else. That choice follows the established machine-principal
// convention in this repository rather than inventing a new one: the
// trusted reverse proxy keys attestation manifests by "the IDevID CN"
// (pkg/proxy/authchain.go), the device-enrollment mTLS middleware reads
// the CN first (pkg/webservice/v1/middleware/mtls.go), and the daemon's
// gRPC interceptor does the same (pkg/api/daemon/mtls_interceptor.go).
//
// The CN is read DIRECTLY rather than through the middleware's
// CN-then-DNS-SAN-then-serialNumber fallback chain. Accepting a DNS SAN
// would widen the binding to a name any CA in the client bundle can also
// put in a server certificate, which is exactly the substitution this
// check exists to prevent. One field, no fallbacks.
//
// # The certificate is read from the verified chain only
//
// The certificate is the leaf tlspeer.VerifiedLeaf returns, which reads
// VerifiedChains and never PeerCertificates; its package doc says why.
// The listener is configured to request the certificate in
// pkg/webservice/webserver_v1.go (requestOptionalClientCert).
//
// Every failure path returns an error: a request with no verified client
// certificate has no gateway identity and is refused, never defaulted.
func gatewayPrincipal(r *http.Request) (string, error) {
	leaf, err := tlspeer.VerifiedLeaf(r.TLS)
	if err != nil {
		return "", ErrGatewayIdentityRequired{Reason: err.Error()}
	}
	// An installer certificate carries clientAuth beside tp-pxeInstaller, so
	// TLS admits it, and its CN can name a gateway. It holds only
	// pxe:complete, never a gateway identity, so it is refused before the CN
	// is read.
	if issuance.HasInstallerMarker(leaf) {
		return "", ErrInstallerNotGateway{CommonName: leaf.Subject.CommonName}
	}
	cn := leaf.Subject.CommonName
	if cn == "" {
		return "", ErrGatewayIdentityRequired{Reason: "client certificate carries no Common Name"}
	}
	// The CN is used verbatim, never normalized. Trimming it here would
	// make a certificate issued for " node-01 " authenticate as node-01,
	// which is an aliasing path into another gateway's record — exactly
	// what an exact binding is for. A padded CN is refused instead, and
	// a CN that is only whitespace is caught by the same rule.
	if strings.TrimSpace(cn) != cn {
		return "", ErrGatewayIdentityRequired{
			Reason: "client certificate Common Name has leading or trailing whitespace; the gateway identity is the Common Name exactly",
		}
	}
	return cn, nil
}

// authenticatedGateway resolves the calling gateway's certificate
// principal. On failure it writes the 401 envelope, or the 403 envelope
// for an installer certificate, which is authenticated but is never a
// gateway, and reports false; the caller returns immediately.
func (c *ControlPlane) authenticatedGateway(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, err := gatewayPrincipal(r)
	if errors.Is(err, ErrInstallerNotGateway{}) {
		c.logger.Warn(err.Error())
		c.respWriter.Error403(w, r, err, nil)
		return "", false
	}
	if err != nil {
		c.respWriter.Error401(w, r, err)
		return "", false
	}
	return principal, true
}

// authorizeGatewayID enforces that a gateway acts only on its own
// records. principal comes from the client certificate; requested is the
// gateway_id carried in the request body or URL path. A mismatch writes
// the 403 envelope and reports false.
//
// The comparison is exact and case-sensitive. A gateway ID is an opaque
// configured identifier, not a hostname, so there is no case-folding
// rule that would make two spellings the same principal — and a loose
// comparison is precisely how an identity check becomes bypassable.
func (c *ControlPlane) authorizeGatewayID(w http.ResponseWriter, r *http.Request, principal, requested string) bool {
	if principal == requested {
		return true
	}
	err := ErrGatewayIdentityMismatch{Principal: principal, Requested: requested}
	c.logger.Warn(err.Error())
	c.respWriter.Error403(w, r, err, nil)
	return false
}

// ErrGatewayIdentityRequired signals that a control-plane request
// carried no verified mTLS client certificate to bind a gateway_id to.
type ErrGatewayIdentityRequired struct {
	Reason string
}

func (e ErrGatewayIdentityRequired) Error() string {
	return "gateway: an mTLS client certificate identity is required: " + e.Reason
}

// ErrGatewayIdentityMismatch signals that an authenticated gateway tried
// to read or write another gateway's record.
type ErrGatewayIdentityMismatch struct {
	// Principal is the Common Name of the verified client certificate.
	Principal string
	// Requested is the gateway_id the request tried to act on.
	Requested string
}

func (e ErrGatewayIdentityMismatch) Error() string {
	return "gateway: certificate principal " + strconv.Quote(e.Principal) +
		" is not authorized for gateway_id " + strconv.Quote(e.Requested)
}

// ErrInstallerNotGateway signals that the verified client certificate
// carries the tp-pxeInstaller marker. An installer is never a gateway,
// whatever its Common Name says.
type ErrInstallerNotGateway struct {
	// CommonName is the Common Name of the installer certificate.
	CommonName string
}

func (e ErrInstallerNotGateway) Error() string {
	return "gateway: certificate " + strconv.Quote(e.CommonName) +
		" is an installer certificate (tp-pxeInstaller) and is not a gateway identity"
}

// Is matches any ErrInstallerNotGateway, whatever its Common Name.
func (e ErrInstallerNotGateway) Is(target error) bool {
	_, ok := target.(ErrInstallerNotGateway)
	return ok
}
