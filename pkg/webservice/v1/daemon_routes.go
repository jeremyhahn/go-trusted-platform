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

package v1

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// DaemonRESTRoutes is the daemon's REST route table: the route groups only
// the daemon serves (health, version, services, protocols, BMC, ceremony,
// PIV, LUKS, FIDO2 and cluster). When a webservices: section replaces the
// daemon REST listener, platformd mounts them on this listener instead
// (docs/daemon/architecture.md). *daemon.Daemon implements it.
type DaemonRESTRoutes interface {
	// MountRESTRoutes registers the daemon-owned groups on api, a router
	// rooted at /api/v1.
	MountRESTRoutes(api *mux.Router) error
	// ClientCAs is the pool the daemon's own listeners verify client
	// certificates against: the platform anchor. Nil when the daemon has
	// no provisioned TLS identity.
	ClientCAs() *x509.CertPool
}

// ErrDaemonRouteClientCertRequired is the 401 a daemon-owned route answers
// a request that presented no verified client certificate.
type ErrDaemonRouteClientCertRequired struct{}

func (ErrDaemonRouteClientCertRequired) Error() string {
	return "daemon route requires a verified client certificate"
}

// ErrDaemonRouteClientCertUntrusted is the 403 a daemon-owned route answers
// a client certificate the webservice handshake verified but that does not
// chain to the daemon's own client roots — for example one issued by an
// attestation caller-admission anchor.
type ErrDaemonRouteClientCertUntrusted struct {
	Cause error
}

func (e ErrDaemonRouteClientCertUntrusted) Error() string {
	return "daemon route refuses a client certificate outside the daemon's client roots: " + e.Cause.Error()
}

func (e ErrDaemonRouteClientCertUntrusted) Unwrap() error { return e.Cause }

// ErrDaemonRouteNoClientRoots is returned by MountDaemonRESTRoutes when the
// daemon has no client roots: no caller could be admitted, so the routes
// are not mounted at all.
type ErrDaemonRouteNoClientRoots struct{}

func (ErrDaemonRouteNoClientRoots) Error() string {
	return "daemon routes not mounted: the daemon has no client certificate roots"
}

// MountDaemonRESTRoutes mounts the daemon-owned route groups on api behind
// a client-certificate gate. On the daemon's own REST listener these
// routes are reached only over mTLS against the daemon's client roots,
// with no JWT. The webservice listener verifies a client certificate when
// one is given (tls.VerifyClientCertIfGiven) against a wider pool — it
// also trusts the attestation caller-admission anchors — so the gate
// re-verifies the chain against routes.ClientCAs() and nothing else.
func MountDaemonRESTRoutes(api *mux.Router, routes DaemonRESTRoutes, writer response.HttpWriter) error {
	roots := routes.ClientCAs()
	if roots == nil {
		return ErrDaemonRouteNoClientRoots{}
	}
	group := api.NewRoute().Subrouter()
	group.Use(requireDaemonClientCert(writer, roots))
	return routes.MountRESTRoutes(group)
}

// requireDaemonClientCert refuses, with 401, a request whose TLS handshake
// verified no client certificate chain, and, with 403, a verified
// certificate that does not chain to roots. VerifiedChains, not
// PeerCertificates, decides "presented": only a chain the TLS stack built
// authenticates the caller at all.
func requireDaemonClientCert(writer response.HttpWriter, roots *x509.CertPool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
				writer.Error401(w, r, ErrDaemonRouteClientCertRequired{})
				return
			}
			if err := verifyDaemonClient(r.TLS, roots); err != nil {
				writer.Error403(w, r, err, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// verifyDaemonClient verifies the peer's leaf, with the peer's other
// certificates as intermediates, against roots for client authentication.
func verifyDaemonClient(state *tls.ConnectionState, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return ErrDaemonRouteClientCertUntrusted{Cause: err}
	}
	return nil
}

// daemonRoutes mounts the daemon-owned REST route groups when the registry
// carries the daemon's route table. Without one (the daemon runs its own
// REST listener, or no daemon is wired) nothing is mounted here.
func (v1Router *Router) daemonRoutes() {
	routes := v1Router.restHandlerRegistry.DaemonRESTRoutes()
	if routes == nil {
		return
	}
	if err := MountDaemonRESTRoutes(v1Router.router, routes, v1Router.responseWriter); err != nil {
		v1Router.logger.Error(err, "Daemon REST routes not mounted")
	}
}
