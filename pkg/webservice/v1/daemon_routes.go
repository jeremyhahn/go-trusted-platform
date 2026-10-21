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
}

// ErrDaemonRouteClientCertRequired is the 401 a daemon-owned route answers
// a request that presented no verified client certificate.
type ErrDaemonRouteClientCertRequired struct{}

func (ErrDaemonRouteClientCertRequired) Error() string {
	return "daemon route requires a verified client certificate"
}

// MountDaemonRESTRoutes mounts the daemon-owned route groups on api behind
// a verified-client-certificate gate. On the daemon's own REST listener
// these routes are reached only over mTLS, with no JWT; the gate keeps that
// contract on the webservice listener, which verifies a client certificate
// when one is given (tls.VerifyClientCertIfGiven) but does not require one.
func MountDaemonRESTRoutes(api *mux.Router, routes DaemonRESTRoutes, writer response.HttpWriter) error {
	group := api.NewRoute().Subrouter()
	group.Use(requireVerifiedClientCert(writer))
	return routes.MountRESTRoutes(group)
}

// requireVerifiedClientCert refuses, with 401, a request whose TLS
// handshake verified no client certificate chain. VerifiedChains, not
// PeerCertificates: only a chain the TLS stack built to a trusted root
// authenticates the caller.
func requireVerifiedClientCert(writer response.HttpWriter) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
				writer.Error401(w, r, ErrDaemonRouteClientCertRequired{})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
