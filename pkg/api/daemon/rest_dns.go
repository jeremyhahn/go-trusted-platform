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

package daemon

import (
	"net/http"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdns "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/dns"
)

// dnsRESTPrefix is the path every DNS route is served under.
const dnsRESTPrefix = restBasePath + restdns.BasePath

// SetDNSService mounts the DNS routes (docs/dns/api.md §2) on the daemon's
// REST router. The handlers are the webservice's (pkg/webservice/v1/rest/dns),
// so both listeners speak one wire format, the one the SDK REST client calls.
// Each route requires the scope its DNSService RPC requires on gRPC, checked
// by the daemon's REST guard.
//
// With no DNS backend every /api/v1/dns route answers 503 with reason
// SERVICE_NOT_CONFIGURED (docs/dns/api.md §5), never a bare 404.
func (s *RESTServer) SetDNSService(svc dns.DNSService, guard *restapi.ScopeGuard) {
	if svc == nil {
		s.router.PathPrefix(dnsRESTPrefix).HandlerFunc(s.handleDNSNotConfigured)
		s.logger.Info("DNS REST routes answer not configured: no DNS service")
		return
	}
	logger := logging.NewFromSlog(s.logger)
	router := restdns.NewDNSRouter(logger, svc, response.NewResponseWriter(logger, nil))
	sub := s.router.PathPrefix(dnsRESTPrefix).Subrouter()
	for _, route := range router.Routes() {
		scope := grpcapi.ScopeForMethod(route.RPC)
		sub.HandleFunc(route.Path, guard.Require(scope, route.Handler)).Methods(route.Method)
	}
	s.logger.Info("DNS REST routes registered")
}

// handleDNSNotConfigured answers a DNS route on a daemon with no DNS backend.
func (s *RESTServer) handleDNSNotConfigured(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusServiceUnavailable,
		response.NewServiceUnavailableResponse("dns", ErrDNSServiceNotAvailable{}.Error()))
}
