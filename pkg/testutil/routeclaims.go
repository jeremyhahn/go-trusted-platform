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

package testutil

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// The helpers below compare the Go SDK's REST route claims
// (sdk/go/transport/rest.RouteClaims) against a server's built mux table.
// Two servers share the /api/v1 prefix: the webservice router
// (pkg/webservice/v1, route_coverage_test.go) and the daemon REST server
// (pkg/api/daemon, rest_route_claims_test.go). Both tests read the table and
// match claims through these functions, so there is one place to be wrong.

// DaemonOnlyPrefixes are the /api/v1 path prefixes the daemon REST server
// serves and the webservice router serves nothing under, each with the setter
// that mounts it. Both tests read this one list, and both verify it: the
// webservice test fails if its router builds any route under an entry, and the
// daemon test fails if its server builds none, then checks every claim under
// each entry against the daemon's own table. An entry therefore cannot excuse
// a claim nobody serves.
var DaemonOnlyPrefixes = map[string]string{
	"bmc":      "RESTServer.SetBMCHandler (pkg/api/daemon/rest_service.go)",
	"ceremony": "RESTServer.SetCeremonyService (pkg/api/daemon/ceremony_rest.go)",
	"cluster":  "RESTServer.SetClusterService (pkg/api/daemon/cluster_rest.go)",
	"fido2":    "RESTServer.SetFIDO2Service (pkg/api/daemon/fido2_rest.go)",
	"luks":     "RESTServer.SetLUKSService (pkg/api/daemon/luks_rest.go)",
	"piv":      "RESTServer.SetPIVService (pkg/api/daemon/piv_rest.go)",
	"proxy":    "RESTServer.SetProxyService (pkg/api/daemon/proxy_rest.go)",
	"version":  "RESTServer.registerRoutes, handleVersion (pkg/api/daemon/rest_service.go)",

	// The webservice router serves /sdn/gateway/ipam, so the gateway surface
	// is listed by the sub-prefixes only the daemon serves.
	"sdn/gateway/nat64":   "RESTServer.SetGatewayIPAMService (pkg/api/daemon/rest_sdn.go)",
	"sdn/gateway/overlay": "RESTServer.SetGatewayIPAMService (pkg/api/daemon/rest_sdn.go)",
	"sdn/gateway/perf":    "RESTServer.SetGatewayIPAMService (pkg/api/daemon/rest_sdn.go)",
}

// DaemonOnlyPrefixOf returns the DaemonOnlyPrefixes entry path falls under.
func DaemonOnlyPrefixOf(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/api/v1/")
	if !ok {
		return "", false
	}
	for prefix := range DaemonOnlyPrefixes {
		if rest == prefix || strings.HasPrefix(rest, prefix+"/") {
			return prefix, true
		}
	}
	return "", false
}

// routePlaceholder matches a mux path variable, with or without a pattern:
// {id} and {id:[0-9]+} both match.
var routePlaceholder = regexp.MustCompile(`\{[^{}]*\}`)

// WalkRoutes returns every "METHOD /template" the finished table exposes,
// sorted.
func WalkRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()

	seen := map[string]bool{}
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			// A route with no method matcher answers all of them;
			// GET is enough to establish whether it is gated.
			methods = []string{http.MethodGet}
		}
		for _, method := range methods {
			seen[method+" "+template] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the route table: %v", err)
	}

	out := make([]string, 0, len(seen))
	for route := range seen {
		out = append(out, route)
	}
	sort.Strings(out)
	return out
}

// ClaimPrefix returns the first path segment under /api/v1/ — "bmc" for
// /api/v1/bmc/{profileID}/power.
func ClaimPrefix(path string) string {
	return strings.SplitN(strings.TrimPrefix(path, "/api/v1/"), "/", 2)[0]
}

// ClaimResolves reports whether a request for the claim, made concrete with
// ConcreteClaim, matches a route on router.
func ClaimResolves(router *mux.Router, method, path string, built []string) bool {
	_, ok := MatchClaim(router, method, path, built)
	return ok
}

// MatchClaim routes a concrete request for the claim through router and
// returns the matched route, or false when nothing matches.
func MatchClaim(router *mux.Router, method, path string, built []string) (*mux.Route, bool) {
	req := httptest.NewRequest(method, ConcreteClaim(method, path, built), nil)
	var match mux.RouteMatch
	if !router.Match(req, &match) || match.MatchErr != nil || match.Route == nil {
		return nil, false
	}
	return match.Route, true
}

// ConcreteFor substitutes every placeholder in a mux path template with a
// value that template's matcher accepts.
func ConcreteFor(template string) string {
	return routePlaceholder.ReplaceAllStringFunc(template, func(v string) string {
		// {name:[0-9]+} and friends: give the matcher something its pattern
		// accepts. Numeric patterns are the only constrained ones in this
		// tree; anything else accepts a bare word.
		if strings.Contains(v, "[0-9]") {
			return "1"
		}
		return "x"
	})
}

// ConcreteClaim turns a claim into a path that can be routed. When a built
// route aligns with the claim segment for segment, that route's own template
// picks the values, so a claim's {id} facing a server's {id:[0-9]+} is sent
// as a value the server's pattern accepts. Otherwise the claim's own template
// is made concrete.
func ConcreteClaim(method, path string, built []string) string {
	for _, route := range built {
		if ClaimAlignsWith(method+" "+path, route) {
			_, template, _ := strings.Cut(route, " ")
			return ConcreteFor(template)
		}
	}
	return ConcreteFor(path)
}

// ClaimAlignsWith reports whether "METHOD /path" claim and route have the same
// method, the same segment count, the same literal segments, and placeholders
// in the same positions. Placeholder names and patterns may differ.
func ClaimAlignsWith(claim, route string) bool {
	claimMethod, claimPath, ok := strings.Cut(claim, " ")
	if !ok {
		return false
	}
	routeMethod, routePath, ok := strings.Cut(route, " ")
	if !ok || claimMethod != routeMethod {
		return false
	}
	claimSegments := strings.Split(claimPath, "/")
	routeSegments := strings.Split(routePath, "/")
	if len(claimSegments) != len(routeSegments) {
		return false
	}
	for i, claimSegment := range claimSegments {
		claimVar, routeVar := isPlaceholder(claimSegment), isPlaceholder(routeSegments[i])
		if claimVar != routeVar {
			return false
		}
		if !claimVar && claimSegment != routeSegments[i] {
			return false
		}
	}
	return true
}

// isPlaceholder reports whether one path segment is a whole mux variable.
func isPlaceholder(segment string) bool {
	return segment != "" && routePlaceholder.FindString(segment) == segment
}

// NormalisePlaceholders rewrites every placeholder to "{}", so templates that
// differ only in variable names and patterns compare equal.
func NormalisePlaceholders(template string) string {
	return routePlaceholder.ReplaceAllString(template, "{}")
}
