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
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// TestSDKRouteClaims_SingularAccessorDoesNotLandOnItsCollectionRoute asserts,
// against the SERVER'S ROUTE TABLE rather than against the client's own
// sibling, that no singular accessor resolves to the same route a List
// accessor on the same service resolves to.
//
// The distinction from the sdk-side check of the same shape
// (TestRouteClaims_NoSingularAccessorSharesACollectionPathWithItsList) is what
// each one can see:
//
//   - the sdk-side check compares path STRINGS, so it sees every collision
//     including the six under prefixes no server in this repo serves at all;
//   - this one ROUTES a concrete path, so it also sees a collision between two
//     DIFFERENT client strings that the server's matcher folds onto one route.
//     A string comparison cannot see that, and the server's matcher is the
//     thing that decides.
//
// Both are cheap. Neither subsumes the other, so #379 ships both.
//
// This check does NOT assert "a singular accessor resolves to a route with an
// identifier segment", which sounds stronger and is wrong: GetCAInfo,
// GetStatus and GetVersion are singleton accessors with no identifier, and the
// property would report all of them.
//
// It also does not assert that every claim resolves to a DISTINCT route.
// Legitimate sharing exists: BMCService's PowerOn, PowerOff, PowerReset and
// PowerCycle all POST /api/v1/bmc/{profileID}/power and are disambiguated by
// the body. Sharing is only a defect when one side of it is a List.
func TestSDKRouteClaims_SingularAccessorDoesNotLandOnItsCollectionRoute(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := testutil.WalkRoutes(t, router)

	claims := sdkrest.RouteClaims()
	// 280, lowered from 300 by #333: deleting 20 ghost route-map entries took
	// the claim count from 311 to 291. A deliberate shrink reads identical to a
	// populate failure at a fixed floor, so it moves with the deletion.
	require.GreaterOrEqualf(t, len(claims), 280,
		"only %d SDK route claims enumerated, below the 280 floor -- the client route "+
			"tables failed to populate and this test would pass over an empty set",
		len(claims))

	// resolved keys a server route by the service that claimed it, so a
	// collision is only reported within one service's own surface.
	type key struct{ service, verb, route string }
	resolved := map[key][]string{}
	matched := 0

	for _, c := range claims {
		service, method := splitClaimMethod(t, c.GRPCMethod)

		route, ok := testutil.MatchClaim(router, c.Method, c.Path, built)
		if !ok {
			// Unresolvable claims are TestSDKRouteClaims_ResolveAgainstBuiltRoutes'
			// finding, not this test's. Reporting them here too would make one
			// defect fail two tests and read as two.
			continue
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			continue
		}
		matched++
		k := key{service: service, verb: c.Method, route: template}
		resolved[k] = append(resolved[k], method)
	}

	require.GreaterOrEqualf(t, matched, 100,
		"only %d of %d claims resolved to a server route; the fixture almost certainly "+
			"failed to build the router, and the collision walk below would have nothing "+
			"to walk", matched, len(claims))

	var defects []string
	for k, methods := range resolved {
		var lists, singulars []string
		for _, m := range methods {
			if strings.HasPrefix(m, "List") {
				lists = append(lists, m)
				continue
			}
			singulars = append(singulars, m)
		}
		if len(lists) == 0 || len(singulars) == 0 {
			continue
		}
		sort.Strings(lists)
		sort.Strings(singulars)
		defects = append(defects, k.service+": "+strings.Join(singulars, ", ")+
			" resolve to the same route as "+strings.Join(lists, ", ")+
			"  ["+k.verb+" "+k.route+"]")
	}
	sort.Strings(defects)

	require.Emptyf(t, defects,
		"%d singular accessor(s) resolve to the route their List sibling resolves to,\n"+
			"so the server answers them with the whole collection and a 200:\n\n  %s\n\n"+
			"Point the accessor at the server's item route, in sdk/go's templatedRouteTable\n"+
			"via itemRoute(), so the identifier travels as a path segment.",
		len(defects), strings.Join(defects, "\n  "))
}

// splitClaimMethod splits "/platform.v1.Service/Method" into the bare service
// name and the method name.
func splitClaimMethod(t *testing.T, grpcMethod string) (string, string) {
	t.Helper()
	parts := strings.SplitN(strings.TrimPrefix(grpcMethod, "/"), "/", 2)
	require.Lenf(t, parts, 2, "malformed gRPC method key %q", grpcMethod)
	dot := strings.LastIndex(parts[0], ".")
	require.GreaterOrEqualf(t, dot, 0, "service %q has no package qualifier", parts[0])
	return parts[0][dot+1:], parts[1]
}
