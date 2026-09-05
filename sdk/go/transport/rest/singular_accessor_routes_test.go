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

package rest

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Registers every platform.v1 service descriptor in the global proto
	// registry. Without this import the registry lookups below find nothing
	// and both tests here degrade into passes over an empty set, which is why
	// each one carries a population floor.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// singularAccessorsWithNoServerRoute are the singular accessors that still
// share their List sibling's collection path BECAUSE THE SERVER SERVES NO
// SINGULAR ROUTE FOR THAT RESOURCE. Repointing them would swap a wrong answer
// for a 404 that reads as fixed, so they stay where they are and are recorded
// here instead.
//
// This map may only SHRINK, and only when the server grows the route named in
// the reason. It is not a suppression list: a new entry means a singular
// accessor was pointed at a collection path, which is the defect this test
// exists to report.
//
// Verified at 8fe42884039dc768b86a9feedf888d4844fca9be against the ROUTER
// SOURCE -- pkg/webservice/v1/rest/*/router.go and the daemon's
// pkg/api/daemon/rest_service.go -- not against
// pkg/webservice/v1/testdata/routes.golden.
//
// That distinction cost four entries. The golden is built by a FIXTURE, and
// Router.iamRoutes() returns early when the test registry's IAMClients()
// yields nil, so the golden contains no /api/v1/iam route and reads as though
// the server serves none. It serves all of them. Four IAM getters were on
// their way into this map on that evidence. A fixture that builds no route is
// not a server that serves none: check the registration, not the snapshot.
var singularAccessorsWithNoServerRoute = map[string]string{
	// The webservice router serves DNS records only under
	// /api/v1/dns/zones/{zone}/records; there is no singular record route.
	// platform_dns.proto has no GetRecord rpc either, and docs/dns/api.md's
	// "Get record" row reads MISSING in both the REST and gRPC columns -- so
	// this table row names a method no generated client can even call.
	"/platform.v1.DNSService/GetRecord": "no singular DNS record route; no GetRecord rpc (docs/dns/api.md, Get record)",

	// GetPermission was exempted here for being fictional in both halves --
	// no /api/v1/iam/permissions route and no GetPermission rpc. #333 deleted
	// the claim itself, so there is nothing left to exempt and the ratchet
	// required this entry to go with it.
}

// minimumClaims is a vacuity floor. The assertions below iterate the route
// tables, so an empty or half-built table would pass every one of them.
//
// Lowered from 300 to 280 by #333, which deleted 20 route-map entries naming
// gRPC methods that exist on no generated client. The claim count fell from
// 311 to 291 -- a deliberate shrink, not a populate failure, which is exactly
// the case a fixed floor cannot tell apart on its own. It is set below the
// current count with headroom rather than at it, so the floor keeps catching
// an empty table without failing on the next legitimate deletion.
const minimumClaims = 280

// TestRouteClaims_NoSingularAccessorSharesACollectionPathWithItsList asserts
// that no singular accessor claims the same (path, verb) as its List sibling.
//
// When it does, the call is not merely wrong, it is SILENTLY wrong: the server
// serves the collection path, so the request returns 200 with a populated body
// forever. A caller reading [0] gets an arbitrary element; a caller checking
// len(...) > 0 concludes the object exists whichever id it asked for. A 404
// would at least fail loudly.
//
// This check needs no router, no server and no reflection over handlers, and
// that is why it is here rather than only in pkg/webservice/v1. The runtime
// handler-resolution instrument that first went looking for this property saw
// 5 of the 16 (#379): it can only detect a mismatch where the server route
// resolves to a recoverable handler name, and most claims fail that
// precondition. Grouping the client's own table finds all of them, including
// the six whose prefix no server in this repo serves at all.
func TestRouteClaims_NoSingularAccessorSharesACollectionPathWithItsList(t *testing.T) {
	claims := RouteClaims()
	require.GreaterOrEqualf(t, len(claims), minimumClaims,
		"only %d route claims enumerated, below the %d floor -- the route tables "+
			"almost certainly failed to populate, and this test would pass over an "+
			"empty set", len(claims), minimumClaims)

	type group struct{ service, path, verb string }
	byGroup := map[group][]string{}
	for _, c := range claims {
		svc, method := splitGRPCMethod(t, c.GRPCMethod)
		g := group{service: svc, path: c.Path, verb: c.Method}
		byGroup[g] = append(byGroup[g], method)
	}

	found := map[string]string{}
	for g, methods := range byGroup {
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
		for _, s := range singulars {
			found["/platform.v1."+g.service+"/"+s] =
				g.verb + " " + g.path + " (shared with " + strings.Join(lists, ", ") + ")"
		}
	}

	var unexpected, stale []string
	for method, detail := range found {
		if _, exempt := singularAccessorsWithNoServerRoute[method]; !exempt {
			unexpected = append(unexpected, method+" -- "+detail)
		}
	}
	for method := range singularAccessorsWithNoServerRoute {
		if _, still := found[method]; !still {
			stale = append(stale, method)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(stale)

	require.Emptyf(t, unexpected,
		"these singular accessors claim their List sibling's path and verb, so they\n"+
			"return the whole collection with a 200 rather than the object asked for:\n\n  %s\n\n"+
			"Give each one the server's item path via itemRoute(), matching the route the\n"+
			"server actually serves (pkg/webservice/v1/testdata/routes.golden is the list).\n"+
			"If the server serves NO singular route for that resource, do not invent one --\n"+
			"add it to singularAccessorsWithNoServerRoute with the route that is missing.",
		strings.Join(unexpected, "\n  "))

	require.Emptyf(t, stale,
		"these entries in singularAccessorsWithNoServerRoute no longer share a path with\n"+
			"a List sibling, so the exemption is stale and must be deleted:\n\n  %s\n\n"+
			"The map is a ratchet: it may shrink, never grow silently.",
		strings.Join(stale, "\n  "))
}

// placeholderPattern matches a {segment} in a route path template.
var placeholderPattern = regexp.MustCompile(`\{[^{}]*\}`)

// TestTemplatedRouteTable_PathParamsResolveOnTheRequestMessage enforces the
// invariant templatedRouteTable's doc comment declares and nothing checked:
// every {placeholder} in a path is satisfied by exactly one pathParam, and
// every pathParam names a real field on that method's request message.
//
// The failure it prevents is invisible until runtime and only on the affected
// call: buildTemplatedRequest returns codes.Internal for a missing field and
// for an unresolved placeholder, so a typo in a field name ships green and
// breaks exactly one method in production.
//
// The request message is resolved from the proto registry via the method's own
// service descriptor, so this reads the same source the adapter reads at
// runtime rather than a second list that can drift.
func TestTemplatedRouteTable_PathParamsResolveOnTheRequestMessage(t *testing.T) {
	require.NotEmpty(t, templatedRouteTable, "templatedRouteTable is empty")

	checked := 0
	for grpcMethod, route := range templatedRouteTable {
		grpcMethod, route := grpcMethod, route
		t.Run(grpcMethod, func(t *testing.T) {
			input := requestDescriptorFor(t, grpcMethod)

			placeholders := placeholderPattern.FindAllString(route.path, -1)
			seen := map[string]int{}
			for _, p := range route.pathParams {
				seen[p.placeholder]++
				fd := input.Fields().ByName(p.field)
				require.NotNilf(t, fd,
					"pathParam %q names proto field %q, which does not exist on %s. "+
						"buildTemplatedRequest returns codes.Internal for this at runtime.",
					p.placeholder, p.field, input.FullName())
			}
			for _, p := range placeholders {
				require.Equalf(t, 1, seen[p],
					"placeholder %s in %q is satisfied by %d pathParams, want exactly 1 -- "+
						"an unsubstituted placeholder makes the adapter return codes.Internal",
					p, route.path, seen[p])
			}
			for _, p := range route.pathParams {
				require.Containsf(t, route.path, p.placeholder,
					"pathParam %q has no matching placeholder in path %q, so the field is "+
						"cleared from the request body without ever reaching the URL",
					p.placeholder, route.path)
			}
			checked++
		})
	}
	require.GreaterOrEqual(t, checked, len(templatedRouteTable)-len(templatedRouteTable)/2,
		"most subtests failed to run; the table walk is not covering the table")
}

// requestDescriptorFor resolves "/platform.v1.Service/Method" to the descriptor
// of that method's request message.
func requestDescriptorFor(t *testing.T, grpcMethod string) protoreflect.MessageDescriptor {
	t.Helper()

	trimmed := strings.TrimPrefix(grpcMethod, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	require.Lenf(t, parts, 2, "malformed gRPC method key %q", grpcMethod)

	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(parts[0]))
	require.NoErrorf(t, err, "service %q is not in the proto registry -- either the "+
		"route table names a service that does not exist, or the generated package "+
		"is no longer imported by this test", parts[0])

	svc, ok := desc.(protoreflect.ServiceDescriptor)
	require.Truef(t, ok, "%q resolved to %T, not a service", parts[0], desc)

	method := svc.Methods().ByName(protoreflect.Name(parts[1]))
	require.NotNilf(t, method, "service %s has no method %s, so this route table row "+
		"is unreachable: no generated client can invoke it", parts[0], parts[1])

	return method.Input()
}

// splitGRPCMethod splits "/platform.v1.Service/Method" into its bare service
// name and method name.
func splitGRPCMethod(t *testing.T, grpcMethod string) (string, string) {
	t.Helper()
	trimmed := strings.TrimPrefix(grpcMethod, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	require.Lenf(t, parts, 2, "malformed gRPC method key %q", grpcMethod)
	dot := strings.LastIndex(parts[0], ".")
	require.GreaterOrEqualf(t, dot, 0, "service %q has no package qualifier", parts[0])
	return parts[0][dot+1:], parts[1]
}
