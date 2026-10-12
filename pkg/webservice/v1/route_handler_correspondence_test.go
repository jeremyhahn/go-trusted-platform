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
	"crypto/x509"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// This file asserts a THIRD property, distinct from the two route guards that
// already exist, and it does not replace either:
//
//   - #331 (route_coverage_test.go) asserts every client claim RESOLVES to a
//     served route. Deliberately one-directional: a server may serve more than
//     any one client calls.
//   - #348 (route_existence_test.go) asserts the served routes are STILL THERE.
//   - this file asserts a resolved claim reaches the RIGHT HANDLER.
//
// Route-resolution is strictly weaker than route-correctness, and the gap is
// where a silent defect lives: a claim pointing at a real route that answers a
// different question. `DeviceService/GetDevice` claims `GET /api/v1/devices`,
// which IS served -- by ListDevices. #331 is green on it. #348 is green on it.
// A caller asking for one device gets every device, with a 200, forever.
//
// Deleting either of the other two because "we have a better route test now"
// would lose properties this file does not assert.

// getListDefects records claims whose Get* method resolves to a List* handler.
//
// A RATCHET, not an allowlist: it may only shrink. Each entry is a live defect
// -- a caller asking for one object receives the whole collection with a 200 --
// tracked separately from this guard, because proving a defect and repairing it
// are different work. Removing an entry is what the fix PR does; adding one
// requires explaining why a new instance is acceptable, and it is not.
var getListDefects = map[string]string{
	// DRAINED 2026-09-05 by #399 (Refs #379). All seven entries were singular
	// accessors claiming their List sibling's collection path; each now claims
	// the server's item route, so each resolves to its own handler.
	//
	// Empty is the goal state, not a reason to delete the map. The forward
	// direction below still reports any NEW Get* that resolves to a List*
	// handler, and it reports it as a defect rather than as a known one --
	// which is the whole point of the list only ever shrinking.
}

// getListCollisions records claims where a Get* and a List* method carry an
// IDENTICAL path and verb in the SDK's own table -- the Get call is byte for
// byte the list call, so it cannot fetch one object whatever the server serves.
//
// A RATCHET: it may only shrink. Sixteen today, measured, not transcribed.
//
// This list is LONGER than getListDefects below, and that is the useful part:
// the cheap table check reaches pairs the handler check cannot see, because a
// claim whose route is unserved, or whose handler is middleware-wrapped, yields
// no handler name to compare. The handler check is stronger in KIND -- it can
// catch a mismatch with no sibling claim at all -- and weaker in REACH.
// Neither subsumes the other, which is why both run.
var getListCollisions = map[string]bool{
	// Fourteen of the original sixteen were repointed at the server's item
	// route by #399 (Refs #379) and removed here. A fifteenth --
	// GET /api/v1/iam/permissions -- went with #333, which deleted
	// GetPermission and ListPermissions from the SDK route map outright:
	// iam.proto declares neither rpc, so the two claims that collided on that
	// path existed on no generated client and could never be produced. The
	// collision did not get fixed; the claims making it stopped existing.
	//
	// One remains, because the server serves NO singular route for it and
	// there is nothing to point at: platform_dns.proto has no GetRecord rpc
	// and records live only under /dns/zones/{zone}/records.
	//
	// It shrinks when that route exists, not before -- repointing it at a path
	// that 404s would turn a wrong answer into a failure that reads as fixed.
	"GET /api/v1/dns/records": true,
}

// minimumResolvedHandlers is a vacuity floor.
//
// The assertions below iterate resolved claims. If the router failed to build,
// or handler names stopped being recoverable, every loop would run zero times
// and the file would pass while checking nothing -- which is the exact defect
// #348 was filed about, one level up. This fails loudly instead.
const minimumResolvedHandlers = 40

var pathConstraint = regexp.MustCompile(`\{(\w+):[^}]*\}`)

// normalisePath strips mux regex constraints so `{id:[0-9]+}` and `{id}` compare
// equal -- the SDK writes the bare form, the server writes the constrained one.
func normalisePath(t string) string { return pathConstraint.ReplaceAllString(t, "{$1}") }

// handlerName returns the handler function's short name, and whether it could
// be recovered at all.
//
// Only a method VALUE registered through HandleFunc carries its identity into
// the built table -- Go names those with an "-fm" suffix. A handler wrapped at
// registration time, e.g. `router.Handle("/tenants", r.systemOnly(h.CreateTenant))`,
// resolves to the wrapper's closure and its identity is gone.
//
// Unrecoverable is returned as a THIRD outcome rather than folded into either
// answer. Treating it as "ok" would hide mismatches; treating it as "mismatch"
// would invent them -- an early version of this walk reported
// `TenantService/CreateTenant -> 1`, which is the closure's name, not a finding.
func handlerName(h any) (string, bool) {
	if h == nil {
		return "", false
	}
	full := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	if !strings.HasSuffix(full, "-fm") {
		return "", false
	}
	short := full[strings.LastIndex(full, ".")+1:]
	return strings.TrimSuffix(short, "-fm"), true
}

// builtHandlers maps "METHOD /normalised/path" to the handler's short name for
// every route whose handler identity survived registration.
func builtHandlers(t *testing.T) (resolved map[string]string, wrapped []string) {
	t.Helper()

	// The diskless per-boot routes register only with a boot handler, and
	// POST /device/boot sits behind the mTLS middleware.
	logger := testLogger()
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &anonymousAuth{},
		bootHandler:  &probeBootHandler{},
		mtls:         middleware.NewMTLSMiddleware(logger, response.NewResponseWriter(logger, nil), x509.NewCertPool()),
	})
	resolved = map[string]string{}

	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{"GET"}
		}
		name, ok := handlerName(route.GetHandler())
		for _, m := range methods {
			key := m + " " + normalisePath(template)
			if !ok {
				wrapped = append(wrapped, key)
				continue
			}
			resolved[key] = name
		}
		return nil
	}))

	sort.Strings(wrapped)
	return resolved, wrapped
}

// TestSDKRouteClaims_NoGetResolvesToList is the assertion.
//
// A Get* claim that lands on a List* handler returns 200 with a populated body
// and no error, forever. It is the shape that survives for years, because
// nothing about the response looks wrong -- a caller reading [0] gets an
// arbitrary object rather than the one it asked for.
func TestSDKRouteClaims_NoGetResolvesToList(t *testing.T) {
	resolved, _ := builtHandlers(t)
	require.GreaterOrEqualf(t, len(resolved), minimumResolvedHandlers,
		"only %d routes yielded a handler name, below the %d floor -- the router "+
			"probably failed to build, so every assertion below would pass over an "+
			"empty set. Fix that rather than lowering the floor", len(resolved), minimumResolvedHandlers)

	var found []string
	for _, claim := range sdkrest.RouteClaims() {
		handler, ok := resolved[claim.Method+" "+normalisePath(claim.Path)]
		if !ok {
			// No route, or a wrapped handler. Not this test's property:
			// #331 owns unresolved claims, and wrapped handlers are
			// enumerated by TestBuiltRoutes_WrappedHandlersAreEnumerated.
			continue
		}
		method := claim.GRPCMethod[strings.LastIndex(claim.GRPCMethod, "/")+1:]
		if !strings.HasPrefix(method, "Get") || !strings.HasPrefix(handler, "List") {
			continue
		}
		if _, known := getListDefects[claim.GRPCMethod]; known {
			continue
		}
		found = append(found, claim.GRPCMethod+" -> "+handler+
			" (claims "+claim.Method+" "+claim.Path+")")
	}

	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d singular-fetch claim(s) resolve to a collection handler.\n"+
			"Each returns 200 with the whole list to a caller asking for one object, "+
			"and no error ever surfaces. Point the claim at the item path:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}

	// The ratchet may only shrink: a repaired entry must be removed.
	for grpcMethod, why := range getListDefects {
		var handler string
		for _, claim := range sdkrest.RouteClaims() {
			if claim.GRPCMethod == grpcMethod {
				handler = resolved[claim.Method+" "+normalisePath(claim.Path)]
			}
		}
		if !strings.HasPrefix(handler, "List") {
			t.Errorf("getListDefects lists %s (%s) but it no longer resolves to a "+
				"List* handler -- it resolves to %q. Remove the entry; this list "+
				"only shrinks", grpcMethod, why, handler)
		}
	}
}

// deviceServiceHandlers names the handler each DeviceService SDK claim must
// dispatch to on the built router (#321). The SDK test
// TestDeviceServiceRoutes_MatchTheServerRouter requires a claim for every
// method in the generated descriptor; this map requires each of those claims
// to land on its own operation here, so the two together pin every method.
var deviceServiceHandlers = map[string]string{
	"CreateDevice":                 "CreateDevice",
	"GetDevice":                    "GetDevice",
	"UpdateDevice":                 "UpdateDevice",
	"DeleteDevice":                 "DeleteDevice",
	"ListDevices":                  "ListDevices",
	"FindDeviceBySerial":           "FindDeviceBySerial",
	"CountDevices":                 "CountDevices",
	"CreateProfile":                "CreateProfile",
	"GetProfile":                   "GetProfileByID",
	"UpdateProfile":                "UpdateProfile",
	"DeleteProfile":                "DeleteProfile",
	"ListProfiles":                 "ListProfiles",
	"FindProfileByMACAddress":      "FindProfileByMAC",
	"FindProfileBySerial":          "FindProfileBySerial",
	"FindMatchingProfile":          "FindMatchingProfile",
	"CountProfiles":                "CountProfiles",
	"ActivateDevice":               "ActivateDevice",
	"AttestDevice":                 "HandleAttestDevice",
	"RecordAttestationCertificate": "HandleRecordAttestCert",
	"CreateProfileFromTemplate":    "CreateProfileFromTemplate",
	"FindConfigForDevice":          "FindConfigForDevice",
	"AssignProfileToDevice":        "AssignProfileToDevice",
	"UnassignProfileFromDevice":    "UnassignProfileFromDevice",
	"BootCertificate":              "HandleBootCertificate",
}

// deviceServiceWrappedRoutes lists the DeviceService claims whose route sits
// behind middleware, so the built router yields no handler name for it. The
// claim must still land on that registered route; the handler the middleware
// reaches is pinned by the router package's own tests.
var deviceServiceWrappedRoutes = map[string]string{
	"BootDelivery": "POST /api/v1/device/boot",
}

// TestSDKRouteClaims_DeviceServiceDispatchesToItsHandler resolves every
// DeviceService SDK claim on the router built in-process and checks the
// handler it reaches. A claim on a path or verb the server does not register,
// or on another operation's route, fails; so does a claim with no row here.
func TestSDKRouteClaims_DeviceServiceDispatchesToItsHandler(t *testing.T) {
	resolved, wrapped := builtHandlers(t)
	behindMiddleware := map[string]bool{}
	for _, route := range wrapped {
		behindMiddleware[route] = true
	}

	const prefix = "/platform.v1.DeviceService/"
	claimed := map[string]bool{}
	for _, claim := range sdkrest.RouteClaims() {
		if !strings.HasPrefix(claim.GRPCMethod, prefix) {
			continue
		}
		method := strings.TrimPrefix(claim.GRPCMethod, prefix)
		claimed[method] = true

		if wantRoute, ok := deviceServiceWrappedRoutes[method]; ok {
			route := claim.Method + " " + normalisePath(claim.Path)
			require.Equalf(t, wantRoute, route, "%s claims the wrong route", claim.GRPCMethod)
			require.Truef(t, behindMiddleware[route],
				"%s claims %q, which the built router does not register behind middleware", claim.GRPCMethod, route)
			continue
		}

		want, ok := deviceServiceHandlers[method]
		if !ok {
			t.Errorf("%s has an SDK claim but no row in deviceServiceHandlers", claim.GRPCMethod)
			continue
		}
		route := claim.Method + " " + normalisePath(claim.Path)
		got, ok := resolved[route]
		if !ok {
			t.Errorf("%s claims %q, which the built router does not register", claim.GRPCMethod, route)
			continue
		}
		require.Equalf(t, want, got, "%s claims %q, which dispatches to the wrong handler",
			claim.GRPCMethod, route)
	}

	for method := range deviceServiceHandlers {
		require.Truef(t, claimed[method], "%s%s has no SDK route claim", prefix, method)
	}
	for method := range deviceServiceWrappedRoutes {
		require.Truef(t, claimed[method], "%s%s has no SDK route claim", prefix, method)
	}
}

// collisionRoute splits a "METHOD /path: Get… is identical to List…" line at
// its separator.
//
// It fails the test rather than slicing on the result of strings.Index
// directly: Index returns -1 when the separator is absent, and c[:-1] PANICS.
// A guard that crashes on an unexpected input reports nothing at all -- the
// same failure its own vacuity floor exists to prevent, and the collision
// strings are built from claim paths, which is exactly where a format
// assumption is likeliest to break. This turns a silent format assumption into
// a named failure.
func collisionRoute(t *testing.T, collision string) string {
	t.Helper()
	i := strings.Index(collision, ":")
	if i < 0 {
		t.Fatalf("collision %q has no %q separator -- the format built above changed, "+
			"and this guard cannot report on entries it cannot parse", collision, ":")
	}
	return collision[:i]
}

// TestSDKRouteTable_NoGetAndListShareAPath is the same property caught earlier
// and more cheaply, without the router or reflection.
//
// When a Get* and a List* claim carry an IDENTICAL path and verb, the Get call
// is byte-identical to the list call -- it cannot do what its name says,
// whatever the server happens to serve. `GetKey` and `ListKeys` are one line
// apart in the SDK's own table.
//
// It is not a replacement for the handler check: this cannot see a Get* claim
// that lands on a collection handler when no sibling List* claim exists.
func TestSDKRouteTable_NoGetAndListShareAPath(t *testing.T) {
	claims := sdkrest.RouteClaims()
	require.NotEmpty(t, claims, "RouteClaims() returned nothing -- the check would be vacuous")

	byRoute := map[string][]string{}
	for _, c := range claims {
		method := c.GRPCMethod[strings.LastIndex(c.GRPCMethod, "/")+1:]
		byRoute[c.Method+" "+c.Path] = append(byRoute[c.Method+" "+c.Path], method)
	}

	var collisions []string
	for route, methods := range byRoute {
		var gets, lists []string
		for _, m := range methods {
			switch {
			case strings.HasPrefix(m, "Get"):
				gets = append(gets, m)
			case strings.HasPrefix(m, "List"):
				lists = append(lists, m)
			}
		}
		if len(gets) > 0 && len(lists) > 0 {
			sort.Strings(gets)
			sort.Strings(lists)
			collisions = append(collisions,
				route+": "+strings.Join(gets, ",")+" is identical to "+strings.Join(lists, ","))
		}
	}

	sort.Strings(collisions)
	var unexpected []string
	for _, c := range collisions {
		route := collisionRoute(t, c)
		if !getListCollisions[route] {
			unexpected = append(unexpected, c)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("%d NEW Get/List claim pair(s) share a path and verb. The Get call "+
			"is byte-identical to the list call and cannot do what its name says:\n  %s",
			len(unexpected), strings.Join(unexpected, "\n  "))
	}

	// Ratchet: a repaired pair must be removed from the list.
	present := map[string]bool{}
	for _, c := range collisions {
		present[collisionRoute(t, c)] = true
	}
	for route := range getListCollisions {
		if !present[route] {
			t.Errorf("getListCollisions lists %q but no Get/List pair shares it any "+
				"more. Remove the entry; this list only shrinks", route)
		}
	}
}

// TestBuiltRoutes_WrappedHandlersAreEnumerated records the routes whose handler
// identity does not survive registration, so the correspondence check's blind
// spot is written down rather than silently skipped.
//
// A guard with a subset it quietly ignores is the defect #348 was filed about.
// These are routes registered as `Handle(path, middleware(h))` rather than
// `HandleFunc(path, h)`; the wrapper's closure replaces the handler's name, so
// nothing can say which operation they serve.
func TestBuiltRoutes_WrappedHandlersAreEnumerated(t *testing.T) {
	resolved, wrapped := builtHandlers(t)
	require.GreaterOrEqualf(t, len(resolved), minimumResolvedHandlers,
		"handler-name recovery appears broken: only %d resolved", len(resolved))

	t.Logf("%d route(s) have a recoverable handler name; %d are middleware-wrapped "+
		"and invisible to the correspondence check:\n  %s",
		len(resolved), len(wrapped), strings.Join(wrapped, "\n  "))

	require.NotEmpty(t, wrapped,
		"expected some wrapped handlers -- if this is now zero the extraction "+
			"probably changed, and the correspondence check may be reporting "+
			"closure names as handler names")
}
