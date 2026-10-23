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

// This file asserts one direction only: every route the Go SDK's REST transport
// CLAIMS must resolve to a route the server actually built.
//
// The asymmetry is deliberate and load-bearing. A server route with no client
// is a roadmap item — the server may serve more than any one client calls, and
// asserting the reverse would turn every unused endpoint into a failure. A
// client method with no route is a lie: it compiles, it ships, and it 404s at
// runtime. #265, #266 and #321 are each an instance, and each was found by a
// person tripping over it rather than by a check, because no check compared the
// two lists.
//
// Do not "fix" this into a bidirectional assertion.
//
// AND DO NOT FIX ROWS UNTIL THIS GOES GREEN.
//
// This walk asserts that a claimed path RESOLVES to a route. It says nothing
// about whether the response that route returns is the shape the client
// decodes. Those are different properties, and only one of them is checked
// here.
//
// The concrete case: sdk/javascript's getTPMInfo fails this walk today because
// /api/v1/tpm/info does not resolve. Repointing it at a route that does resolve
// makes the walk pass while the client silently decodes to undefined — a green
// test over a broken call, which is strictly worse than the red one it
// replaced, because the red one was telling the truth.
//
// So a row leaving unroutedClaims is necessary and not sufficient. The response
// contract is #325's gate, and repointing without it converts a visible failure
// into an invisible one.

func serverRoutes(t *testing.T) []string {
	t.Helper()
	return testutil.WalkRoutes(t, newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}}))
}

// Claims under testutil.DaemonOnlyPrefixes are not checked here. The daemon
// REST server serves those prefixes, this router builds nothing under them,
// and pkg/api/daemon/rest_route_claims_test.go checks every such claim against
// the daemon's own table. TestDaemonOnlyPrefixes_ThisRouterServesNone keeps
// the two sets apart, so an entry cannot excuse one broken route among
// working ones on this router.
//
// iam was once exempted here (#400), and the reason was false:
// rest/iam/router.go registers the whole IAM surface unconditionally; the
// fixture simply wired no IAM client, so the walk saw zero /api/v1/iam routes
// and the exemption looked justified. newGatedTestRouter now wires probeIAM,
// the golden carries the 70 routes, and every IAM claim is resolved below
// like any other.

// unroutedClaims are the claims where this router DOES serve the prefix but
// the client asks for a path that does not resolve. This is #321's shape at
// scale, and it is the actionable half of this test's findings.
//
// The dominant pattern was an item operation claiming a collection path:
//
//	DELETE /api/v1/compute/containers (client)   vs   /api/v1/compute/containers/{id} (server)
//	DELETE /api/v1/iam/users          (client)   vs   an item path
//
// The flat route table's path is passed to DoRequest VERBATIM — no identifier is
// appended, it travels in the body — so these are the paths actually sent.
//
// Keyed by gRPC method, because a route need not be unique: until #452
// GET /api/v1/dns/records was claimed by both GetRecord and ListRecords — a
// get-one and a list-many on the same collection path, which is #266's shape
// ("answers four operations and 404s on three") showing up in the client
// table rather than the server one. #452 moved the DNS claims to the
// zone-scoped item routes the server serves and deleted the GetRecord claim,
// which named an rpc platform_dns.proto does not declare. This map shrinking
// is what progress looks like; it is not a suppression list. Nothing may be
// added without a route having genuinely gone missing, which is the failure
// this test reports.
//
// The six GatewayService claims once recorded here — NAT64 status (#601), the
// three perf verbs and the two admitted-VTEP reads (#709) — are served by the
// daemon REST server under /sdn/gateway/{nat64,perf,overlay}, which are
// testutil.DaemonOnlyPrefixes entries, and the daemon test resolves them there
// (#452).
//
// ProvisioningGateway/GetBootConfig is the one entry left (#452): its three
// neighbours resolve under /provisioning/devices/{mac}
// (rest/pxe/gateway.go), but platformd holds no per-MAC boot configuration to
// answer it from — the PXE service's devices carry no kernel, initrd or
// cmdline. The daemon REST server serves no route for it either; its own
// ledger in rest_route_claims_test.go records the same claim.
var unroutedClaims = map[string]string{
	"/platform.v1.ProvisioningGateway/GetBootConfig": "GET /api/v1/provisioning/devices/{mac}/boot-config",

	// IAM (#400) has no row. (a) Seven item operations that sent a collection
	// path were repaired in #416: the SDK claims the item routes the server
	// serves (sdk/go/transport/rest/adapter.go, templatedRouteTable);
	// RemoveGroupMember and GetCurrentUser were fixed in #414 (#415).
	// (b) The four claims the IAM router did not serve were settled in #452:
	// CheckPermission is now served at POST /api/v1/iam/permissions/check,
	// and CreateToken, RevokeToken and VerifyToken are refused inside the SDK
	// REST transport (restRefusedMethods, sdk/go/transport/rest/iam.go), so
	// they make no claim. Token issuance is the OIDC login flow
	// (docs/iam/api.md §6). (c) The 19 ghost methods once recorded here were
	// deleted from the SDK table in #333.
}

func TestSDKRouteClaims_ResolveAgainstBuiltRoutes(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	built := serverRoutes(t)
	require.NotEmpty(t, built, "the fixture built no routes; this test would pass vacuously")
	t.Logf("server built %d routes", len(built))

	claims := sdkrest.RouteClaims()
	require.NotEmpty(t, claims, "the SDK reported no route claims; this test would pass vacuously")

	sort.Slice(claims, func(i, j int) bool { return claims[i].GRPCMethod < claims[j].GRPCMethod })

	var unresolved []string
	for _, c := range claims {
		key := c.Method + " " + c.Path
		if _, ok := testutil.DaemonOnlyPrefixOf(c.Path); ok {
			continue
		}
		if want, ok := unroutedClaims[c.GRPCMethod]; ok {
			require.Equal(t, want, key,
				"%s is recorded in unroutedClaims as %q but now claims %q; update the entry "+
					"or remove it if the route now resolves", c.GRPCMethod, want, key)
			continue
		}

		if testutil.ClaimResolves(router, c.Method, c.Path, built) {
			continue
		}
		unresolved = append(unresolved, key+"   ("+c.GRPCMethod+")")
	}

	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		t.Errorf("%d SDK route claim(s) resolve to no server route:\n  %s\n\n"+
			"Each is a client method that compiles and 404s at runtime. Either register the\n"+
			"route, or record it in unroutedClaims with the issue that tracks it — never\n"+
			"silently.", len(unresolved), strings.Join(unresolved, "\n  "))
	}
}

// TestSDKRouteClaims_ServerMayServeMore pins the asymmetry so nobody later
// "completes" this into a bidirectional check.
func TestSDKRouteClaims_ServerMayServeMore(t *testing.T) {
	claimed := map[string]bool{}
	for _, c := range sdkrest.RouteClaims() {
		claimed[c.Method+" "+c.Path] = true
	}

	var unclaimed int
	for _, r := range serverRoutes(t) {
		if !claimed[r] {
			unclaimed++
		}
	}

	require.Positive(t, unclaimed,
		"every built route is claimed by the Go SDK, which means this test can no longer "+
			"demonstrate the asymmetry it exists to pin. That is not a failure of the server; "+
			"re-read the comment at the top of this file before changing anything.")
	t.Logf("%d built routes have no Go SDK claim — expected: the server may serve more than any one client calls", unclaimed)
}

// TestUnroutedClaims_EveryEntryStillFailsToResolve keeps the ledger honest in
// the other direction from TestUnroutedClaims_EveryEntryIsStillAClaim: an entry
// whose claim now routes records a defect that is gone, and hides the claim
// from the walks that check where it lands.
func TestUnroutedClaims_EveryEntryStillFailsToResolve(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := testutil.WalkRoutes(t, router)

	var resolving []string
	for _, c := range sdkrest.RouteClaims() {
		if _, ok := unroutedClaims[c.GRPCMethod]; !ok {
			continue
		}
		if testutil.ClaimResolves(router, c.Method, c.Path, built) {
			resolving = append(resolving, c.GRPCMethod+"   ("+c.Method+" "+c.Path+")")
		}
	}
	sort.Strings(resolving)

	require.Emptyf(t, resolving,
		"%d unroutedClaims entr(ies) now resolve to a server route:\n  %s\n\n"+
			"Delete them.",
		len(resolving), strings.Join(resolving, "\n  "))
}

// TestDaemonOnlyPrefixes_ThisRouterServesNone keeps the shared list honest on
// this side: claims under an entry are skipped here because the daemon test
// checks them, which is only true while this router builds nothing there.
func TestDaemonOnlyPrefixes_ThisRouterServesNone(t *testing.T) {
	require.NotEmpty(t, testutil.DaemonOnlyPrefixes)

	var overlapping []string
	for _, route := range serverRoutes(t) {
		_, path, _ := strings.Cut(route, " ")
		if prefix, ok := testutil.DaemonOnlyPrefixOf(path); ok {
			overlapping = append(overlapping, route+"   (under "+prefix+")")
		}
	}

	require.Emptyf(t, overlapping,
		"this router builds %d route(s) under testutil.DaemonOnlyPrefixes:\n  %s\n\n"+
			"Claims there are skipped by this file's walks. Remove the prefix from the list "+
			"so both servers' tests check it.",
		len(overlapping), strings.Join(overlapping, "\n  "))
}
