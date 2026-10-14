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
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

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

// placeholder matches a mux path variable, with or without a pattern:
// {id} and {id:[0-9]+} both match.
var placeholder = regexp.MustCompile(`\{[^{}]*\}`)

// concreteFor turns a route template into a path a client would actually send.
//
// Matching has to be done by ROUTING a concrete path, not by comparing template
// strings. #321's silent case was a client sending a collection path where the
// server serves an item path: the strings differ, so a string comparison
// reports "no match" correctly, but a client sending the WRONG concrete path
// would be reported as fine. Routing catches both directions because it asks
// the same question the server asks.
func concreteFor(template string) string {
	return placeholder.ReplaceAllStringFunc(template, func(v string) string {
		// {name:[0-9]+} and friends: give the matcher something its pattern
		// accepts. Numeric patterns are the only constrained ones in this
		// tree; anything else accepts a bare word.
		if strings.Contains(v, "[0-9]") {
			return "1"
		}
		return "x"
	})
}

// concreteClaim is concreteFor for a client claim, given the routes the server
// built.
//
// A claim's placeholder carries no pattern; the server's may. The SDK writes
// /api/v1/eab/credentials/{id} and the server serves {id:[0-9]+}, so
// concreteFor alone sends "x" there, a value the client never sends:
// credential_id is a uint64. When a built route names the claim position by
// position, its template is the one made concrete, so the server's pattern
// picks the value. Routing still decides which route answers, so a shadowing
// route is still caught.
func concreteClaim(method, path string, built []string) string {
	for _, route := range built {
		if claimAlignsWith(method+" "+path, route) {
			_, template, _ := strings.Cut(route, " ")
			return concreteFor(template)
		}
	}
	return concreteFor(path)
}

// claimAlignsWith reports whether a claim and a built route, each written
// "METHOD /template", name the same route: the same method, the same number
// of segments, every literal segment equal, and every placeholder facing a
// placeholder whatever its pattern.
func claimAlignsWith(claim, route string) bool {
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

// isPlaceholder reports whether a whole path segment is one mux variable.
func isPlaceholder(segment string) bool {
	return segment != "" && placeholder.FindString(segment) == segment
}

// serverRoutes returns every route the fixture's router actually built, as
// "METHOD /template". It reads the built mux table via walkRoutes — the same
// enumerator router_authz_test.go uses, so both tests read one list and there
// is one place to be wrong.
func serverRoutes(t *testing.T) []string {
	t.Helper()
	return walkRoutes(t, newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}}))
}

// unservedPrefixes are whole path prefixes this router serves NOTHING under —
// 64 claims across eight prefixes. Two different reasons, kept apart on purpose:
// a route on the other server, and a route that does not exist yet.
//
// This category is separate from unroutedClaims because conflating them would
// let a genuinely missing route hide behind "oh, that one is on the other
// server". That ambiguity is exactly what made #290's evidence read as wrong:
// /api/v1/status names a handler on each server.
//
// A prefix exemption is blunt, and it is used ONLY where the router builds zero
// routes under that prefix — verified by counting the built table, so a prefix
// cannot be listed here to excuse a single broken route among working ones.
var unservedPrefixes = map[string]string{
	// Served by the DAEMON REST server (pkg/api/daemon/rest_service.go), not by
	// the webservice router this test walks. The templated route table says so
	// itself: "Server registrations live in rest_service.go::SetBMCHandler".
	"bmc": "daemon REST server, rest_service.go:SetBMCHandler (see #312)",

	// Re-exported quicbaas/xkms surfaces. The platform re-exports the composed
	// stack (00 L5), and these prefixes have NO registration in either server in
	// this repository — verified, not assumed. They are docs/13 G7's population:
	// a client method exists, the route does not yet.
	//
	// iam is deliberately NOT here (#400). It was, with the same reason as its
	// neighbours, and the reason was false: rest/iam/router.go registers the
	// whole IAM surface unconditionally; the fixture simply wired no IAM
	// client, so the walk saw zero /api/v1/iam routes and the exemption looked
	// justified. newGatedTestRouter now wires probeIAM, the golden carries the
	// 70 routes, and every IAM claim is resolved below like any other.
	"proxy":    "quicbaas re-export, no REST route in this repo (docs/13 G7)",
	"luks":     "xkms re-export, no REST route in this repo (docs/13 G7)",
	"piv":      "served by the daemon REST server (pkg/api/daemon/piv_rest.go), not this router",
	"ceremony": "served by the daemon REST server (pkg/api/daemon/ceremony_rest.go), not this router",
	"fido2":    "served by the daemon REST server (pkg/api/daemon/fido2_rest.go), not this router",
	"cluster":  "quicbaas re-export, no REST route in this repo (docs/13 G7)",

	// /api/v1/version is served by the daemon REST server (handleVersion), not
	// by the webservice router.
	"version": "daemon REST server, rest_service.go:handleVersion",
}

// unroutedClaims are the 49 claims where the server DOES serve the prefix but
// the client asks for a path that does not resolve. This is #321's shape at
// scale, and it is the actionable half of this test's findings.
//
// The dominant pattern is an item operation claiming a collection path:
//
//	DELETE /api/v1/compute/containers (client)   vs   /api/v1/compute/containers/{id} (server)
//	DELETE /api/v1/iam/users          (client)   vs   an item path
//
// The flat route table's path is passed to DoRequest VERBATIM — no identifier is
// appended, it travels in the body — so these are the paths actually sent.
//
// Keyed by gRPC method, because a route need not be unique: today 49 methods
// claim 49 distinct routes, but until #452 GET /api/v1/dns/records was claimed
// by both GetRecord and ListRecords — a get-one and a list-many on the same
// collection path, which is #266's shape ("answers four operations and 404s on
// three") showing up in the client table rather than the server one. #452 moved
// the DNS claims to the zone-scoped item routes the server serves and deleted
// the GetRecord claim, which named an rpc platform_dns.proto does not declare.
// This map shrinking is what progress looks
// like; it is not a suppression list. Nothing may be added without a route
// having genuinely gone missing, which is the failure this test reports.
//
// The six GatewayService entries are one group with one cause: NAT64 status
// (#601), the three perf verbs and the two admitted-VTEP reads (#709) are
// registered on the DAEMON REST stack (pkg/api/rest/), and this router builds
// nothing for them. NAT64 is recorded
// alongside its neighbours rather than registered here because #660 leaves no
// production backend wired to any gatewayd-resident gateway surface — a route
// added here would resolve and then return unavailable — and because #154/#656
// is actively mounting the /sdn/gateway prefix on this router. The claims
// describe the intended surface correctly; this router's half is what is
// missing.
var unroutedClaims = map[string]string{
	"/platform.v1.CAService/RenewCertificate":                "POST /api/v1/ca/certificates/renew",
	"/platform.v1.CAService/RevokeCertificate":               "POST /api/v1/ca/certificates/revoke",
	"/platform.v1.CAService/VerifyCertificate":               "POST /api/v1/ca/certificates/verify",
	"/platform.v1.ComputeService/AttestContainer":            "POST /api/v1/compute/containers/attest",
	"/platform.v1.ComputeService/DeleteContainer":            "DELETE /api/v1/compute/containers",
	"/platform.v1.ComputeService/StartContainer":             "POST /api/v1/compute/containers/start",
	"/platform.v1.ComputeService/StopContainer":              "POST /api/v1/compute/containers/stop",
	"/platform.v1.GatewayService/GetGatewayAdmittedVTEP":     "GET /api/v1/sdn/gateway/overlay/vteps/{vtep}",
	"/platform.v1.GatewayService/GetNAT64Status":             "GET /api/v1/sdn/gateway/nat64/status",
	"/platform.v1.GatewayService/GetPerfConntrack":           "GET /api/v1/sdn/gateway/perf/conntrack",
	"/platform.v1.GatewayService/GetPerfDatapath":            "GET /api/v1/sdn/gateway/perf/datapath",
	"/platform.v1.GatewayService/GetPerfFlows":               "POST /api/v1/sdn/gateway/perf/flows",
	"/platform.v1.GatewayService/ListGatewayAdmittedVTEPs":   "GET /api/v1/sdn/gateway/overlay/vteps",
	"/platform.v1.IDevIDService/CreateLDevID":                "POST /api/v1/idevid/ldevid",
	"/platform.v1.IDevIDService/Generate":                    "POST /api/v1/idevid",
	"/platform.v1.IDevIDService/GetCSR":                      "GET /api/v1/idevid/csr",
	"/platform.v1.IDevIDService/GetCert":                     "GET /api/v1/idevid/cert",
	"/platform.v1.IDevIDService/InstallCert":                 "POST /api/v1/idevid/cert",
	"/platform.v1.InvitationService/DeleteInvitation":        "DELETE /api/v1/invitations",
	"/platform.v1.InvitationService/GetInvitationByToken":    "GET /api/v1/invitations/by-token",
	"/platform.v1.InvitationService/RevokeInvitation":        "POST /api/v1/invitations/revoke",
	"/platform.v1.OverlayService/DeleteVNI":                  "DELETE /api/v1/overlay/vnis",
	"/platform.v1.PXEService/Authorize":                      "POST /api/v1/pxe/devices/authorize",
	"/platform.v1.PXEService/Quarantine":                     "POST /api/v1/pxe/devices/quarantine",
	"/platform.v1.PXEService/UpdateState":                    "PUT /api/v1/pxe/devices/state",
	"/platform.v1.PlatformDaemon/GetHealth":                  "GET /health",
	"/platform.v1.PlatformDaemon/Liveness":                   "GET /health/live",
	"/platform.v1.PlatformDaemon/Readiness":                  "GET /health/ready",
	"/platform.v1.ProvisioningGateway/GetBootConfig":         "GET /api/v1/provisioning/boot-config",
	"/platform.v1.ProvisioningGateway/NotifyInstallComplete": "POST /api/v1/provisioning/devices/install-complete",
	"/platform.v1.ProvisioningGateway/RegisterPXEDevice":     "POST /api/v1/provisioning/pxe/register",
	"/platform.v1.ProvisioningGateway/ReportDeviceState":     "POST /api/v1/provisioning/devices/state",
	"/platform.v1.SDNService/ApplyPolicy":                    "POST /api/v1/sdn/policies/apply",
	"/platform.v1.SwitchService/DisablePort":                 "POST /api/v1/switches/ports/disable",
	"/platform.v1.SwitchService/EnablePort":                  "POST /api/v1/switches/ports/enable",
	"/platform.v1.SwitchService/GetPortStatus":               "GET /api/v1/switches/ports/status",
	"/platform.v1.SwitchService/ListPorts":                   "GET /api/v1/switches/ports",
	"/platform.v1.SwitchService/SetPortVLAN":                 "POST /api/v1/switches/ports/vlan",
	"/platform.v1.TPMService/ReadNVRAM":                      "GET /api/v1/tpm/nvram",
	"/platform.v1.TPMService/UndefineNVRAM":                  "DELETE /api/v1/tpm/nvram",
	"/platform.v1.TPMService/WriteNVRAM":                     "PUT /api/v1/tpm/nvram",
	"/platform.v1.TenantService/DeleteTenant":                "DELETE /api/v1/tenants",
	"/platform.v1.TenantService/ResumeTenant":                "POST /api/v1/tenants/resume",
	"/platform.v1.TenantService/SuspendTenant":               "POST /api/v1/tenants/suspend",
	"/platform.v1.TenantService/UpdateTenant":                "PUT /api/v1/tenants",

	// The IAM rows sit after the alphabetical run above, in their own block,
	// so that adding them did not re-align every row beneath them and turn a
	// 30-row addition into a 70-line diff.
	//
	// IAM (#400). Thirty claims, three families, each row a judgment made
	// against the built router rather than against router.go's comments.
	//
	// (a) REPAIRED (#416). Seven item operations sent a collection path
	// (#379's shape on the mutating verbs): DeleteUser, DeleteRole,
	// DeleteGroup, DeleteTenant, AssignRole, RevokeRole and AddGroupMember.
	// The SDK now claims the item routes the server serves
	// (sdk/go/transport/rest/adapter.go, templatedRouteTable), so they resolve
	// in the walk below and have no row here. RemoveGroupMember and
	// GetCurrentUser, the two that resolved to the WRONG route, were fixed in
	// #414 (#415). The group operations have since gone with IAM groups
	// (go-quicbaas v0.14).

	// (b) RECORD — the rpc exists in iam.proto but rest/iam/router.go registers
	// no route for it under any path: the REST surface is users, roles,
	// policies, apps and tenants, and nothing else (docs/iam/api.md §2). This
	// is docs/13 G7's population: the route that is missing is the one named
	// by the claim.
	"/platform.v1.PlatformIAMService/CheckPermission": "POST /api/v1/iam/permissions/check",
	"/platform.v1.PlatformIAMService/CreateToken":     "POST /api/v1/iam/tokens",
	"/platform.v1.PlatformIAMService/RevokeToken":     "POST /api/v1/iam/tokens/revoke",
	"/platform.v1.PlatformIAMService/VerifyToken":     "POST /api/v1/iam/tokens/verify",

	// (c) RECORD — the claim names a gRPC method that does not exist. iam.proto
	// declares 41 rpcs; these 19 keys are none of them, and no route serves
	// their paths on either server. They are dead rows in the SDK's flat route
	// table (the MCP adapter maps Authenticate to iam_authenticate; nothing
	// else references any of them). Whether to delete them from the SDK table
	// or keep them as G7 roadmap is an owner call raised on #400; until it is
	// made they are recorded, not repaired.
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
		prefix := strings.SplitN(strings.TrimPrefix(c.Path, "/api/v1/"), "/", 2)[0]
		if _, ok := unservedPrefixes[prefix]; ok {
			continue
		}
		if want, ok := unroutedClaims[c.GRPCMethod]; ok {
			require.Equal(t, want, key,
				"%s is recorded in unroutedClaims as %q but now claims %q; update the entry "+
					"or remove it if the route now resolves", c.GRPCMethod, want, key)
			continue
		}

		req := httptest.NewRequest(c.Method, concreteClaim(c.Method, c.Path, built), nil)
		var match mux.RouteMatch
		if router.Match(req, &match) && match.MatchErr == nil {
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

func TestClaimAlignsWith(t *testing.T) {
	cases := []struct {
		name         string
		claim, route string
		want         bool
	}{
		{"pattern placeholder faces plain one", "GET /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}", true},
		{"placeholders differ only in name", "POST /api/v1/eab/credentials/{cid}/revoke", "POST /api/v1/eab/credentials/{id:[0-9]+}/revoke", true},
		{"identical literal route", "POST /api/v1/eab/credentials/validate", "POST /api/v1/eab/credentials/validate", true},
		{"different literal segment", "POST /api/v1/eab/credentials/{id}/revoke", "POST /api/v1/eab/credentials/{id:[0-9]+}/used", false},
		{"different method", "DELETE /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}", false},
		{"different segment count", "GET /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}/url", false},
		{"placeholder faces literal", "POST /api/v1/eab/credentials/{id}", "POST /api/v1/eab/credentials/validate", false},
		{"literal faces placeholder", "GET /api/v1/eab/credentials/abc", "GET /api/v1/eab/credentials/{id:[0-9]+}", false},
		{"claim without method", "/api/v1/eab/credentials", "GET /api/v1/eab/credentials", false},
		{"route without method", "GET /api/v1/eab/credentials", "/api/v1/eab/credentials", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, claimAlignsWith(tc.claim, tc.route))
		})
	}
}

func TestConcreteClaim(t *testing.T) {
	built := []string{
		"GET /api/v1/eab/credentials/key/{key}",
		"GET /api/v1/eab/credentials/{id:[0-9]+}",
	}

	require.Equal(t, "/api/v1/eab/credentials/1",
		concreteClaim("GET", "/api/v1/eab/credentials/{id}", built),
		"an aligned server route's pattern must pick the value")
	require.Equal(t, "/api/v1/eab/credentials/x",
		concreteClaim("DELETE", "/api/v1/eab/credentials/{id}", built),
		"with no aligned route the claim's own template is made concrete")
	require.Equal(t, "/api/v1/eab/credentials/key/x",
		concreteClaim("GET", "/api/v1/eab/credentials/key/{key}", built))
}

// TestUnroutedClaims_EveryEntryStillFailsToResolve keeps the ledger honest in
// the other direction from TestUnroutedClaims_EveryEntryIsStillAClaim: an entry
// whose claim now routes records a defect that is gone, and hides the claim
// from the walks that check where it lands.
func TestUnroutedClaims_EveryEntryStillFailsToResolve(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := walkRoutes(t, router)

	var resolving []string
	for _, c := range sdkrest.RouteClaims() {
		if _, ok := unroutedClaims[c.GRPCMethod]; !ok {
			continue
		}
		req := httptest.NewRequest(c.Method, concreteClaim(c.Method, c.Path, built), nil)
		var match mux.RouteMatch
		if router.Match(req, &match) && match.MatchErr == nil {
			resolving = append(resolving, c.GRPCMethod+"   ("+c.Method+" "+c.Path+")")
		}
	}
	sort.Strings(resolving)

	require.Emptyf(t, resolving,
		"%d unroutedClaims entr(ies) now resolve to a server route:\n  %s\n\n"+
			"Delete them and fix the count above unroutedClaims.",
		len(resolving), strings.Join(resolving, "\n  "))
}
