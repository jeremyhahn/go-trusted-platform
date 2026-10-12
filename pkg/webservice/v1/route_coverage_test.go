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
	"piv":      "xkms re-export, no REST route in this repo (docs/13 G7)",
	"ceremony": "qrdb re-export, no REST route in this repo (docs/13 G7)",
	"fido2":    "xkms re-export, no REST route in this repo (docs/13 G7)",
	"cluster":  "quicbaas re-export, no REST route in this repo (docs/13 G7)",

	// /api/v1/version is served by the daemon REST server (handleVersion), not
	// by the webservice router.
	"version": "daemon REST server, rest_service.go:handleVersion",
}

// unroutedClaims are the 98 claims where the server DOES serve the prefix but
// the client asks for a path that does not resolve. This is #321's shape at
// scale, and it is the actionable half of this test's findings.
//
// The dominant pattern is an item operation claiming a collection path:
//
//	DELETE /api/v1/dns/zones      (client)   vs   /api/v1/dns/zones/{zone}   (server)
//	DELETE /api/v1/iam/users      (client)   vs   an item path
//
// The flat route table's path is passed to DoRequest VERBATIM — no identifier is
// appended, it travels in the body — so these are the paths actually sent.
//
// Keyed by gRPC method, because the route is NOT unique: 94 methods claim 93
// distinct routes. GET /api/v1/dns/records is claimed by both GetRecord and
// ListRecords — a get-one and a list-many on the same collection path, which is
// #266's shape ("answers four operations and 404s on three") showing up in the
// client table rather than the server one. This map shrinking is what progress looks
// like; it is not a suppression list. Nothing may be added without a route
// having genuinely gone missing, which is the failure this test reports.
//
// The four GatewayService entries are one group with one cause: NAT64 status
// (#601) and the three perf verbs are registered on the DAEMON REST stack
// (pkg/api/rest/), and this router builds nothing for them. NAT64 is recorded
// alongside its neighbours rather than registered here because #660 leaves no
// production backend wired to any gatewayd-resident gateway surface — a route
// added here would resolve and then return unavailable — and because #154/#656
// is actively mounting the /sdn/gateway prefix on this router. The claims
// describe the intended surface correctly; this router's half is what is
// missing.
var unroutedClaims = map[string]string{
	"/platform.v1.AttestationService/ChallengeAK":              "POST /api/v1/attestation/challenge",
	"/platform.v1.AttestationService/CreateAK":                 "POST /api/v1/attestation/ak",
	"/platform.v1.AttestationService/GetAK":                    "GET /api/v1/attestation/ak",
	"/platform.v1.AttestationService/GetEK":                    "GET /api/v1/attestation/ek",
	"/platform.v1.AttestationService/VerifyChalleng":           "POST /api/v1/attestation/challenge/verify",
	"/platform.v1.AttestationService/VerifyQuote":              "POST /api/v1/attestation/verify",
	"/platform.v1.CAService/RenewCertificate":                  "POST /api/v1/ca/certificates/renew",
	"/platform.v1.CAService/RevokeCertificate":                 "POST /api/v1/ca/certificates/revoke",
	"/platform.v1.CAService/VerifyCertificate":                 "POST /api/v1/ca/certificates/verify",
	"/platform.v1.ComputeService/AttestContainer":              "POST /api/v1/compute/containers/attest",
	"/platform.v1.ComputeService/DeleteContainer":              "DELETE /api/v1/compute/containers",
	"/platform.v1.ComputeService/StartContainer":               "POST /api/v1/compute/containers/start",
	"/platform.v1.ComputeService/StopContainer":                "POST /api/v1/compute/containers/stop",
	"/platform.v1.DNSService/AddRecord":                        "POST /api/v1/dns/records",
	"/platform.v1.DNSService/DeleteRecord":                     "DELETE /api/v1/dns/records",
	"/platform.v1.DNSService/DeleteZone":                       "DELETE /api/v1/dns/zones",
	"/platform.v1.DNSService/GetRecord":                        "GET /api/v1/dns/records",
	"/platform.v1.DNSService/ListRecords":                      "GET /api/v1/dns/records",
	"/platform.v1.DNSService/Resolve":                          "GET /api/v1/dns/resolve",
	"/platform.v1.DeviceService/ActivateDevice":                "POST /api/v1/devices/activate",
	"/platform.v1.DeviceService/DeleteDevice":                  "DELETE /api/v1/devices",
	"/platform.v1.DeviceService/DeleteProfile":                 "DELETE /api/v1/device/profiles",
	"/platform.v1.DeviceService/FindDeviceBySerial":            "GET /api/v1/devices/by-serial",
	"/platform.v1.DeviceService/FindProfileByMACAddress":       "GET /api/v1/device/profiles/by-mac",
	"/platform.v1.DeviceService/FindProfileBySerial":           "GET /api/v1/device/profiles/by-serial",
	"/platform.v1.DeviceService/UpdateDevice":                  "PUT /api/v1/devices",
	"/platform.v1.DeviceService/UpdateProfile":                 "PUT /api/v1/device/profiles",
	"/platform.v1.EABService/DeleteCredential":                 "DELETE /api/v1/eab/credentials/{id}",
	"/platform.v1.EABService/GetCredential":                    "GET /api/v1/eab/credentials/{id}",
	"/platform.v1.EABService/GetCredentialQRCode":              "GET /api/v1/eab/credentials/{id}/qrcode",
	"/platform.v1.EABService/GetEnrollmentURL":                 "GET /api/v1/eab/credentials/{id}/url",
	"/platform.v1.EABService/MarkCredentialUsed":               "POST /api/v1/eab/credentials/{id}/used",
	"/platform.v1.EABService/RevokeCredential":                 "POST /api/v1/eab/credentials/{id}/revoke",
	"/platform.v1.GatewayService/GetNAT64Status":               "GET /api/v1/sdn/gateway/nat64/status",
	"/platform.v1.GatewayService/GetPerfConntrack":             "GET /api/v1/sdn/gateway/perf/conntrack",
	"/platform.v1.GatewayService/GetPerfDatapath":              "GET /api/v1/sdn/gateway/perf/datapath",
	"/platform.v1.GatewayService/GetPerfFlows":                 "POST /api/v1/sdn/gateway/perf/flows",
	"/platform.v1.IDevIDService/CreateLDevID":                  "POST /api/v1/idevid/ldevid",
	"/platform.v1.IDevIDService/Generate":                      "POST /api/v1/idevid",
	"/platform.v1.IDevIDService/GetCSR":                        "GET /api/v1/idevid/csr",
	"/platform.v1.IDevIDService/GetCert":                       "GET /api/v1/idevid/cert",
	"/platform.v1.IDevIDService/InstallCert":                   "POST /api/v1/idevid/cert",
	"/platform.v1.InvitationService/DeleteInvitation":          "DELETE /api/v1/invitations",
	"/platform.v1.InvitationService/GetInvitationByToken":      "GET /api/v1/invitations/by-token",
	"/platform.v1.InvitationService/RevokeInvitation":          "POST /api/v1/invitations/revoke",
	"/platform.v1.KeyManagementService/Decrypt":                "POST /api/v1/kms/decrypt",
	"/platform.v1.KeyManagementService/DeleteKey":              "DELETE /api/v1/kms/keys",
	"/platform.v1.KeyManagementService/Encrypt":                "POST /api/v1/kms/encrypt",
	"/platform.v1.KeyManagementService/GenerateDataKey":        "POST /api/v1/kms/data-keys",
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": "POST /api/v1/kms/data-keys/wrapped",
	"/platform.v1.KeyManagementService/RotateKey":              "POST /api/v1/kms/keys/rotate",
	"/platform.v1.KeyManagementService/Sign":                   "POST /api/v1/kms/sign",
	"/platform.v1.KeyManagementService/Verify":                 "POST /api/v1/kms/verify",
	"/platform.v1.OverlayService/DeleteVNI":                    "DELETE /api/v1/overlay/vnis",
	"/platform.v1.PXEService/Authorize":                        "POST /api/v1/pxe/devices/authorize",
	"/platform.v1.PXEService/Quarantine":                       "POST /api/v1/pxe/devices/quarantine",
	"/platform.v1.PXEService/UpdateState":                      "PUT /api/v1/pxe/devices/state",
	"/platform.v1.PlatformDaemon/GetHealth":                    "GET /health",
	"/platform.v1.PlatformDaemon/Liveness":                     "GET /health/live",
	"/platform.v1.PlatformDaemon/Readiness":                    "GET /health/ready",
	"/platform.v1.ProvisioningGateway/GetBootConfig":           "GET /api/v1/provisioning/boot-config",
	"/platform.v1.ProvisioningGateway/NotifyInstallComplete":   "POST /api/v1/provisioning/devices/install-complete",
	"/platform.v1.ProvisioningGateway/RegisterPXEDevice":       "POST /api/v1/provisioning/pxe/register",
	"/platform.v1.ProvisioningGateway/ReportDeviceState":       "POST /api/v1/provisioning/devices/state",
	"/platform.v1.SDNService/AddPort":                          "POST /api/v1/sdn/ports",
	"/platform.v1.SDNService/ApplyPolicy":                      "POST /api/v1/sdn/policies/apply",
	"/platform.v1.SDNService/AuthenticatePort":                 "POST /api/v1/sdn/ports/auth",
	"/platform.v1.SDNService/DeleteBridge":                     "DELETE /api/v1/sdn/bridges",
	"/platform.v1.SDNService/DeletePort":                       "DELETE /api/v1/sdn/ports",
	"/platform.v1.SDNService/GetPortState":                     "GET /api/v1/sdn/ports/state",
	"/platform.v1.SDNService/RevokePortAuth":                   "DELETE /api/v1/sdn/ports/auth",
	"/platform.v1.SDNService/SetPortState":                     "POST /api/v1/sdn/ports/state",
	"/platform.v1.SwitchService/DisablePort":                   "POST /api/v1/switches/ports/disable",
	"/platform.v1.SwitchService/EnablePort":                    "POST /api/v1/switches/ports/enable",
	"/platform.v1.SwitchService/GetPortStatus":                 "GET /api/v1/switches/ports/status",
	"/platform.v1.SwitchService/ListPorts":                     "GET /api/v1/switches/ports",
	"/platform.v1.SwitchService/SetPortVLAN":                   "POST /api/v1/switches/ports/vlan",
	"/platform.v1.TPMService/ReadNVRAM":                        "GET /api/v1/tpm/nvram",
	"/platform.v1.TPMService/UndefineNVRAM":                    "DELETE /api/v1/tpm/nvram",
	"/platform.v1.TPMService/WriteNVRAM":                       "PUT /api/v1/tpm/nvram",
	"/platform.v1.TenantService/DeleteTenant":                  "DELETE /api/v1/tenants",
	"/platform.v1.TenantService/ResumeTenant":                  "POST /api/v1/tenants/resume",
	"/platform.v1.TenantService/SuspendTenant":                 "POST /api/v1/tenants/suspend",
	"/platform.v1.TenantService/UpdateTenant":                  "PUT /api/v1/tenants",
	"/platform.v1.VTPMService/Create":                          "POST /api/v1/vtpm/instances",
	"/platform.v1.VTPMService/Delete":                          "DELETE /api/v1/vtpm/instances",
	"/platform.v1.VTPMService/ExtendVTPMPCR":                   "POST /api/v1/vtpm/pcrs/extend",
	"/platform.v1.VTPMService/GetState":                        "GET /api/v1/vtpm/instances/state",
	"/platform.v1.VTPMService/List":                            "GET /api/v1/vtpm/instances",
	"/platform.v1.VTPMService/QuoteVTPM":                       "POST /api/v1/vtpm/quote",
	"/platform.v1.VTPMService/ReadVTPMPCR":                     "GET /api/v1/vtpm/pcrs",
	"/platform.v1.VTPMService/SealVTPM":                        "POST /api/v1/vtpm/seal",
	"/platform.v1.VTPMService/Start":                           "POST /api/v1/vtpm/instances/start",
	"/platform.v1.VTPMService/Stop":                            "POST /api/v1/vtpm/instances/stop",
	"/platform.v1.VTPMService/UnsealVTPM":                      "POST /api/v1/vtpm/unseal",

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
	// #414 (#415).

	// (b) RECORD — the rpc exists in iam.proto but rest/iam/router.go registers
	// no route for it under any path: the REST surface is users, groups, roles,
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

		req := httptest.NewRequest(c.Method, concreteFor(c.Path), nil)
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
