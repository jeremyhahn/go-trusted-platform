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
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// Route-table-only backends. Each embeds the interface it stands in for and
// implements nothing: the setters below only register routes, and no request
// is served, so no method is ever called.
type (
	routeTableConfigDelivery struct{ configdelivery.RestHandler }
	routeTableBMC            struct{ bmcwebsvc.RestHandler }
	routeTableDevices        struct{ restapi.DeviceServiceInterface }
	routeTableProfiles       struct {
		restapi.ProfileServiceInterface
	}
	routeTableTenants struct{ restapi.TenantManagerInterface }
	routeTableKMS     struct{ restapi.KMSService }
	routeTableOverlay struct {
		restapi.OverlayServiceInterface
	}
	routeTableCA struct {
		quicbaasca.CACertificateAuthority
	}
	routeTableVTPM  struct{ vtpm.VTPMService }
	routeTableProxy struct{ restapi.ProxyServiceBackend }
)

// daemonRouteTable builds a daemon REST server with every route-mounting
// setter wired, and returns it with its built table.
func daemonRouteTable(t *testing.T) (*RESTServer, []string) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	log := logging.DefaultLogger()
	s.SetConfigDeliveryHandler(routeTableConfigDelivery{})
	s.SetBMCHandler(routeTableBMC{})
	s.SetNTPHandlers(platformv1.UnimplementedNTPServiceServer{}, nil)
	s.SetOrchestratorHandlers(platformv1.UnimplementedOrchestratorServiceServer{}, nil, "")
	s.SetVPNHandlers(platformv1.UnimplementedVPNServiceServer{}, nil)
	s.SetAppServiceHandlers(restapi.AppServiceServers{}, nil)
	s.SetDeviceHandlers(routeTableDevices{}, routeTableProfiles{}, platformv1.UnimplementedDeviceServiceServer{})
	s.SetTenantHandlers(routeTableTenants{}, nil, "")
	s.SetKMSHandlers(routeTableKMS{})
	s.SetComputeHandlers(platformv1.UnimplementedComputeServiceServer{}, nil)
	s.SetOverlayHandlers(routeTableOverlay{})
	s.SetCAHandlers(routeTableCA{}, nil)
	s.SetTPMHandlers(platformv1.UnimplementedTPMServiceServer{}, nil)
	s.SetVTPMService(routeTableVTPM{})
	s.SetSDNService(nil)
	s.SetGatewayIPAMService(nil, nil)
	s.SetProxyService(routeTableProxy{})
	s.SetClusterService(nil)
	s.SetCeremonyService(NewCeremonyService(log, nil))
	s.SetPIVService(NewPIVService(log, nil))
	s.SetLUKSService(NewLUKSService(log, nil, RootCheckerFunc(func() bool { return true })))
	s.SetFIDO2Service(NewFIDO2Service(log, nil))

	return s, testutil.WalkRoutes(t, s.Router())
}

// daemonDivergentClaims are SDK claims under a prefix both REST servers serve
// that reach no daemon route of their own shape. All but GetBootConfig and
// GetContainerLogs resolve on the webservice router, where
// route_coverage_test.go checks them. One SDK route table addresses both
// servers, so repointing a claim at the daemon's shape would break it on the
// webservice: which server answers the operation, or the daemon gaining the
// webservice's route, is a capability decision (#452). Keyed by gRPC method.
// TestDaemonDivergentClaims_StillDiverge makes the map shrink-only.
var daemonDivergentClaims = map[string]string{
	"/platform.v1.CAService/RevokeCertificate": "#452: the daemon revokes at POST /api/v1/ca/certificates/{serial}/revoke; the claim is the webservice's DELETE shape",

	"/platform.v1.ComputeService/GetContainerLogs": "#452: lands on GET /api/v1/compute/containers/{id} with id=\"logs\"; neither server serves container logs (claim_operation_resolution_test.go)",

	"/platform.v1.DeviceService/CountDevices":                 "#452: the daemon has no count route; the request lands on GET /api/v1/devices/{id} with id=\"count\"",
	"/platform.v1.DeviceService/DisableDevice":                "#452: the daemon's device routes (pkg/api/rest) have no disable",
	"/platform.v1.DeviceService/EnableDevice":                 "#452: the daemon's device routes (pkg/api/rest) have no enable",
	"/platform.v1.DeviceService/RecordAttestationCertificate": "#452: the daemon's device routes (pkg/api/rest) have no attest-cert/record",

	"/platform.v1.IDevIDService/ActivateCredential":       idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/CreateIAKCSR":             idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/CreateIDevIDCSR":          idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/DeleteIAKCertificate":     idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/DeleteIDevIDCertificate":  idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/FlushTransientContexts":   idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GenerateIAK":              idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GenerateIDevID":           idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GetDeviceAttributes":      idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GetIAKCertificate":        idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GetIAKInfo":               idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GetIDevIDCertificate":     idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/GetIDevIDInfo":            idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/HasIAK":                   idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/HasIDevID":                idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/InstallIAKCertificate":    idevidOnTPMPrefix,
	"/platform.v1.IDevIDService/InstallIDevIDCertificate": idevidOnTPMPrefix,

	"/platform.v1.KeyManagementService/Decrypt":                kmsKeyInBody,
	"/platform.v1.KeyManagementService/Encrypt":                kmsKeyInBody,
	"/platform.v1.KeyManagementService/Sign":                   kmsKeyInBody,
	"/platform.v1.KeyManagementService/Verify":                 kmsKeyInBody,
	"/platform.v1.KeyManagementService/GenerateDataKey":        "#452: the daemon's KMS routes have no data-keys",
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": "#452: the daemon's KMS routes have no data-keys/wrapped",

	"/platform.v1.ProvisioningGateway/GetBootConfig":         "#452: no server serves it; platformd holds no per-MAC boot configuration (route_coverage_test.go unroutedClaims)",
	"/platform.v1.ProvisioningGateway/NotifyInstallComplete": pxeGatewayOnWebservice,
	"/platform.v1.ProvisioningGateway/RegisterPXEDevice":     pxeGatewayOnWebservice,
	"/platform.v1.ProvisioningGateway/ReportDeviceState":     pxeGatewayOnWebservice,

	"/platform.v1.SDNService/AuthenticatePort": "#452: the daemon's SDN routes have no port auth",
	"/platform.v1.SDNService/RevokePortAuth":   "#452: the daemon's SDN routes have no port auth",
	"/platform.v1.SDNService/DeleteFlow":       "#452: the daemon deletes at DELETE /api/v1/sdn/flows/{id}; the claim is the webservice's collection path",

	"/platform.v1.TenantService/CheckQuota":             "#452 (claim from #304): the daemon checks at POST /api/v1/tenants/{id}/check-quota with its own JSON; the claim is the webservice's /quota-check (sdk_rest_roundtrip_test.go)",
	"/platform.v1.TenantService/GetTenantBarrierStatus": "#452: the daemon serves GET /api/v1/tenants/{id}/barrier/status (docs/tenant/api.md); the claim is the webservice's /barrier",
	"/platform.v1.TenantService/GetTenantByName":        "#452 (claim from #304): the daemon looks up at GET /api/v1/tenants/name/{name}; the claim is the webservice's system-only /by-name/{name} (sdk_rest_roundtrip_test.go)",
	"/platform.v1.TenantService/GetTenantDEKStatus":     "#452 (claim from #304): the daemon serves GET /api/v1/tenants/{id}/dek/status with its own JSON; the claim is the webservice's /dek (sdk_rest_roundtrip_test.go)",

	"/platform.v1.VTPMService/ReadVTPMPCR":   "#452: the daemon reads one PCR at GET /api/v1/vtpm/bundles/{id}/pcr/{index}; the claim is the webservice's /pcrs",
	"/platform.v1.VTPMService/ExtendVTPMPCR": "#452: the daemon's vTPM routes have no PCR extend",
}

const (
	idevidOnTPMPrefix      = "#452: the daemon serves IDevID and IAK under /api/v1/tpm/idevid and /api/v1/tpm/iak (rest_idevid.go, registerIDevIDRoutes); the claim is the webservice's /api/v1/idevid shape"
	kmsKeyInBody           = "#452: the daemon takes the key in the body at POST /api/v1/kms/{encrypt,decrypt,sign,verify}; the claim is the webservice's /{name} path"
	pxeGatewayOnWebservice = "#452: the per-MAC PXE gateway routes are the webservice's (rest/pxe/gateway.go); the daemon mounts none"
)

// landsOnClaimedShape routes the claim through the daemon's table. It returns
// the template the request reached, and whether that template has the claim's
// shape: a claim that resolves to a sibling route is answered by a different
// operation, which is no better than a 404 (#321).
func landsOnClaimedShape(s *RESTServer, built []string, c sdkrest.RouteClaim) (string, bool) {
	route, ok := testutil.MatchClaim(s.Router(), c.Method, c.Path, built)
	if !ok {
		return "", false
	}
	template, err := route.GetPathTemplate()
	if err != nil {
		return "", false
	}
	return template, testutil.NormalisePlaceholders(template) == testutil.NormalisePlaceholders(c.Path)
}

// servedPrefixes counts the daemon's built /api/v1 routes by first segment.
func servedPrefixes(built []string) map[string]int {
	served := map[string]int{}
	for _, route := range built {
		_, path, _ := strings.Cut(route, " ")
		if strings.HasPrefix(path, "/api/v1/") {
			served[testutil.ClaimPrefix(path)]++
		}
	}
	return served
}

// TestDaemonRESTRouteClaims_ResolveAgainstBuiltRoutes is the daemon half of
// route_coverage_test.go: every SDK claim under a prefix this server serves
// must route to a template of the claim's own shape, or be recorded in
// daemonDivergentClaims. As there, the check runs one way; the daemon may
// serve more than any SDK method calls.
func TestDaemonRESTRouteClaims_ResolveAgainstBuiltRoutes(t *testing.T) {
	s, built := daemonRouteTable(t)
	served := servedPrefixes(built)
	require.NotEmpty(t, served, "the fixture built no /api/v1 routes; this test would pass vacuously")

	claims := sdkrest.RouteClaims()
	sort.Slice(claims, func(i, j int) bool { return claims[i].GRPCMethod < claims[j].GRPCMethod })

	checked := map[string]int{}
	var broken []string
	for _, c := range claims {
		prefix := testutil.ClaimPrefix(c.Path)
		if served[prefix] == 0 {
			continue
		}
		checked[prefix]++
		if _, ok := daemonDivergentClaims[c.GRPCMethod]; ok {
			continue
		}
		template, ok := landsOnClaimedShape(s, built, c)
		if ok {
			continue
		}
		if template == "" {
			template = "no route"
		}
		broken = append(broken, c.GRPCMethod+"\n      claims:  "+c.Method+" "+c.Path+"\n      matched: "+template)
	}

	prefixes := make([]string, 0, len(checked))
	total := 0
	for prefix, n := range checked {
		prefixes = append(prefixes, prefix)
		total += n
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		t.Logf("%-14s %3d claim(s) checked against %3d daemon route(s)", prefix, checked[prefix], served[prefix])
	}
	t.Logf("%d claims checked, %d recorded in daemonDivergentClaims", total, len(daemonDivergentClaims))
	require.GreaterOrEqual(t, total, 200,
		"only %d claims fell under a daemon prefix; the fixture almost certainly failed to wire a setter", total)

	require.Emptyf(t, broken,
		"%d SDK route claim(s) do not reach a daemon route of their own shape:\n\n    %s\n\n"+
			"Fix the claim in sdk/go/transport/rest/adapter.go when the daemon's route is the "+
			"contract, or, when the webservice serves the claim and the choice of server is "+
			"open, record it in daemonDivergentClaims with the issue that tracks it.",
		len(broken), strings.Join(broken, "\n\n    "))
}

// TestDaemonOnlyPrefixes_DaemonServesEach keeps testutil.DaemonOnlyPrefixes
// honest on this side. The webservice walk skips claims under each entry, so
// an entry this server builds nothing under would leave those claims checked
// by neither test.
func TestDaemonOnlyPrefixes_DaemonServesEach(t *testing.T) {
	_, built := daemonRouteTable(t)

	routes := map[string]int{}
	for _, route := range built {
		_, path, _ := strings.Cut(route, " ")
		if prefix, ok := testutil.DaemonOnlyPrefixOf(path); ok {
			routes[prefix]++
		}
	}

	var empty []string
	for prefix := range testutil.DaemonOnlyPrefixes {
		if routes[prefix] == 0 {
			empty = append(empty, prefix)
		}
	}
	sort.Strings(empty)
	require.Emptyf(t, empty,
		"the daemon REST server builds no route under %v; remove the entries from "+
			"testutil.DaemonOnlyPrefixes so the webservice walk checks their claims", empty)
}

// TestDaemonDivergentClaims_StillDiverge makes daemonDivergentClaims a
// ratchet: an entry whose claim now lands on its own shape, which is no
// longer a claim, or whose prefix the daemon no longer serves must be deleted.
func TestDaemonDivergentClaims_StillDiverge(t *testing.T) {
	s, built := daemonRouteTable(t)
	served := servedPrefixes(built)

	live := map[string]sdkrest.RouteClaim{}
	for _, c := range sdkrest.RouteClaims() {
		live[c.GRPCMethod] = c
	}

	var stale []string
	for method, reason := range daemonDivergentClaims {
		require.Containsf(t, reason, "#452", "%s: every entry names the issue that tracks it", method)
		c, ok := live[method]
		switch {
		case !ok:
			stale = append(stale, method+" (no longer a claim)")
		case served[testutil.ClaimPrefix(c.Path)] == 0:
			stale = append(stale, method+" (the daemon no longer serves "+testutil.ClaimPrefix(c.Path)+")")
		default:
			if _, lands := landsOnClaimedShape(s, built, c); lands {
				stale = append(stale, method+" (now lands on "+c.Method+" "+c.Path+")")
			}
		}
	}

	sort.Strings(stale)
	require.Emptyf(t, stale,
		"%d daemonDivergentClaims entr(ies) no longer describe a divergence:\n  %s\n\nDelete them.",
		len(stale), strings.Join(stale, "\n  "))
}
