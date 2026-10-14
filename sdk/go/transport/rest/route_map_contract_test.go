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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serviceClientContracts maps a proto service name to the generated client
// interface that defines its methods. The generated interface is the
// authority on what a service HAS: it is produced from the .proto, so a
// method absent here does not exist on any transport.
//
// All 31 generated *Client interfaces are listed. Reflection cannot
// enumerate the types in a package, so this is hand-written — but it is
// COMPLETE, and completeness is the point: a partial list would make the
// test report a clean run over services it never looked at, which is the
// defect class this whole campaign keeps finding. An unrecognised service
// name is therefore treated as a finding rather than skipped.
func serviceClientContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"AttestationService":    reflect.TypeOf((*platformv1.AttestationServiceClient)(nil)).Elem(),
		"BMCService":            reflect.TypeOf((*platformv1.BMCServiceClient)(nil)).Elem(),
		"BarrierService":        reflect.TypeOf((*platformv1.BarrierServiceClient)(nil)).Elem(),
		"CAService":             reflect.TypeOf((*platformv1.CAServiceClient)(nil)).Elem(),
		"CacheService":          reflect.TypeOf((*platformv1.CacheServiceClient)(nil)).Elem(),
		"CeremonyService":       reflect.TypeOf((*platformv1.CeremonyServiceClient)(nil)).Elem(),
		"ClusterService":        reflect.TypeOf((*platformv1.ClusterServiceClient)(nil)).Elem(),
		"ComputeService":        reflect.TypeOf((*platformv1.ComputeServiceClient)(nil)).Elem(),
		"ConfigDeliveryService": reflect.TypeOf((*platformv1.ConfigDeliveryServiceClient)(nil)).Elem(),
		"DNSService":            reflect.TypeOf((*platformv1.DNSServiceClient)(nil)).Elem(),
		"DeviceService":         reflect.TypeOf((*platformv1.DeviceServiceClient)(nil)).Elem(),
		"EABService":            reflect.TypeOf((*platformv1.EABServiceClient)(nil)).Elem(),
		"FIDO2Service":          reflect.TypeOf((*platformv1.FIDO2ServiceClient)(nil)).Elem(),
		"GatewayService":        reflect.TypeOf((*platformv1.GatewayServiceClient)(nil)).Elem(),
		"IDevIDService":         reflect.TypeOf((*platformv1.IDevIDServiceClient)(nil)).Elem(),
		"InvitationService":     reflect.TypeOf((*platformv1.InvitationServiceClient)(nil)).Elem(),
		"KeyManagementService":  reflect.TypeOf((*platformv1.KeyManagementServiceClient)(nil)).Elem(),
		"LUKSService":           reflect.TypeOf((*platformv1.LUKSServiceClient)(nil)).Elem(),
		"MessagingService":      reflect.TypeOf((*platformv1.MessagingServiceClient)(nil)).Elem(),
		"NTPService":            reflect.TypeOf((*platformv1.NTPServiceClient)(nil)).Elem(),
		"OverlayService":        reflect.TypeOf((*platformv1.OverlayServiceClient)(nil)).Elem(),
		"PIVService":            reflect.TypeOf((*platformv1.PIVServiceClient)(nil)).Elem(),
		"PXEService":            reflect.TypeOf((*platformv1.PXEServiceClient)(nil)).Elem(),
		"PlatformDaemon":        reflect.TypeOf((*platformv1.PlatformDaemonClient)(nil)).Elem(),
		"PlatformIAMService":    reflect.TypeOf((*platformv1.PlatformIAMServiceClient)(nil)).Elem(),
		"ProvisioningGateway":   reflect.TypeOf((*platformv1.ProvisioningGatewayClient)(nil)).Elem(),
		"ProxyService":          reflect.TypeOf((*platformv1.ProxyServiceClient)(nil)).Elem(),
		"RegistryService":       reflect.TypeOf((*platformv1.RegistryServiceClient)(nil)).Elem(),
		"SDNService":            reflect.TypeOf((*platformv1.SDNServiceClient)(nil)).Elem(),
		"SchedulerService":      reflect.TypeOf((*platformv1.SchedulerServiceClient)(nil)).Elem(),
		"SwitchService":         reflect.TypeOf((*platformv1.SwitchServiceClient)(nil)).Elem(),
		"TPMService":            reflect.TypeOf((*platformv1.TPMServiceClient)(nil)).Elem(),
		"TenantService":         reflect.TypeOf((*platformv1.TenantServiceClient)(nil)).Elem(),
		"VPNService":            reflect.TypeOf((*platformv1.VPNServiceClient)(nil)).Elem(),
		"VTPMService":           reflect.TypeOf((*platformv1.VTPMServiceClient)(nil)).Elem(),
	}
}

// declaredMethods returns every gRPC method named by the REST route maps,
// from BOTH maps.
//
// Reading both is the point. An earlier count of this population read only
// grpcMethodToRESTMap, reported ProxyService as 8 declared, and missed the 6
// entries in templatedRouteTable — a bounded view answering as though it were
// the whole. The two are disjoint and both are authoritative.
func declaredMethods() []string {
	out := make([]string, 0, len(grpcMethodToRESTMap)+len(templatedRouteTable))
	for m := range grpcMethodToRESTMap {
		out = append(out, m)
	}
	for m := range templatedRouteTable {
		out = append(out, m)
	}
	return out
}

// TestRouteMaps_DeclareNoMethodThatDoesNotExist is the regression guard for
// the ghost entries removed in #333.
//
// The REST route maps declared 20 IAM methods that exist in NO proto service
// — `ListActiveSesss` and `RevokeAllSesss` among them, visibly truncated
// names. Each had exactly one reference in the entire repository: its own map
// entry. They could never route, because no generated client can produce
// those method strings.
//
// A map entry naming a method that does not exist is worse than a missing
// route. A missing route is a gap; an entry like this is a claim about a
// surface that was never proposed, and it inflates any measurement of the
// SDK's shipped surface — which is exactly what happened when this population
// was first counted for docs/13 G7.
func TestRouteMaps_DeclareNoMethodThatDoesNotExist(t *testing.T) {
	contracts := serviceClientContracts()

	var ghosts []string
	for _, full := range declaredMethods() {
		// "/platform.v1.SomeService/SomeMethod"
		parts := strings.Split(strings.TrimPrefix(full, "/"), "/")
		if len(parts) != 2 {
			continue
		}
		pkgParts := strings.Split(parts[0], ".")
		service := pkgParts[len(pkgParts)-1]
		method := parts[1]

		iface, known := contracts[service]
		if !known {
			// Every generated *Client interface is listed above, so an
			// unknown service name here means the maps reference a service
			// that does not exist at all — a ghost one level up.
			ghosts = append(ghosts, full+" (unknown service)")
			continue
		}
		if _, ok := iface.MethodByName(method); !ok {
			ghosts = append(ghosts, full)
		}
	}

	// knownUnroutable is a BASELINE, not an exemption list, and it differs
	// from the hand-maintained manifests this repo keeps finding stale in one
	// way that matters: this test IS its checker. A new ghost fails here
	// immediately; the list can only shrink.
	//
	// They are not all the same defect, which is why they are not simply
	// deleted along with the IAM entries removed in #333:
	//
	//   - Some name a method that does not exist AND a path that is served
	//     nowhere — pure cruft, safe to delete.
	//   - Others name a method that does not exist but a path that IS served.
	//     Liveness and Readiness map to routes pkg/api/daemon/rest_service.go
	//     serves, but the proto declares no such methods. They are MISNAMED
	//     BRIDGES to working routes; Health was one until #138 renamed its key
	//     to the real GetHealth.
	//
	// Sorting the two apart is per-entry work tracked separately; doing it by
	// eye here would be the guess this test exists to remove.
	knownUnroutable := map[string]bool{
		"/platform.v1.PlatformDaemon/Liveness":  true,
		"/platform.v1.PlatformDaemon/Readiness": true,
	}

	var unexpected []string
	for _, g := range ghosts {
		if !knownUnroutable[g] {
			unexpected = append(unexpected, g)
		}
	}

	assert.Empty(t, unexpected,
		"the REST route maps name %d NEW gRPC method(s) that do not exist on their "+
			"service's generated client, so no caller can produce them and no route can "+
			"serve them: %v", len(unexpected), unexpected)

	// The baseline must shrink, never grow silently: an entry that has been
	// fixed should be removed from the list above.
	for entry := range knownUnroutable {
		found := false
		for _, g := range ghosts {
			if g == entry {
				found = true
				break
			}
		}
		assert.True(t, found,
			"%s is in knownUnroutable but is no longer a ghost — delete the baseline "+
				"entry so the list keeps shrinking", entry)
	}
}

// TestRouteMaps_AreDisjoint pins the assumption the count above rests on: a
// method declared in both maps would be counted twice and dispatched by
// whichever branch runs first.
func TestRouteMaps_AreDisjoint(t *testing.T) {
	for m := range templatedRouteTable {
		_, dup := grpcMethodToRESTMap[m]
		assert.False(t, dup,
			"%s is declared in BOTH templatedRouteTable and grpcMethodToRESTMap; "+
				"the flat branch is unreachable for it and any census counts it twice", m)
	}
}

// TestRouteMaps_IAMDeclaresOnlyRealMethods is the specific case, kept
// separate so a failure names IAM rather than a list.
func TestRouteMaps_IAMDeclaresOnlyRealMethods(t *testing.T) {
	iface := reflect.TypeOf((*platformv1.PlatformIAMServiceClient)(nil)).Elem()
	require.Positive(t, iface.NumMethod())

	for _, full := range declaredMethods() {
		if !strings.Contains(full, "PlatformIAMService/") {
			continue
		}
		method := full[strings.LastIndex(full, "/")+1:]
		_, ok := iface.MethodByName(method)
		assert.True(t, ok,
			"the REST map declares PlatformIAMService/%s, which is not on the generated "+
				"IAM client — it exists on no transport", method)
	}
}
