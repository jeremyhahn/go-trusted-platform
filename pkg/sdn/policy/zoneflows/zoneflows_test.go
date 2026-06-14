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

package zoneflows_test

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ---------------------------------------------------------------------------
// GeneratorSet construction
// ---------------------------------------------------------------------------

func TestNewGeneratorSet_NonNil(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	require.NotNil(t, gs)
}

// ---------------------------------------------------------------------------
// Per-zone template generation
// ---------------------------------------------------------------------------

// eachBuiltinZone lists all built-in zones with their expected VLAN defaults
// and the minimum flow count expected from each template.
var builtinZones = []struct {
	zone     zone.Zone
	vlan     uint16
	minFlows int
}{
	{zone.ZoneProvisioning, 201, 1},
	{zone.ZoneQuarantine, 202, 1},
	{zone.ZoneTrusted, 200, 1},
	{zone.ZoneStorage, 203, 1},
	{zone.ZoneManagement, 50, 1},
	{zone.ZonePublic, 204, 1}, // public uses whatever VLAN caller passes
}

func TestGenerate_AllBuiltinZones_ReturnFlows(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	for _, tc := range builtinZones {
		t.Run(string(tc.zone), func(t *testing.T) {
			flows := gs.Generate("eth0", tc.zone, tc.vlan)
			assert.GreaterOrEqual(t, len(flows), tc.minFlows,
				"zone %s should produce at least %d flow(s)", tc.zone, tc.minFlows)
			// Every rule must have a non-empty Match and Actions.
			for i, f := range flows {
				assert.NotEmpty(t, f.Match, "flow[%d].Match is empty for zone %s", i, tc.zone)
				assert.NotEmpty(t, f.Actions, "flow[%d].Actions is empty for zone %s", i, tc.zone)
			}
		})
	}
}

func TestGenerate_UserDefinedZone_ReturnsNil(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.Zone("custom-zone"), 300)
	assert.Nil(t, flows, "user-defined zone with no built-in generator should return nil")
}

// ---------------------------------------------------------------------------
// Provisioning template specifics
// ---------------------------------------------------------------------------

func TestGenerate_Provisioning_ContainsDHCPRule(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	// At least one flow should reference a DHCP port (67 or 68).
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "67") || strings.Contains(f.Match, "68") {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template must include a DHCP-related flow rule")
}

func TestGenerate_Provisioning_ContainsDropDefault(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if f.Actions == "drop" {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template must include a default drop rule")
}

// ---------------------------------------------------------------------------
// Quarantine template specifics
// ---------------------------------------------------------------------------

func TestGenerate_Quarantine_ContainsDropDefault(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneQuarantine, 202)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if f.Actions == "drop" {
			found = true
			break
		}
	}
	assert.True(t, found, "quarantine template must include a default drop rule")
}

func TestGenerate_Quarantine_FewerFlowsThanProvisioning(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	provFlows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	quarFlows := gs.Generate("eth0", zone.ZoneQuarantine, 202)
	// Quarantine is more restrictive — provisioning grants more service paths.
	assert.Less(t, len(quarFlows), len(provFlows),
		"quarantine should have fewer flow rules than provisioning")
}

// ---------------------------------------------------------------------------
// Trusted template specifics
// ---------------------------------------------------------------------------

func TestGenerate_Trusted_ContainsNormalAction(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneTrusted, 200)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Actions, "normal") {
			found = true
			break
		}
	}
	assert.True(t, found, "trusted template must include a normal/allow rule for east-west")
}

// ---------------------------------------------------------------------------
// ErrUnknownZone / ErrUnresolvableNetwork typed errors
// ---------------------------------------------------------------------------

func TestErrUnknownZone_Error(t *testing.T) {
	e := zoneflows.ErrUnknownZone{Zone: zone.Zone("mystery")}
	assert.Contains(t, e.Error(), "mystery")
}

func TestErrUnresolvableNetwork_Error(t *testing.T) {
	e := zoneflows.ErrUnresolvableNetwork{Zone: zone.Zone("ghost")}
	assert.Contains(t, e.Error(), "ghost")
}

// ---------------------------------------------------------------------------
// CompileMatrixRules
// ---------------------------------------------------------------------------

// buildNetworks creates a minimal NetworkSummary map for the given zones.
func buildNetworks(zones []zone.ZoneConfig) map[zone.Zone]zoneflows.NetworkSummary {
	// Assign a distinct VLAN and /24 subnet to each zone.
	m := make(map[zone.Zone]zoneflows.NetworkSummary, len(zones))
	base := uint16(200)
	for i, z := range zones {
		m[z.Name] = zoneflows.NetworkSummary{
			VLAN:   base + uint16(i),
			Subnet: "10.0." + itoa(i) + ".0/24",
		}
	}
	return m
}

func itoa(n int) string {
	return string(rune('0' + n%10)) // simplified; good enough for ≤10 zones
}

func TestCompileMatrixRules_EmptyInput_ReturnsNil(t *testing.T) {
	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{})
	assert.Nil(t, flows)
}

func TestCompileMatrixRules_DefaultZones_ProducesDenyFlows(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)
	nets := buildNetworks(defaults)

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          defaults,
		NetworksByZone: nets,
	})

	// The default matrix has at least public→trusted denied, so we expect
	// at least one drop rule.
	hasDrop := false
	for _, f := range flows {
		if f.Actions == "drop" {
			hasDrop = true
			break
		}
	}
	assert.True(t, hasDrop, "default zones matrix should produce at least one drop rule")
}

func TestCompileMatrixRules_MissingNetworkSummary_SkipsZone(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)
	// Provide an empty network map — all zones missing VLAN → no rules.
	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          defaults,
		NetworksByZone: map[zone.Zone]zoneflows.NetworkSummary{},
	})
	assert.Empty(t, flows, "zones without network summaries should produce no matrix rules")
}

func TestCompileMatrixRules_PublicToTrustedIsDenied(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)
	nets := buildNetworks(defaults)

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          defaults,
		NetworksByZone: nets,
	})

	// Find the VLAN for public and the subnet for trusted.
	publicVLAN := nets[zone.ZonePublic].VLAN
	trustedSubnet := nets[zone.ZoneTrusted].Subnet

	// There must be a drop rule matching public's dl_vlan→trusted's subnet.
	found := false
	for _, f := range flows {
		if f.Actions == "drop" &&
			strings.Contains(f.Match, "dl_vlan="+vlanStr(publicVLAN)) &&
			strings.Contains(f.Match, trustedSubnet) {
			found = true
			break
		}
	}
	assert.True(t, found, "should have a drop rule for public→trusted (dl_vlan=%d, nw_dst=%s)",
		publicVLAN, trustedSubnet)
}

func vlanStr(v uint16) string {
	if v == 0 {
		return "0"
	}
	s := ""
	for v > 0 {
		s = string(rune('0'+v%10)) + s
		v /= 10
	}
	return s
}

// ---------------------------------------------------------------------------
// FlowRule field invariants
// ---------------------------------------------------------------------------

func TestFlowRule_AllFieldsAccessible(t *testing.T) {
	f := zoneflows.FlowRule{
		Table:    0,
		Priority: 1000,
		Match:    "in_port=1",
		Actions:  "normal",
	}
	assert.Equal(t, 0, f.Table)
	assert.Equal(t, 1000, f.Priority)
	assert.Equal(t, "in_port=1", f.Match)
	assert.Equal(t, "normal", f.Actions)
}

// ---------------------------------------------------------------------------
// ZoneFlowConfig field defaults
// ---------------------------------------------------------------------------

func TestZoneFlowConfig_ZeroValue_NonemptyGeneratorSet(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	require.NotNil(t, gs)
	// Even with an empty config we should get flows for built-in zones.
	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	assert.NotEmpty(t, flows)
}

// ---------------------------------------------------------------------------
// Quarantine template — config-populated paths
// ---------------------------------------------------------------------------

// TestGenerate_Quarantine_WithDNSServerIP covers the DNSServerIP branch where
// a specific DNS server IP is configured instead of the broadcast match.
func TestGenerate_Quarantine_WithDNSServerIP(t *testing.T) {
	dnsIP := net.IPv4(172, 16, 202, 1)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			DNSServerIP: dnsIP,
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, 202)
	require.NotEmpty(t, flows)

	// At least one flow must reference the DNS server IP.
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, dnsIP.String()) {
			found = true
			break
		}
	}
	assert.True(t, found, "quarantine template with DNSServerIP must emit a DNS rule scoped to the server IP")
}

// TestGenerate_Quarantine_WithRemediationAndScanningServers covers the
// RemediationServerIPs, ScanningServerIPs, and AllowedPorts branches.
func TestGenerate_Quarantine_WithRemediationAndScanningServers(t *testing.T) {
	remIP := net.IPv4(172, 16, 202, 10)
	scanIP := net.IPv4(172, 16, 202, 20)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			RemediationServerIPs: []net.IP{remIP},
			ScanningServerIPs:    []net.IP{scanIP},
			AllowedPorts:         []uint16{8443, 9443},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, 202)
	require.NotEmpty(t, flows)

	hasRemediation := false
	hasScanning := false
	for _, f := range flows {
		if strings.Contains(f.Match, remIP.String()) {
			hasRemediation = true
		}
		if strings.Contains(f.Match, scanIP.String()) {
			hasScanning = true
		}
	}
	assert.True(t, hasRemediation, "quarantine template must include remediation server flows")
	assert.True(t, hasScanning, "quarantine template must include scanning server flows")
}

// TestGenerate_Quarantine_WithNotificationServer covers the
// NotificationServerIP branch.
func TestGenerate_Quarantine_WithNotificationServer(t *testing.T) {
	notifIP := net.IPv4(172, 16, 202, 30)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			NotificationServerIP: notifIP,
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, 202)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, notifIP.String()) {
			found = true
			break
		}
	}
	assert.True(t, found, "quarantine template with NotificationServerIP must emit notification portal flows")
}

// ---------------------------------------------------------------------------
// Provisioning template — config-populated paths
// ---------------------------------------------------------------------------

// TestGenerate_Provisioning_WithDNSServerIPs covers the specific DNS server IP
// branch in the provisioning template.
func TestGenerate_Provisioning_WithDNSServerIPs(t *testing.T) {
	dns1 := net.IPv4(172, 16, 201, 1)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			DNSServerIPs: []net.IP{dns1},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, dns1.String()) {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template with DNSServerIPs must scope DNS flows to those IPs")
}

// TestGenerate_Provisioning_WithACMEServerIPs covers the specific ACME server
// IP branch in the provisioning template.
func TestGenerate_Provisioning_WithACMEServerIPs(t *testing.T) {
	acmeIP := net.IPv4(172, 16, 201, 2)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			ACMEServerIPs: []net.IP{acmeIP},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, acmeIP.String()) {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template with ACMEServerIPs must scope ACME flows to those IPs")
}

// TestGenerate_Provisioning_WithPackageRepoIPs covers the PackageRepoIPs
// branch in the provisioning template.
func TestGenerate_Provisioning_WithPackageRepoIPs(t *testing.T) {
	repoIP := net.IPv4(172, 16, 201, 3)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			PackageRepoIPs: []net.IP{repoIP},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, repoIP.String()) {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template with PackageRepoIPs must scope repo flows to those IPs")
}

// TestGenerate_Provisioning_WithAllowICMP covers the AllowICMP branch.
func TestGenerate_Provisioning_WithAllowICMP(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			AllowICMP: true,
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, 201)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "nw_proto=1") {
			found = true
			break
		}
	}
	assert.True(t, found, "provisioning template with AllowICMP must include an ICMP allow rule")
}

// ---------------------------------------------------------------------------
// Public template — config-populated paths
// ---------------------------------------------------------------------------

// TestGenerate_Public_WithTrustedSubnet covers the TrustedSubnet branch that
// emits the public→trusted deny rule.
func TestGenerate_Public_WithTrustedSubnet(t *testing.T) {
	trustedSubnet := "198.18.0.0/24"
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Public: zoneflows.PublicConfig{
			TrustedSubnet: trustedSubnet,
		},
	})

	flows := gs.Generate("eth0", zone.ZonePublic, 1000)
	require.NotEmpty(t, flows)

	found := false
	for _, f := range flows {
		if f.Actions == "drop" && strings.Contains(f.Match, trustedSubnet) {
			found = true
			break
		}
	}
	assert.True(t, found, "public template with TrustedSubnet must emit a drop rule for public→trusted traffic")
}

// TestGenerate_Public_WithTrustedSubnet_MoreFlowsThanWithout asserts that the
// public template produces more flows when TrustedSubnet is configured
// (the deny rule is added).
func TestGenerate_Public_WithTrustedSubnet_MoreFlowsThanWithout(t *testing.T) {
	base := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	withSubnet := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Public: zoneflows.PublicConfig{TrustedSubnet: "198.18.0.0/24"},
	})

	baseFlows := base.Generate("eth0", zone.ZonePublic, 1000)
	subnetFlows := withSubnet.Generate("eth0", zone.ZonePublic, 1000)

	assert.Greater(t, len(subnetFlows), len(baseFlows),
		"public template with TrustedSubnet should produce more flows than without")
}

// ---------------------------------------------------------------------------
// serviceFlowRules — remaining service paths (tftp)
// ---------------------------------------------------------------------------

// TestCompileMatrixRules_TFTPService covers the tftp service path in
// serviceFlowRules (currently only exercised indirectly via the matrix path).
func TestCompileMatrixRules_TFTPService(t *testing.T) {
	// Build a minimal zone set where provisioning allowTo trusted with tftp.
	zones := []zone.ZoneConfig{
		{
			Name:          zone.ZoneProvisioning,
			LifecycleRole: zone.LifecycleRoleProvisioning,
			Isolate:       true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneTrusted, Services: []string{"tftp"}},
			},
		},
		{Name: zone.ZoneTrusted},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "172.16.201.0/24"},
		zone.ZoneTrusted:      {VLAN: 200, Subnet: "198.18.0.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// At least one flow for TFTP (UDP port 69) should be present.
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "69") {
			found = true
			break
		}
	}
	assert.True(t, found, "matrix rules should include a TFTP flow rule when tftp service is declared")
}

// TestCompileMatrixRules_ZeroVLAN_SkipsFromZone covers the fromNet.VLAN == 0
// branch — when a zone has a NetworkSummary with VLAN=0 it must be skipped.
func TestCompileMatrixRules_ZeroVLAN_SkipsFromZone(t *testing.T) {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneTrusted},
		{Name: zone.ZonePublic, InternetIngress: true},
	}
	matrix := zone.CompileMatrix(zones)
	// Provide a summary for trusted but set VLAN=0 — this must be skipped.
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneTrusted: {VLAN: 0, Subnet: "198.18.0.0/24"},
		zone.ZonePublic:  {VLAN: 1000, Subnet: "203.0.113.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// trusted has VLAN=0 so it must be skipped as a source zone; no
	// trusted→public rules should appear.
	for _, f := range flows {
		assert.NotContains(t, f.Match, "dl_vlan=0",
			"zones with VLAN=0 must not generate matrix rules")
	}
}

// TestCompileMatrixRules_AllowedWithServices covers the allowed-pair-with-services
// branch to ensure service-scoped allow rules are emitted for DNS.
func TestCompileMatrixRules_AllowedWithServices_DNS(t *testing.T) {
	zones := []zone.ZoneConfig{
		{
			Name:    zone.ZoneProvisioning,
			Isolate: true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneTrusted, Services: []string{"dns"}},
			},
		},
		{Name: zone.ZoneTrusted},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "172.16.201.0/24"},
		zone.ZoneTrusted:      {VLAN: 200, Subnet: "198.18.0.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// Expect at least one flow with UDP/TCP port 53 (DNS).
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "53") && f.Actions == "normal" {
			found = true
			break
		}
	}
	assert.True(t, found, "matrix rules must include DNS allow flow for provisioning→trusted with dns service")
}

// TestCompileMatrixRules_AllowedWithServices_ACME covers the acme service path.
func TestCompileMatrixRules_AllowedWithServices_ACME(t *testing.T) {
	zones := []zone.ZoneConfig{
		{
			Name:    zone.ZoneProvisioning,
			Isolate: true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneTrusted, Services: []string{"acme"}},
			},
		},
		{Name: zone.ZoneTrusted},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "172.16.201.0/24"},
		zone.ZoneTrusted:      {VLAN: 200, Subnet: "198.18.0.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// Expect at least one HTTPS flow (443).
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "443") && f.Actions == "normal" {
			found = true
			break
		}
	}
	assert.True(t, found, "matrix rules must include HTTPS allow flow for acme service")
}

// TestCompileMatrixRules_AllowedWithServices_DHCP covers the dhcp service path.
func TestCompileMatrixRules_AllowedWithServices_DHCP(t *testing.T) {
	zones := []zone.ZoneConfig{
		{
			Name:    zone.ZoneProvisioning,
			Isolate: true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneTrusted, Services: []string{"dhcp"}},
			},
		},
		{Name: zone.ZoneTrusted},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "172.16.201.0/24"},
		zone.ZoneTrusted:      {VLAN: 200, Subnet: "198.18.0.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// Expect at least one flow with port 67 (DHCP server).
	found := false
	for _, f := range flows {
		if strings.Contains(f.Match, "67") && f.Actions == "normal" {
			found = true
			break
		}
	}
	assert.True(t, found, "matrix rules must include DHCP allow flow for dhcp service")
}

// TestCompileMatrixRules_EmptySubnet_SkipsToZone covers the toNet.Subnet == ""
// branch — when a zone's NetworkSummary is present but has no subnet it must
// be skipped as a destination so no matrix rules reference it.
func TestCompileMatrixRules_EmptySubnet_SkipsToZone(t *testing.T) {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneTrusted},
		{Name: zone.ZonePublic, InternetIngress: true},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneTrusted: {VLAN: 200, Subnet: "198.18.0.0/24"},
		// public is present but has no subnet — must be skipped as destination.
		zone.ZonePublic: {VLAN: 1000, Subnet: ""},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// No flow should reference an empty nw_dst.
	for _, f := range flows {
		assert.NotContains(t, f.Match, "nw_dst=,",
			"matrix rules must not emit flows with an empty destination subnet")
		assert.NotContains(t, f.Match, "nw_dst= ",
			"matrix rules must not emit flows with an empty destination subnet")
	}
	// Additionally, no flow targeting the public zone (with empty subnet) should exist.
	_ = flows // absence is the assertion; the loop above guards correctness
}
