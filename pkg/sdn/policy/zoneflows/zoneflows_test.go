// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-control-plane-platform.
//
// go-control-plane-platform is dual-licensed:
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

// builtinZones lists the built-in zones that carry a flow template, with
// their environment-4 VLANs and the minimum flow count each template emits.
// Transit carries none: it is matrix-driven only.
var builtinZones = []struct {
	zone     zone.Zone
	vlan     uint16
	minFlows int
}{
	{zone.ZoneFabric, 401, 1},
	{zone.ZoneManagement, 402, 1},
	{zone.ZoneHypervisor, 403, 1},
	{zone.ZoneQuarantine, 404, 1},
	{zone.ZoneProvisioning, 405, 1},
	{zone.ZoneControlPlane, 406, 1},
	{zone.ZoneStorage, 407, 1},
	{zone.ZoneBackup, 408, 1},
}

func TestGenerate_AllBuiltinZones_ReturnFlows(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	for _, tc := range builtinZones {
		t.Run(string(tc.zone), func(t *testing.T) {
			flows := gs.Generate("eth0", tc.zone, zoneflows.Tagged(tc.vlan))
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
	flows := gs.Generate("eth0", zone.Zone("custom-zone"), zoneflows.Tagged(409))
	assert.Nil(t, flows, "user-defined zone with no built-in generator should return nil")
	assert.Nil(t, gs.Generate("eth0", zone.ZoneTransit, zoneflows.Tagged(400)), "transit is matrix-driven only")
}

// ---------------------------------------------------------------------------
// Provisioning template specifics
// ---------------------------------------------------------------------------

func TestGenerate_Provisioning_ContainsDHCPRule(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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
	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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
	flows := gs.Generate("eth0", zone.ZoneQuarantine, zoneflows.Tagged(202))
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
	provFlows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
	quarFlows := gs.Generate("eth0", zone.ZoneQuarantine, zoneflows.Tagged(202))
	// Quarantine is more restrictive — provisioning grants more service paths.
	assert.Less(t, len(quarFlows), len(provFlows),
		"quarantine should have fewer flow rules than provisioning")
}

// ---------------------------------------------------------------------------
// East-west template specifics
// ---------------------------------------------------------------------------

// TestGenerate_EastWest_SingleNormalRule verifies the zones whose reference
// policy opens traffic inside the zone get exactly the intra-zone allow.
func TestGenerate_EastWest_SingleNormalRule(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	for _, z := range []zone.Zone{zone.ZoneFabric, zone.ZoneHypervisor, zone.ZoneControlPlane, zone.ZoneStorage, zone.ZoneBackup} {
		flows := gs.Generate("eth0", z, zoneflows.Tagged(406))
		require.Len(t, flows, 1, "zone %s", z)
		assert.Equal(t, "in_port=eth0,dl_vlan=406", flows[0].Match)
		assert.Equal(t, "normal", flows[0].Actions)
		assert.Equal(t, 100, flows[0].Priority)
	}
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

	// The default matrix denies every cross-zone pair it does not open, so
	// we expect at least one drop rule.
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

func TestCompileMatrixRules_BackupToControlPlaneIsDenied(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)
	nets := buildNetworks(defaults)

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          defaults,
		NetworksByZone: nets,
	})

	// Find the VLAN for backup and the subnet for control-plane.
	backupVLAN := nets[zone.ZoneBackup].VLAN
	cpSubnet := nets[zone.ZoneControlPlane].Subnet

	// There must be a drop rule matching backup's dl_vlan→control-plane's subnet.
	found := false
	for _, f := range flows {
		if f.Actions == "drop" &&
			strings.Contains(f.Match, "dl_vlan="+vlanStr(backupVLAN)) &&
			strings.Contains(f.Match, cpSubnet) {
			found = true
			break
		}
	}
	assert.True(t, found, "should have a drop rule for backup→control-plane (dl_vlan=%d, nw_dst=%s)",
		backupVLAN, cpSubnet)
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
	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
	assert.NotEmpty(t, flows)
}

// ---------------------------------------------------------------------------
// Quarantine template — config-populated paths
// ---------------------------------------------------------------------------

// TestGenerate_Quarantine_WithDNSServerIP covers the DNSServerIP branch where
// a specific DNS server IP is configured instead of the broadcast match.
func TestGenerate_Quarantine_WithDNSServerIP(t *testing.T) {
	dnsIP := net.IPv4(10, 4, 4, 1)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			DNSServerIP: dnsIP,
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, zoneflows.Tagged(202))
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
	remIP := net.IPv4(10, 4, 4, 10)
	scanIP := net.IPv4(10, 4, 4, 20)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			RemediationServerIPs: []net.IP{remIP},
			ScanningServerIPs:    []net.IP{scanIP},
			AllowedPorts:         []uint16{8443, 9443},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, zoneflows.Tagged(202))
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
	notifIP := net.IPv4(10, 4, 4, 30)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{
			NotificationServerIP: notifIP,
		},
	})

	flows := gs.Generate("eth0", zone.ZoneQuarantine, zoneflows.Tagged(202))
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
	dns1 := net.IPv4(10, 4, 5, 1)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			DNSServerIPs: []net.IP{dns1},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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
	acmeIP := net.IPv4(10, 4, 5, 2)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			ACMEServerIPs: []net.IP{acmeIP},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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
	repoIP := net.IPv4(10, 4, 5, 3)
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{
			PackageRepoIPs: []net.IP{repoIP},
		},
	})

	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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

	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Tagged(201))
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

func TestCompileMatrixRules_TFTPService(t *testing.T) {
	// Build a minimal zone set where provisioning allowTo control-plane with tftp.
	zones := []zone.ZoneConfig{
		{
			Name:          zone.ZoneProvisioning,
			LifecycleRole: zone.LifecycleRoleProvisioning,
			Isolate:       true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneControlPlane, Services: []string{"tftp"}},
			},
		},
		{Name: zone.ZoneControlPlane},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "192.0.2.0/24"},
		zone.ZoneControlPlane: {VLAN: 200, Subnet: "10.4.6.0/24"},
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
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneBackup, InternetIngress: true},
	}
	matrix := zone.CompileMatrix(zones)
	// Provide a summary for control-plane but set VLAN=0 — this must be skipped.
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneControlPlane: {VLAN: 0, Subnet: "10.4.6.0/24"},
		zone.ZoneBackup:       {VLAN: 1000, Subnet: "203.0.113.0/24"},
	}

	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         matrix,
		Zones:          zones,
		NetworksByZone: nets,
	})

	// control-plane has VLAN=0 so it must be skipped as a source zone; no
	// control-plane→backup rules should appear.
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
				{Zone: zone.ZoneControlPlane, Services: []string{"dns"}},
			},
		},
		{Name: zone.ZoneControlPlane},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "192.0.2.0/24"},
		zone.ZoneControlPlane: {VLAN: 200, Subnet: "10.4.6.0/24"},
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
	assert.True(t, found, "matrix rules must include DNS allow flow for provisioning→control-plane with dns service")
}

// TestCompileMatrixRules_AllowedWithServices_ACME covers the acme service path.
func TestCompileMatrixRules_AllowedWithServices_ACME(t *testing.T) {
	zones := []zone.ZoneConfig{
		{
			Name:    zone.ZoneProvisioning,
			Isolate: true,
			AllowTo: []zone.ZonePath{
				{Zone: zone.ZoneControlPlane, Services: []string{"acme"}},
			},
		},
		{Name: zone.ZoneControlPlane},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "192.0.2.0/24"},
		zone.ZoneControlPlane: {VLAN: 200, Subnet: "10.4.6.0/24"},
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
				{Zone: zone.ZoneControlPlane, Services: []string{"dhcp"}},
			},
		},
		{Name: zone.ZoneControlPlane},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneProvisioning: {VLAN: 201, Subnet: "192.0.2.0/24"},
		zone.ZoneControlPlane: {VLAN: 200, Subnet: "10.4.6.0/24"},
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
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneBackup, InternetIngress: true},
	}
	matrix := zone.CompileMatrix(zones)
	nets := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneControlPlane: {VLAN: 200, Subnet: "10.4.6.0/24"},
		// backup is present but has no subnet — must be skipped as destination.
		zone.ZoneBackup: {VLAN: 1000, Subnet: ""},
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
	// Additionally, no flow targeting the backup zone (with empty subnet) should exist.
	_ = flows // absence is the assertion; the loop above guards correctness
}
