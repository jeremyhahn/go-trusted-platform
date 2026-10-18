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

package bootstrap

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// tgw01Example is the shipped VLAN 405 boot-node example.
const tgw01Example = "../../configs/bootstrap/tgw01-vlan405.example.yaml"

// tgw01Address is tgw-01's address on VLAN 405: the boot server and, until
// the CM4 is proven, the control plane.
const tgw01Address = "192.0.2.1"

// loadTGW01Example loads the example and completes it with a netboot media
// build whose Pi set carries a diskless root, the one thing the example
// cannot carry, so Validate runs as it would before a run.
func loadTGW01Example(t *testing.T) *BootstrapConfig {
	t.Helper()
	cfg, err := LoadBootstrapConfig(tgw01Example)
	require.NoError(t, err)
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, true, false, container.MediaSetRaspberryPi)
	markMediaSetDiskless(t, cfg.Deployer.NetbootMediaDir, container.MediaSetRaspberryPi)
	return cfg
}

// tgw01Orchestrator builds an orchestrator over cfg loaded from configPath,
// so templates and overrides files resolve against that file's directory.
func tgw01Orchestrator(t *testing.T, cfg *BootstrapConfig, configPath string) *Orchestrator {
	t.Helper()
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     cfg,
		ConfigPath: configPath,
		BMCFactory: &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:     orchTestLogger(),
	})
	require.NoError(t, err)
	return o
}

// writeTGW01Variant writes the example with old replaced by repl to a temp
// dir and returns its path. The example's relative template and overrides
// paths are made absolute so they still resolve from there.
func writeTGW01Variant(t *testing.T, old, repl string) string {
	t.Helper()
	raw, err := os.ReadFile(tgw01Example)
	require.NoError(t, err)
	require.Contains(t, string(raw), old)
	variant := strings.Replace(string(raw), old, repl, 1)

	exampleDir, err := filepath.Abs(filepath.Dir(tgw01Example))
	require.NoError(t, err)
	for _, rel := range []string{"../platform/templates/", "tgw01-vlan405-pi.overrides.yaml"} {
		require.Contains(t, variant, rel)
		abs := filepath.Join(exampleDir, rel)
		if strings.HasSuffix(rel, "/") {
			abs += "/"
		}
		variant = strings.ReplaceAll(variant, rel, abs)
	}

	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte(variant), 0o600))
	return path
}

// TestTGW01VLAN405Example loads the shipped example through the real loader
// and validation, so an edit to either that would break the file an operator
// copies fails here first.
func TestTGW01VLAN405Example(t *testing.T) {
	cfg := loadTGW01Example(t)
	require.NoError(t, cfg.ValidateDefinition())
	require.NoError(t, cfg.Validate())

	d := cfg.Deployer
	assert.True(t, d.BootNode, "tgw-01 keeps serving VLAN 405")
	assert.True(t, d.BootstrapNoRouter, "VLAN 405 is isolated: no router option")
	assert.Empty(t, d.BootstrapGateway)
	assert.False(t, d.ProxyDHCP, "the only DHCP server on the VLAN")
	assert.Empty(t, d.RedeployMode, "if-stale stays the default")
	assert.Equal(t, "bond0.405", d.BootstrapInterface)
	assert.Equal(t, "192.0.2.1", d.BootstrapServerIP)
	assert.Equal(t, 8080, d.BootstrapHTTPPort)
	assert.Equal(t, 18081, d.BootstrapDeviceScriptPort)
	assert.Equal(t, "192.0.2.100", d.BootstrapDHCPStart)
	assert.Equal(t, "192.0.2.200", d.BootstrapDHCPEnd)

	// What the deployer is handed, with the manifest Deploy writes, passes
	// its own validation and reaches the container as no-router.
	dc := newLinuxDeployerAdapter(&cfg.Deployer, nil, nil).deployConfig(filepath.Join(t.TempDir(), "manifest.json"))
	dc.ApplyDefaults()
	require.NoError(t, dc.Validate())
	assert.True(t, dc.BootstrapNoRouter)

	var controlPlanes []NodeConfig
	workers := map[string][]string{}
	for _, n := range cfg.Nodes {
		switch n.Role {
		case RoleControlPlane:
			controlPlanes = append(controlPlanes, n)
		case RoleWorker:
			workers[n.Hostname] = n.MACs
			assert.Equal(t, PlatformRaspberryPi, n.Platform, n.Hostname)
			assert.Equal(t, "rpi4", n.Model, n.Hostname)
			assert.Equal(t, BootModelDiskless, n.BootModel, n.Hostname)
			assert.False(t, n.SkipInstall, n.Hostname)
		}
	}
	require.Len(t, controlPlanes, 1)
	cp := controlPlanes[0]
	assert.Equal(t, "tgw-01", cp.Hostname)
	assert.True(t, cp.SkipInstall, "tgw-01 runs the control plane already; this run does not install it")
	assert.Empty(t, cp.Platform, "tgw-01 is a generic server")
	assert.Equal(t, []string{tgw01Address}, cp.StaticIPv4s())
	assert.Equal(t, d.BootstrapServerIP, cp.StaticIPv4s()[0], "the control plane shares the boot server's address")
	assert.Equal(t, map[string][]string{
		"rpi4-01": {"dc:a6:32:50:76:60"},
		"rpi4-02": {"dc:a6:32:50:76:18"},
		"rpi4-03": {"dc:a6:32:50:75:43"},
	}, workers)

	// Both templates the example names ship beside it.
	for _, role := range []string{RoleControlPlane, RoleWorker} {
		template, ok := cfg.TemplatePath(role, filepath.Dir(tgw01Example))
		require.True(t, ok, "the example names a %s template", role)
		_, err := os.Stat(template)
		require.NoError(t, err, role)
	}
}

// TestTGW01VLAN405Example_NodeConfigsResolve resolves every node's merged
// config as a run stages it (stagePerMACConfig: the Pis have no BMC, so no
// hardware identity) and checks each Pi is pointed at tgw-01 for DNS, the
// control plane's internal and public zones, and that nothing still names the
// reference network's control plane.
func TestTGW01VLAN405Example_NodeConfigsResolve(t *testing.T) {
	o := tgw01Orchestrator(t, loadTGW01Example(t), tgw01Example)

	resolved, err := o.ResolveNodeConfigs()
	require.NoError(t, err)
	hosts := make([]string, 0, len(resolved))
	for _, r := range resolved {
		hosts = append(hosts, r.Hostname)
	}
	require.Equal(t, []string{"tgw-01", "rpi4-01", "rpi4-02", "rpi4-03"}, hosts)

	for _, r := range resolved[1:] {
		var merged struct {
			InstallTarget string `yaml:"install-target"`
			OS            struct {
				Hostname string `yaml:"hostname"`
			} `yaml:"os"`
			Network struct {
				DNS struct {
					UpstreamDNS string `yaml:"upstream-dns"`
				} `yaml:"dns"`
				Dnsmasq struct {
					UpstreamServers []string `yaml:"upstream-servers"`
				} `yaml:"dnsmasq"`
			} `yaml:"network"`
			DNS struct {
				Resolver struct {
					Servers []struct {
						Address string `yaml:"address"`
						Port    int    `yaml:"port"`
					} `yaml:"servers"`
				} `yaml:"resolver"`
			} `yaml:"dns"`
			Trust struct {
				BMC struct {
					DANE struct {
						DNSServer string `yaml:"dns-server"`
					} `yaml:"dane"`
				} `yaml:"bmc"`
			} `yaml:"trust"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(r.Config), &merged), r.Hostname)

		assert.Equal(t, r.Hostname, merged.OS.Hostname)
		assert.Equal(t, "disk", merged.InstallTarget, "%s: the installer runs on the Pi, not on a build host", r.Hostname)
		assert.Equal(t, tgw01Address+"#9053", merged.Network.DNS.UpstreamDNS,
			"%s: the bootstrap points the Pi at the control plane's internal zone", r.Hostname)
		assert.Equal(t, []string{"/example.internal/" + tgw01Address + "#9053", tgw01Address + "#8053"},
			merged.Network.Dnsmasq.UpstreamServers, r.Hostname)
		require.Len(t, merged.DNS.Resolver.Servers, 1, r.Hostname)
		assert.Equal(t, tgw01Address, merged.DNS.Resolver.Servers[0].Address, r.Hostname)
		assert.Equal(t, 8053, merged.DNS.Resolver.Servers[0].Port, r.Hostname)
		assert.Equal(t, tgw01Address+":8053", merged.Trust.BMC.DANE.DNSServer, r.Hostname)
		assert.NotContains(t, r.Config, "10.4.6.10", "%s still names the reference network's control plane", r.Hostname)
	}

	// Each Pi has its own address in the platform VRF and in each zone
	// VLAN (.20/.21/.22), and tgw-01 alone holds 192.0.2.1, the address
	// every Pi takes DNS from.
	owners := map[string]string{}
	for i, r := range resolved {
		addresses, err := mergedAddresses(r.Hostname, r.Config)
		require.NoError(t, err, r.Hostname)
		got := map[string]string{}
		for _, a := range addresses {
			require.NotContains(t, owners, a.addr.String(), "%s reuses an address", r.Hostname)
			owners[a.addr.String()] = r.Hostname
			got[a.where] = a.addr.String()
		}
		if i == 0 {
			assert.Equal(t, map[string]string{"interface bond0.405": tgw01Address}, got)
			continue
		}
		host := strconv.Itoa(19 + i)
		assert.Equal(t, map[string]string{
			"platform-vrf": "10.4.144." + host,
			"vlan zone401": "10.4.1." + host,
			"vlan zone403": "10.4.3." + host,
			"vlan zone407": "10.4.7." + host,
		}, got, r.Hostname)
	}
	assert.Equal(t, "tgw-01", owners[tgw01Address])

	// The Pis are diskless, so all three keep the template's IDevID serial
	// and still resolve: platformd replaces it with each Pi's EK-derived name
	// on every boot (keepsConfigSerial).
	for _, r := range resolved[1:] {
		idevid, err := mergedIDevID(r.Config)
		require.NoError(t, err, r.Hostname)
		assert.Equal(t, nodeIDevID{Model: "Raspberry Pi 4 Model B", Serial: "rpi4-compute-01"}, idevid, r.Hostname)
	}

	// The certificate name the orchestrator verifies the control plane by
	// comes from the standalone template's public webservice, not from the
	// address it dials, which is also the boot server's.
	name, source, err := webserviceTLSNameFromConfig(resolved[0].Config, o.config.EffectiveControlPlanePort())
	require.NoError(t, err)
	assert.Equal(t, "cp.example.com", name)
	assert.Equal(t, "webservices[0].certificate.subject.cn", source)

	o.discovered = []DiscoveredNode{{NodeConfig: o.config.Nodes[0]}}
	name, err = o.ControlPlaneTLSName()
	require.NoError(t, err)
	assert.Equal(t, "cp.example.com", name)
}

// TestTGW01VLAN405Example_SecondControlPlaneRefused: the commented CM4 cannot
// be added beside tgw-01; it replaces it.
func TestTGW01VLAN405Example_SecondControlPlaneRefused(t *testing.T) {
	const cm4 = "  # - hostname: cm4-01\n" +
		"  #   role: control-plane\n" +
		"  #   skip_install: true\n" +
		"  #   platform: raspberrypi\n" +
		"  #   model: cm4\n" +
		"  #   interfaces:\n" +
		"  #     - name: eth0\n" +
		"  #       type: static\n" +
		"  #       ipv4-address: 192.0.2.10/24\n"
	uncommented := strings.ReplaceAll(cm4, "  # ", "  ")
	cfg, err := LoadBootstrapConfig(writeTGW01Variant(t, cm4, uncommented))
	require.NoError(t, err)

	var count ErrInvalidControlPlaneCount
	require.ErrorAs(t, cfg.ValidateDefinition(), &count)
	assert.Equal(t, 2, count.Count)
}

// TestTGW01VLAN405Example_NoControlPlaneTemplate: the Pis' DNS comes from the
// control plane's merged config, so without a control-plane template no Pi
// resolves.
func TestTGW01VLAN405Example_NoControlPlaneTemplate(t *testing.T) {
	const cpTemplate = "  control-plane: ../platform/templates/single-node/standalone-cp.example.yaml\n"
	path := writeTGW01Variant(t, cpTemplate, "")
	cfg, err := LoadBootstrapConfig(path)
	require.NoError(t, err)

	_, err = tgw01Orchestrator(t, cfg, path).ResolveNodeConfigs("rpi4-01")
	var failed ErrNodeConfigResolveFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "rpi4-01", failed.Hostname)
	var noTemplate ErrTemplateNotFoundForRole
	require.ErrorAs(t, err, &noTemplate)
	assert.Equal(t, RoleControlPlane, noTemplate.Role)
}

// TestTGW01VLAN405Example_GatewayRefused: the example's no-router setting is
// enforced through the loader, so a gateway added to the file is refused
// rather than silently advertised on the isolated VLAN.
func TestTGW01VLAN405Example_GatewayRefused(t *testing.T) {
	const noRouter = "  bootstrap_no_router: true"
	cfg, err := LoadBootstrapConfig(writeTGW01Variant(t, noRouter, noRouter+"\n  bootstrap_gateway: 192.0.2.1"))
	require.NoError(t, err)

	var conflict deployer.ErrNoRouterWithGateway
	require.ErrorAs(t, cfg.ValidateDefinition(), &conflict)
	assert.Equal(t, "192.0.2.1", conflict.Gateway)
}

// TestTGW01VLAN405Example_DuplicateAddressRefused: two Pis given the same
// zone address are refused when the configs resolve, before a run touches
// anything, naming both nodes.
func TestTGW01VLAN405Example_DuplicateAddressRefused(t *testing.T) {
	path := writeTGW01Variant(t, "ipv4-address: 10.4.1.21/24", "ipv4-address: 10.4.1.20/24")
	cfg, err := LoadBootstrapConfig(path)
	require.NoError(t, err)
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, true, false, container.MediaSetRaspberryPi)
	markMediaSetDiskless(t, cfg.Deployer.NetbootMediaDir, container.MediaSetRaspberryPi)
	require.NoError(t, cfg.Validate())
	o := tgw01Orchestrator(t, cfg, path)

	_, err = o.ResolveNodeConfigs("rpi4-01")
	var dup ErrDuplicateNodeAddress
	require.ErrorAs(t, err, &dup, "the clash is refused even when only one of the nodes is asked for")
	assert.Equal(t, ErrDuplicateNodeAddress{
		Address:       "10.4.1.20",
		Hostname:      "rpi4-02",
		Where:         "vlan zone401",
		OtherHostname: "rpi4-01",
		OtherWhere:    "vlan zone401",
	}, dup)

	dry, err := o.DryRun(t.Context())
	require.ErrorAs(t, err, &dup)
	assert.Contains(t, dry.Errors, dup.Error())

	result, err := o.Run(t.Context())
	var failed ErrBootstrapFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, phaseDiscovery, failed.Phase)
	require.ErrorAs(t, err, &dup)
	assert.Empty(t, result.Nodes, "refused before discovery")
}

// tgw01SDVariant writes the example with every Pi booting from its SD card
// instead of diskless, and each of edits' keys replaced by its value, and
// loads it with a netboot media build. An SD Pi keeps its config's IDevID
// serial.
func tgw01SDVariant(t *testing.T, edits map[string]string) (*BootstrapConfig, string) {
	t.Helper()
	const diskless, sd = "    boot_model: diskless\n", "    boot_model: sd\n"
	path := writeTGW01Variant(t, diskless, sd)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	variant := strings.ReplaceAll(string(raw), diskless, sd)
	for old, repl := range edits {
		require.Contains(t, variant, old)
		variant = strings.Replace(variant, old, repl, 1)
	}
	require.NoError(t, os.WriteFile(path, []byte(variant), 0o600))

	cfg, err := LoadBootstrapConfig(path)
	require.NoError(t, err)
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, true, false, container.MediaSetRaspberryPi)
	require.NoError(t, cfg.Validate())
	return cfg, path
}

// TestTGW01VLAN405Example_DuplicateSerialRefused: Pis that keep their
// config's IDevID serial all take the template's rpi4-compute-01, so their
// certificates would name one device. They are refused when the configs
// resolve, before a run touches anything, naming both nodes.
func TestTGW01VLAN405Example_DuplicateSerialRefused(t *testing.T) {
	cfg, path := tgw01SDVariant(t, nil)
	o := tgw01Orchestrator(t, cfg, path)

	_, err := o.ResolveNodeConfigs("rpi4-03")
	var dup ErrDuplicateIDevIDSerial
	require.ErrorAs(t, err, &dup, "the clash is refused even when only another node is asked for")
	assert.Equal(t, ErrDuplicateIDevIDSerial{
		Model:         "Raspberry Pi 4 Model B",
		Serial:        "rpi4-compute-01",
		Hostname:      "rpi4-02",
		OtherHostname: "rpi4-01",
	}, dup)

	dry, err := o.DryRun(t.Context())
	require.ErrorAs(t, err, &dup)
	assert.Contains(t, dry.Errors, dup.Error())

	result, err := o.Run(t.Context())
	var failed ErrBootstrapFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, phaseDiscovery, failed.Phase)
	require.ErrorAs(t, err, &dup)
	assert.Empty(t, result.Nodes, "refused before discovery")
}

// TestTGW01VLAN405Example_SerialPerModel: a serial names a device within its
// model, so Pis of two models may share one, and a Pi given its own serial
// in its overrides is accepted beside them.
func TestTGW01VLAN405Example_SerialPerModel(t *testing.T) {
	const rpi02 = "    overrides:\n      network:\n        platform-vrf:\n          address: 10.4.144.21/32\n"
	const rpi03 = "    overrides:\n      network:\n        platform-vrf:\n          address: 10.4.144.22/32\n"
	cfg, path := tgw01SDVariant(t, map[string]string{
		rpi02: "    overrides:\n      tpm:\n        idevid:\n          model: Raspberry Pi 400\n" + rpi02[len("    overrides:\n"):],
		rpi03: "    overrides:\n      tpm:\n        idevid:\n          serial: rpi4-compute-03\n" + rpi03[len("    overrides:\n"):],
	})

	resolved, err := tgw01Orchestrator(t, cfg, path).ResolveNodeConfigs()
	require.NoError(t, err)
	got := map[string]nodeIDevID{}
	for _, r := range resolved[1:] {
		idevid, err := mergedIDevID(r.Config)
		require.NoError(t, err, r.Hostname)
		got[r.Hostname] = idevid
	}
	assert.Equal(t, map[string]nodeIDevID{
		"rpi4-01": {Model: "Raspberry Pi 4 Model B", Serial: "rpi4-compute-01"},
		"rpi4-02": {Model: "Raspberry Pi 400", Serial: "rpi4-compute-01"},
		"rpi4-03": {Model: "Raspberry Pi 4 Model B", Serial: "rpi4-compute-03"},
	}, got)
}

// TestTGW01VLAN405Example_DisklessImageRefused: a diskless Pi left on the
// template's install-target: image is refused at resolve time; the
// installer runs on the Pi and needs the disk target.
func TestTGW01VLAN405Example_DisklessImageRefused(t *testing.T) {
	const overrides = "    overrides:\n      network:\n        platform-vrf:\n          address: 10.4.144.20/32\n"
	path := writeTGW01Variant(t, overrides, "    overrides:\n      install-target: image\n"+overrides[len("    overrides:\n"):])
	cfg, err := LoadBootstrapConfig(path)
	require.NoError(t, err)

	_, err = tgw01Orchestrator(t, cfg, path).ResolveNodeConfigs("rpi4-02")
	var failed ErrNodeConfigResolveFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "rpi4-01", failed.Hostname)
	var image ErrDisklessImageTarget
	require.ErrorAs(t, err, &image)
	assert.Equal(t, ErrDisklessImageTarget{Hostname: "rpi4-01", BootModel: BootModelDiskless}, image)
}

// TestTGW01VLAN405Example_SDPiKeepsManualTrunk: a Pi that is not diskless
// is unchanged: its trunk eth0 stays manual, with no address, and the image
// target is not refused for it.
func TestTGW01VLAN405Example_SDPiKeepsManualTrunk(t *testing.T) {
	const overrides = "    overrides:\n      network:\n        platform-vrf:\n          address: 10.4.144.20/32\n"
	variant := "    overrides:\n      install-target: image\n" + overrides[len("    overrides:\n"):]
	path := writeTGW01Variant(t, overrides, variant)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sd := strings.Replace(string(raw), "    boot_model: diskless\n", "    boot_model: sd\n", 1)
	require.NoError(t, os.WriteFile(path, []byte(sd), 0o600))
	cfg, err := LoadBootstrapConfig(path)
	require.NoError(t, err)
	require.Equal(t, BootModelSD, cfg.Nodes[1].BootModel)

	resolved, err := tgw01Orchestrator(t, cfg, path).ResolveNodeConfigs("rpi4-01")
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	var merged struct {
		InstallTarget string                  `yaml:"install-target"`
		Network       installer.NetworkConfig `yaml:"network"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(resolved[0].Config), &merged))
	assert.Equal(t, string(installer.InstallTargetImage), merged.InstallTarget)
	require.Len(t, merged.Network.Interfaces, 1)
	eth0 := merged.Network.Interfaces[0]
	assert.Equal(t, "eth0", eth0.Name)
	assert.Equal(t, installer.InterfaceTypeManual, eth0.Type)
	assert.Empty(t, eth0.IPv4Address)
}
