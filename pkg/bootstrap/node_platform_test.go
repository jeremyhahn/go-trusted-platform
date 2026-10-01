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
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container/containertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// piWorker is a valid Raspberry Pi worker added to minimalConfig.
func piWorker() NodeConfig {
	return NodeConfig{
		Hostname: "pi1",
		Role:     RoleWorker,
		MACs:     []string{"dc:a6:32:01:36:c2"},
		Platform: PlatformRaspberryPi,
		Model:    "rpi4",
		Serial:   "9ffefdef",
	}
}

func configWith(node NodeConfig) *BootstrapConfig {
	cfg := minimalConfig()
	cfg.Nodes = append(cfg.Nodes, node)
	return cfg
}

// netbootBuild writes a netboot media build holding the named sets (the
// x86_64 set is its architecture's default; the first arm64 one is when
// defaultArm64 is set) and, with pi, the Raspberry Pi TFTP tree and arm64
// iPXE.
func netbootBuild(t *testing.T, pi, defaultArm64 bool, sets ...string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, containertest.WriteNetbootBuild(root, pi, defaultArm64, sets...))
	return root
}

// fleetMedia is a complete netboot media build — every set, the Pi stage —
// that minimalConfig deploys, written once for the package's tests.
var fleetMedia string

func TestMain(m *testing.M) {
	os.Exit(runWithFleetMedia(m))
}

// runWithFleetMedia writes fleetMedia, runs the tests and removes it.
func runWithFleetMedia(m *testing.M) int {
	root, err := os.MkdirTemp("", "bootstrap-netboot-media-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating the fleet media build:", err)
		return 1
	}
	fleetMedia = root
	if err := containertest.WriteNetbootBuild(root, true, true, container.MediaSetARM64Virt, container.MediaSetRaspberryPi, container.MediaSetX86_64); err != nil {
		fmt.Fprintln(os.Stderr, "writing the fleet media build:", err)
		return 1
	}
	code := m.Run()
	if err := os.RemoveAll(root); err != nil {
		fmt.Fprintln(os.Stderr, "removing the fleet media build:", err)
		return 1
	}
	return code
}

// piConfig is a valid fleet with one Pi and the build it needs.
func piConfig(t *testing.T, node NodeConfig) *BootstrapConfig {
	t.Helper()
	cfg := configWith(node)
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, true, false, container.MediaSetRaspberryPi, container.MediaSetX86_64)
	return cfg
}

func TestNodePlatform_ValidRaspberryPi(t *testing.T) {
	cfg := piConfig(t, piWorker())
	require.NoError(t, cfg.Validate())

	pi := &cfg.Nodes[1]
	assert.True(t, pi.IsRaspberryPi())
	assert.Equal(t, ArchitectureAArch64, pi.EffectiveArchitecture(), "a Pi defaults to aarch64")
	assert.Equal(t, BootModelSD, pi.EffectiveBootModel(), "and to the SD-card boot model")
	serial, ok := pi.PiSerial()
	require.True(t, ok)
	assert.Equal(t, uint32(0x9ffefdef), serial)

	generic := &cfg.Nodes[0]
	assert.False(t, generic.IsRaspberryPi())
	assert.Equal(t, ArchitectureX86_64, generic.EffectiveArchitecture())
	assert.Empty(t, generic.EffectiveBootModel())
	_, ok = generic.PiSerial()
	assert.False(t, ok)
}

func TestNodePlatform_ExplicitValuesAccepted(t *testing.T) {
	pi := piWorker()
	pi.Architecture, pi.BootModel, pi.Serial, pi.Model = ArchitectureAArch64, BootModelSD, "0x1a2b", "rpi5"
	require.NoError(t, piConfig(t, pi).Validate())

	pi = piWorker()
	pi.Serial = "" // the per-device directory is optional
	require.NoError(t, piConfig(t, pi).Validate())

	arm := NodeConfig{Hostname: "arm1", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:09"}, Architecture: ArchitectureAArch64}
	cfg := configWith(arm)
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, false, true, container.MediaSetARM64Virt, container.MediaSetX86_64)
	require.NoError(t, cfg.Validate(), "a generic aarch64 server boots the arm64 default")
}

func TestNodePlatform_Rejections(t *testing.T) {
	cases := map[string]struct {
		mutate func(*NodeConfig)
		field  string
	}{
		"unknown platform":     {func(n *NodeConfig) { n.Platform = "beaglebone" }, "platform"},
		"pi without model":     {func(n *NodeConfig) { n.Model = "" }, "model"},
		"pi unknown model":     {func(n *NodeConfig) { n.Model = "rpi2" }, "model"},
		"pi on x86_64":         {func(n *NodeConfig) { n.Architecture = ArchitectureX86_64 }, "architecture"},
		"unknown architecture": {func(n *NodeConfig) { n.Architecture = "riscv64" }, "architecture"},
		"unknown boot model":   {func(n *NodeConfig) { n.BootModel = "diskless-nfs" }, "boot_model"},
		"pi with a BMC":        {func(n *NodeConfig) { n.BMCAddress = "10.0.0.9" }, "bmc_address"},
		"pi bad serial":        {func(n *NodeConfig) { n.Serial = "not-hex" }, "serial"},
		"pi serial too long":   {func(n *NodeConfig) { n.Serial = "123456789" }, "serial"},
		"generic with model":   {func(n *NodeConfig) { n.Platform = ""; n.Serial = "" }, "model"},
		"generic with serial":  {func(n *NodeConfig) { n.Platform = ""; n.Model = "" }, "serial"},
		"generic boot model":   {func(n *NodeConfig) { n.Platform = ""; n.Model = ""; n.Serial = ""; n.BootModel = BootModelSD }, "boot_model"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pi := piWorker()
			tc.mutate(&pi)
			err := piConfig(t, pi).Validate()
			var platformErr ErrInvalidNodePlatform
			require.True(t, errors.As(err, &platformErr), "got %v", err)
			assert.Equal(t, tc.field, platformErr.Field)
			assert.Equal(t, "pi1", platformErr.Hostname)
			assert.Contains(t, platformErr.Error(), tc.field)
		})
	}
}

func TestNodePlatform_PiOnVirtualMediaIsRejected(t *testing.T) {
	// Virtual media needs a BMC and a Pi has none; the existing rule
	// already says so, before the platform rules run.
	pi := piWorker()
	pi.BootMethod = BootMethodVirtualMedia
	var vmErr ErrVirtualMediaRequiresBMC
	assert.ErrorAs(t, piConfig(t, pi).Validate(), &vmErr)
}

func TestNodePlatform_YAMLKeys(t *testing.T) {
	var node NodeConfig
	require.NoError(t, yaml.Unmarshal([]byte(`
hostname: pi1
role: worker
macs: ["dc:a6:32:01:36:c2"]
platform: raspberrypi
model: cm4
architecture: aarch64
serial: 9ffefdef
boot_model: sd
`), &node))
	assert.Equal(t, PlatformRaspberryPi, node.Platform)
	assert.Equal(t, "cm4", node.Model)
	assert.Equal(t, ArchitectureAArch64, node.Architecture)
	assert.Equal(t, "9ffefdef", node.Serial)
	assert.Equal(t, BootModelSD, node.BootModel)
}

func TestValidateNetbootMedia(t *testing.T) {
	var need ErrNetbootMediaRequired

	x86 := minimalConfig()
	x86.Deployer.NetbootMediaDir = ""
	require.ErrorAs(t, x86.Validate(), &need, "the image carries no installer: even an x86 fleet needs a build")
	assert.Contains(t, need.Error(), "netboot_media_dir")
	assert.Empty(t, need.Hostname)

	x86.Deployer.NetbootMediaDir = netbootBuild(t, false, false, container.MediaSetARM64Virt)
	require.ErrorAs(t, x86.Validate(), &need, "an x86 PXE node needs the x86_64 set")
	assert.Equal(t, "cp1", need.Hostname)
	assert.Contains(t, need.Error(), "no default x86_64 media set")

	x86.Nodes[0].BootMethod = BootMethodVirtualMedia
	x86.Nodes[0].BMCAddress = "10.0.0.2"
	x86.ISOPath = "/isos/platform.iso"
	require.NoError(t, x86.Validate(), "a virtual-media node boots its ISO, not a media set")

	cfg := configWith(piWorker())
	cfg.Deployer.NetbootMediaDir = netbootBuild(t, true, true, container.MediaSetARM64Virt, container.MediaSetX86_64)
	require.ErrorAs(t, cfg.Validate(), &need, "the build lacks the Pi set")
	assert.Contains(t, need.Error(), "no media set aarch64-rpi")

	cfg.Deployer.NetbootMediaDir = netbootBuild(t, false, false, container.MediaSetRaspberryPi, container.MediaSetX86_64)
	require.ErrorAs(t, cfg.Validate(), &need, "the Pi set without the bootloader stage")
	assert.Contains(t, need.Error(), "TFTP tree")

	arm := configWith(NodeConfig{Hostname: "arm1", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:09"}, Architecture: ArchitectureAArch64})
	arm.Deployer.NetbootMediaDir = netbootBuild(t, true, false, container.MediaSetRaspberryPi, container.MediaSetX86_64)
	require.ErrorAs(t, arm.Validate(), &need, "no arm64 default for a generic aarch64 node")
	assert.Contains(t, need.Error(), "default arm64")

	arm.Deployer.NetbootMediaDir = t.TempDir()
	require.ErrorAs(t, arm.Validate(), &need, "a directory that is not a build")
	assert.NotNil(t, need.Unwrap())

	skipped := piWorker()
	skipped.SkipInstall = true
	installed := configWith(skipped)
	installed.Deployer.NetbootMediaDir = netbootBuild(t, false, false, container.MediaSetX86_64)
	require.NoError(t, installed.Validate(), "an installed Pi boots from its card")
	require.NoError(t, minimalConfig().Validate(), "the fleet build serves an x86 fleet")
}

func TestNodeMediaSetAndIPXEArchitecture(t *testing.T) {
	pi := piWorker()
	assert.Equal(t, container.MediaSetRaspberryPi, pi.MediaSet())
	assert.Equal(t, "arm64", pi.IPXEArchitecture())
	arm := NodeConfig{Architecture: ArchitectureAArch64}
	assert.Empty(t, arm.MediaSet(), "the arm64 default")
	assert.Equal(t, "arm64", arm.IPXEArchitecture())
	x86 := NodeConfig{}
	assert.Empty(t, x86.MediaSet())
	assert.Equal(t, "x86_64", x86.IPXEArchitecture())

	infos := toDiscoveredNodeInfos([]DiscoveredNode{{NodeConfig: pi, DiscoveredMACs: pi.MACs}, {NodeConfig: NodeConfig{Hostname: "x"}, DiscoveredMACs: []string{"aa:bb:cc:dd:ee:01"}}})
	assert.Equal(t, "arm64", infos[0].Architecture)
	assert.Equal(t, container.MediaSetRaspberryPi, infos[0].MediaSet)
	assert.Equal(t, "x86_64", infos[1].Architecture)
	assert.Empty(t, infos[1].MediaSet)
}
