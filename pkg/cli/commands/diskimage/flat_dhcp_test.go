package diskimage

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// rpi4ComputeTemplate is the template `diskimage create --target rpi --model
// rpi4 --role compute` builds from.
var rpi4ComputeTemplate = filepath.Join(repoRoot, "configs", "platform", "templates", "dedicated", "raspberrypi", "rpi4", "compute.yaml")

// loadMerged merges overrides onto template the way `diskimage create
// --overrides` does and loads the result the way `diskimage assemble` does.
func loadMerged(t *testing.T, template, overrides string) *installer.Config {
	t.Helper()
	merged, err := mergeOverrides(template, overrides)
	if err != nil {
		t.Fatalf("mergeOverrides: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(merged); err != nil {
			t.Errorf("remove merged config: %v", err)
		}
	})
	cfg, err := loadInstallerConfig(&assembleFlags{platformConfig: merged})
	if err != nil {
		t.Fatalf("loadInstallerConfig: %v", err)
	}
	if cfg.Network == nil {
		t.Fatal("merged config has no network section")
	}
	return cfg
}

// requirePlatformdAccepts runs the host-network check platformd runs at
// config load (app.validateHostNetwork): the network section against the
// plan app.NetworkPlan derives, which loadInstallerConfig carries as
// cfg.Plan. platformd refuses to start on any error it returns.
func requirePlatformdAccepts(t *testing.T, cfg *installer.Config) {
	t.Helper()
	if cfg.Plan == nil {
		t.Fatal("the merged config derives no network plan; platformd would check it plan-free")
	}
	if err := cfg.Network.Validate(cfg.Plan); err != nil {
		t.Fatalf("platformd refuses the merged network section: %v", err)
	}
}

// findInterface returns the named interface of a network section.
func findInterface(t *testing.T, network *installer.NetworkConfig, name string) installer.InterfaceConfig {
	t.Helper()
	for _, iface := range network.Interfaces {
		if iface.Name == name {
			return iface
		}
	}
	t.Fatalf("no interface %s in %+v", name, network.Interfaces)
	return installer.InterfaceConfig{}
}

// TestRPi4FlatDHCPOverridesRenderAnAccessPort builds a Pi 4 compute node for a
// flat DHCP network (the office VLAN 101) from the rack template and overrides
// alone: platformd accepts the merged network section, eth0 takes its address
// by DHCP, and nothing of the rack's trunk, zone VLANs, platform VRF or 10.4.x
// DNS upstreams is rendered.
func TestRPi4FlatDHCPOverridesRenderAnAccessPort(t *testing.T) {
	cfg := loadMerged(t, rpi4ComputeTemplate, filepath.Join("testdata", "rpi4-flat-dhcp.yaml"))
	network := cfg.Network
	requirePlatformdAccepts(t, cfg)

	// The null role is what lets it load: with the template's role back the
	// same section is refused, so the role rule itself is unchanged.
	withRole := *network
	withRole.Role = installer.HostRoleCompute
	var dhcp *installer.ErrDHCPNotPermitted
	if err := withRole.Validate(cfg.Plan); !errors.As(err, &dhcp) {
		t.Errorf("with role compute, Validate = %v, want ErrDHCPNotPermitted", err)
	}

	// Checked before rendering: a dnsmasq section would make the installer
	// chroot and mount /proc to install dnsmasq.
	if network.DNS != nil || network.DNSMasq != nil {
		t.Fatalf("the null dns/dnsmasq overrides did not delete the template's: dns=%+v dnsmasq=%+v", network.DNS, network.DNSMasq)
	}
	if network.PlatformVRF != nil {
		t.Errorf("the null platform-vrf override did not delete the template's: %+v", network.PlatformVRF)
	}
	if len(network.VLANs) != 0 {
		t.Errorf("the [] vlans override did not replace the template's: %+v", network.VLANs)
	}
	if got := findInterface(t, network, "eth0").Type; got != installer.InterfaceTypeDHCP {
		t.Errorf("eth0 type = %q, want %q", got, installer.InterfaceTypeDHCP)
	}

	inst, err := installer.NewOSInstaller(logging.DefaultLogger(), cfg.OS)
	if err != nil {
		t.Fatalf("NewOSInstaller: %v", err)
	}
	root := t.TempDir()
	if err := inst.ConfigureNetwork(context.Background(), root, network, cfg.Plan); err != nil {
		t.Fatalf("ConfigureNetwork: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "etc", "network", "interfaces"))
	if err != nil {
		t.Fatal(err)
	}
	interfaces := string(data)
	if !strings.Contains(interfaces, "iface eth0 inet dhcp") {
		t.Errorf("eth0 does not take its address by DHCP:\n%s", interfaces)
	}
	for _, rack := range []string{"vlan-raw-device", "vlan-id", "vrf-table", "vrf-member", "iface eth0 inet manual"} {
		if strings.Contains(interfaces, rack) {
			t.Errorf("interfaces still renders %q:\n%s", rack, interfaces)
		}
	}

	// The DHCP client owns resolv.conf: the installer writes none.
	if _, err := os.Stat(filepath.Join(root, "etc", "resolv.conf")); !os.IsNotExist(err) {
		t.Errorf("resolv.conf was rendered (stat error %v); the resolver should come from DHCP", err)
	}

	// No rack address or DNS upstream survives in anything rendered.
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), "10.4.") {
			t.Errorf("%s still names a 10.4.x address:\n%s", strings.TrimPrefix(path, root), content)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRPi4ComputeTemplateKeepsTheRackTrunk pins the template's default: with
// an empty override the node is the rack's compute node, a trunk with zone
// VLANs, a platform VRF and the control plane's DNS upstream.
func TestRPi4ComputeTemplateKeepsTheRackTrunk(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	network := loadMerged(t, rpi4ComputeTemplate, empty).Network

	if got := findInterface(t, network, "eth0").Type; got != installer.InterfaceTypeManual {
		t.Errorf("eth0 type = %q, want %q", got, installer.InterfaceTypeManual)
	}
	if len(network.VLANs) != 3 {
		t.Errorf("template has %d zone VLANs, want 3: %+v", len(network.VLANs), network.VLANs)
	}
	if network.PlatformVRF == nil || network.PlatformVRF.Address != "10.4.144.20/32" {
		t.Errorf("platform-vrf = %+v, want address 10.4.144.20/32", network.PlatformVRF)
	}
	if network.DNSMasq == nil || !strings.Contains(strings.Join(network.DNSMasq.UpstreamServers, " "), "10.4.6.10") {
		t.Errorf("dnsmasq = %+v, want an upstream at 10.4.6.10", network.DNSMasq)
	}
}
