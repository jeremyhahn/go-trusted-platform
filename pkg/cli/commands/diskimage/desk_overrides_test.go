package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// cm4TemplateDir holds the CM4 control-plane template and the desk overrides
// shipped beside it.
var cm4TemplateDir = filepath.Join(repoRoot, "configs", "platform", "templates", "dedicated", "raspberrypi", "cm4")

// The shipped desk overrides turn the rack control plane into a standalone
// one at 192.0.2.10/24 on an untagged eth0, with no gateway, and platformd
// accepts the merged network section.
func TestCM4DeskOverridesLoadAsAStandaloneControlPlane(t *testing.T) {
	cfg := loadMerged(t, filepath.Join(cm4TemplateDir, "control-plane.yaml"), filepath.Join(cm4TemplateDir, "desk-overrides.yaml"))
	network := cfg.Network
	requirePlatformdAccepts(t, cfg)

	// The null role is what lets it load: with the template's role back,
	// 192.0.2.10 is refused, so the role rule itself is unchanged.
	withRole := *network
	withRole.Role = installer.HostRoleControlPlane
	var outside *installer.ErrAddressNotPermitted
	if err := withRole.Validate(cfg.Plan); !errors.As(err, &outside) {
		t.Errorf("with role control-plane, Validate = %v, want ErrAddressNotPermitted", err)
	}

	if network.Role != "" {
		t.Errorf("role = %q, want none", network.Role)
	}
	if network.PlatformVRF != nil {
		t.Errorf("the null platform-vrf override did not delete the template's: %+v", network.PlatformVRF)
	}
	if len(network.VLANs) != 0 {
		t.Errorf("the [] vlans override did not replace the template's: %+v", network.VLANs)
	}
	if network.DNS == nil || !slices.Equal(network.DNS.Nameservers, []string{"192.0.2.10"}) {
		t.Errorf("dns = %+v, want the one nameserver 192.0.2.10", network.DNS)
	}
	eth0 := findInterface(t, network, "eth0")
	if eth0.Type != installer.InterfaceTypeStatic || eth0.IPv4Address != "192.0.2.10/24" || eth0.IPv4Gateway != "" {
		t.Errorf("eth0 = type %q address %q gateway %q, want static 192.0.2.10/24 with no gateway", eth0.Type, eth0.IPv4Address, eth0.IPv4Gateway)
	}

	inst, err := installer.NewOSInstaller(logging.DefaultLogger(), cfg.OS)
	if err != nil {
		t.Fatalf("NewOSInstaller: %v", err)
	}
	// A rootfs has /etc; the installer writes resolv.conf into it.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := inst.ConfigureNetwork(context.Background(), root, network, cfg.Plan); err != nil {
		t.Fatalf("ConfigureNetwork: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "etc", "network", "interfaces"))
	if err != nil {
		t.Fatal(err)
	}
	interfaces := string(data)
	for _, want := range []string{"iface eth0 inet static", "address 192.0.2.10/24"} {
		if !strings.Contains(interfaces, want) {
			t.Errorf("interfaces does not render %q:\n%s", want, interfaces)
		}
	}
	for _, rack := range []string{"gateway", "vlan-raw-device", "vlan-id", "vrf-table", "vrf-member"} {
		if strings.Contains(interfaces, rack) {
			t.Errorf("interfaces still renders %q:\n%s", rack, interfaces)
		}
	}

	resolv, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resolv), "nameserver 192.0.2.10") || strings.Contains(string(resolv), "10.4.6.") {
		t.Errorf("resolv.conf does not resolve through 192.0.2.10 alone:\n%s", resolv)
	}
}
