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
	"testing"
)

// validBootstrapYAML returns a valid bootstrap YAML string with the given
// number of control-plane, gateway, and worker nodes.
func validBootstrapYAML(cpCount, gwCount, workerCount int) string {
	yaml := `deployer:
  target: linux
  host: deploy.example.com
  user: deployer
  ssh_key: /home/deployer/.ssh/id_ed25519
  container_runtime: podman
provisioning_network:
  subnet: 10.100.0.0/24
  gateway: 10.100.0.1
  dhcp_range_start: 10.100.0.100
  dhcp_range_end: 10.100.0.200
  dns:
    - 10.100.0.1
platform:
  domain: example.com
  internal_domain: internal.example.com
  hostmaster: admin@example.com
  tenant_id: tenant-001
  environment: production
  upstream_dns:
    - 1.1.1.1:53
    - 8.8.8.8:53
  bootstrap_strategy: dane
templates:
  control-plane: /etc/platform/templates/control-plane.yaml
  gateway: /etc/platform/templates/gateway.yaml
  worker: /etc/platform/templates/worker.yaml
nodes:
`
	for i := 0; i < cpCount; i++ {
		yaml += `  - hostname: cp-` + string(rune('0'+i)) + `
    role: control-plane
    bmc_address: 10.200.0.` + string(rune('0'+i+1)) + `0
    bmc_user: admin
    bmc_password: secret
    bmc_protocol: redfish
`
	}
	for i := 0; i < gwCount; i++ {
		yaml += `  - hostname: gw-` + string(rune('0'+i)) + `
    role: gateway
    mac: "AA:BB:CC:DD:0` + string(rune('0'+i)) + `:01"
`
	}
	for i := 0; i < workerCount; i++ {
		yaml += `  - hostname: worker-` + string(rune('0'+i)) + `
    role: worker
    mac: "AA:BB:CC:DD:1` + string(rune('0'+i)) + `:01"
`
	}
	return yaml
}

func writeYAMLFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test YAML: %v", err)
	}
	return path
}

func TestLoadBootstrapConfig_Valid(t *testing.T) {
	yamlContent := `deployer:
  target: linux
  host: deploy.example.com
  user: deployer
  ssh_key: /home/deployer/.ssh/id_ed25519
  container_runtime: podman
provisioning_network:
  subnet: 10.100.0.0/24
  gateway: 10.100.0.1
  dhcp_range_start: 10.100.0.100
  dhcp_range_end: 10.100.0.200
  dns:
    - 10.100.0.1
platform:
  domain: example.com
  internal_domain: internal.example.com
  hostmaster: admin@example.com
  tenant_id: tenant-001
  environment: production
  upstream_dns:
    - 1.1.1.1:53
  bootstrap_strategy: dane
  networks:
    management:
      vlan: 100
      subnet: 10.100.0.0/24
templates:
  control-plane: /etc/platform/templates/cp.yaml
nodes:
  - hostname: cp-0
    role: control-plane
    bmc_address: 10.200.0.10
    bmc_user: admin
    bmc_password: secret
    bmc_protocol: redfish
`

	path := writeYAMLFile(t, yamlContent)

	config, err := LoadBootstrapConfig(path)
	if err != nil {
		t.Fatalf("LoadBootstrapConfig returned error: %v", err)
	}

	if config.Deployer.Host != "deploy.example.com" {
		t.Errorf("expected deployer host deploy.example.com, got %s", config.Deployer.Host)
	}
	if config.Platform.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", config.Platform.Domain)
	}
	if len(config.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(config.Nodes))
	}
	if config.Platform.Networks["management"].VLAN != 100 {
		t.Errorf("expected management VLAN 100, got %d", config.Platform.Networks["management"].VLAN)
	}
}

func TestLoadBootstrapConfig_FileNotFound(t *testing.T) {
	_, err := LoadBootstrapConfig("/nonexistent/path/bootstrap.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	if _, ok := err.(ErrConfigFileNotFound); !ok {
		t.Errorf("expected ErrConfigFileNotFound, got %T: %v", err, err)
	}
}

func TestLoadBootstrapConfig_EmptyPath(t *testing.T) {
	_, err := LoadBootstrapConfig("")
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}

	if _, ok := err.(ErrMissingRequiredField); !ok {
		t.Errorf("expected ErrMissingRequiredField, got %T: %v", err, err)
	}
}

func TestLoadBootstrapConfig_InvalidYAML(t *testing.T) {
	path := writeYAMLFile(t, "{{{{invalid yaml")

	_, err := LoadBootstrapConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}

	if _, ok := err.(ErrParseYAML); !ok {
		t.Errorf("expected ErrParseYAML, got %T: %v", err, err)
	}
}

func TestValidate_Valid_3CP_2GW_2Worker(t *testing.T) {
	config := &BootstrapConfig{
		Deployer: DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{
			Subnet: "10.100.0.0/24",
		},
		Platform: PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10", BMCUser: "admin", BMCPassword: "secret"},
			{Hostname: "cp-1", Role: RoleControlPlane, BMCAddress: "10.200.0.11", BMCUser: "admin", BMCPassword: "secret"},
			{Hostname: "cp-2", Role: RoleControlPlane, BMCAddress: "10.200.0.12", BMCUser: "admin", BMCPassword: "secret"},
			{Hostname: "gw-0", Role: RoleGateway, MACs: []string{"AA:BB:CC:DD:00:01"}},
			{Hostname: "gw-1", Role: RoleGateway, MACs: []string{"AA:BB:CC:DD:00:02"}},
			{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
			{Hostname: "w-1", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:02"}},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error: %v", err)
	}
}

func TestValidate_EvenControlPlane(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
			{Hostname: "cp-1", Role: RoleControlPlane, BMCAddress: "10.200.0.11"},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for even control-plane count, got nil")
	}

	if _, ok := err.(ErrInvalidControlPlaneCount); !ok {
		t.Errorf("expected ErrInvalidControlPlaneCount, got %T: %v", err, err)
	}
}

func TestValidate_NoControlPlane(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for zero control-plane count, got nil")
	}

	if e, ok := err.(ErrInvalidControlPlaneCount); !ok {
		t.Errorf("expected ErrInvalidControlPlaneCount, got %T: %v", err, err)
	} else if e.Count != 0 {
		t.Errorf("expected count 0, got %d", e.Count)
	}
}

func TestValidate_SingleControlPlane(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error for standalone: %v", err)
	}
}

func TestValidate_DuplicateMAC(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
			{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate MAC, got nil")
	}

	if _, ok := err.(ErrDuplicateMAC); !ok {
		t.Errorf("expected ErrDuplicateMAC, got %T: %v", err, err)
	}
}

func TestValidate_DuplicateBMCAddress(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
			{Hostname: "cp-1", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate BMC address, got nil")
	}

	if _, ok := err.(ErrInvalidBootstrapConfig); !ok {
		t.Errorf("expected ErrInvalidBootstrapConfig, got %T: %v", err, err)
	}
}

func TestValidate_NoMACOrBMC(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "orphan", Role: RoleControlPlane},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for node without MAC or BMC, got nil")
	}

	if _, ok := err.(ErrNodeMissingIdentity); !ok {
		t.Errorf("expected ErrNodeMissingIdentity, got %T: %v", err, err)
	}
}

func TestValidate_InvalidRole(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "bad-role", Role: "database", MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for invalid role, got nil")
	}

	if _, ok := err.(ErrInvalidNodeRole); !ok {
		t.Errorf("expected ErrInvalidNodeRole, got %T: %v", err, err)
	}
}

func TestValidate_MissingDeployerHost(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing deployer host, got nil")
	}

	if e, ok := err.(ErrMissingRequiredField); !ok {
		t.Errorf("expected ErrMissingRequiredField, got %T: %v", err, err)
	} else if e.Field != "deployer.host" {
		t.Errorf("expected field deployer.host, got %s", e.Field)
	}
}

func TestValidate_MissingSubnet(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing subnet, got nil")
	}

	if e, ok := err.(ErrMissingRequiredField); !ok || e.Field != "provisioning_network.subnet" {
		t.Errorf("expected ErrMissingRequiredField for provisioning_network.subnet, got %T: %v", err, err)
	}
}

func TestValidate_MissingDomain(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing domain, got nil")
	}

	if e, ok := err.(ErrMissingRequiredField); !ok || e.Field != "platform.domain" {
		t.Errorf("expected ErrMissingRequiredField for platform.domain, got %T: %v", err, err)
	}
}

func TestValidate_MissingHostname(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing hostname, got nil")
	}

	if _, ok := err.(ErrMissingRequiredField); !ok {
		t.Errorf("expected ErrMissingRequiredField, got %T: %v", err, err)
	}
}

func TestValidate_NoNodes(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes:               []NodeConfig{},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for no nodes, got nil")
	}

	if _, ok := err.(ErrInvalidBootstrapConfig); !ok {
		t.Errorf("expected ErrInvalidBootstrapConfig, got %T: %v", err, err)
	}
}

func TestValidate_FiveControlPlane(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
			{Hostname: "cp-1", Role: RoleControlPlane, BMCAddress: "10.200.0.11"},
			{Hostname: "cp-2", Role: RoleControlPlane, BMCAddress: "10.200.0.12"},
			{Hostname: "cp-3", Role: RoleControlPlane, BMCAddress: "10.200.0.13"},
			{Hostname: "cp-4", Role: RoleControlPlane, BMCAddress: "10.200.0.14"},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error for 5 control-plane nodes: %v", err)
	}
}

func TestValidate_FourControlPlane(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, BMCAddress: "10.200.0.10"},
			{Hostname: "cp-1", Role: RoleControlPlane, BMCAddress: "10.200.0.11"},
			{Hostname: "cp-2", Role: RoleControlPlane, BMCAddress: "10.200.0.12"},
			{Hostname: "cp-3", Role: RoleControlPlane, BMCAddress: "10.200.0.13"},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for 4 control-plane nodes, got nil")
	}

	if _, ok := err.(ErrInvalidControlPlaneCount); !ok {
		t.Errorf("expected ErrInvalidControlPlaneCount, got %T: %v", err, err)
	}
}

func TestNodeConfig_IsBMCManaged(t *testing.T) {
	tests := []struct {
		name     string
		node     NodeConfig
		expected bool
	}{
		{"with BMC address", NodeConfig{BMCAddress: "10.200.0.10"}, true},
		{"without BMC address", NodeConfig{MACs: []string{"AA:BB:CC:DD:EE:FF"}}, false},
		{"empty", NodeConfig{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.IsBMCManaged(); got != tt.expected {
				t.Errorf("IsBMCManaged() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNodeConfig_IsManual(t *testing.T) {
	tests := []struct {
		name     string
		node     NodeConfig
		expected bool
	}{
		{"manual with MAC only", NodeConfig{MACs: []string{"AA:BB:CC:DD:EE:FF"}}, true},
		{"BMC managed", NodeConfig{BMCAddress: "10.200.0.10", MACs: []string{"AA:BB:CC:DD:EE:FF"}}, false},
		{"empty", NodeConfig{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.IsManual(); got != tt.expected {
				t.Errorf("IsManual() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestValidRoles(t *testing.T) {
	validTests := []string{RoleControlPlane, RoleGateway, RoleWorker}
	for _, role := range validTests {
		if _, ok := validRoles[role]; !ok {
			t.Errorf("expected role %q to be valid", role)
		}
	}

	invalidTests := []string{"database", "loadbalancer", ""}
	for _, role := range invalidTests {
		if _, ok := validRoles[role]; ok {
			t.Errorf("expected role %q to be invalid", role)
		}
	}
}

// --- SkipInstall validation tests ---

func TestValidate_SkipInstallNodeWithoutMACOrBMC(t *testing.T) {
	// A skip_install node should pass validation without BMC or MAC.
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, SkipInstall: true},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error for skip_install node without MAC/BMC: %v", err)
	}
}

func TestValidate_SkipInstallDoesNotRequireISO(t *testing.T) {
	// A skip_install node with virtual-media boot method should not
	// trigger the iso_path requirement.
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{
				Hostname:    "cp-0",
				Role:        RoleControlPlane,
				BMCAddress:  "10.200.0.10",
				BootMethod:  BootMethodVirtualMedia,
				SkipInstall: true,
			},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error for skip_install virtual-media node without iso_path: %v", err)
	}
}

func TestValidate_SkipInstallCountsAsControlPlane(t *testing.T) {
	// A skip_install control-plane node should count toward the
	// control-plane quorum.
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, SkipInstall: true},
			{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error: %v", err)
	}
}

func TestValidate_NonSkipInstallStillRequiresIdentity(t *testing.T) {
	// A non-skip_install node still requires BMC or MAC.
	config := &BootstrapConfig{
		Deployer:            DeployerConfig{Host: "deploy.example.com"},
		ProvisioningNetwork: ProvisioningNetwork{Subnet: "10.100.0.0/24"},
		Platform:            PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, SkipInstall: true},
			{Hostname: "w-0", Role: RoleWorker}, // no MAC, no BMC, no skip_install
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for non-skip_install node without MAC or BMC")
	}

	if _, ok := err.(ErrNodeMissingIdentity); !ok {
		t.Errorf("expected ErrNodeMissingIdentity, got %T: %v", err, err)
	}
}

func TestLoadBootstrapConfig_SkipInstallYAML(t *testing.T) {
	yamlContent := `deployer:
  host: deploy.example.com
provisioning_network:
  subnet: 10.100.0.0/24
platform:
  domain: example.com
nodes:
  - hostname: cp-0
    role: control-plane
    skip_install: true
  - hostname: w-0
    role: worker
    mac: "AA:BB:CC:DD:00:01"
`
	path := writeYAMLFile(t, yamlContent)

	config, err := LoadBootstrapConfig(path)
	if err != nil {
		t.Fatalf("LoadBootstrapConfig returned error: %v", err)
	}

	if len(config.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(config.Nodes))
	}
	if !config.Nodes[0].SkipInstall {
		t.Error("expected cp-0 SkipInstall to be true")
	}
	if config.Nodes[1].SkipInstall {
		t.Error("expected w-0 SkipInstall to be false")
	}
}
