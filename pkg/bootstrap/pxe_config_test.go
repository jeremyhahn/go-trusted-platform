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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

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
  host: deploy.example.com
  user: deployer
  ssh_key: /home/deployer/.ssh/id_ed25519
  container_runtime: podman
environment:
  id: 4
platform:
  domain: example.com
  internal_domain: internal.example.com
  hostmaster: admin@example.com
  tenant_id: tenant-001
  environment: production
  upstream_dns:
    - 1.1.1.1:53
  bootstrap_strategy: dane
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
	if config.Environment == nil || config.Environment.ID != 4 {
		t.Errorf("expected environment 4, got %+v", config.Environment)
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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

func TestValidate_MissingEnvironment(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: nil,
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
		Nodes: []NodeConfig{
			{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing environment, got nil")
	}

	if e, ok := err.(ErrMissingRequiredField); !ok || e.Field != "environment" {
		t.Errorf("expected ErrMissingRequiredField for environment, got %T: %v", err, err)
	}
}

func TestValidate_MissingDomain(t *testing.T) {
	config := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
		Nodes:       []NodeConfig{},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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

func TestNodeConfig_HasBoardManagement(t *testing.T) {
	tests := []struct {
		name     string
		node     NodeConfig
		expected bool
	}{
		{"BMC block present", NodeConfig{BMCAddress: "10.200.0.10"}, true},
		{"BMC block present with redfish protocol", NodeConfig{BMCAddress: "10.200.0.10", BMCProtocol: "redfish"}, true},
		{"unmanaged PXE node (MAC only)", NodeConfig{MACs: []string{"AA:BB:CC:DD:EE:FF"}}, false},
		{"unmanaged headless node (no BMC, no MAC)", NodeConfig{Hostname: "rpi-01"}, false},
		{"empty", NodeConfig{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.HasBoardManagement(); got != tt.expected {
				t.Errorf("HasBoardManagement() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrVirtualMediaRequiresBoardManagement(t *testing.T) {
	err := ErrVirtualMediaRequiresBoardManagement{Hostname: "rpi-01"}
	msg := err.Error()
	if !strings.Contains(msg, "rpi-01") {
		t.Errorf("error message %q should name the host", msg)
	}
	if !strings.Contains(msg, "virtual-media") || !strings.Contains(msg, "pxe") {
		t.Errorf("error message %q should explain the virtual-media/pxe remedy", msg)
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "example.com"},
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
environment:
  id: 4
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

// --- Interfaces field tests ---

func TestLoadBootstrapConfig_ParsesInterfaces(t *testing.T) {
	yamlContent := `deployer:
  host: deploy.example.com
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp-0
    role: control-plane
    bmc_address: 10.200.0.10
    interfaces:
      - name: eth0
        type: static
        ipv4-address: 198.18.1.140/24
        ipv4-gateway: 198.18.1.1
      - name: eth1
        type: dhcp
`
	path := writeYAMLFile(t, yamlContent)

	config, err := LoadBootstrapConfig(path)
	if err != nil {
		t.Fatalf("LoadBootstrapConfig returned error: %v", err)
	}
	if len(config.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(config.Nodes))
	}
	ifaces := config.Nodes[0].Interfaces
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(ifaces))
	}
	if ifaces[0].Name != "eth0" {
		t.Errorf("interfaces[0].Name = %q, want eth0", ifaces[0].Name)
	}
	if ifaces[0].Type != installer.InterfaceTypeStatic {
		t.Errorf("interfaces[0].Type = %q, want static", ifaces[0].Type)
	}
	if ifaces[0].IPv4Address != "198.18.1.140/24" {
		t.Errorf("interfaces[0].IPv4Address = %q, want 198.18.1.140/24", ifaces[0].IPv4Address)
	}
	if ifaces[0].IPv4Gateway != "198.18.1.1" {
		t.Errorf("interfaces[0].IPv4Gateway = %q, want 198.18.1.1", ifaces[0].IPv4Gateway)
	}
	if ifaces[1].Type != installer.InterfaceTypeDHCP {
		t.Errorf("interfaces[1].Type = %q, want dhcp", ifaces[1].Type)
	}
}

func TestNodeConfig_StaticIPv4s(t *testing.T) {
	tests := []struct {
		name string
		node NodeConfig
		want []string
	}{
		{
			name: "no interfaces",
			node: NodeConfig{},
			want: nil,
		},
		{
			name: "CIDR suffix stripped",
			node: NodeConfig{Interfaces: []installer.InterfaceConfig{
				{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "198.18.1.140/24"},
			}},
			want: []string{"198.18.1.140"},
		},
		{
			name: "plain address preserved",
			node: NodeConfig{Interfaces: []installer.InterfaceConfig{
				{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.0.9"},
			}},
			want: []string{"10.0.0.9"},
		},
		{
			name: "interface without address filtered",
			node: NodeConfig{Interfaces: []installer.InterfaceConfig{
				{Name: "eth0", Type: installer.InterfaceTypeDHCP},
				{Name: "eth1", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.0.9/16"},
			}},
			want: []string{"10.0.0.9"},
		},
		{
			name: "declared address counts regardless of type (historical semantics)",
			node: NodeConfig{Interfaces: []installer.InterfaceConfig{
				{Name: "eth0", Type: installer.InterfaceTypeDHCP, IPv4Address: "172.16.0.5/24"},
			}},
			want: []string{"172.16.0.5"},
		},
		{
			name: "multiple static interfaces preserve order",
			node: NodeConfig{Interfaces: []installer.InterfaceConfig{
				{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.0.1/24"},
				{Name: "eth1", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.1.1/24"},
			}},
			want: []string{"10.0.0.1", "10.0.1.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.StaticIPv4s()
			if len(got) != len(tt.want) {
				t.Fatalf("StaticIPv4s() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("StaticIPv4s()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// --- Forbidden override key tests ---

// forbiddenTestConfig builds a valid single-node config whose overrides can
// be mutated per test case.
func forbiddenTestConfig(overrides map[string]interface{}) *BootstrapConfig {
	return &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
		Environment: testEnvironment(),
		Platform: PlatformGlobalConfig{
			Domain:      "example.com",
			Hostmaster:  "admin@example.com",
			TenantID:    "tenant-001",
			Environment: "production",
		},
		Nodes: []NodeConfig{
			{
				Hostname:   "cp-0",
				Role:       RoleControlPlane,
				BMCAddress: "10.200.0.10",
				Overrides:  overrides,
			},
		},
	}
}

func TestValidate_ForbiddenOverrideKeys_ClassA(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]interface{}
		keyPath   string
		useField  string
	}{
		{
			name:      "os.hostname",
			overrides: map[string]interface{}{"os": map[string]interface{}{"hostname": "x"}},
			keyPath:   "os.hostname",
			useField:  "nodes[].hostname",
		},
		{
			name:      "network.interfaces",
			overrides: map[string]interface{}{"network": map[string]interface{}{"interfaces": []interface{}{}}},
			keyPath:   "network.interfaces",
			useField:  "nodes[].interfaces",
		},
		{
			name:      "bmc.address",
			overrides: map[string]interface{}{"bmc": map[string]interface{}{"address": "10.0.0.1"}},
			keyPath:   "bmc.address",
			useField:  "nodes[].bmc_address",
		},
		{
			name:      "bmc.username",
			overrides: map[string]interface{}{"bmc": map[string]interface{}{"username": "admin"}},
			keyPath:   "bmc.username",
			useField:  "nodes[].bmc_user",
		},
		{
			name:      "bmc.password",
			overrides: map[string]interface{}{"bmc": map[string]interface{}{"password": "secret"}},
			keyPath:   "bmc.password",
			useField:  "nodes[].bmc_password",
		},
		{
			name:      "bmc.protocol",
			overrides: map[string]interface{}{"bmc": map[string]interface{}{"protocol": "redfish"}},
			keyPath:   "bmc.protocol",
			useField:  "nodes[].bmc_protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := forbiddenTestConfig(tt.overrides)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected ErrForbiddenOverrideKey for %s", tt.keyPath)
			}
			fk, ok := err.(ErrForbiddenOverrideKey)
			if !ok {
				t.Fatalf("expected ErrForbiddenOverrideKey, got %T: %v", err, err)
			}
			if fk.KeyPath != tt.keyPath {
				t.Errorf("KeyPath = %q, want %q", fk.KeyPath, tt.keyPath)
			}
			if fk.UseField != tt.useField {
				t.Errorf("UseField = %q, want %q", fk.UseField, tt.useField)
			}
			if fk.Hostname != "cp-0" {
				t.Errorf("Hostname = %q, want cp-0", fk.Hostname)
			}
			if fk.Source != "" || fk.Line != 0 {
				t.Errorf("merged backstop should have empty Source/Line, got %q:%d", fk.Source, fk.Line)
			}
		})
	}
}

func TestValidate_ForbiddenOverrideKeys_ClassB(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]interface{}
		wantErr   bool
		keyPath   string
	}{
		{
			name:      "domain equal to platform global rejected",
			overrides: map[string]interface{}{"domain": "example.com"},
			wantErr:   true,
			keyPath:   "domain",
		},
		{
			name:      "domain differing from platform global accepted",
			overrides: map[string]interface{}{"domain": "custom.example.org"},
			wantErr:   false,
		},
		{
			name:      "hostmaster equal rejected",
			overrides: map[string]interface{}{"hostmaster": "admin@example.com"},
			wantErr:   true,
			keyPath:   "hostmaster",
		},
		{
			name:      "tenant-id equal rejected",
			overrides: map[string]interface{}{"tenant-id": "tenant-001"},
			wantErr:   true,
			keyPath:   "tenant-id",
		},
		{
			name:      "legacy tenant_id equal rejected",
			overrides: map[string]interface{}{"tenant_id": "tenant-001"},
			wantErr:   true,
			keyPath:   "tenant_id",
		},
		{
			name:      "environment equal rejected",
			overrides: map[string]interface{}{"environment": "production"},
			wantErr:   true,
			keyPath:   "environment",
		},
		{
			name:      "environment differing accepted",
			overrides: map[string]interface{}{"environment": "staging"},
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := forbiddenTestConfig(tt.overrides)
			err := cfg.Validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected ErrForbiddenOverrideKey for %s", tt.keyPath)
			}
			fk, ok := err.(ErrForbiddenOverrideKey)
			if !ok {
				t.Fatalf("expected ErrForbiddenOverrideKey, got %T: %v", err, err)
			}
			if fk.KeyPath != tt.keyPath {
				t.Errorf("KeyPath = %q, want %q", fk.KeyPath, tt.keyPath)
			}
		})
	}
}

func TestLoadBootstrapConfig_ForbiddenKeyInOverridesFile(t *testing.T) {
	dir := t.TempDir()
	overridesPath := filepath.Join(dir, "cp-0.yaml")
	overridesContent := `tpm:
  idevid:
    serial: cp-0-serial
network:
  interfaces:
    - name: eth0
      ipv4-address: 10.0.0.5/24
`
	if err := os.WriteFile(overridesPath, []byte(overridesContent), 0600); err != nil {
		t.Fatalf("write overrides: %v", err)
	}

	bootstrapContent := `deployer:
  host: deploy.example.com
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp-0
    role: control-plane
    bmc_address: 10.200.0.10
    overrides_file: cp-0.yaml
`
	bootstrapPath := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(bootstrapPath, []byte(bootstrapContent), 0600); err != nil {
		t.Fatalf("write bootstrap.yaml: %v", err)
	}

	_, err := LoadBootstrapConfig(bootstrapPath)
	if err == nil {
		t.Fatal("expected ErrForbiddenOverrideKey for network.interfaces in overrides file")
	}
	fk, ok := err.(ErrForbiddenOverrideKey)
	if !ok {
		t.Fatalf("expected ErrForbiddenOverrideKey, got %T: %v", err, err)
	}
	if fk.Source != overridesPath {
		t.Errorf("Source = %q, want %q", fk.Source, overridesPath)
	}
	if fk.Line != 5 {
		t.Errorf("Line = %d, want 5 (line of the interfaces key)", fk.Line)
	}
	if fk.KeyPath != "network.interfaces" {
		t.Errorf("KeyPath = %q, want network.interfaces", fk.KeyPath)
	}
	if fk.Hostname != "cp-0" {
		t.Errorf("Hostname = %q, want cp-0", fk.Hostname)
	}
}

func TestLoadBootstrapConfig_ForbiddenKeyInline(t *testing.T) {
	dir := t.TempDir()
	bootstrapContent := `deployer:
  host: deploy.example.com
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp-0
    role: control-plane
    bmc_address: 10.200.0.10
    overrides:
      os:
        hostname: sneaky-host
`
	bootstrapPath := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(bootstrapPath, []byte(bootstrapContent), 0600); err != nil {
		t.Fatalf("write bootstrap.yaml: %v", err)
	}

	_, err := LoadBootstrapConfig(bootstrapPath)
	if err == nil {
		t.Fatal("expected ErrForbiddenOverrideKey for inline os.hostname override")
	}
	fk, ok := err.(ErrForbiddenOverrideKey)
	if !ok {
		t.Fatalf("expected ErrForbiddenOverrideKey, got %T: %v", err, err)
	}
	if fk.Source != bootstrapPath {
		t.Errorf("Source = %q, want %q", fk.Source, bootstrapPath)
	}
	if fk.Line != 13 {
		t.Errorf("Line = %d, want 13 (line of the hostname key)", fk.Line)
	}
	if fk.KeyPath != "os.hostname" {
		t.Errorf("KeyPath = %q, want os.hostname", fk.KeyPath)
	}
}

func TestLoadBootstrapConfig_LegalOverridesPass(t *testing.T) {
	dir := t.TempDir()
	overridesPath := filepath.Join(dir, "cp-0.yaml")
	if err := os.WriteFile(overridesPath, []byte("tpm:\n  idevid:\n    serial: cp-0-serial\n"), 0600); err != nil {
		t.Fatalf("write overrides: %v", err)
	}
	bootstrapContent := `deployer:
  host: deploy.example.com
  netboot_media_dir: ` + fleetMedia + `
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp-0
    role: control-plane
    bmc_address: 10.200.0.10
    overrides_file: cp-0.yaml
    interfaces:
      - name: eth0
        type: static
        ipv4-address: 10.0.0.5/24
    overrides:
      os:
        timezone: UTC
      domain: custom.example.org
`
	bootstrapPath := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(bootstrapPath, []byte(bootstrapContent), 0600); err != nil {
		t.Fatalf("write bootstrap.yaml: %v", err)
	}

	config, err := LoadBootstrapConfig(bootstrapPath)
	if err != nil {
		t.Fatalf("LoadBootstrapConfig returned error for legal overrides: %v", err)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned error for legal overrides: %v", err)
	}
	// The typed interfaces and merged overrides must both survive.
	if got := config.Nodes[0].StaticIPv4s(); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Errorf("StaticIPv4s = %v, want [10.0.0.5]", got)
	}
	tpm, ok := config.Nodes[0].Overrides["tpm"].(map[string]interface{})
	if !ok {
		t.Fatal("overrides file content should be merged into node.Overrides")
	}
	if idevid, ok := tpm["idevid"].(map[string]interface{}); !ok || idevid["serial"] != "cp-0-serial" {
		t.Errorf("tpm.idevid.serial = %v, want cp-0-serial", tpm["idevid"])
	}
}

func TestBootstrapConfig_TemplatePath(t *testing.T) {
	cfg := &BootstrapConfig{Templates: map[string]string{
		RoleControlPlane: filepath.Join("roles", "control-plane.yaml"),
		RoleGateway:      filepath.Join(string(filepath.Separator), "etc", "platform", "gateway.yaml"),
	}}

	tests := []struct {
		name      string
		role      string
		configDir string
		wantPath  string
		wantOK    bool
	}{
		{
			name:      "relative path joins the config directory",
			role:      RoleControlPlane,
			configDir: filepath.Join(string(filepath.Separator), "srv", "deploy"),
			wantPath:  filepath.Join(string(filepath.Separator), "srv", "deploy", "roles", "control-plane.yaml"),
			wantOK:    true,
		},
		{
			name:      "absolute path is returned unchanged",
			role:      RoleGateway,
			configDir: filepath.Join(string(filepath.Separator), "srv", "deploy"),
			wantPath:  filepath.Join(string(filepath.Separator), "etc", "platform", "gateway.yaml"),
			wantOK:    true,
		},
		{
			name:      "empty config dir leaves the path as written",
			role:      RoleControlPlane,
			configDir: "",
			wantPath:  filepath.Join("roles", "control-plane.yaml"),
			wantOK:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cfg.TemplatePath(tt.role, tt.configDir)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantPath {
				t.Errorf("path = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestBootstrapConfig_TemplatePath_UnconfiguredRole(t *testing.T) {
	cfg := &BootstrapConfig{Templates: map[string]string{
		RoleControlPlane: "control-plane.yaml",
	}}

	got, ok := cfg.TemplatePath(RoleWorker, "/srv/deploy")
	if ok {
		t.Errorf("ok = true for an unconfigured role, want false")
	}
	if got != "" {
		t.Errorf("path = %q for an unconfigured role, want empty", got)
	}

	// A nil Templates map must behave the same way rather than panic.
	empty := &BootstrapConfig{}
	if _, ok := empty.TemplatePath(RoleControlPlane, "/srv/deploy"); ok {
		t.Errorf("ok = true for a config with no templates, want false")
	}
}

func TestLoadBootstrapConfig_NetbootMediaDirIsRelativeToTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.yaml")
	content := `deployer:
  host: deploy.example.com
  netboot_media_dir: build/netboot-media
  proxy_dhcp: true
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp1
    role: control-plane
    macs: ["aa:bb:cc:dd:ee:01"]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadBootstrapConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if want := filepath.Join(dir, "build", "netboot-media"); cfg.Deployer.NetbootMediaDir != want {
		t.Fatalf("netboot_media_dir = %q, want %q (relative to bootstrap.yaml, like overrides_file)", cfg.Deployer.NetbootMediaDir, want)
	}
	if !cfg.Deployer.ProxyDHCP {
		t.Fatal("proxy_dhcp was not read")
	}
}

// TestLoadBootstrapConfig_BackupsDirBelongsToTheConfig: the BMC cert
// backups live with the deployment's configuration — beside bootstrap.yaml
// by default, a relative path resolved against it, ~ expanded, an absolute
// path kept.
func TestLoadBootstrapConfig_BackupsDirBelongsToTheConfig(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "deployments", "fleet", "bootstrap.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, line, want string
	}{
		{"default beside the config", "", filepath.Join(dir, "deployments", "fleet", "backups")},
		{"relative to the config", "backups_dir: ../../backups\n", filepath.Join(dir, "backups")},
		{"home", "backups_dir: ~/fleet-backups\n", filepath.Join(home, "fleet-backups")},
		{"absolute", "backups_dir: /srv/backups\n", "/srv/backups"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.line + `deployer:
  host: deploy.example.com
environment:
  id: 4
platform:
  domain: example.com
nodes:
  - hostname: cp1
    role: control-plane
    macs: ["aa:bb:cc:dd:ee:01"]
`
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadBootstrapConfig(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			got, err := cfg.EffectiveBackupsDir()
			if err != nil || got != tc.want {
				t.Fatalf("backups dir = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestEffectiveBackupsDir_InMemory: a config built in memory, never loaded
// from a file, falls back to the default relative to the working directory
// and still expands ~.
func TestEffectiveBackupsDir_InMemory(t *testing.T) {
	got, err := (&BootstrapConfig{}).EffectiveBackupsDir()
	if err != nil || got != defaultBackupsDir {
		t.Fatalf("EffectiveBackupsDir = %q, %v; want %q", got, err, defaultBackupsDir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	got, err = (&BootstrapConfig{BackupsDir: "~/b"}).EffectiveBackupsDir()
	if err != nil || got != filepath.Join(home, "b") {
		t.Fatalf("EffectiveBackupsDir(~/b) = %q, %v", got, err)
	}
}
