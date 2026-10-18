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

package deployer

import (
	"errors"
	"testing"
)

func TestDeployConfig_Validate_RequiresImage(t *testing.T) {
	config := &DeployConfig{
		Host:       "192.168.1.1",
		User:       "root",
		SSHKeyPath: "/tmp/key",
		Port:       22,
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for linux target without container_image")
	}
	var target ErrInvalidDeployConfig
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidDeployConfig, got %T: %v", err, err)
	}
}

// TestDeployConfig_Validate_RequiresNetbootMedia: the image
// carries no installer media, so a Linux deploy without the netboot media
// build would start a container with nothing to serve.
func TestDeployConfig_Validate_RequiresNetbootMedia(t *testing.T) {
	config := &DeployConfig{
		Host:           "192.168.1.1",
		User:           "root",
		SSHKeyPath:     "/tmp/key",
		Port:           22,
		ContainerImage: "platform-pxeboot:latest",
		ManifestPath:   "/tmp/manifest.yaml",
	}
	var target ErrInvalidDeployConfig
	if err := config.Validate(); !errors.As(err, &target) || target.Field != "netboot_media_dir" {
		t.Fatalf("expected ErrInvalidDeployConfig for netboot_media_dir, got %v", err)
	}

	config.NetbootMediaDir = "/tmp/netboot-media"
	if err := config.Validate(); err != nil {
		t.Errorf("expected a complete linux config to validate, got %v", err)
	}
}

func TestErrSSHNotConnected(t *testing.T) {
	err := ErrSSHNotConnected{Host: "192.168.1.1", Port: 22}
	expected := "deployer: SSH client not connected to 192.168.1.1:22"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// bootNodeConfig is a complete deploy config in boot-node mode.
func bootNodeConfig(dataDir, firmwareCacheDir string) *DeployConfig {
	return &DeployConfig{
		Host:             "192.168.1.1",
		User:             "root",
		SSHKeyPath:       "/tmp/key",
		ContainerImage:   "platform-pxeboot:latest",
		ManifestPath:     "/tmp/manifest.yaml",
		NetbootMediaDir:  "/tmp/netboot-media",
		DataDir:          dataDir,
		BootNode:         true,
		FirmwareCacheDir: firmwareCacheDir,
	}
}

func TestDeployConfig_ApplyDefaults_FirmwareCacheDir(t *testing.T) {
	tests := []struct {
		name     string
		config   *DeployConfig
		wantDir  string
		wantData string
	}{
		{"boot node defaults beside data_dir", bootNodeConfig("/srv/pxeboot", ""), "/srv/pxeboot-firmware", "/srv/pxeboot"},
		{"trailing slash on data_dir", bootNodeConfig("/srv/pxeboot/", ""), "/srv/pxeboot-firmware", "/srv/pxeboot/"},
		{"explicit path kept", bootNodeConfig("/srv/pxeboot", "/var/lib/pxe-firmware"), "/var/lib/pxe-firmware", "/srv/pxeboot"},
		{"default mode leaves it empty", &DeployConfig{DataDir: "/srv/pxeboot"}, "", "/srv/pxeboot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.ApplyDefaults()
			if tt.config.FirmwareCacheDir != tt.wantDir {
				t.Errorf("FirmwareCacheDir = %q, want %q", tt.config.FirmwareCacheDir, tt.wantDir)
			}
			if tt.config.DataDir != tt.wantData {
				t.Errorf("DataDir = %q, want %q", tt.config.DataDir, tt.wantData)
			}
		})
	}
}

func TestDeployConfig_Validate_BootNode(t *testing.T) {
	tests := []struct {
		name      string
		config    *DeployConfig
		wantField string // "" = valid
	}{
		{"persistent data_dir with default cache", bootNodeConfig("/srv/pxeboot", ""), ""},
		{"explicit cache elsewhere", bootNodeConfig("/srv/pxeboot", "/var/cache/pxe-firmware"), ""},
		{"/tmpfoo is not under /tmp", bootNodeConfig("/tmpfoo/pxeboot", ""), ""},
		{"default data_dir is under /tmp", bootNodeConfig("", ""), "data_dir"},
		{"data_dir under /tmp", bootNodeConfig("/tmp/pxeboot", "/srv/pxeboot-firmware"), "data_dir"},
		{"data_dir under /run", bootNodeConfig("/run/pxeboot", "/srv/pxeboot-firmware"), "data_dir"},
		{"data_dir relative", bootNodeConfig("srv/pxeboot", "/srv/pxeboot-firmware"), "data_dir"},
		{"data_dir is root", bootNodeConfig("/", "/srv/pxeboot-firmware"), "data_dir"},
		{"cache under /dev/shm", bootNodeConfig("/srv/pxeboot", "/dev/shm/firmware"), "firmware_cache_dir"},
		{"cache relative", bootNodeConfig("/srv/pxeboot", "firmware"), "firmware_cache_dir"},
		{"cache inside data_dir", bootNodeConfig("/srv/pxeboot", "/srv/pxeboot/firmware"), "firmware_cache_dir"},
		{"cache equals data_dir", bootNodeConfig("/srv/pxeboot", "/srv/pxeboot/"), "firmware_cache_dir"},
		{"data_dir inside cache", bootNodeConfig("/srv/cache/pxeboot", "/srv/cache"), "firmware_cache_dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.ApplyDefaults()
			err := tt.config.Validate()
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			var target ErrInvalidBootNodeConfig
			if !errors.As(err, &target) {
				t.Fatalf("Validate = %v (%T), want ErrInvalidBootNodeConfig", err, err)
			}
			if target.Field != tt.wantField {
				t.Errorf("field = %q, want %q (%v)", target.Field, tt.wantField, err)
			}
		})
	}
}

// TestDeployConfig_Validate_FirmwareCacheWithoutBootNode: the cache is
// mounted only in boot-node mode, so setting it alone is an error rather
// than a silently ignored key.
func TestDeployConfig_Validate_FirmwareCacheWithoutBootNode(t *testing.T) {
	config := bootNodeConfig("/srv/pxeboot", "/srv/pxeboot-firmware")
	config.BootNode = false
	config.ApplyDefaults()
	var target ErrInvalidBootNodeConfig
	if err := config.Validate(); !errors.As(err, &target) || target.Field != "firmware_cache_dir" {
		t.Fatalf("Validate = %v, want ErrInvalidBootNodeConfig for firmware_cache_dir", err)
	}

	config.FirmwareCacheDir = ""
	if err := config.Validate(); err != nil {
		t.Errorf("default mode without a cache must validate, got %v", err)
	}
}

func TestErrInvalidBootNodeConfig_Error(t *testing.T) {
	err := ErrInvalidBootNodeConfig{Field: "data_dir", Value: "/tmp/bootstrap", Reason: "is under /tmp, which does not survive a reboot"}
	want := `deployer: invalid boot-node config: field data_dir "/tmp/bootstrap": is under /tmp, which does not survive a reboot`
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestDeployConfig_Validate_NoRouter: no-router and a gateway say opposite
// things about the DHCP router option, so together they are refused;
// either one alone is a valid config.
func TestDeployConfig_Validate_NoRouter(t *testing.T) {
	config := &DeployConfig{
		Host:            "192.168.1.1",
		User:            "root",
		SSHKeyPath:      "/tmp/key",
		Port:            22,
		ContainerImage:  "platform-pxeboot:latest",
		ManifestPath:    "/tmp/manifest.yaml",
		NetbootMediaDir: "/tmp/netboot-media",
	}

	config.BootstrapNoRouter = true
	if err := config.Validate(); err != nil {
		t.Fatalf("no-router alone must validate, got %v", err)
	}

	config.BootstrapGateway = "192.0.2.1"
	var target ErrNoRouterWithGateway
	if err := config.Validate(); !errors.As(err, &target) || target.Gateway != "192.0.2.1" {
		t.Fatalf("Validate = %v, want ErrNoRouterWithGateway for 192.0.2.1", err)
	}

	config.BootstrapNoRouter = false
	if err := config.Validate(); err != nil {
		t.Errorf("a gateway without no-router must validate, got %v", err)
	}
}

func TestErrNoRouterWithGateway_Error(t *testing.T) {
	err := ErrNoRouterWithGateway{Gateway: "192.0.2.1"}
	want := `deployer: invalid config: bootstrap_no_router advertises no gateway, but bootstrap_gateway is "192.0.2.1": set one or the other`
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
