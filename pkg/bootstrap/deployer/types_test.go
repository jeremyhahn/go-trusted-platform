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
