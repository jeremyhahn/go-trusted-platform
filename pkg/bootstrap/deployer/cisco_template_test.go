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
	"strings"
	"testing"
)

func TestRenderCiscoConfig(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:          "platform-pxeboot",
		VLANs:          []int{201},
		GuestInterface: 0,
		GuestIP:        "172.16.201.1",
		GuestNetmask:   "255.255.255.0",
		ImageFile:      "platform-pxeboot.tar",
		RunOpts:        []string{"-v $(APP_DATA):/data"},
	}

	output, err := RenderCiscoConfig(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "app-hosting appid platform-pxeboot") {
		t.Error("expected app-hosting appid in output")
	}
	if !strings.Contains(output, "vlan 201 guest-interface 0") {
		t.Error("expected vlan 201 guest-interface 0 in output")
	}
	if !strings.Contains(output, "guest-ipaddress 172.16.201.1 netmask 255.255.255.0") {
		t.Error("expected guest-ipaddress in output")
	}
	if !strings.Contains(output, "app-resource docker") {
		t.Error("expected app-resource docker in output")
	}
	if !strings.Contains(output, `run-opts 1 "-v $(APP_DATA):/data"`) {
		t.Error("expected run-opts in output")
	}
}

func TestRenderCiscoConfig_MultipleVLANs(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:          "platform-pxeboot",
		VLANs:          []int{100, 200, 300},
		GuestInterface: 0,
		GuestIP:        "10.0.0.1",
		GuestNetmask:   "255.255.255.0",
		ImageFile:      "platform-pxeboot.tar",
	}

	output, err := RenderCiscoConfig(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "vlan 100 guest-interface 0") {
		t.Error("expected vlan 100 in output")
	}
	if !strings.Contains(output, "vlan 200 guest-interface 0") {
		t.Error("expected vlan 200 in output")
	}
	if !strings.Contains(output, "vlan 300 guest-interface 0") {
		t.Error("expected vlan 300 in output")
	}
}

func TestRenderCiscoConfig_NoIP(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:          "platform-pxeboot",
		VLANs:          []int{201},
		GuestInterface: 0,
		ImageFile:      "platform-pxeboot.tar",
	}

	output, err := RenderCiscoConfig(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if strings.Contains(output, "guest-ipaddress") {
		t.Error("expected no guest-ipaddress when GuestIP is empty")
	}
}

func TestRenderCiscoConfig_NoRunOpts(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:          "platform-pxeboot",
		VLANs:          []int{201},
		GuestInterface: 0,
		GuestIP:        "172.16.201.1",
		GuestNetmask:   "255.255.255.0",
		ImageFile:      "platform-pxeboot.tar",
	}

	output, err := RenderCiscoConfig(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if strings.Contains(output, "app-resource docker") {
		t.Error("expected no app-resource docker when RunOpts is empty")
	}
	if strings.Contains(output, "run-opts") {
		t.Error("expected no run-opts when RunOpts is empty")
	}
}

func TestRenderCiscoConfig_MultipleRunOpts(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:          "platform-pxeboot",
		VLANs:          []int{201},
		GuestInterface: 0,
		ImageFile:      "platform-pxeboot.tar",
		RunOpts:        []string{"-v $(APP_DATA):/data", "--net=host"},
	}

	output, err := RenderCiscoConfig(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, `run-opts 1 "-v $(APP_DATA):/data"`) {
		t.Error("expected run-opts 1 in output")
	}
	if !strings.Contains(output, `run-opts 2 "--net=host"`) {
		t.Error("expected run-opts 2 in output")
	}
}

func TestRenderCiscoInstall(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:     "platform-pxeboot",
		ImageFile: "platform-pxeboot.tar",
	}

	output, err := RenderCiscoInstall(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "app-hosting install appid platform-pxeboot package flash:platform-pxeboot.tar") {
		t.Error("expected install command in output")
	}
	if !strings.Contains(output, "app-hosting activate appid platform-pxeboot") {
		t.Error("expected activate command in output")
	}
	if !strings.Contains(output, "app-hosting start appid platform-pxeboot") {
		t.Error("expected start command in output")
	}

	// Verify the commands are in the correct order.
	lines := strings.Split(output, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "app-hosting install") {
		t.Error("expected install as first command")
	}
	if !strings.HasPrefix(lines[1], "app-hosting activate") {
		t.Error("expected activate as second command")
	}
	if !strings.HasPrefix(lines[2], "app-hosting start") {
		t.Error("expected start as third command")
	}
}

func TestRenderCiscoInstall_CustomAppID(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID:     "custom-app",
		ImageFile: "custom-app.tar",
	}

	output, err := RenderCiscoInstall(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "appid custom-app") {
		t.Error("expected custom appid in output")
	}
	if !strings.Contains(output, "flash:custom-app.tar") {
		t.Error("expected custom image file in output")
	}
}

func TestRenderCiscoTeardown(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID: "platform-pxeboot",
	}

	output, err := RenderCiscoTeardown(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "app-hosting stop appid platform-pxeboot") {
		t.Error("expected stop command in output")
	}
	if !strings.Contains(output, "app-hosting deactivate appid platform-pxeboot") {
		t.Error("expected deactivate command in output")
	}
	if !strings.Contains(output, "app-hosting uninstall appid platform-pxeboot") {
		t.Error("expected uninstall command in output")
	}
	if !strings.Contains(output, "no app-hosting appid platform-pxeboot") {
		t.Error("expected no app-hosting command in output")
	}

	// Verify teardown order: stop -> deactivate -> uninstall -> remove config.
	lines := strings.Split(output, "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "app-hosting stop") {
		t.Error("expected stop as first teardown command")
	}
	if !strings.HasPrefix(lines[1], "app-hosting deactivate") {
		t.Error("expected deactivate as second teardown command")
	}
	if !strings.HasPrefix(lines[2], "app-hosting uninstall") {
		t.Error("expected uninstall as third teardown command")
	}
	if !strings.HasPrefix(lines[3], "no app-hosting") {
		t.Error("expected no app-hosting as fourth teardown command")
	}
}

func TestRenderCiscoTeardown_CustomAppID(t *testing.T) {
	params := &CiscoAppHostingParams{
		AppID: "my-service",
	}

	output, err := RenderCiscoTeardown(params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "appid my-service") {
		t.Error("expected custom appid in all teardown commands")
	}
}

func TestRenderCiscoDeployPlan(t *testing.T) {
	output, err := RenderCiscoDeployPlan("172.16.201.1", 201)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should contain config mode section.
	if !strings.Contains(output, "configure terminal") {
		t.Error("expected configure terminal in output")
	}
	if !strings.Contains(output, "app-hosting appid platform-pxeboot") {
		t.Error("expected app-hosting appid in output")
	}
	if !strings.Contains(output, "end") {
		t.Error("expected end in output")
	}

	// Should contain exec mode section.
	if !strings.Contains(output, "app-hosting install") {
		t.Error("expected install command in output")
	}
	if !strings.Contains(output, "app-hosting activate") {
		t.Error("expected activate command in output")
	}
	if !strings.Contains(output, "app-hosting start") {
		t.Error("expected start command in output")
	}

	// Should contain the correct VLAN and IP.
	if !strings.Contains(output, "vlan 201") {
		t.Error("expected vlan 201 in output")
	}
	if !strings.Contains(output, "172.16.201.1") {
		t.Error("expected gateway IP in output")
	}
}

func TestRenderCiscoDeployPlan_EmptyGateway(t *testing.T) {
	output, err := RenderCiscoDeployPlan("", 201)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should still render without guest IP section.
	if strings.Contains(output, "guest-ipaddress") {
		t.Error("expected no guest-ipaddress when gateway is empty")
	}
	if !strings.Contains(output, "app-hosting appid platform-pxeboot") {
		t.Error("expected app-hosting appid in output")
	}
}

func TestErrCiscoDeployFailed(t *testing.T) {
	cause := ErrSSHCommand{Command: "test", Cause: errors.New("connection reset")}
	err := ErrCiscoDeployFailed{
		Host:  "198.18.1.252",
		Phase: "install",
		Cause: cause,
	}

	msg := err.Error()
	if !strings.Contains(msg, "198.18.1.252") {
		t.Error("expected host in error message")
	}
	if !strings.Contains(msg, "install") {
		t.Error("expected phase in error message")
	}

	// Verify unwrap.
	var target ErrSSHCommand
	if !errors.As(err, &target) {
		t.Error("expected ErrCiscoDeployFailed to unwrap to ErrSSHCommand")
	}
}

func TestErrCiscoDeployFailed_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	err := ErrCiscoDeployFailed{
		Host:  "router-01",
		Phase: "copy-image",
		Cause: inner,
	}

	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestErrTemplateRender(t *testing.T) {
	cause := errors.New("parse error")
	err := ErrTemplateRender{
		Name:  "cisco-config",
		Cause: cause,
	}

	msg := err.Error()
	if !strings.Contains(msg, "cisco-config") {
		t.Error("expected template name in error message")
	}
	if !strings.Contains(msg, "parse error") {
		t.Error("expected cause in error message")
	}
}

func TestErrTemplateRender_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := ErrTemplateRender{Name: "test", Cause: inner}

	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}
