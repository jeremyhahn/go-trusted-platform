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
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCopyCommand_TFTP(t *testing.T) {
	cmd := BuildCopyCommand("tftp", "198.18.1.91", "admin", "platform-pxeboot.tar")
	expected := "copy tftp://198.18.1.91/platform-pxeboot.tar bootflash:platform-pxeboot.tar"
	if cmd != expected {
		t.Errorf("BuildCopyCommand(tftp) = %q, want %q", cmd, expected)
	}
}

func TestBuildCopyCommand_SCP(t *testing.T) {
	cmd := BuildCopyCommand("scp", "198.18.1.91", "admin", "platform-pxeboot.tar")
	expected := "copy scp://admin@198.18.1.91/platform-pxeboot.tar bootflash:platform-pxeboot.tar"
	if cmd != expected {
		t.Errorf("BuildCopyCommand(scp) = %q, want %q", cmd, expected)
	}
}

func TestBuildCopyCommand_HTTP(t *testing.T) {
	cmd := BuildCopyCommand("http", "198.18.1.91", "admin", "platform-pxeboot.tar")
	expected := "copy http://198.18.1.91/platform-pxeboot.tar bootflash:platform-pxeboot.tar"
	if cmd != expected {
		t.Errorf("BuildCopyCommand(http) = %q, want %q", cmd, expected)
	}
}

func TestBuildCopyCommand_DefaultsTFTP(t *testing.T) {
	cmd := BuildCopyCommand("unknown", "10.0.0.1", "user", "image.tar")
	expected := "copy tftp://10.0.0.1/image.tar bootflash:image.tar"
	if cmd != expected {
		t.Errorf("BuildCopyCommand(unknown) = %q, want %q", cmd, expected)
	}
}

func TestParseConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.cfg")

	content := `! Cisco IOS-XE Configuration
! Generated for platform-pxeboot

app-hosting appid platform-pxeboot
 app-vnic AppGigabitEthernet trunk
  vlan 201 guest-interface 0

! End of configuration
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	lines, err := ParseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	if len(lines) != 3 {
		t.Fatalf("expected 3 config lines, got %d: %v", len(lines), lines)
	}

	if lines[0] != "app-hosting appid platform-pxeboot" {
		t.Errorf("line[0] = %q, want %q", lines[0], "app-hosting appid platform-pxeboot")
	}
	if lines[1] != "app-vnic AppGigabitEthernet trunk" {
		t.Errorf("line[1] = %q, want %q", lines[1], "app-vnic AppGigabitEthernet trunk")
	}
	if lines[2] != "vlan 201 guest-interface 0" {
		t.Errorf("line[2] = %q, want %q", lines[2], "vlan 201 guest-interface 0")
	}
}

func TestParseConfigFile_Empty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "empty.cfg")

	if err := os.WriteFile(cfgPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty config: %v", err)
	}

	lines, err := ParseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	if len(lines) != 0 {
		t.Errorf("expected 0 lines from empty file, got %d", len(lines))
	}
}

func TestParseConfigFile_OnlyComments(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "comments.cfg")

	content := `! Comment 1
! Comment 2

! Comment 3
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	lines, err := ParseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	if len(lines) != 0 {
		t.Errorf("expected 0 lines from comments-only file, got %d", len(lines))
	}
}

func TestParseConfigFile_NonExistent(t *testing.T) {
	_, err := ParseConfigFile("/nonexistent/path/config.cfg")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	var target ErrConfigFileRead
	if !errors.As(err, &target) {
		t.Errorf("expected ErrConfigFileRead, got %T: %v", err, err)
	}
}

func TestParseAppHostingRunning_Running(t *testing.T) {
	output := `App id                                   State
------------------------------------------------------
platform-pxeboot                          RUNNING
`
	if !ParseAppHostingRunning(output, "platform-pxeboot") {
		t.Error("expected ParseAppHostingRunning to return true for RUNNING app")
	}
}

func TestParseAppHostingRunning_NotRunning(t *testing.T) {
	output := `App id                                   State
------------------------------------------------------
platform-pxeboot                          STOPPED
`
	if ParseAppHostingRunning(output, "platform-pxeboot") {
		t.Error("expected ParseAppHostingRunning to return false for STOPPED app")
	}
}

func TestParseAppHostingRunning_NotPresent(t *testing.T) {
	output := `App id                                   State
------------------------------------------------------
other-app                                 RUNNING
`
	if ParseAppHostingRunning(output, "platform-pxeboot") {
		t.Error("expected ParseAppHostingRunning to return false when app not listed")
	}
}

func TestParseAppHostingRunning_EmptyOutput(t *testing.T) {
	if ParseAppHostingRunning("", "platform-pxeboot") {
		t.Error("expected ParseAppHostingRunning to return false for empty output")
	}
}

func TestParseAppHostingRunning_CaseInsensitive(t *testing.T) {
	output := `platform-pxeboot    Running`
	if !ParseAppHostingRunning(output, "platform-pxeboot") {
		t.Error("expected ParseAppHostingRunning to handle case-insensitive RUNNING")
	}
}

func TestCiscoDeployer_BuildParams(t *testing.T) {
	d := &CiscoDeployer{logger: testLogger()}
	config := &DeployConfig{
		Target:     TargetCisco,
		Host:       "198.18.1.252",
		User:       "admin",
		SSHKeyPath: "/tmp/key",
		ProvisioningSubnet: &installer.SubnetConfig{
			Gateway: "172.16.201.1",
		},
	}

	params := d.buildParams(config)

	if params.AppID != DefaultCiscoAppID {
		t.Errorf("expected appid %s, got %s", DefaultCiscoAppID, params.AppID)
	}
	if params.GuestIP != "172.16.201.1" {
		t.Errorf("expected guest IP 172.16.201.1, got %s", params.GuestIP)
	}
	if params.GuestNetmask != DefaultCiscoGuestNetmask {
		t.Errorf("expected netmask %s, got %s", DefaultCiscoGuestNetmask, params.GuestNetmask)
	}
	if len(params.VLANs) != 1 || params.VLANs[0] != DefaultCiscoProvisioningVLAN {
		t.Errorf("expected VLAN %d, got %v", DefaultCiscoProvisioningVLAN, params.VLANs)
	}
	if params.ImageFile != DefaultCiscoImageFile {
		t.Errorf("expected image file %s, got %s", DefaultCiscoImageFile, params.ImageFile)
	}
	if len(params.RunOpts) != 1 {
		t.Fatalf("expected 1 run opt, got %d", len(params.RunOpts))
	}
}

func TestCiscoDeployer_BuildParams_NoGateway(t *testing.T) {
	d := &CiscoDeployer{logger: testLogger()}
	config := &DeployConfig{
		Target:     TargetCisco,
		Host:       "198.18.1.252",
		User:       "admin",
		SSHKeyPath: "/tmp/key",
	}

	params := d.buildParams(config)

	if params.GuestIP != "" {
		t.Errorf("expected empty guest IP, got %s", params.GuestIP)
	}
	if params.GuestNetmask != "" {
		t.Errorf("expected empty netmask, got %s", params.GuestNetmask)
	}
}

func TestCiscoDeployer_BuildParams_CustomAppID(t *testing.T) {
	d := &CiscoDeployer{logger: testLogger()}
	config := &DeployConfig{
		Target:         TargetCisco,
		Host:           "198.18.1.252",
		User:           "admin",
		SSHKeyPath:     "/tmp/key",
		CiscoAppID:     "custom-app",
		CiscoImageFile: "custom-app.tar",
	}

	params := d.buildParams(config)

	if params.AppID != "custom-app" {
		t.Errorf("expected appid custom-app, got %s", params.AppID)
	}
	if params.ImageFile != "custom-app.tar" {
		t.Errorf("expected image file custom-app.tar, got %s", params.ImageFile)
	}
}

func TestDeployConfig_Validate_CiscoTarget(t *testing.T) {
	config := &DeployConfig{
		Target:     TargetCisco,
		Host:       "198.18.1.252",
		User:       "admin",
		SSHKeyPath: "/tmp/key",
		Port:       22,
	}

	if err := config.Validate(); err != nil {
		t.Errorf("expected no error for cisco target without container_image, got %v", err)
	}
}

func TestDeployConfig_Validate_LinuxTarget_RequiresImage(t *testing.T) {
	config := &DeployConfig{
		Target:     TargetLinux,
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

func TestErrUnsupportedTransferProtocol(t *testing.T) {
	err := ErrUnsupportedTransferProtocol{Protocol: "ftp"}
	if err.Error() != "deployer: unsupported transfer protocol: ftp" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrConfigFileRead(t *testing.T) {
	inner := errors.New("permission denied")
	err := ErrConfigFileRead{Path: "/etc/config.cfg", Cause: inner}
	msg := err.Error()
	if msg != "deployer: failed to read config file /etc/config.cfg: permission denied" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestErrShellSession(t *testing.T) {
	inner := errors.New("connection reset")
	err := ErrShellSession{Phase: "request-pty", Cause: inner}
	msg := err.Error()
	if msg != "deployer: shell session failed at request-pty: connection reset" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestErrShellCommand(t *testing.T) {
	inner := errors.New("write failed")
	err := ErrShellCommand{Command: "show version", Cause: inner}
	msg := err.Error()
	if msg != `deployer: shell command "show version" failed: write failed` {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestErrSSHNotConnected(t *testing.T) {
	err := ErrSSHNotConnected{Host: "192.168.1.1", Port: 22}
	expected := "deployer: SSH client not connected to 192.168.1.1:22"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestCiscoDeployer_GenerateExpectScript(t *testing.T) {
	params := &expectParams{
		SSHKey:           "/home/user/.ssh/id_rsa",
		Host:             "198.18.1.252",
		Port:             22,
		User:             "admin",
		TransferServer:   "198.18.1.91",
		TransferProtocol: "tftp",
		ImageFile:        "platform-pxeboot.tar",
		AppID:            "platform-pxeboot",
		ConfigLines: []string{
			"app-hosting appid platform-pxeboot",
			"app-vnic AppGigabitEthernet trunk",
			"vlan 201 guest-interface 0",
		},
		SkipTransfer: false,
		Timeout:      600,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	// Verify SSH connection parameters.
	if !strings.Contains(script, "spawn ssh") {
		t.Error("expected script to contain 'spawn ssh'")
	}
	if !strings.Contains(script, "-i /home/user/.ssh/id_rsa") {
		t.Error("expected script to contain SSH key path")
	}
	if !strings.Contains(script, "-p 22") {
		t.Error("expected script to contain SSH port")
	}
	if !strings.Contains(script, "admin@198.18.1.252") {
		t.Error("expected script to contain user@host")
	}

	// Verify transfer command.
	if !strings.Contains(script, "copy tftp://198.18.1.91/platform-pxeboot.tar bootflash:platform-pxeboot.tar") {
		t.Error("expected script to contain TFTP copy command")
	}
	if !strings.Contains(script, "Destination filename") {
		t.Error("expected script to handle Destination filename prompt")
	}
	if !strings.Contains(script, "bytes copied") {
		t.Error("expected script to wait for bytes copied confirmation")
	}

	// Verify config application.
	if !strings.Contains(script, "configure terminal") {
		t.Error("expected script to enter config mode")
	}
	if !strings.Contains(script, "app-hosting appid platform-pxeboot") {
		t.Error("expected script to contain first config line")
	}
	if !strings.Contains(script, "vlan 201 guest-interface 0") {
		t.Error("expected script to contain last config line")
	}
	if !strings.Contains(script, `send "end\r"`) {
		t.Error("expected script to exit config mode with end command")
	}

	// Verify install/activate/start lifecycle.
	if !strings.Contains(script, "app-hosting install appid platform-pxeboot package bootflash:platform-pxeboot.tar") {
		t.Error("expected script to contain install command")
	}
	if !strings.Contains(script, "app-hosting activate appid platform-pxeboot") {
		t.Error("expected script to contain activate command")
	}
	if !strings.Contains(script, "app-hosting start appid platform-pxeboot") {
		t.Error("expected script to contain start command")
	}

	// Verify success/failure markers.
	if !strings.Contains(script, "DEPLOY_SUCCESS") {
		t.Error("expected script to contain DEPLOY_SUCCESS marker")
	}
	if !strings.Contains(script, "DEPLOY_ERROR:") {
		t.Error("expected script to contain DEPLOY_ERROR markers")
	}

	// Verify timeout.
	if !strings.Contains(script, "set timeout 600") {
		t.Error("expected script to set timeout to 600")
	}

	// Verify polling for DEPLOYED status.
	if !strings.Contains(script, "show app-hosting list") {
		t.Error("expected script to poll app-hosting list")
	}
}

func TestCiscoDeployer_GenerateExpectScript_SkipTransfer(t *testing.T) {
	params := &expectParams{
		SSHKey:       "/home/user/.ssh/id_rsa",
		Host:         "198.18.1.252",
		Port:         22,
		User:         "admin",
		ImageFile:    "platform-pxeboot.tar",
		AppID:        "platform-pxeboot",
		ConfigLines:  []string{"app-hosting appid platform-pxeboot"},
		SkipTransfer: true,
		Timeout:      600,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	// Transfer section should be absent when SkipTransfer is true.
	if strings.Contains(script, "copy tftp://") {
		t.Error("expected script to skip transfer when SkipTransfer is true")
	}
	if strings.Contains(script, "Destination filename") {
		t.Error("expected script to skip Destination filename prompt when SkipTransfer is true")
	}

	// Install should still be present.
	if !strings.Contains(script, "app-hosting install appid platform-pxeboot") {
		t.Error("expected script to contain install command even with SkipTransfer")
	}
}

func TestCiscoDeployer_GenerateExpectScript_NoConfigLines(t *testing.T) {
	params := &expectParams{
		SSHKey:           "/home/user/.ssh/id_rsa",
		Host:             "localhost",
		Port:             2222,
		User:             "admin",
		TransferServer:   "10.0.0.1",
		TransferProtocol: "http",
		ImageFile:        "app.tar",
		AppID:            "myapp",
		ConfigLines:      nil,
		SkipTransfer:     false,
		Timeout:          300,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	// Config section should be absent when no config lines.
	if strings.Contains(script, "configure terminal") {
		t.Error("expected script to skip config mode when no config lines")
	}

	// Transfer should use http.
	if !strings.Contains(script, "copy http://10.0.0.1/app.tar bootflash:app.tar") {
		t.Error("expected script to contain HTTP copy command")
	}

	// Custom port should be present.
	if !strings.Contains(script, "-p 2222") {
		t.Error("expected script to contain custom port 2222")
	}
}

func TestCiscoDeployer_GenerateVerifyScript(t *testing.T) {
	params := &expectParams{
		SSHKey:  "/home/user/.ssh/id_rsa",
		Host:    "198.18.1.252",
		Port:    22,
		User:    "admin",
		AppID:   "platform-pxeboot",
		Timeout: 30,
	}

	script, err := renderExpectTemplate(verifyExpectTemplate, "verify", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	if !strings.Contains(script, "show app-hosting list") {
		t.Error("expected verify script to contain show app-hosting list")
	}
	if !strings.Contains(script, "VERIFY_RUNNING") {
		t.Error("expected verify script to contain VERIFY_RUNNING marker")
	}
	if !strings.Contains(script, "VERIFY_NOT_RUNNING") {
		t.Error("expected verify script to contain VERIFY_NOT_RUNNING marker")
	}
	if !strings.Contains(script, "set timeout 30") {
		t.Error("expected verify script to set timeout to 30")
	}
}

func TestCiscoDeployer_GenerateTeardownScript(t *testing.T) {
	params := &expectParams{
		SSHKey:    "/home/user/.ssh/id_rsa",
		Host:      "198.18.1.252",
		Port:      22,
		User:      "admin",
		AppID:     "platform-pxeboot",
		ImageFile: "platform-pxeboot.tar",
		Timeout:   120,
	}

	script, err := renderExpectTemplate(teardownExpectTemplate, "teardown", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	// Verify stop/deactivate/uninstall lifecycle.
	if !strings.Contains(script, "app-hosting stop appid platform-pxeboot") {
		t.Error("expected teardown script to contain stop command")
	}
	if !strings.Contains(script, "app-hosting deactivate appid platform-pxeboot") {
		t.Error("expected teardown script to contain deactivate command")
	}
	if !strings.Contains(script, "app-hosting uninstall appid platform-pxeboot") {
		t.Error("expected teardown script to contain uninstall command")
	}

	// Verify config removal.
	if !strings.Contains(script, "no app-hosting appid platform-pxeboot") {
		t.Error("expected teardown script to remove app-hosting config")
	}

	// Verify image cleanup.
	if !strings.Contains(script, "delete /force flash:platform-pxeboot.tar") {
		t.Error("expected teardown script to delete image from flash")
	}

	// Verify success marker.
	if !strings.Contains(script, "TEARDOWN_SUCCESS") {
		t.Error("expected teardown script to contain TEARDOWN_SUCCESS marker")
	}
}

func TestCiscoDeployer_ParseDeployOutput_Success(t *testing.T) {
	output := `spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i /tmp/key -p 22 admin@198.18.1.252
Router#
terminal length 0
Router#
app-hosting install appid platform-pxeboot package bootflash:platform-pxeboot.tar
Router#
DEPLOY_SUCCESS
`
	errMsg := parseDeployError(output)
	if errMsg != "" {
		t.Errorf("expected no error in successful output, got %q", errMsg)
	}

	if !strings.Contains(output, deploySuccessMarker) {
		t.Error("expected output to contain DEPLOY_SUCCESS marker")
	}
}

func TestCiscoDeployer_ParseDeployOutput_Error(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		wantErr  string
		wantFail bool
	}{
		{
			name:     "transfer failed",
			output:   "DEPLOY_ERROR: transfer failed\n",
			wantErr:  "transfer failed",
			wantFail: true,
		},
		{
			name:     "transfer timeout",
			output:   "some output\nDEPLOY_ERROR: transfer timeout\nmore output\n",
			wantErr:  "transfer timeout",
			wantFail: true,
		},
		{
			name:     "SSH connection timeout",
			output:   "DEPLOY_ERROR: SSH connection timeout\n",
			wantErr:  "SSH connection timeout",
			wantFail: true,
		},
		{
			name:     "application did not reach DEPLOYED state",
			output:   "DEPLOY_ERROR: application did not reach DEPLOYED state\n",
			wantErr:  "application did not reach DEPLOYED state",
			wantFail: true,
		},
		{
			name:     "application did not reach RUNNING state",
			output:   "DEPLOY_ERROR: application did not reach RUNNING state\n",
			wantErr:  "application did not reach RUNNING state",
			wantFail: true,
		},
		{
			name:     "no error marker",
			output:   "normal output without errors\n",
			wantErr:  "",
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := parseDeployError(tt.output)
			if tt.wantFail {
				if errMsg == "" {
					t.Error("expected error message but got empty string")
				}
				if errMsg != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, errMsg)
				}
			} else {
				if errMsg != "" {
					t.Errorf("expected no error, got %q", errMsg)
				}
			}
		})
	}
}

func TestCiscoDeployer_ExpandPath(t *testing.T) {
	// Test absolute path remains unchanged.
	absPath, err := expandPath("/tmp/test-key")
	if err != nil {
		t.Fatalf("expandPath failed for absolute path: %v", err)
	}
	if absPath != "/tmp/test-key" {
		t.Errorf("expected /tmp/test-key, got %s", absPath)
	}
}

func TestCiscoDeployer_ExpandPath_Relative(t *testing.T) {
	// Test relative path is converted to absolute.
	relPath, err := expandPath("relative/path/key")
	if err != nil {
		t.Fatalf("expandPath failed for relative path: %v", err)
	}
	if !filepath.IsAbs(relPath) {
		t.Errorf("expected absolute path, got %s", relPath)
	}
}

func TestCiscoDeployer_ExpandPath_HomeTilde(t *testing.T) {
	expanded, err := expandPath("~/.ssh/id_rsa")
	if err != nil {
		t.Fatalf("expandPath failed for tilde path: %v", err)
	}
	if !filepath.IsAbs(expanded) {
		t.Errorf("expected absolute path, got %s", expanded)
	}
	if strings.Contains(expanded, "~") {
		t.Errorf("expected tilde to be expanded, got %s", expanded)
	}
	if !strings.HasSuffix(expanded, ".ssh/id_rsa") {
		t.Errorf("expected path to end with .ssh/id_rsa, got %s", expanded)
	}
}

func TestCiscoDeployer_ExpectNotFound(t *testing.T) {
	err := ErrExpectNotFound{}
	expected := "deployer: expect binary not found in PATH; install expect (apt-get install expect)"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrExpectScript(t *testing.T) {
	err := ErrExpectScript{Message: "transfer failed"}
	expected := "deployer: expect script error: transfer failed"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrExpectExecution(t *testing.T) {
	inner := errors.New("exit status 1")
	err := ErrExpectExecution{Path: "/tmp/script.exp", Cause: inner}
	expected := "deployer: expect execution failed for /tmp/script.exp: exit status 1"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestErrExpectScriptWrite(t *testing.T) {
	inner := errors.New("permission denied")
	err := ErrExpectScriptWrite{Path: "/tmp/script.exp", Cause: inner}
	expected := "deployer: failed to write expect script to /tmp/script.exp: permission denied"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return the inner cause")
	}
}

func TestCiscoDeployer_GenerateExpectScript_SCPTransfer(t *testing.T) {
	params := &expectParams{
		SSHKey:           "/home/user/.ssh/id_rsa",
		Host:             "198.18.1.252",
		Port:             22,
		User:             "admin",
		TransferServer:   "198.18.1.91",
		TransferProtocol: "scp",
		ImageFile:        "platform-pxeboot.tar",
		AppID:            "platform-pxeboot",
		SkipTransfer:     false,
		Timeout:          600,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	if !strings.Contains(script, "copy scp://198.18.1.91/platform-pxeboot.tar bootflash:platform-pxeboot.tar") {
		t.Error("expected script to contain SCP copy command")
	}
}

func TestCiscoDeployer_GenerateExpectScript_TunnelHost(t *testing.T) {
	params := &expectParams{
		SSHKey:       "/home/user/.ssh/id_rsa",
		Host:         "localhost",
		Port:         2222,
		User:         "admin",
		ImageFile:    "app.tar",
		AppID:        "myapp",
		SkipTransfer: true,
		Timeout:      600,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		t.Fatalf("renderExpectTemplate failed: %v", err)
	}

	if !strings.Contains(script, "admin@localhost") {
		t.Error("expected script to connect to localhost for tunnel")
	}
	if !strings.Contains(script, "-p 2222") {
		t.Error("expected script to use tunnel port 2222")
	}
}
