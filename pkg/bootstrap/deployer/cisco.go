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
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
)

const (
	// DefaultCiscoAppID is the default IOS-XE app-hosting application identifier.
	DefaultCiscoAppID = "platform-pxeboot"

	// DefaultCiscoImageFile is the default container image filename on router flash.
	DefaultCiscoImageFile = "platform-pxeboot.tar"

	// DefaultCiscoProvisioningVLAN is the default VLAN ID for the provisioning network.
	DefaultCiscoProvisioningVLAN = 201

	// DefaultCiscoGuestNetmask is the default netmask for the container guest IP.
	DefaultCiscoGuestNetmask = "255.255.255.0"

	// DefaultCiscoTransferProtocol is the default protocol for image transfer.
	DefaultCiscoTransferProtocol = "tftp"

	// DefaultExpectTimeout is the default timeout in seconds for expect scripts.
	DefaultExpectTimeout = 600

	// deploySuccessMarker is emitted by expect scripts on successful deployment.
	deploySuccessMarker = "DEPLOY_SUCCESS"

	// deployErrorMarker is the prefix for error messages from expect scripts.
	deployErrorMarker = "DEPLOY_ERROR:"

	// verifyRunningMarker indicates the app is running during verification.
	verifyRunningMarker = "VERIFY_RUNNING"

	// verifyNotRunningMarker indicates the app is not running during verification.
	verifyNotRunningMarker = "VERIFY_NOT_RUNNING"

	// teardownSuccessMarker is emitted by expect scripts on successful teardown.
	teardownSuccessMarker = "TEARDOWN_SUCCESS"
)

// supportedTransferProtocols is the set of protocols supported for image transfer.
var supportedTransferProtocols = map[string]struct{}{
	"tftp": {},
	"scp":  {},
	"http": {},
}

// expectParams holds the template parameters for generating expect scripts.
type expectParams struct {
	SSHKey           string
	Host             string
	Port             int
	User             string
	TransferServer   string
	TransferProtocol string
	ImageFile        string
	AppID            string
	ConfigLines      []string
	SkipTransfer     bool
	Timeout          int
}

// CiscoDeployer deploys the bootstrap container to a Cisco IOS-XE router
// using the system expect command for reliable interactive SSH automation.
// IOS-XE's SSH implementation does not support programmatic shell sessions
// via Go's ssh.Session.Shell() with PTY, so expect scripts are generated
// and executed to drive the interactive CLI.
type CiscoDeployer struct {
	logger *slog.Logger
}

// Deploy deploys the bootstrap container to a Cisco IOS-XE router. It
// generates an expect script that handles SSH connection, image transfer,
// configuration, and app-hosting install/activate/start lifecycle.
func (d *CiscoDeployer) Deploy(ctx context.Context, config *DeployConfig) (*DeployResult, error) {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if err := requireExpect(); err != nil {
		return nil, err
	}

	appID := config.CiscoAppID
	if appID == "" {
		appID = DefaultCiscoAppID
	}
	imageFile := config.CiscoImageFile
	if imageFile == "" {
		imageFile = DefaultCiscoImageFile
	}
	transferProto := config.TransferProtocol
	if transferProto == "" {
		transferProto = DefaultCiscoTransferProtocol
	}

	if _, ok := supportedTransferProtocols[transferProto]; !ok {
		return nil, ErrUnsupportedTransferProtocol{Protocol: transferProto}
	}

	sshKey, err := expandPath(config.SSHKeyPath)
	if err != nil {
		return nil, ErrSSHKeyRead{Path: config.SSHKeyPath, Cause: err}
	}

	// Parse the config file if provided.
	var configLines []string
	if config.CiscoConfigFile != "" {
		configLines, err = ParseConfigFile(config.CiscoConfigFile)
		if err != nil {
			return nil, err
		}
	}

	skipTransfer := config.TransferServer == "" || imageFile == ""

	params := &expectParams{
		SSHKey:           sshKey,
		Host:             config.Host,
		Port:             config.Port,
		User:             config.User,
		TransferServer:   config.TransferServer,
		TransferProtocol: transferProto,
		ImageFile:        imageFile,
		AppID:            appID,
		ConfigLines:      configLines,
		SkipTransfer:     skipTransfer,
		Timeout:          DefaultExpectTimeout,
	}

	script, err := renderExpectTemplate(deployExpectTemplate, "deploy", params)
	if err != nil {
		return nil, err
	}

	output, err := d.executeExpect(ctx, script, "cisco-deploy-"+appID)
	if err != nil {
		return nil, ErrCiscoDeployFailed{Host: config.Host, Phase: "expect-execute", Cause: err}
	}

	if errMsg := parseDeployError(output); errMsg != "" {
		return nil, ErrCiscoDeployFailed{
			Host:  config.Host,
			Phase: "expect-script",
			Cause: ErrExpectScript{Message: errMsg},
		}
	}

	if !strings.Contains(output, deploySuccessMarker) {
		return nil, ErrCiscoDeployFailed{
			Host:  config.Host,
			Phase: "verify",
			Cause: ErrContainerNotRunning{ContainerID: appID, Host: config.Host},
		}
	}

	d.logger.Info("bootstrap container deployed and running",
		slog.String("host", config.Host),
		slog.String("appid", appID))

	return &DeployResult{
		ContainerID: appID,
		Host:        config.Host,
		Running:     true,
	}, nil
}

// Verify checks that the bootstrap container is running on the Cisco device
// by generating and executing an expect script that queries the app-hosting
// list output.
func (d *CiscoDeployer) Verify(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()

	if err := requireExpect(); err != nil {
		return err
	}

	appID := config.CiscoAppID
	if appID == "" {
		appID = DefaultCiscoAppID
	}

	sshKey, err := expandPath(config.SSHKeyPath)
	if err != nil {
		return ErrSSHKeyRead{Path: config.SSHKeyPath, Cause: err}
	}

	params := &expectParams{
		SSHKey:  sshKey,
		Host:    config.Host,
		Port:    config.Port,
		User:    config.User,
		AppID:   appID,
		Timeout: 30,
	}

	script, err := renderExpectTemplate(verifyExpectTemplate, "verify", params)
	if err != nil {
		return err
	}

	output, err := d.executeExpect(ctx, script, "cisco-verify-"+appID)
	if err != nil {
		return ErrCiscoDeployFailed{Host: config.Host, Phase: "verify-execute", Cause: err}
	}

	if strings.Contains(output, verifyRunningMarker) {
		d.logger.Info("container verified running",
			slog.String("host", config.Host),
			slog.String("appid", appID))
		return nil
	}

	return ErrContainerNotRunning{ContainerID: appID, Host: config.Host}
}

// Teardown stops and removes the bootstrap container from the Cisco device
// by generating and executing an expect script that runs stop, deactivate,
// uninstall, removes the app-hosting config, and optionally deletes the image.
func (d *CiscoDeployer) Teardown(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()

	if err := requireExpect(); err != nil {
		return err
	}

	appID := config.CiscoAppID
	if appID == "" {
		appID = DefaultCiscoAppID
	}
	imageFile := config.CiscoImageFile
	if imageFile == "" {
		imageFile = DefaultCiscoImageFile
	}

	sshKey, err := expandPath(config.SSHKeyPath)
	if err != nil {
		return ErrSSHKeyRead{Path: config.SSHKeyPath, Cause: err}
	}

	params := &expectParams{
		SSHKey:    sshKey,
		Host:      config.Host,
		Port:      config.Port,
		User:      config.User,
		AppID:     appID,
		ImageFile: imageFile,
		Timeout:   120,
	}

	script, err := renderExpectTemplate(teardownExpectTemplate, "teardown", params)
	if err != nil {
		return err
	}

	output, err := d.executeExpect(ctx, script, "cisco-teardown-"+appID)
	if err != nil {
		d.logger.Warn("teardown expect execution returned error",
			slog.String("host", config.Host),
			slog.String("error", err.Error()))
	}

	if strings.Contains(output, teardownSuccessMarker) {
		d.logger.Info("teardown complete",
			slog.String("host", config.Host),
			slog.String("appid", appID))
		return nil
	}

	// Teardown is best-effort; log but do not fail if marker is absent.
	d.logger.Warn("teardown completed without success marker, some steps may have failed",
		slog.String("host", config.Host),
		slog.String("appid", appID))

	return nil
}

// executeExpect writes the expect script to a temporary file, executes it
// via the system expect binary, and returns the combined output. The
// temporary script file is removed after execution.
func (d *CiscoDeployer) executeExpect(ctx context.Context, script, name string) (string, error) {
	scriptPath := filepath.Join(os.TempDir(), name+".exp")

	d.logger.Debug("writing expect script",
		slog.String("path", scriptPath))

	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		return "", ErrExpectScriptWrite{Path: scriptPath, Cause: err}
	}
	defer os.Remove(scriptPath)

	d.logger.Info("executing expect script",
		slog.String("path", scriptPath),
		slog.String("name", name))

	cmd := exec.CommandContext(ctx, "expect", "-f", scriptPath)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	d.logger.Debug("expect script output",
		slog.String("name", name),
		slog.Int("output_bytes", len(outputStr)))

	if err != nil {
		// Check if expect itself failed vs the script reporting an error.
		if errMsg := parseDeployError(outputStr); errMsg != "" {
			return outputStr, ErrExpectScript{Message: errMsg}
		}
		return outputStr, ErrExpectExecution{Path: scriptPath, Cause: err}
	}

	return outputStr, nil
}

// requireExpect checks that the expect binary is available on the system PATH.
func requireExpect() error {
	if _, err := exec.LookPath("expect"); err != nil {
		return ErrExpectNotFound{}
	}
	return nil
}

// expandPath expands a leading ~ in a file path to the user's home directory
// and returns an absolute path.
func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		path = filepath.Join(u.HomeDir, path[2:])
	}
	return filepath.Abs(path)
}

// parseDeployError scans the output for DEPLOY_ERROR: markers and returns
// the error message if found, or an empty string.
func parseDeployError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, deployErrorMarker) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, deployErrorMarker))
		}
	}
	return ""
}

// renderExpectTemplate renders an expect TCL script from the given template
// string and parameters.
func renderExpectTemplate(tmplStr, name string, params *expectParams) (string, error) {
	tmpl, err := template.New(name).Parse(tmplStr)
	if err != nil {
		return "", ErrTemplateRender{Name: name, Cause: err}
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", ErrTemplateRender{Name: name, Cause: err}
	}
	return buf.String(), nil
}

// BuildCopyCommand constructs the IOS-XE copy command for the given transfer
// protocol, server, user, and image filename.
func BuildCopyCommand(protocol, server, user, imageFile string) string {
	switch protocol {
	case "scp":
		return "copy scp://" + user + "@" + server + "/" + imageFile + " bootflash:" + imageFile
	case "http":
		return "copy http://" + server + "/" + imageFile + " bootflash:" + imageFile
	default:
		return "copy tftp://" + server + "/" + imageFile + " bootflash:" + imageFile
	}
}

// ParseConfigFile reads a Cisco IOS-XE configuration file and returns the
// non-empty, non-comment lines suitable for sending as config commands.
// Lines beginning with '!' are treated as comments.
func ParseConfigFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfigFileRead{Path: path, Cause: err}
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrConfigFileRead{Path: path, Cause: err}
	}

	return lines, nil
}

// ParseAppHostingRunning parses the output of "show app-hosting list" and
// returns true if the specified appID has a RUNNING status.
func ParseAppHostingRunning(output, appID string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, appID) && strings.Contains(strings.ToUpper(line), "RUNNING") {
			return true
		}
	}
	return false
}

// buildParams creates CiscoAppHostingParams from the deploy configuration.
func (d *CiscoDeployer) buildParams(config *DeployConfig) *CiscoAppHostingParams {
	appID := config.CiscoAppID
	if appID == "" {
		appID = DefaultCiscoAppID
	}
	imageFile := config.CiscoImageFile
	if imageFile == "" {
		imageFile = DefaultCiscoImageFile
	}

	params := &CiscoAppHostingParams{
		AppID:          appID,
		GuestInterface: 0,
		ImageFile:      imageFile,
		VLANs:          []int{DefaultCiscoProvisioningVLAN},
		RunOpts:        []string{"-v $(APP_DATA):/data"},
	}

	if config.ProvisioningNetwork.Gateway != "" {
		params.GuestIP = config.ProvisioningNetwork.Gateway
		params.GuestNetmask = DefaultCiscoGuestNetmask
	}

	return params
}

// deployExpectTemplate is the TCL expect script template for deploying a
// bootstrap container to a Cisco IOS-XE router. It handles SSH connection,
// image transfer, config application, and app-hosting lifecycle.
var deployExpectTemplate = `#!/usr/bin/expect -f
set timeout {{.Timeout}}
log_user 1

spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i {{.SSHKey}} -p {{.Port}} {{.User}}@{{.Host}}

expect {
    "#" { }
    ">" { }
    timeout {
        puts "DEPLOY_ERROR: SSH connection timeout"
        exit 1
    }
    eof {
        puts "DEPLOY_ERROR: SSH connection closed"
        exit 1
    }
}

send "terminal length 0\r"
expect "#"
{{if not .SkipTransfer}}
# Transfer container image to bootflash
send "copy {{.TransferProtocol}}://{{.TransferServer}}/{{.ImageFile}} bootflash:{{.ImageFile}}\r"
expect {
    "Destination filename" {
        send "\r"
        expect {
            "bytes copied" { }
            "Error" {
                puts "DEPLOY_ERROR: transfer failed"
                exit 1
            }
            "%Error" {
                puts "DEPLOY_ERROR: transfer failed"
                exit 1
            }
            timeout {
                puts "DEPLOY_ERROR: transfer timeout"
                exit 1
            }
        }
    }
    "bytes copied" { }
    "Error" {
        puts "DEPLOY_ERROR: transfer failed"
        exit 1
    }
    "%Error" {
        puts "DEPLOY_ERROR: transfer failed"
        exit 1
    }
    timeout {
        puts "DEPLOY_ERROR: transfer timeout"
        exit 1
    }
}
expect "#"
{{end}}
{{if .ConfigLines}}
# Apply configuration
send "configure terminal\r"
expect "(config)#"
{{range .ConfigLines}}
send "{{.}}\r"
expect "#"
{{end}}
send "end\r"
expect "#"
{{end}}
# Install application
send "app-hosting install appid {{.AppID}} package bootflash:{{.ImageFile}}\r"
expect "#"

# Poll for DEPLOYED status
set deployed 0
set poll_attempts 60
for {set i 0} {$i < $poll_attempts} {incr i} {
    send "show app-hosting list\r"
    expect "#"
    if {[string match "*{{.AppID}}*DEPLOYED*" $expect_out(buffer)]} {
        set deployed 1
        break
    }
    if {[string match "*{{.AppID}}*RUNNING*" $expect_out(buffer)]} {
        set deployed 1
        break
    }
    sleep 5
}

if {!$deployed} {
    puts "DEPLOY_ERROR: application did not reach DEPLOYED state"
    send "exit\r"
    exit 1
}

# Activate application
send "app-hosting activate appid {{.AppID}}\r"
expect "#"

# Start application
send "app-hosting start appid {{.AppID}}\r"
expect "#"

# Verify RUNNING status
set running 0
set verify_attempts 12
for {set i 0} {$i < $verify_attempts} {incr i} {
    send "show app-hosting list\r"
    expect "#"
    if {[string match "*{{.AppID}}*RUNNING*" $expect_out(buffer)]} {
        set running 1
        break
    }
    sleep 5
}

if {$running} {
    puts "DEPLOY_SUCCESS"
} else {
    puts "DEPLOY_ERROR: application did not reach RUNNING state"
}

send "exit\r"
expect eof
`

// verifyExpectTemplate is the TCL expect script template for verifying that
// the bootstrap container is running on a Cisco IOS-XE router.
var verifyExpectTemplate = `#!/usr/bin/expect -f
set timeout {{.Timeout}}
log_user 1

spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i {{.SSHKey}} -p {{.Port}} {{.User}}@{{.Host}}

expect {
    "#" { }
    ">" { }
    timeout {
        puts "VERIFY_NOT_RUNNING"
        exit 1
    }
    eof {
        puts "VERIFY_NOT_RUNNING"
        exit 1
    }
}

send "terminal length 0\r"
expect "#"

send "show app-hosting list\r"
expect "#"

if {[string match "*{{.AppID}}*RUNNING*" $expect_out(buffer)]} {
    puts "VERIFY_RUNNING"
} else {
    puts "VERIFY_NOT_RUNNING"
}

send "exit\r"
expect eof
`

// teardownExpectTemplate is the TCL expect script template for stopping,
// deactivating, uninstalling, and cleaning up a bootstrap container from
// a Cisco IOS-XE router.
var teardownExpectTemplate = `#!/usr/bin/expect -f
set timeout {{.Timeout}}
log_user 1

spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i {{.SSHKey}} -p {{.Port}} {{.User}}@{{.Host}}

expect {
    "#" { }
    ">" { }
    timeout {
        puts "DEPLOY_ERROR: SSH connection timeout"
        exit 1
    }
    eof {
        puts "DEPLOY_ERROR: SSH connection closed"
        exit 1
    }
}

send "terminal length 0\r"
expect "#"

# Stop the application (may already be stopped)
send "app-hosting stop appid {{.AppID}}\r"
expect "#"

# Deactivate the application
send "app-hosting deactivate appid {{.AppID}}\r"
expect "#"

# Uninstall the application
send "app-hosting uninstall appid {{.AppID}}\r"
expect "#"

# Remove the app-hosting configuration
send "configure terminal\r"
expect "(config)#"
send "no app-hosting appid {{.AppID}}\r"
expect "#"
send "end\r"
expect "#"

# Delete the image from flash
send "delete /force flash:{{.ImageFile}}\r"
expect "#"

puts "TEARDOWN_SUCCESS"

send "exit\r"
expect eof
`
