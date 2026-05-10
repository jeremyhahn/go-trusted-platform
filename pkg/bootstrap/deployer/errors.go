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

import "fmt"

// ErrNotImplemented is returned when a deployer target is not yet implemented.
type ErrNotImplemented struct {
	Target DeployTarget
}

func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("deployer: target %q is not implemented", string(e.Target))
}

// ErrUnknownTarget is returned when the deploy target is not recognized.
type ErrUnknownTarget struct {
	Target DeployTarget
}

func (e ErrUnknownTarget) Error() string {
	return fmt.Sprintf("deployer: unknown target %q", string(e.Target))
}

// ErrSSHConnect is returned when an SSH connection fails.
type ErrSSHConnect struct {
	Host  string
	Port  int
	Cause error
}

func (e ErrSSHConnect) Error() string {
	return fmt.Sprintf("deployer: SSH connection to %s:%d failed: %v", e.Host, e.Port, e.Cause)
}

func (e ErrSSHConnect) Unwrap() error {
	return e.Cause
}

// ErrSSHNotConnected is returned when an operation requires an active SSH
// connection but the client is not connected.
type ErrSSHNotConnected struct {
	Host string
	Port int
}

func (e ErrSSHNotConnected) Error() string {
	return fmt.Sprintf("deployer: SSH client not connected to %s:%d", e.Host, e.Port)
}

// ErrSSHCommand is returned when a remote SSH command fails.
type ErrSSHCommand struct {
	Command string
	Output  string
	Cause   error
}

func (e ErrSSHCommand) Error() string {
	return fmt.Sprintf("deployer: SSH command %q failed: %v (output: %s)", e.Command, e.Cause, e.Output)
}

func (e ErrSSHCommand) Unwrap() error {
	return e.Cause
}

// ErrSSHKeyRead is returned when reading the SSH private key fails.
type ErrSSHKeyRead struct {
	Path  string
	Cause error
}

func (e ErrSSHKeyRead) Error() string {
	return fmt.Sprintf("deployer: failed to read SSH key %s: %v", e.Path, e.Cause)
}

func (e ErrSSHKeyRead) Unwrap() error {
	return e.Cause
}

// ErrSSHKeyParse is returned when parsing the SSH private key fails.
type ErrSSHKeyParse struct {
	Path  string
	Cause error
}

func (e ErrSSHKeyParse) Error() string {
	return fmt.Sprintf("deployer: failed to parse SSH key %s: %v", e.Path, e.Cause)
}

func (e ErrSSHKeyParse) Unwrap() error {
	return e.Cause
}

// ErrFileCopy is returned when copying a file to the remote host fails.
type ErrFileCopy struct {
	Local  string
	Remote string
	Cause  error
}

func (e ErrFileCopy) Error() string {
	return fmt.Sprintf("deployer: failed to copy %s to %s: %v", e.Local, e.Remote, e.Cause)
}

func (e ErrFileCopy) Unwrap() error {
	return e.Cause
}

// ErrFileRead is returned when reading a local file for copy fails.
type ErrFileRead struct {
	Path  string
	Cause error
}

func (e ErrFileRead) Error() string {
	return fmt.Sprintf("deployer: failed to read local file %s: %v", e.Path, e.Cause)
}

func (e ErrFileRead) Unwrap() error {
	return e.Cause
}

// ErrRemoteFileNotFound is returned by StatRemote when the remote file does
// not exist. Callers should treat it as a "needs upload" signal rather than
// a fatal error.
type ErrRemoteFileNotFound struct {
	Path string
}

func (e ErrRemoteFileNotFound) Error() string {
	return fmt.Sprintf("deployer: remote file not found: %s", e.Path)
}

// ErrUnexpectedStatOutput is returned when StatRemote can't parse the
// output of `stat -c '%s %Y'` from the remote host. Wrapped inside
// ErrFileRead so callers see a typed cause they can errors.As on.
type ErrUnexpectedStatOutput struct {
	Output string
}

func (e ErrUnexpectedStatOutput) Error() string {
	return fmt.Sprintf("deployer: unexpected stat output: %q", e.Output)
}

// ErrContainerNotRunning is returned when the container is expected to be running but is not.
type ErrContainerNotRunning struct {
	ContainerID string
	Host        string
}

func (e ErrContainerNotRunning) Error() string {
	return fmt.Sprintf("deployer: container %s on %s is not running", e.ContainerID, e.Host)
}

// ErrContainerStateMismatch is returned when a container with the
// configured name is running on the deployer host but with a different
// image or bind-mount than the current DeployConfig expects. The
// orchestrator's RedeployMode determines whether this is a hard error or
// a redeploy trigger.
type ErrContainerStateMismatch struct {
	ContainerID string
	Host        string
	Field       string // "image" | "bind-mount"
	Want        string
	Got         string
}

func (e ErrContainerStateMismatch) Error() string {
	return fmt.Sprintf("deployer: container %s on %s state mismatch: %s want=%q got=%q",
		e.ContainerID, e.Host, e.Field, e.Want, e.Got)
}

// ErrAssetStageFailed indicates the deployer could not extract image-
// baked PXE assets (vmlinuz, initramfs, autoinstall.sh) from the
// container image into the host bind-mount source. The bootstrap
// container will not start without these because the bind-mount
// overlays the image's /data with the (otherwise empty) host directory.
type ErrAssetStageFailed struct {
	Phase string // "create" | "cp:<asset>"
	Cause error
}

func (e ErrAssetStageFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("deployer: asset stage failed at phase %s", e.Phase)
	}
	return fmt.Sprintf("deployer: asset stage failed at phase %s: %v", e.Phase, e.Cause)
}

func (e ErrAssetStageFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidDeployConfig is returned when the deploy configuration is invalid.
type ErrInvalidDeployConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidDeployConfig) Error() string {
	return fmt.Sprintf("deployer: invalid config: field %s: %s", e.Field, e.Reason)
}

// ErrCiscoDeployFailed indicates a Cisco app-hosting deployment step failed.
type ErrCiscoDeployFailed struct {
	Host  string
	Phase string
	Cause error
}

func (e ErrCiscoDeployFailed) Error() string {
	return "deployer: cisco deploy failed on " + e.Host + " at phase " + e.Phase + ": " + e.Cause.Error()
}

func (e ErrCiscoDeployFailed) Unwrap() error {
	return e.Cause
}

// ErrTemplateRender indicates a CLI template rendering failure.
type ErrTemplateRender struct {
	Name  string
	Cause error
}

func (e ErrTemplateRender) Error() string {
	return "deployer: template render failed for " + e.Name + ": " + e.Cause.Error()
}

func (e ErrTemplateRender) Unwrap() error {
	return e.Cause
}

// ErrShellSession is returned when creating or initializing an interactive
// SSH shell session fails.
type ErrShellSession struct {
	Phase string
	Cause error
}

func (e ErrShellSession) Error() string {
	return "deployer: shell session failed at " + e.Phase + ": " + e.Cause.Error()
}

func (e ErrShellSession) Unwrap() error {
	return e.Cause
}

// ErrShellCommand is returned when sending a command via the interactive
// shell session fails.
type ErrShellCommand struct {
	Command string
	Cause   error
}

func (e ErrShellCommand) Error() string {
	return fmt.Sprintf("deployer: shell command %q failed: %v", e.Command, e.Cause)
}

func (e ErrShellCommand) Unwrap() error {
	return e.Cause
}

// ErrShellRead is returned when reading from the shell session stdout fails.
type ErrShellRead struct {
	Cause error
}

func (e ErrShellRead) Error() string {
	return "deployer: shell read failed: " + e.Cause.Error()
}

func (e ErrShellRead) Unwrap() error {
	return e.Cause
}

// ErrConfigFileRead is returned when reading a Cisco IOS-XE configuration
// file fails.
type ErrConfigFileRead struct {
	Path  string
	Cause error
}

func (e ErrConfigFileRead) Error() string {
	return fmt.Sprintf("deployer: failed to read config file %s: %v", e.Path, e.Cause)
}

func (e ErrConfigFileRead) Unwrap() error {
	return e.Cause
}

// ErrCiscoCopyFailed is returned when a file copy operation on the Cisco
// device fails (e.g., TFTP/SCP/HTTP transfer).
type ErrCiscoCopyFailed struct {
	Protocol string
	Source   string
	Cause    error
}

func (e ErrCiscoCopyFailed) Error() string {
	return fmt.Sprintf("deployer: cisco copy via %s from %s failed: %v", e.Protocol, e.Source, e.Cause)
}

func (e ErrCiscoCopyFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsupportedTransferProtocol is returned when the configured transfer
// protocol is not supported.
type ErrUnsupportedTransferProtocol struct {
	Protocol string
}

func (e ErrUnsupportedTransferProtocol) Error() string {
	return "deployer: unsupported transfer protocol: " + e.Protocol
}

// ErrExpectNotFound is returned when the expect binary is not available on
// the system PATH.
type ErrExpectNotFound struct{}

func (e ErrExpectNotFound) Error() string {
	return "deployer: expect binary not found in PATH; install expect (apt-get install expect)"
}

// ErrExpectScript is returned when an expect script reports an error via
// the DEPLOY_ERROR marker.
type ErrExpectScript struct {
	Message string
}

func (e ErrExpectScript) Error() string {
	return "deployer: expect script error: " + e.Message
}

// ErrExpectExecution is returned when executing the expect binary fails.
type ErrExpectExecution struct {
	Path  string
	Cause error
}

func (e ErrExpectExecution) Error() string {
	return fmt.Sprintf("deployer: expect execution failed for %s: %v", e.Path, e.Cause)
}

func (e ErrExpectExecution) Unwrap() error {
	return e.Cause
}

// ErrExpectScriptWrite is returned when writing the temporary expect script
// file to disk fails.
type ErrExpectScriptWrite struct {
	Path  string
	Cause error
}

func (e ErrExpectScriptWrite) Error() string {
	return fmt.Sprintf("deployer: failed to write expect script to %s: %v", e.Path, e.Cause)
}

func (e ErrExpectScriptWrite) Unwrap() error {
	return e.Cause
}
