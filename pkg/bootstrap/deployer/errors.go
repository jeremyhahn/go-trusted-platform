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
	Field       string // "image" | "image-digest" | "bind-mount"
	Want        string
	Got         string
}

func (e ErrContainerStateMismatch) Error() string {
	return fmt.Sprintf("deployer: container %s on %s state mismatch: %s want=%q got=%q",
		e.ContainerID, e.Host, e.Field, e.Want, e.Got)
}

// ErrImageShipFailed indicates the deployer could not ship a
// locally-built container image to the remote host. Shipping a local
// image is required when the bootstrap image is built on the orchestrator
// host (where platformctl runs) instead of pulled from a registry: the
// image is saved to a tar, streamed over SSH, and loaded on the remote.
// Phase identifies which step failed.
type ErrImageShipFailed struct {
	Phase string // "save:tempfile" | "save" | "copy" | "load"
	Cause error
}

func (e ErrImageShipFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("deployer: image ship failed at phase %s", e.Phase)
	}
	return fmt.Sprintf("deployer: image ship failed at phase %s: %v", e.Phase, e.Cause)
}

func (e ErrImageShipFailed) Unwrap() error {
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

// ErrInvalidBootNodeConfig is returned when the boot-node settings cannot
// keep the container serving: a data or firmware cache directory that does
// not survive a reboot, the two overlapping, or a firmware cache set
// without boot-node mode.
type ErrInvalidBootNodeConfig struct {
	Field  string
	Value  string
	Reason string
}

func (e ErrInvalidBootNodeConfig) Error() string {
	return fmt.Sprintf("deployer: invalid boot-node config: field %s %q: %s", e.Field, e.Value, e.Reason)
}

// ErrNoRouterWithGateway is returned when a deploy config sets both
// bootstrap_no_router and bootstrap_gateway: one drops the DHCP router
// option, the other advertises it.
type ErrNoRouterWithGateway struct {
	Gateway string
}

func (e ErrNoRouterWithGateway) Error() string {
	return fmt.Sprintf("deployer: invalid config: bootstrap_no_router advertises no gateway, but bootstrap_gateway is %q: set one or the other", e.Gateway)
}

// ErrNetbootMediaStage is a failure staging a netboot media build onto the
// deploy target, at the named step.
type ErrNetbootMediaStage struct {
	Step string
	Err  error
}

func (e ErrNetbootMediaStage) Error() string {
	return "deployer: netboot media: " + e.Step + ": " + e.Err.Error()
}

func (e ErrNetbootMediaStage) Unwrap() error { return e.Err }
