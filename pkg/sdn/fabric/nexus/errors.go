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

// Package nexus implements the fabric Driver for Cisco Nexus switches
// using SSH CLI commands.
package nexus

import "fmt"

// ErrVLANExists is returned when attempting to create a VLAN that already
// exists with a different name.
type ErrVLANExists struct {
	VLAN          uint16
	ExistingName  string
	RequestedName string
}

func (e ErrVLANExists) Error() string {
	return fmt.Sprintf("nexus: vlan %d already exists as %q, requested %q",
		e.VLAN, e.ExistingName, e.RequestedName)
}

// ErrCommandExec is returned when an NX-OS command execution fails.
type ErrCommandExec struct {
	Command string
	Output  string
	Cause   error
}

func (e ErrCommandExec) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("nexus: command %q failed: %s (output: %s)",
			e.Command, e.Cause, e.Output)
	}
	return fmt.Sprintf("nexus: command %q failed: %s", e.Command, e.Cause)
}

func (e ErrCommandExec) Unwrap() error {
	return e.Cause
}

// ErrParseOutput is returned when NX-OS show command output cannot be parsed.
type ErrParseOutput struct {
	Command string
	Reason  string
}

func (e ErrParseOutput) Error() string {
	return fmt.Sprintf("nexus: failed to parse output of %q: %s", e.Command, e.Reason)
}

// ErrNotConnected is returned when an operation is attempted without
// a connection.
type ErrNotConnected struct{}

func (e ErrNotConnected) Error() string {
	return "nexus: not connected"
}

// ErrInvalidConfig is returned when the driver configuration is invalid.
type ErrInvalidConfig struct {
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("nexus: invalid config: %s", e.Reason)
}

// ErrSSHKeyLoad is returned when the SSH private key or known-hosts
// store at the configured path cannot be loaded into the xkms ssh
// enclave-backed stack.
type ErrSSHKeyLoad struct {
	Path  string
	Cause error
}

func (e ErrSSHKeyLoad) Error() string {
	return fmt.Sprintf("nexus: failed to load ssh material at %q: %s", e.Path, e.Cause)
}

func (e ErrSSHKeyLoad) Unwrap() error {
	return e.Cause
}
