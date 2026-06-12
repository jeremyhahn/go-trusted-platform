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

import "fmt"

// ErrInvalidBootstrapConfig indicates the PXE bootstrap configuration is invalid.
type ErrInvalidBootstrapConfig struct {
	Reason string
}

func (e ErrInvalidBootstrapConfig) Error() string {
	return fmt.Sprintf("bootstrap: invalid bootstrap config: %s", e.Reason)
}

// ErrNodeDiscoveryFailed indicates that node discovery failed for a specific host.
type ErrNodeDiscoveryFailed struct {
	Hostname string
	Cause    error
}

func (e ErrNodeDiscoveryFailed) Error() string {
	msg := fmt.Sprintf("bootstrap: node discovery failed for %s", e.Hostname)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrNodeDiscoveryFailed) Unwrap() error {
	return e.Cause
}

// ErrMACDiscoveryFailed indicates that MAC address discovery failed for a BMC.
type ErrMACDiscoveryFailed struct {
	BMCAddress string
	Cause      error
}

func (e ErrMACDiscoveryFailed) Error() string {
	msg := fmt.Sprintf("bootstrap: MAC discovery failed for BMC at %s", e.BMCAddress)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrMACDiscoveryFailed) Unwrap() error {
	return e.Cause
}

// ErrDuplicateMAC indicates that two or more nodes share the same MAC address.
type ErrDuplicateMAC struct {
	MAC       string
	Hostnames []string
}

func (e ErrDuplicateMAC) Error() string {
	return fmt.Sprintf("bootstrap: duplicate MAC %s found on nodes: %v", e.MAC, e.Hostnames)
}

// ErrInvalidControlPlaneCount indicates an invalid number of control-plane nodes.
type ErrInvalidControlPlaneCount struct {
	Count int
}

func (e ErrInvalidControlPlaneCount) Error() string {
	return fmt.Sprintf("bootstrap: invalid control-plane node count: %d (must be 1 or odd >= 3)", e.Count)
}

// ErrMissingRequiredField indicates a required field is empty or missing.
type ErrMissingRequiredField struct {
	Field string
}

func (e ErrMissingRequiredField) Error() string {
	return fmt.Sprintf("bootstrap: missing required field: %s", e.Field)
}

// ErrInvalidNodeRole indicates a node has an unrecognized role.
type ErrInvalidNodeRole struct {
	Hostname string
	Role     string
}

func (e ErrInvalidNodeRole) Error() string {
	return fmt.Sprintf("bootstrap: invalid role %q for node %s", e.Role, e.Hostname)
}

// ErrNodeMissingIdentity indicates a node has neither a BMC address nor a MAC.
type ErrNodeMissingIdentity struct {
	Hostname string
}

func (e ErrNodeMissingIdentity) Error() string {
	return fmt.Sprintf("bootstrap: node %s has neither bmc_address nor mac", e.Hostname)
}

// ErrInvalidBMCTrust indicates a bmc_trust strategy value is not in the
// ClassBMC allowlist (dane, spki, ca-file, tofu).
type ErrInvalidBMCTrust struct {
	Hostname string
	Strategy string
}

func (e ErrInvalidBMCTrust) Error() string {
	return fmt.Sprintf("bootstrap: node %s: invalid bmc_trust strategy %q (allowed: dane, spki, ca-file, tofu)",
		e.Hostname, e.Strategy)
}
