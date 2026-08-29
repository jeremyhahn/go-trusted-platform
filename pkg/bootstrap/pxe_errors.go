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
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

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
// ClassBMC allowlist (dane, spki, ca-file).
//
// tofu gets a dedicated explanation because it was allowed here until #83:
// it is a CA-bundle fetch pinned on first contact, and a BMC serves
// Redfish rather than a CA bundle, so it can never verify one. Endpoint
// pinning for a BMC is bmc_spki_pin.
type ErrInvalidBMCTrust struct {
	Hostname string
	Strategy string
}

func (e ErrInvalidBMCTrust) Error() string {
	if trust.Strategy(e.Strategy) == trust.StrategyTOFU {
		return fmt.Sprintf("bootstrap: node %s: bmc_trust strategy \"tofu\" cannot verify a BMC: "+
			"tofu fetches a CA bundle from a server, and a BMC serves Redfish rather than a CA bundle. "+
			"Use bmc_spki_pin to pin the BMC's own certificate (allowed bmc_trust: dane, spki, ca-file)",
			e.Hostname)
	}
	return fmt.Sprintf("bootstrap: node %s: invalid bmc_trust strategy %q (allowed: dane, spki, ca-file)",
		e.Hostname, e.Strategy)
}

// ErrForbiddenOverrideKey reports an override key that duplicates an
// authoritative first-class NodeConfig or platform field.
type ErrForbiddenOverrideKey struct {
	Source   string // file path (overrides file or bootstrap.yaml); "" = unknown
	Line     int    // 1-based YAML line of the offending key; 0 = unknown
	Hostname string
	KeyPath  string // e.g. "network.interfaces"
	UseField string // e.g. "nodes[].interfaces"
}

func (e ErrForbiddenOverrideKey) Error() string {
	location := ""
	if e.Source != "" {
		location = e.Source
		if e.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, e.Line)
		}
		location += ": "
	}
	return fmt.Sprintf("bootstrap: %snode %s: override key %q duplicates authoritative field %s; delete it — the bootstrap injects this value automatically",
		location, e.Hostname, e.KeyPath, e.UseField)
}

// ErrNilConfigMap reports that ApplyNodeIdentity was called with a nil
// merged device-config map.
type ErrNilConfigMap struct{}

func (e ErrNilConfigMap) Error() string {
	return "bootstrap: apply node identity: merged config map is nil"
}

// ErrConfigKeyNotMap reports that a merged device-config key expected to
// hold a nested map holds a non-map value, blocking node-identity injection.
type ErrConfigKeyNotMap struct {
	Hostname string
	Key      string
}

func (e ErrConfigKeyNotMap) Error() string {
	return fmt.Sprintf("bootstrap: node %s: merged config key %q holds a non-map value; cannot inject node identity",
		e.Hostname, e.Key)
}

// ErrInterfaceConvertFailed reports a failure converting a node's typed
// Interfaces into the generic map form used by the merged device config.
type ErrInterfaceConvertFailed struct {
	Hostname string
	Cause    error
}

func (e ErrInterfaceConvertFailed) Error() string {
	return fmt.Sprintf("bootstrap: node %s: converting interfaces for merged config: %v",
		e.Hostname, e.Cause)
}

func (e ErrInterfaceConvertFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPort indicates a configured port is outside the usable
// range, or would derive one that is.
type ErrInvalidPort struct {
	// Field is the bootstrap.yaml key at fault.
	Field string
	// Port is the offending value.
	Port int
	// Reason explains why it cannot be used.
	Reason string
}

func (e ErrInvalidPort) Error() string {
	return fmt.Sprintf("bootstrap: %s = %d: %s", e.Field, e.Port, e.Reason)
}
