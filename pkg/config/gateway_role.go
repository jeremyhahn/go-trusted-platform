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

package config

import (
	"gopkg.in/yaml.v2"
)

// GatewaydConfigSections are the top-level sections of a platform
// configuration that gatewayd decodes (pkg/sdn/gateway/commands
// LoadServeConfig): the SDN node services, the authenticating reverse
// proxy, the trust resolver classes, the OVS runtime, and the control-plane
// reporter. A gateway-role node's /etc/gatewayd/config.yaml is exactly
// these sections of its platform config and nothing else.
var GatewaydConfigSections = []string{"gateway", "proxy", "trust", "sdn", "control-plane"}

// gatewayRoleProbe is the minimal shape of the `gateway:` section a role
// decision needs. The rest of the section belongs to gatewayd.
type gatewayRoleProbe struct {
	Gateway *struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"gateway"`
}

// GatewayRoleEnabled reports whether a platform configuration puts the node
// in the gateway role: `gateway.enabled: true`. This is the one signal the
// installer, the ISO builder and firstboot share, so gatewayd is packaged
// for exactly the nodes whose configuration will run it (#66). A
// configuration that does not parse is an error, never "not a gateway" —
// a broken config must not silently produce a node without its edge daemon.
func GatewayRoleEnabled(configData []byte) (bool, error) {
	var probe gatewayRoleProbe
	if err := yaml.Unmarshal(configData, &probe); err != nil {
		return false, &ErrPlatformConfigUnreadable{Cause: err}
	}
	return probe.Gateway != nil && probe.Gateway.Enabled, nil
}

// ErrPlatformConfigUnreadable is returned when the platform configuration
// cannot be parsed for a role decision.
type ErrPlatformConfigUnreadable struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrPlatformConfigUnreadable) Error() string {
	return "platform configuration could not be parsed: " + e.Cause.Error()
}

// Unwrap returns the parse failure.
func (e *ErrPlatformConfigUnreadable) Unwrap() error {
	return e.Cause
}
