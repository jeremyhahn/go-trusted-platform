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

package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// computeHost is a reference compute node's network section: a fabric VTEP
// and a hypervisor address on an OVS bond.
func computeHost() *installer.NetworkConfig {
	return &installer.NetworkConfig{
		Role: installer.HostRoleCompute,
		Bonds: []installer.BondConfig{{
			Name: "bond0", Type: installer.BondTypeOVS, Mode: "balance-tcp", Interfaces: []string{"eth6", "eth7"},
			VLANs: []installer.BondVLANConfig{
				{Zone: "fabric", IPv4Address: "10.4.1.20/24"},
				{Zone: "hypervisor", IPv4Address: "10.4.3.20/24"},
			},
		}},
	}
}

func sdnEnv4() *sdn.Config {
	return &sdn.Config{Enabled: true, Environment: &netplan.Environment{ID: 4}}
}

// TestApp_NetworkPlan derives the plan from sdn.environment, and none when
// SDN is absent or disabled.
func TestApp_NetworkPlan(t *testing.T) {
	plan, err := (&App{SDNConfig: sdnEnv4()}).NetworkPlan()
	require.NoError(t, err)
	require.NotNil(t, plan)
	fabric, ok := plan.Zone("fabric")
	require.True(t, ok)
	assert.Equal(t, uint16(401), fabric.VLAN)

	plan, err = (&App{}).NetworkPlan()
	require.NoError(t, err)
	assert.Nil(t, plan)
	plan, err = (&App{SDNConfig: &sdn.Config{Enabled: false}}).NetworkPlan()
	require.NoError(t, err)
	assert.Nil(t, plan)
}

// TestApp_NetworkPlan_InvalidSDN surfaces an SDN section that cannot be
// validated.
func TestApp_NetworkPlan_InvalidSDN(t *testing.T) {
	_, err := (&App{SDNConfig: &sdn.Config{Enabled: true}}).NetworkPlan()
	var target ErrSDNConfigValidation
	require.True(t, errors.As(err, &target), "got %v", err)
	var envErr sdn.ErrEnvironmentRequired
	assert.True(t, errors.As(err, &envErr))
}

// TestApp_ValidateHostNetwork accepts a reference compute node and a node
// with no network section.
func TestApp_ValidateHostNetwork(t *testing.T) {
	require.NoError(t, (&App{SDNConfig: sdnEnv4(), NetworkConfig: computeHost()}).validateHostNetwork())
	require.NoError(t, (&App{}).validateHostNetwork())
}

// TestApp_ValidateHostNetwork_Errors refuses a forwarding compute node, a
// role with no plan, and an invalid SDN section.
func TestApp_ValidateHostNetwork_Errors(t *testing.T) {
	forwarding := computeHost()
	forwarding.IPForward = true
	err := (&App{SDNConfig: sdnEnv4(), NetworkConfig: forwarding}).validateHostNetwork()
	var hostErr ErrHostNetworkValidation
	require.True(t, errors.As(err, &hostErr), "got %v", err)
	var fwdErr *installer.ErrForwardingNotAllowed
	assert.True(t, errors.As(err, &fwdErr))
	assert.Contains(t, hostErr.Error(), "host network configuration is invalid")

	err = (&App{NetworkConfig: computeHost()}).validateHostNetwork()
	var planErr *installer.ErrNetworkPlanRequired
	require.True(t, errors.As(err, &planErr), "got %v", err)

	err = (&App{SDNConfig: &sdn.Config{Enabled: true}, NetworkConfig: computeHost()}).validateHostNetwork()
	var sdnErr ErrSDNConfigValidation
	require.True(t, errors.As(err, &sdnErr), "got %v", err)
}

// TestApp_GetInstallerConfig_CarriesPlan hands the installer the plan, and
// fails when the SDN section is invalid.
func TestApp_GetInstallerConfig_CarriesPlan(t *testing.T) {
	cfg, err := (&App{SDNConfig: sdnEnv4(), NetworkConfig: computeHost()}).GetInstallerConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.Plan)
	require.NoError(t, cfg.Network.Validate(cfg.Plan))

	_, err = (&App{SDNConfig: &sdn.Config{Enabled: true}}).GetInstallerConfig()
	var target ErrSDNConfigValidation
	require.True(t, errors.As(err, &target), "got %v", err)
}
