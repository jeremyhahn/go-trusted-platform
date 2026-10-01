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

package switchmgmt

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
)

type ciscoNexusConfigurator struct {
	config   *Config
	logger   *slog.Logger
	executor SSHExecutor
}

func newCiscoNexusConfigurator(config *Config, logger *slog.Logger) (Configurator, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &ciscoNexusConfigurator{
		config: config,
		logger: logger,
	}, nil
}

// newCiscoNexusWithExecutor creates a ciscoNexusConfigurator with an injected
// SSHExecutor, used for testing.
func newCiscoNexusWithExecutor(config *Config, logger *slog.Logger, executor SSHExecutor) *ciscoNexusConfigurator {
	return &ciscoNexusConfigurator{
		config:   config,
		logger:   logger,
		executor: executor,
	}
}

func (c *ciscoNexusConfigurator) ConfigureVLANs(ctx context.Context, vlans []VLANConfig) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	commands := GenerateVLANCommands(vlans)
	for _, cmd := range commands {
		c.logger.Debug("executing vlan command", "command", cmd)
		output, err := c.executor.Execute(ctx, cmd)
		if err != nil {
			return ErrVLANConfigFailed{
				VLANID: 0,
				Cause:  err,
			}
		}
		if containsError(output) {
			return ErrVLANConfigFailed{
				VLANID: 0,
				Cause: ErrCommandFailed{
					Command: cmd,
					Output:  output,
				},
			}
		}
	}
	return nil
}

func (c *ciscoNexusConfigurator) ConfigurePorts(ctx context.Context, ports []PortConfig) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	commands, err := GeneratePortCommands(ports)
	if err != nil {
		return err
	}

	for _, cmd := range commands {
		c.logger.Debug("executing port command", "command", cmd)
		output, execErr := c.executor.Execute(ctx, cmd)
		if execErr != nil {
			return ErrPortConfigFailed{
				Port:  "",
				Cause: execErr,
			}
		}
		if containsError(output) {
			return ErrPortConfigFailed{
				Port: "",
				Cause: ErrCommandFailed{
					Command: cmd,
					Output:  output,
				},
			}
		}
	}
	return nil
}

func (c *ciscoNexusConfigurator) Configure(ctx context.Context, config *Config) error {
	if config == nil {
		return ErrNilConfig{}
	}

	if len(config.VLANs) > 0 {
		if err := c.ConfigureVLANs(ctx, config.VLANs); err != nil {
			return err
		}
	}

	if len(config.Ports) > 0 {
		if err := c.ConfigurePorts(ctx, config.Ports); err != nil {
			return err
		}
	}

	return nil
}

func (c *ciscoNexusConfigurator) Verify(ctx context.Context, config *Config) error {
	if config == nil {
		return ErrNilConfig{}
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	// Verify VLANs
	if len(config.VLANs) > 0 {
		output, err := c.executor.Execute(ctx, "show vlan brief")
		if err != nil {
			return ErrVerificationFailed{Details: fmt.Sprintf("failed to retrieve vlan info: %v", err)}
		}
		for _, vlan := range config.VLANs {
			vlanIDStr := strconv.Itoa(vlan.ID)
			if !strings.Contains(output, vlanIDStr) {
				return ErrVerificationFailed{
					Details: fmt.Sprintf("vlan %d not found in switch output", vlan.ID),
				}
			}
		}
	}

	// Verify ports
	if len(config.Ports) > 0 {
		output, err := c.executor.Execute(ctx, "show interface status")
		if err != nil {
			return ErrVerificationFailed{Details: fmt.Sprintf("failed to retrieve interface info: %v", err)}
		}
		for _, port := range config.Ports {
			expanded, expandErr := ExpandPortRange(port.Port)
			if expandErr != nil {
				return expandErr
			}
			for _, iface := range expanded {
				if !strings.Contains(output, iface) {
					return ErrVerificationFailed{
						Details: fmt.Sprintf("port %s not found in interface status", iface),
					}
				}
			}
		}
	}

	return nil
}

func (c *ciscoNexusConfigurator) Close() error {
	if c.executor != nil {
		return c.executor.Close()
	}
	return nil
}

func (c *ciscoNexusConfigurator) ensureConnected(ctx context.Context) error {
	if c.executor != nil {
		return nil
	}
	executor, err := NewSSHExecutor(ctx, c.config)
	if err != nil {
		return err
	}
	c.executor = executor
	return nil
}

// GenerateVLANCommands produces the NX-OS CLI commands to configure VLANs.
func GenerateVLANCommands(vlans []VLANConfig) []string {
	if len(vlans) == 0 {
		return nil
	}

	commands := []string{"configure terminal"}
	for _, vlan := range vlans {
		commands = append(commands, fmt.Sprintf("vlan %d", vlan.ID))
		if vlan.Name != "" {
			commands = append(commands, fmt.Sprintf("  name %s", vlan.Name))
		}
		if vlan.Description != "" {
			commands = append(commands, fmt.Sprintf("  description %s", vlan.Description))
		}
	}
	commands = append(commands, "exit")
	commands = append(commands, "copy running-config startup-config")
	return commands
}

// GeneratePortCommands produces the NX-OS CLI commands to configure ports.
func GeneratePortCommands(ports []PortConfig) ([]string, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	commands := []string{"configure terminal"}
	for _, port := range ports {
		if err := ValidatePortConfig(port); err != nil {
			return nil, ErrPortConfigFailed{Port: port.Port, Cause: err}
		}
		expanded, err := ExpandPortRange(port.Port)
		if err != nil {
			return nil, err
		}

		for _, iface := range expanded {
			commands = append(commands, fmt.Sprintf("interface %s", iface))
			if port.Description != "" {
				commands = append(commands, fmt.Sprintf("  description %s", port.Description))
			}

			switch port.Mode {
			case "trunk":
				commands = append(commands, "  switchport mode trunk")
				if len(port.VLANs) > 0 {
					vlanList := joinInts(port.VLANs, ",")
					commands = append(commands, fmt.Sprintf("  switchport trunk allowed vlan %s", vlanList))
				}
				if port.NativeVLAN > 0 {
					commands = append(commands, fmt.Sprintf("  switchport trunk native vlan %d", port.NativeVLAN))
				} else {
					// A re-used port must not keep an old native VLAN: on a
					// gateway trunk it would put untagged frames on provisioning.
					commands = append(commands, "  no switchport trunk native vlan")
				}
			case "access":
				commands = append(commands, "  switchport mode access")
				if port.AccessVLAN > 0 {
					commands = append(commands, fmt.Sprintf("  switchport access vlan %d", port.AccessVLAN))
				}
			}
			if port.MTU > 0 {
				commands = append(commands, fmt.Sprintf("  mtu %d", port.MTU))
			}

			commands = append(commands, "  no shutdown")
		}
	}
	commands = append(commands, "exit")
	commands = append(commands, "copy running-config startup-config")
	return commands, nil
}

// ExpandPortRange expands a port range like "Eth1/3-5" into individual
// interface names ["Eth1/3", "Eth1/4", "Eth1/5"]. Single ports like
// "Eth1/1" are returned as-is in a single-element slice.
func ExpandPortRange(port string) ([]string, error) {
	if port == "" {
		return nil, ErrInvalidPortRange{Port: port, Reason: "empty port specification"}
	}

	// Find the last '/' to separate prefix from port number(s)
	slashIdx := strings.LastIndex(port, "/")
	if slashIdx < 0 {
		// No slash — could be a simple name like "mgmt0"
		return []string{port}, nil
	}

	prefix := port[:slashIdx+1] // e.g., "Eth1/"
	suffix := port[slashIdx+1:] // e.g., "3-5" or "3"

	dashIdx := strings.Index(suffix, "-")
	if dashIdx < 0 {
		// Single port, no range
		return []string{port}, nil
	}

	startStr := suffix[:dashIdx]
	endStr := suffix[dashIdx+1:]

	start, err := strconv.Atoi(startStr)
	if err != nil {
		return nil, ErrInvalidPortRange{
			Port:   port,
			Reason: fmt.Sprintf("invalid range start %q", startStr),
		}
	}

	end, err := strconv.Atoi(endStr)
	if err != nil {
		return nil, ErrInvalidPortRange{
			Port:   port,
			Reason: fmt.Sprintf("invalid range end %q", endStr),
		}
	}

	if start > end {
		return nil, ErrInvalidPortRange{
			Port:   port,
			Reason: fmt.Sprintf("range start %d greater than end %d", start, end),
		}
	}

	result := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		result = append(result, fmt.Sprintf("%s%d", prefix, i))
	}
	return result, nil
}

// validateConfig checks that the switch configuration has required fields.
func validateConfig(config *Config) error {
	if config == nil {
		return ErrNilConfig{}
	}
	if config.Host == "" {
		return ErrInvalidConfig{Field: "host", Reason: "must not be empty"}
	}
	if config.User == "" {
		return ErrInvalidConfig{Field: "user", Reason: "must not be empty"}
	}
	if config.SSHKey == "" {
		return ErrInvalidConfig{Field: "ssh_key", Reason: "must not be empty"}
	}
	return nil
}

// ValidateVLANConfig validates a VLANConfig.
func ValidateVLANConfig(vlan VLANConfig) error {
	if vlan.ID < 1 || vlan.ID > 4094 {
		return ErrInvalidConfig{
			Field:  "vlan.id",
			Reason: fmt.Sprintf("vlan id %d out of range [1, 4094]", vlan.ID),
		}
	}
	if vlan.Name == "" {
		return ErrInvalidConfig{Field: "vlan.name", Reason: "must not be empty"}
	}
	return nil
}

// ValidatePortConfig validates a PortConfig.
func ValidatePortConfig(port PortConfig) error {
	if port.Port == "" {
		return ErrInvalidConfig{Field: "port.port", Reason: "must not be empty"}
	}
	if port.Mode != "trunk" && port.Mode != "access" {
		return ErrInvalidConfig{
			Field:  "port.mode",
			Reason: fmt.Sprintf("must be 'trunk' or 'access', got %q", port.Mode),
		}
	}
	if port.Mode == "access" && port.AccessVLAN < 1 {
		return ErrInvalidConfig{Field: "port.access_vlan", Reason: "must be set for access mode"}
	}
	if port.Mode == "trunk" && len(port.VLANs) == 0 {
		return ErrInvalidConfig{Field: "port.vlans", Reason: "must specify allowed vlans for trunk mode"}
	}
	if port.NativeVLAN != 0 {
		if port.Mode != "trunk" {
			return ErrInvalidConfig{Field: "port.native_vlan", Reason: "only a trunk has a native vlan"}
		}
		if !slices.Contains(port.VLANs, port.NativeVLAN) {
			return ErrInvalidConfig{
				Field:  "port.native_vlan",
				Reason: fmt.Sprintf("native vlan %d is not in the trunk's allowed vlans", port.NativeVLAN),
			}
		}
	}
	if port.MTU != 0 && (port.MTU < MinMTU || port.MTU > MaxMTU) {
		return ErrInvalidConfig{
			Field:  "port.mtu",
			Reason: fmt.Sprintf("mtu %d out of range [%d, %d]", port.MTU, MinMTU, MaxMTU),
		}
	}
	return nil
}

// MinMTU and MaxMTU bound a port MTU. Platform ports run MaxMTU so VXLAN
// encapsulation never fragments.
const (
	MinMTU = 1500
	MaxMTU = 9216
)

// containsError checks if NX-OS output contains an error indicator.
func containsError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "% ")
}

// joinInts joins a slice of ints with the given separator.
func joinInts(ints []int, sep string) string {
	strs := make([]string, len(ints))
	for i, v := range ints {
		strs[i] = strconv.Itoa(v)
	}
	return strings.Join(strs, sep)
}
