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
	"regexp"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// sshManager implements Manager using SSH CLI commands compatible with
// Cisco IOS, IOS-XE, NX-OS, Arista EOS, and similar platforms.
type sshManager struct {
	config   *Config
	logger   *slog.Logger
	executor SSHExecutor
}

// newSSHManager creates an SSH-based Manager for the given config.
func newSSHManager(config *Config, logger *slog.Logger) (Manager, error) {
	if err := validateSSHManagerConfig(config); err != nil {
		return nil, err
	}
	return &sshManager{
		config: config,
		logger: logger,
	}, nil
}

// newSSHManagerWithExecutor creates an sshManager with an injected SSHExecutor
// for testing.
func newSSHManagerWithExecutor(config *Config, logger *slog.Logger, executor SSHExecutor) *sshManager {
	return &sshManager{
		config:   config,
		logger:   logger,
		executor: executor,
	}
}

func (m *sshManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
	if err := m.ensureConnected(ctx); err != nil {
		return err
	}

	commands := buildConfigCommands(
		fmt.Sprintf("interface %s", port),
		"switchport mode access",
		fmt.Sprintf("switchport access vlan %d", vlanID),
	)

	for _, cmd := range commands {
		m.logger.Debug("ssh set port vlan", "command", cmd)
		output, err := m.executor.Execute(ctx, cmd)
		if err != nil {
			return ErrPortVLANSetFailed{
				Port:   port,
				VLANID: vlanID,
				Cause:  err,
			}
		}
		if containsError(output) {
			return ErrPortVLANSetFailed{
				Port:   port,
				VLANID: vlanID,
				Cause: ErrSSHCommandFailed{
					Command: cmd,
					Output:  output,
				},
			}
		}
	}
	return nil
}

func (m *sshManager) GetPortVLAN(ctx context.Context, port string) (uint16, error) {
	if err := m.ensureConnected(ctx); err != nil {
		return 0, err
	}

	cmd := fmt.Sprintf("show interfaces %s switchport", port)
	m.logger.Debug("ssh get port vlan", "command", cmd)

	output, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return 0, ErrSSHCommandFailed{Command: cmd, Cause: err}
	}

	vlan, parseErr := parseAccessVLANFromSwitchport(output)
	if parseErr != nil {
		return 0, ErrSSHParseOutputFailed{
			Command: cmd,
			Output:  output,
			Reason:  parseErr.Error(),
		}
	}
	return vlan, nil
}

func (m *sshManager) GetPortStatus(ctx context.Context, port string) (*switchwire.PortStatus, error) {
	if err := m.ensureConnected(ctx); err != nil {
		return nil, err
	}

	cmd := fmt.Sprintf("show interfaces %s switchport", port)
	m.logger.Debug("ssh get port status", "command", cmd)

	output, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return nil, ErrSSHCommandFailed{Command: cmd, Cause: err}
	}

	status, parseErr := parseSwitchportOutput(port, output)
	if parseErr != nil {
		return nil, ErrSSHParseOutputFailed{
			Command: cmd,
			Output:  output,
			Reason:  parseErr.Error(),
		}
	}
	return status, nil
}

func (m *sshManager) ListPorts(ctx context.Context) ([]*switchwire.PortStatus, error) {
	if err := m.ensureConnected(ctx); err != nil {
		return nil, err
	}

	cmd := "show interfaces status"
	m.logger.Debug("ssh list ports", "command", cmd)

	output, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return nil, ErrSSHCommandFailed{Command: cmd, Cause: err}
	}

	ports, parseErr := parseInterfaceStatusTable(output)
	if parseErr != nil {
		return nil, ErrSSHParseOutputFailed{
			Command: cmd,
			Output:  output,
			Reason:  parseErr.Error(),
		}
	}
	return ports, nil
}

func (m *sshManager) EnablePort(ctx context.Context, port string) error {
	if err := m.ensureConnected(ctx); err != nil {
		return err
	}

	commands := buildConfigCommands(
		fmt.Sprintf("interface %s", port),
		"no shutdown",
	)

	for _, cmd := range commands {
		m.logger.Debug("ssh enable port", "command", cmd)
		output, err := m.executor.Execute(ctx, cmd)
		if err != nil {
			return ErrSSHCommandFailed{Command: cmd, Cause: err}
		}
		if containsError(output) {
			return ErrSSHCommandFailed{Command: cmd, Output: output}
		}
	}
	return nil
}

func (m *sshManager) DisablePort(ctx context.Context, port string) error {
	if err := m.ensureConnected(ctx); err != nil {
		return err
	}

	commands := buildConfigCommands(
		fmt.Sprintf("interface %s", port),
		"shutdown",
	)

	for _, cmd := range commands {
		m.logger.Debug("ssh disable port", "command", cmd)
		output, err := m.executor.Execute(ctx, cmd)
		if err != nil {
			return ErrSSHCommandFailed{Command: cmd, Cause: err}
		}
		if containsError(output) {
			return ErrSSHCommandFailed{Command: cmd, Output: output}
		}
	}
	return nil
}

func (m *sshManager) Close() error {
	if m.executor != nil {
		return m.executor.Close()
	}
	return nil
}

func (m *sshManager) ensureConnected(ctx context.Context) error {
	if m.executor != nil {
		return nil
	}
	executor, err := NewSSHExecutor(ctx, m.config)
	if err != nil {
		return err
	}
	m.executor = executor
	return nil
}

// buildConfigCommands wraps interface-level commands with configure terminal / end.
func buildConfigCommands(interfaceCommands ...string) []string {
	commands := make([]string, 0, len(interfaceCommands)+2)
	commands = append(commands, "configure terminal")
	commands = append(commands, interfaceCommands...)
	commands = append(commands, "end")
	return commands
}

// validateSSHManagerConfig validates config fields required for SSH Manager.
func validateSSHManagerConfig(config *Config) error {
	if config == nil {
		return ErrNilConfig{}
	}
	if config.Host == "" {
		return ErrInvalidConfig{Field: "host", Reason: "must not be empty"}
	}
	if config.User == "" {
		return ErrInvalidConfig{Field: "user", Reason: "must not be empty"}
	}
	if config.SSHKey == "" && config.Password == "" {
		return ErrInvalidConfig{
			Field:  "ssh_key",
			Reason: "either ssh_key or password must be provided",
		}
	}
	return nil
}

// accessVLANRegexp matches "Access Mode VLAN: 100 (vlan-name)" style output.
var accessVLANRegexp = regexp.MustCompile(`(?i)access\s+mode\s+vlan:\s*(\d+)`)

// adminModeRegexp matches "Administrative Mode: static access" or "trunk" etc.
var adminModeRegexp = regexp.MustCompile(`(?i)administrative\s+mode:\s*(.+)`)

// operModeRegexp matches "Operational Mode: static access" or "trunk" etc.
var operModeRegexp = regexp.MustCompile(`(?i)operational\s+mode:\s*(.+)`)

// trunkAllowedVLANRegexp matches "Trunking VLANs Allowed: 10,20,30" or similar.
var trunkAllowedVLANRegexp = regexp.MustCompile(`(?i)trunking\s+vlans?\s+(?:allowed|enabled):\s*(.+)`)

// trunkNativeVLANRegexp matches "Trunking Native Mode VLAN: 405 (provisioning)".
var trunkNativeVLANRegexp = regexp.MustCompile(`(?i)trunking\s+native\s+mode\s+vlan:\s*(\d+)`)

// parseAccessVLANFromSwitchport extracts the access VLAN ID from
// "show interfaces {port} switchport" text output.
func parseAccessVLANFromSwitchport(output string) (uint16, error) {
	matches := accessVLANRegexp.FindStringSubmatch(output)
	if matches == nil {
		return 0, ErrSSHParseOutputFailed{
			Command: "show interfaces switchport",
			Output:  output,
			Reason:  "access mode vlan not found in output",
		}
	}
	vlan, err := strconv.ParseUint(matches[1], 10, 16)
	if err != nil {
		return 0, ErrSSHParseOutputFailed{
			Command: "show interfaces switchport",
			Output:  output,
			Reason:  fmt.Sprintf("invalid vlan number %q", matches[1]),
		}
	}
	return uint16(vlan), nil
}

// parseSwitchportOutput parses "show interfaces {port} switchport" text output
// into a PortStatus.
func parseSwitchportOutput(port string, output string) (*switchwire.PortStatus, error) {
	status := &switchwire.PortStatus{Port: port}

	// Determine mode from administrative or operational mode line.
	if matches := operModeRegexp.FindStringSubmatch(output); matches != nil {
		modeLine := strings.TrimSpace(strings.ToLower(matches[1]))
		if strings.Contains(modeLine, "trunk") {
			status.Mode = switchwire.PortModeTrunk
		} else {
			status.Mode = switchwire.PortModeAccess
		}
	} else if matches := adminModeRegexp.FindStringSubmatch(output); matches != nil {
		modeLine := strings.TrimSpace(strings.ToLower(matches[1]))
		if strings.Contains(modeLine, "trunk") {
			status.Mode = switchwire.PortModeTrunk
		} else {
			status.Mode = switchwire.PortModeAccess
		}
	}

	// Parse access VLAN.
	if matches := accessVLANRegexp.FindStringSubmatch(output); matches != nil {
		if vlan, err := strconv.ParseUint(matches[1], 10, 16); err == nil {
			status.AccessVLAN = uint16(vlan)
		}
	}

	// Parse trunk allowed VLANs.
	if matches := trunkAllowedVLANRegexp.FindStringSubmatch(output); matches != nil {
		status.TrunkVLANs = parseTrunkVLANList(matches[1])
	}

	// Parse the trunk native VLAN.
	if matches := trunkNativeVLANRegexp.FindStringSubmatch(output); matches != nil {
		if vlan, err := strconv.ParseUint(matches[1], 10, 16); err == nil {
			status.NativeVLAN = uint16(vlan)
		}
	}

	// Parse enabled state from Switchport: Enabled/Disabled line.
	lowerOutput := strings.ToLower(output)
	if strings.Contains(lowerOutput, "switchport: enabled") {
		status.Enabled = true
	}

	return status, nil
}

// parseInterfaceStatusTable parses the tabular output of "show interfaces status".
//
// Example output:
//
//	Port      Name               Status       Vlan       Duplex  Speed   Type
//	Eth1/1    uplink             connected    trunk      full    1000    10/100/1000
//	Eth1/2    server-01          connected    100        full    1000    10/100/1000
//	Eth1/3    --                 disabled     200        auto    auto    10/100/1000
func parseInterfaceStatusTable(output string) ([]*switchwire.PortStatus, error) {
	lines := strings.Split(output, "\n")

	// Find the header line to determine column positions.
	headerIdx := -1
	for i, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "port") && strings.Contains(lower, "status") && strings.Contains(lower, "vlan") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, ErrSSHParseOutputFailed{
			Command: "show interfaces status",
			Output:  output,
			Reason:  "header line not found",
		}
	}

	// Parse column positions from the header.
	header := lines[headerIdx]
	cols := parseColumnPositions(header)

	var ports []*switchwire.PortStatus
	for i := headerIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Skip separator lines (all dashes).
		if strings.Count(line, "-") > len(line)/2 {
			continue
		}

		ps := parseStatusLine(line, cols)
		if ps != nil {
			ports = append(ports, ps)
		}
	}

	return ports, nil
}

// columnPositions holds the start indices for each column in "show interfaces status".
type columnPositions struct {
	port   int
	name   int
	status int
	vlan   int
	duplex int
	speed  int
	typ    int
}

// parseColumnPositions determines column start positions from the header line.
func parseColumnPositions(header string) columnPositions {
	lower := strings.ToLower(header)
	return columnPositions{
		port:   0,
		name:   indexOrEnd(lower, "name"),
		status: indexOrEnd(lower, "status"),
		vlan:   indexOrEnd(lower, "vlan"),
		duplex: indexOrEnd(lower, "duplex"),
		speed:  indexOrEnd(lower, "speed"),
		typ:    indexOrEnd(lower, "type"),
	}
}

// indexOrEnd returns the index of substr in s, or len(s) if not found.
func indexOrEnd(s, substr string) int {
	idx := strings.Index(s, substr)
	if idx < 0 {
		return len(s)
	}
	return idx
}

// extractColumn extracts a fixed-width column value from a line.
func extractColumn(line string, start, end int) string {
	if start >= len(line) {
		return ""
	}
	if end > len(line) {
		end = len(line)
	}
	return strings.TrimSpace(line[start:end])
}

// parseStatusLine parses a single data line from "show interfaces status" output.
func parseStatusLine(line string, cols columnPositions) *switchwire.PortStatus {
	port := extractColumn(line, cols.port, cols.name)
	if port == "" {
		return nil
	}

	statusStr := strings.ToLower(extractColumn(line, cols.status, cols.vlan))
	vlanStr := extractColumn(line, cols.vlan, cols.duplex)

	ps := &switchwire.PortStatus{
		Port: port,
	}

	// Parse link/admin state.
	switch {
	case strings.Contains(statusStr, "connected"):
		ps.Enabled = true
		ps.LinkUp = true
	case strings.Contains(statusStr, "notconnect"), strings.Contains(statusStr, "not connect"):
		ps.Enabled = true
		ps.LinkUp = false
	case strings.Contains(statusStr, "disabled"):
		ps.Enabled = false
		ps.LinkUp = false
	default:
		ps.Enabled = true
	}

	// Parse VLAN / mode.
	vlanLower := strings.ToLower(strings.TrimSpace(vlanStr))
	if vlanLower == "trunk" || vlanLower == "routed" {
		ps.Mode = switchwire.PortModeTrunk
	} else {
		ps.Mode = switchwire.PortModeAccess
		if vlan, err := strconv.ParseUint(strings.TrimSpace(vlanStr), 10, 16); err == nil {
			ps.AccessVLAN = uint16(vlan)
		}
	}

	// Parse description (Name column).
	desc := extractColumn(line, cols.name, cols.status)
	if desc != "" && desc != "--" {
		ps.Description = desc
	}

	return ps
}

// parseTrunkVLANList parses a comma-separated VLAN list (e.g. "10,20,30") into a uint16 slice.
func parseTrunkVLANList(s string) []uint16 {
	parts := strings.Split(s, ",")
	vlans := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if v, err := strconv.ParseUint(p, 10, 16); err == nil {
			vlans = append(vlans, uint16(v))
		}
	}
	return vlans
}
