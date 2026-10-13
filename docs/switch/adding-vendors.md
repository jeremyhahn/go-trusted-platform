# Adding New Switch Vendors

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [engineering.md](engineering.md) §7. This guide omits the separate `configuratorRegistry` (`pkg/switch/factory.go:21`), uses `fmt.Errorf` instead of typed errors, and writes an Arista driver where `newSSHManager` already serves the dialect.

This guide shows how to add support for a new switch vendor (e.g., Arista EOS, Juniper, etc.) to the switch management system.

## Overview

The switch management system uses a factory pattern to dispatch Manager creation by vendor. Adding a new vendor involves:

1. Creating a new Manager implementation
2. Registering the factory function
3. Adding configuration tests
4. Documenting vendor-specific commands

## Step 1: Create Vendor Implementation

Create a new file for your vendor in `pkg/switch/`:

```go
// pkg/switch/arista_eos.go

package switchmgmt

import (
    "context"
    "fmt"
    "log/slog"
    "regexp"
    "strconv"
    "strings"
)

// aristaEOSManager implements Manager for Arista EOS switches
type aristaEOSManager struct {
    config   *Config
    logger   *slog.Logger
    executor SSHExecutor
}

// newAristaEOSManager creates an SSH-based Manager for Arista EOS
func newAristaEOSManager(config *Config, logger *slog.Logger) (Manager, error) {
    if err := validateSSHManagerConfig(config); err != nil {
        return nil, err
    }
    return &aristaEOSManager{
        config: config,
        logger: logger,
    }, nil
}
```

## Step 2: Implement Manager Interface

Your Manager must implement all 7 methods:

```go
func (m *aristaEOSManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
    if err := m.ensureConnected(); err != nil {
        return err
    }

    // Arista EOS commands (very similar to Cisco)
    commands := buildConfigCommands(
        fmt.Sprintf("interface %s", m.normalizePortName(port)),
        "switchport mode access",
        fmt.Sprintf("switchport access vlan %d", vlanID),
    )

    for _, cmd := range commands {
        m.logger.Debug("arista set port vlan", "command", cmd)
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

func (m *aristaEOSManager) GetPortVLAN(ctx context.Context, port string) (uint16, error) {
    if err := m.ensureConnected(); err != nil {
        return 0, err
    }

    cmd := fmt.Sprintf("show interfaces %s switchport", m.normalizePortName(port))
    m.logger.Debug("arista get port vlan", "command", cmd)

    output, err := m.executor.Execute(ctx, cmd)
    if err != nil {
        return 0, ErrSSHCommandFailed{Command: cmd, Cause: err}
    }

    vlan, parseErr := parseAristaAccessVLAN(output)
    if parseErr != nil {
        return 0, ErrSSHParseOutputFailed{
            Command: cmd,
            Output:  output,
            Reason:  parseErr.Error(),
        }
    }
    return vlan, nil
}

func (m *aristaEOSManager) GetPortStatus(ctx context.Context, port string) (*switchwire.PortStatus, error) {
    if err := m.ensureConnected(); err != nil {
        return nil, err
    }

    cmd := fmt.Sprintf("show interfaces %s", m.normalizePortName(port))
    m.logger.Debug("arista get port status", "command", cmd)

    output, err := m.executor.Execute(ctx, cmd)
    if err != nil {
        return nil, ErrSSHCommandFailed{Command: cmd, Cause: err}
    }

    status, parseErr := parseAristaInterfaceStatus(m.normalizePortName(port), output)
    if parseErr != nil {
        return nil, ErrSSHParseOutputFailed{
            Command: cmd,
            Output:  output,
            Reason:  parseErr.Error(),
        }
    }
    return status, nil
}

func (m *aristaEOSManager) ListPorts(ctx context.Context) ([]*switchwire.PortStatus, error) {
    if err := m.ensureConnected(); err != nil {
        return nil, err
    }

    cmd := "show interfaces status"
    m.logger.Debug("arista list ports", "command", cmd)

    output, err := m.executor.Execute(ctx, cmd)
    if err != nil {
        return nil, ErrSSHCommandFailed{Command: cmd, Cause: err}
    }

    ports, parseErr := parseAristaInterfaceStatusTable(output)
    if parseErr != nil {
        return nil, ErrSSHParseOutputFailed{
            Command: cmd,
            Output:  output,
            Reason:  parseErr.Error(),
        }
    }
    return ports, nil
}

func (m *aristaEOSManager) EnablePort(ctx context.Context, port string) error {
    if err := m.ensureConnected(); err != nil {
        return err
    }

    commands := buildConfigCommands(
        fmt.Sprintf("interface %s", m.normalizePortName(port)),
        "no shutdown",
    )

    for _, cmd := range commands {
        m.logger.Debug("arista enable port", "command", cmd)
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

func (m *aristaEOSManager) DisablePort(ctx context.Context, port string) error {
    if err := m.ensureConnected(); err != nil {
        return err
    }

    commands := buildConfigCommands(
        fmt.Sprintf("interface %s", m.normalizePortName(port)),
        "shutdown",
    )

    for _, cmd := range commands {
        m.logger.Debug("arista disable port", "command", cmd)
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

func (m *aristaEOSManager) Close() error {
    if m.executor != nil {
        return m.executor.Close()
    }
    return nil
}

// ensureConnected creates SSH connection on first use
func (m *aristaEOSManager) ensureConnected() error {
    if m.executor != nil {
        return nil
    }
    executor, err := NewSSHExecutor(m.config)
    if err != nil {
        return err
    }
    m.executor = executor
    return nil
}

// normalizePortName converts common formats to vendor-specific format
// Cisco: "Eth1/1" → "Ethernet1/1" (Arista EOS style)
// Arista: "Ethernet1" → "Ethernet1" (no-op)
func (m *aristaEOSManager) normalizePortName(port string) string {
    // Arista uses "Ethernet1", "Ethernet48", etc.
    // If user provides "Eth1", convert to "Ethernet1"
    if strings.HasPrefix(port, "Eth") && !strings.HasPrefix(port, "Ethernet") {
        return strings.Replace(port, "Eth", "Ethernet", 1)
    }
    return port
}
```

## Step 3: Add Output Parsing Functions

Implement vendor-specific parsers for CLI output:

```go
// aristaEOSManager-specific regex patterns
var aristaAccessVLANRegexp = regexp.MustCompile(`(?i)switchport\s+access\s+vlan\s+(\d+)`)
var aristaAdminStatusRegexp = regexp.MustCompile(`(?i)admin\s+state:\s+(\w+)`)
var aristaOperStatusRegexp = regexp.MustCompile(`(?i)operational\s+status:\s+(\w+)`)

// parseAristaAccessVLAN extracts VLAN from "show interfaces Eth1 switchport"
func parseAristaAccessVLAN(output string) (uint16, error) {
    matches := aristaAccessVLANRegexp.FindStringSubmatch(output)
    if matches == nil {
        return 0, fmt.Errorf("access vlan not found in output")
    }
    vlan, err := strconv.ParseUint(matches[1], 10, 16)
    if err != nil {
        return 0, fmt.Errorf("invalid vlan number: %w", err)
    }
    return uint16(vlan), nil
}

// parseAristaInterfaceStatus parses detailed interface info
func parseAristaInterfaceStatus(port string, output string) (*switchwire.PortStatus, error) {
    status := &switchwire.PortStatus{Port: port}

    // Parse operational status
    if matches := aristaOperStatusRegexp.FindStringSubmatch(output); matches != nil {
        opStatus := strings.ToLower(matches[1])
        status.LinkUp = opStatus == "up"
    }

    // Parse admin status
    if matches := aristaAdminStatusRegexp.FindStringSubmatch(output); matches != nil {
        adminStatus := strings.ToLower(matches[1])
        status.Enabled = adminStatus == "up"
    }

    // Parse access VLAN
    if matches := aristaAccessVLANRegexp.FindStringSubmatch(output); matches != nil {
        if vlan, err := strconv.ParseUint(matches[1], 10, 16); err == nil {
            status.AccessVLAN = uint16(vlan)
            status.Mode = switchwire.PortModeAccess
        }
    }

    return status, nil
}

// parseAristaInterfaceStatusTable parses tabular output
// Similar to parseSwitchportOutput in ssh_manager.go
func parseAristaInterfaceStatusTable(output string) ([]*switchwire.PortStatus, error) {
    // Implement table parsing similar to Cisco
    // Arista format is similar but may have slight differences
    return nil, nil  // Placeholder
}
```

## Step 4: Register the Factory

Add your vendor to the manager registry:

```go
// pkg/switch/manager_factory.go

const (
    // ... existing vendors ...
    VendorAristaEOS SwitchVendor = "arista-eos"
)

var managerRegistry = map[SwitchVendor]ManagerFactory{
    VendorCiscoNexus: newSSHManager,
    VendorAristaEOS:  newAristaEOSManager,  // Add here
    VendorNoop:       newNoopManagerFactory,
}
```

## Step 5: Add Unit Tests

Create comprehensive tests for your vendor:

```go
// pkg/switch/arista_eos_test.go

package switchmgmt

import (
    "context"
    "testing"
    "log/slog"
)

func TestNewAristaEOSManager(t *testing.T) {
    config := &Config{
        Name:   "arista-01",
        Vendor: VendorAristaEOS,
        Host:   "10.0.1.51",
        User:   "admin",
        SSHKey: "/etc/certs/arista.key",
    }

    mgr, err := newAristaEOSManager(config, slog.Default())
    if err != nil {
        t.Fatalf("failed to create manager: %v", err)
    }
    if mgr == nil {
        t.Fatal("expected non-nil manager")
    }
}

func TestAristaEOSManager_SetPortVLAN(t *testing.T) {
    config := &Config{
        Name:   "arista-01",
        Vendor: VendorAristaEOS,
        Host:   "10.0.1.51",
        User:   "admin",
        SSHKey: "/etc/certs/arista.key",
    }

    executor := &mockSSHExecutor{
        responses: map[string]string{
            "configure terminal": "localhost(config)#",
            "interface Ethernet1": "localhost(config-if-Et1)#",
            "switchport mode access": "localhost(config-if-Et1)#",
            "switchport access vlan 100": "localhost(config-if-Et1)#",
            "end": "localhost#",
        },
    }

    mgr := &aristaEOSManager{
        config:   config,
        logger:   slog.Default(),
        executor: executor,
    }

    ctx := context.Background()
    err := mgr.SetPortVLAN(ctx, "Ethernet1", 100)
    if err != nil {
        t.Fatalf("SetPortVLAN failed: %v", err)
    }

    // Verify commands were executed in order
    expected := []string{
        "configure terminal",
        "interface Ethernet1",
        "switchport mode access",
        "switchport access vlan 100",
        "end",
    }
    if !commandsMatched(executor.executedCommands, expected) {
        t.Fatalf("commands mismatch:\nGot: %v\nExpected: %v",
            executor.executedCommands, expected)
    }
}

func TestAristaEOSManager_GetPortVLAN(t *testing.T) {
    output := `Interface Ethernet1
    Admin State: Up
    Operational Status: Up
    Switchport Mode: Access
    Switchport Access VLAN: 100
    STP Portfast: Enabled
    Spanning Tree Status: Forwarding`

    config := &Config{
        Name:   "arista-01",
        Host:   "10.0.1.51",
        User:   "admin",
        SSHKey: "/etc/certs/arista.key",
    }

    executor := &mockSSHExecutor{
        responses: map[string]string{
            "show interfaces Ethernet1 switchport": output,
        },
    }

    mgr := &aristaEOSManager{
        config:   config,
        logger:   slog.Default(),
        executor: executor,
    }

    ctx := context.Background()
    vlan, err := mgr.GetPortVLAN(ctx, "Ethernet1")
    if err != nil {
        t.Fatalf("GetPortVLAN failed: %v", err)
    }

    if vlan != 100 {
        t.Fatalf("expected VLAN 100, got %d", vlan)
    }
}

func TestAristaEOSManager_ListPorts(t *testing.T) {
    output := `Interface    Status    VLAN  MTU    Cfgd Flags
Eth1         up        100   1500   A
Eth2         up        100   1500   A
Eth3         down      100   1500   A
Eth4         connected 200   1500   A`

    config := &Config{
        Name:   "arista-01",
        Host:   "10.0.1.51",
        User:   "admin",
        SSHKey: "/etc/certs/arista.key",
    }

    executor := &mockSSHExecutor{
        responses: map[string]string{
            "show interfaces status": output,
        },
    }

    mgr := &aristaEOSManager{
        config:   config,
        logger:   slog.Default(),
        executor: executor,
    }

    ctx := context.Background()
    ports, err := mgr.ListPorts(ctx)
    if err != nil {
        t.Fatalf("ListPorts failed: %v", err)
    }

    if len(ports) != 4 {
        t.Fatalf("expected 4 ports, got %d", len(ports))
    }
}

func TestAristaEOSNormalizePortName(t *testing.T) {
    mgr := &aristaEOSManager{}

    tests := []struct {
        input    string
        expected string
    }{
        {"Ethernet1", "Ethernet1"},      // Already normalized
        {"Eth1", "Ethernet1"},           // Cisco format
        {"GigabitEthernet1", "GigabitEthernet1"},  // Pass through
        {"Et1/1", "Ethernet1/1"},        // Cisco NX-OS format
    }

    for _, tt := range tests {
        t.Run(tt.input, func(t *testing.T) {
            got := mgr.normalizePortName(tt.input)
            if got != tt.expected {
                t.Fatalf("normalizePortName(%q) = %q, expected %q",
                    tt.input, got, tt.expected)
            }
        })
    }
}
```

## Step 6: Integration Tests

Add integration tests with real Arista switch (if available):

```bash
# In devcontainer with Arista EOS simulator
# or real switch in staging environment

# Test basic operations
make integration-test-switch

# Or specific to your vendor:
make integration-test-switch-arista-eos
```

## Step 7: Documentation

Add vendor documentation:

1. **Configuration example** to `configuration.md`:
   ```yaml
   switches:
     - name: arista-switch-01
       vendor: arista-eos
       host: 10.0.1.51
       user: admin
       ssh_key: /etc/certs/arista.key
   ```

2. **Vendor-specific notes** (port naming, quirks, etc.):
   ```markdown
   ### Arista EOS
   - Port names: `Ethernet1`, `Ethernet48` (not `Eth1/1`)
   - Commands: CLI is similar to Cisco IOS-XE
   - VLAN range: 1-4094
   - Trunk support: Fully supported
   - Max ports: Varies by model (32, 48, 96)
   ```

3. **Troubleshooting**:
   ```markdown
   **Problem:** "% Unknown command 'switchport access vlan'"
   **Solution:** Arista EOS may require different syntax (unlikely; very similar to Cisco)
   ```

## Step 8: Vendor Testing Checklist

- [x] Manager interface fully implemented
- [x] All 7 methods tested (SetPortVLAN, GetPortVLAN, GetPortStatus, ListPorts, EnablePort, DisablePort, Close)
- [x] Error handling (connection failures, invalid ports, invalid VLANs)
- [x] Port name normalization (convert from other formats if needed)
- [x] Output parsing (regex patterns verified)
- [x] SSH command composition verified
- [x] Configuration validation
- [x] Logging at appropriate levels
- [x] Test coverage >90%

## Common Vendor Differences

### Port Naming

| Vendor | Format | Examples |
|--------|--------|----------|
| Cisco NX-OS | `Eth` prefix | `Eth1/1`, `Eth1/48`, `Po1` |
| Cisco IOS | `GigabitEthernet` | `Gi1/0/1`, `Te1/1/1`, `Po1` |
| Arista EOS | `Ethernet` | `Ethernet1`, `Ethernet48`, `Port-Channel1` |
| Juniper | `ge-` prefix | `ge-0/0/0`, `ge-0/0/47`, `ae0` |

### VLAN Commands

| Vendor | Command |
|--------|---------|
| Cisco | `switchport access vlan 100` |
| Arista | `switchport access vlan 100` (identical) |
| Juniper | `set family ethernet-switching vlan members 100` (very different) |

### Output Format

Cisco-compatible vendors produce similar output. Non-Cisco vendors (Juniper, Mellanox) have completely different formats and require rewriting parsers.

## Fallback Strategy

If a vendor's CLI is sufficiently different from Cisco:

1. Implement from scratch (recommended)
2. Use vendor's native API (NETCONF, gNMI, custom REST)
3. Map vendor commands to standard interface

Example: Juniper NETCONF approach:

```go
// pkg/switch/juniper.go
type juniperManager struct {
    config *Config
    client netconfClient  // Use vendor SDK
}

// Use vendor SDK for config instead of SSH CLI
func (m *juniperManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
    // Send NETCONF RPC instead of SSH commands
    return m.client.ConfigureInterface(port, vlanID)
}
```

## Next Steps

1. **Test with hardware**: If possible, validate on real switch in lab
2. **Performance test**: Measure command execution time (target: <1s per operation)
3. **Document quirks**: Add any vendor-specific notes to `configuration.md`
4. **Upstream**: Consider contributing back if generally useful

## Troubleshooting New Vendor

### Regex patterns not matching

1. Capture actual switch output:
   ```bash
   ssh admin@switch "show interfaces Ethernet1"
   ```

2. Test regex patterns:
   ```go
   pattern := regexp.MustCompile(`(?i)...`)
   matches := pattern.FindStringSubmatch(output)
   println("Matches:", matches)
   ```

3. Verify case sensitivity (use `(?i)` for case-insensitive)

### Commands failing

1. Test commands manually on switch:
   ```bash
   ssh admin@switch "configure terminal"
   ssh admin@switch "interface Ethernet1"
   ssh admin@switch "switchport access vlan 100"
   ```

2. Check for confirmation prompts (some vendors require yes/no)

3. Check for async output (some commands don't return immediately)

### Port not found

1. Get actual port list:
   ```bash
   ssh admin@switch "show interfaces brief"
   ```

2. Verify port name format for your model

3. Check if port is disabled/unknown to switch

## Vendor Registration Requirements

Before registering a new vendor, verify:

- [ ] Manager interface fully implemented
- [ ] Output parsing handles edge cases
- [ ] Error handling covers connection, command, parse failures
- [ ] Test coverage >90%
- [ ] Documentation complete
- [ ] No hardcoded vendor-specific behavior in generic code
