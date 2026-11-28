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
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// maxVLANID is the highest 802.1Q VLAN ID a port may carry.
const maxVLANID = 4094

// memoryManager is a Manager that keeps port state in memory. It is seeded
// from the config's ports and touches no hardware: it backs a daemon or the
// web harness when no switch is attached.
type memoryManager struct {
	mu    sync.Mutex
	order []string
	ports map[string]*switchwire.PortStatus
}

// newMemoryManagerFactory builds the memory vendor's Manager from config.
func newMemoryManagerFactory(config *Config, _ *slog.Logger) (Manager, error) {
	return NewMemoryManager(config)
}

// NewMemoryManager returns a Manager that serves port state from memory,
// seeded with one enabled, link-up port per expanded config port in config
// order. A mode other than "access", "" or "trunk", a VLAN outside 0..4094
// or a repeated port returns ErrInvalidConfig; a malformed port range
// returns ErrInvalidPortRange.
func NewMemoryManager(config *Config) (Manager, error) {
	m := &memoryManager{ports: make(map[string]*switchwire.PortStatus)}
	if config == nil {
		return m, nil
	}
	for _, pc := range config.Ports {
		var mode switchwire.PortMode
		switch pc.Mode {
		case "", "access":
			mode = switchwire.PortModeAccess
		case "trunk":
			mode = switchwire.PortModeTrunk
		default:
			return nil, ErrInvalidConfig{Field: "mode", Reason: fmt.Sprintf("port %q: must be 'trunk' or 'access', got %q", pc.Port, pc.Mode)}
		}
		access, err := configVLAN(pc.Port, pc.AccessVLAN)
		if err != nil {
			return nil, err
		}
		native, err := configVLAN(pc.Port, pc.NativeVLAN)
		if err != nil {
			return nil, err
		}
		var trunk []uint16
		for _, v := range pc.VLANs {
			id, err := configVLAN(pc.Port, v)
			if err != nil {
				return nil, err
			}
			trunk = append(trunk, id)
		}
		names, err := ExpandPortRange(pc.Port)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if _, dup := m.ports[name]; dup {
				return nil, ErrInvalidConfig{Field: "port", Reason: fmt.Sprintf("port %q is configured more than once", name)}
			}
			st := &switchwire.PortStatus{
				Port:        name,
				Mode:        mode,
				Enabled:     true,
				LinkUp:      true,
				Description: pc.Description,
			}
			if mode == switchwire.PortModeTrunk {
				st.TrunkVLANs = slices.Clone(trunk)
				st.NativeVLAN = native
			} else {
				st.AccessVLAN = access
			}
			m.ports[name] = st
			m.order = append(m.order, name)
		}
	}
	return m, nil
}

// configVLAN converts a config VLAN value, refusing one outside 0..4094.
func configVLAN(port string, v int) (uint16, error) {
	if v < 0 || v > maxVLANID {
		return 0, ErrInvalidConfig{Field: "vlan", Reason: fmt.Sprintf("port %q: vlan %d out of range [0, %d]", port, v, maxVLANID)}
	}
	return uint16(v), nil
}

// copyStatus returns a deep copy of st.
func copyStatus(st *switchwire.PortStatus) *switchwire.PortStatus {
	c := *st
	c.TrunkVLANs = slices.Clone(st.TrunkVLANs)
	return &c
}

// lookup returns the port's state; the caller holds m.mu.
func (m *memoryManager) lookup(port string) (*switchwire.PortStatus, error) {
	st, ok := m.ports[port]
	if !ok {
		return nil, ErrPortNotFound{Port: port}
	}
	return st, nil
}

// SetPortVLAN makes the port an access port on vlanID (1..4094), clearing
// its trunk VLANs and native VLAN.
func (m *memoryManager) SetPortVLAN(_ context.Context, port string, vlanID uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.lookup(port)
	if err != nil {
		return err
	}
	if vlanID < 1 || vlanID > maxVLANID {
		return ErrInvalidConfig{Field: "vlan", Reason: fmt.Sprintf("vlan %d out of range [1, %d]", vlanID, maxVLANID)}
	}
	st.Mode = switchwire.PortModeAccess
	st.AccessVLAN = vlanID
	st.TrunkVLANs = nil
	st.NativeVLAN = 0
	return nil
}

// GetPortVLAN returns the port's access VLAN.
func (m *memoryManager) GetPortVLAN(_ context.Context, port string) (uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.lookup(port)
	if err != nil {
		return 0, err
	}
	return st.AccessVLAN, nil
}

// GetPortStatus returns a copy of the port's state.
func (m *memoryManager) GetPortStatus(_ context.Context, port string) (*switchwire.PortStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.lookup(port)
	if err != nil {
		return nil, err
	}
	return copyStatus(st), nil
}

// ListPorts returns a copy of every port's state in config order.
func (m *memoryManager) ListPorts(_ context.Context) ([]*switchwire.PortStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*switchwire.PortStatus, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, copyStatus(m.ports[name]))
	}
	return out, nil
}

// EnablePort marks the port enabled with its link up.
func (m *memoryManager) EnablePort(_ context.Context, port string) error {
	return m.setEnabled(port, true)
}

// DisablePort marks the port disabled with its link down.
func (m *memoryManager) DisablePort(_ context.Context, port string) error {
	return m.setEnabled(port, false)
}

// setEnabled sets the port's Enabled and LinkUp together.
func (m *memoryManager) setEnabled(port string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.lookup(port)
	if err != nil {
		return err
	}
	st.Enabled = enabled
	st.LinkUp = enabled
	return nil
}

// Close releases nothing: the memory vendor holds no connections.
func (m *memoryManager) Close() error {
	return nil
}
