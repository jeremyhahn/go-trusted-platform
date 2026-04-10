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

package netlink

import (
	"net"
	"sync"
	"syscall"

	vnl "github.com/vishvananda/netlink"
)

// Manager provides thread-safe network link management operations
type Manager struct {
	mu sync.RWMutex
}

// NewManager creates a new network link manager
func NewManager() *Manager {
	return &Manager{}
}

// GetLink retrieves information about a network link by name
func (m *Manager) GetLink(name string) (*LinkInfo, error) {
	if len(name) == 0 {
		return nil, ErrInvalidName(name)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	link, err := getOps().LinkByName(name)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrNotFound(name)
		}
		return nil, ErrSetupFailed(name, "get link", err)
	}

	return linkToInfo(link), nil
}

// SetLinkUp brings a network interface up
func (m *Manager) SetLinkUp(name string) error {
	if len(name) == 0 {
		return ErrInvalidName(name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := getOps().LinkByName(name)
	if err != nil {
		if isNotFoundError(err) {
			return ErrNotFound(name)
		}
		return ErrSetupFailed(name, "get link for up", err)
	}

	if err := getOps().LinkSetUp(link); err != nil {
		if isPermissionError(err) {
			return ErrPermission("set link up", err)
		}
		return ErrStateFailed(name, "up", err)
	}

	return nil
}

// SetLinkDown brings a network interface down
func (m *Manager) SetLinkDown(name string) error {
	if len(name) == 0 {
		return ErrInvalidName(name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := getOps().LinkByName(name)
	if err != nil {
		if isNotFoundError(err) {
			return ErrNotFound(name)
		}
		return ErrSetupFailed(name, "get link for down", err)
	}

	if err := getOps().LinkSetDown(link); err != nil {
		if isPermissionError(err) {
			return ErrPermission("set link down", err)
		}
		return ErrStateFailed(name, "down", err)
	}

	return nil
}

// SetLinkMTU sets the MTU of a network interface
func (m *Manager) SetLinkMTU(name string, mtu int) error {
	if len(name) == 0 {
		return ErrInvalidName(name)
	}

	if mtu < 68 || mtu > 65536 {
		return ErrSetupFailed(name, "invalid MTU", nil)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := getOps().LinkByName(name)
	if err != nil {
		if isNotFoundError(err) {
			return ErrNotFound(name)
		}
		return ErrSetupFailed(name, "get link for MTU", err)
	}

	if err := getOps().LinkSetMTU(link, mtu); err != nil {
		if isPermissionError(err) {
			return ErrPermission("set link MTU", err)
		}
		return ErrSetupFailed(name, "set MTU", err)
	}

	return nil
}

// DeleteLink deletes a network interface
func (m *Manager) DeleteLink(name string) error {
	if len(name) == 0 {
		return ErrInvalidName(name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := getOps().LinkByName(name)
	if err != nil {
		if isNotFoundError(err) {
			return ErrNotFound(name)
		}
		return ErrDeleteFailed(name, err)
	}

	if err := getOps().LinkDel(link); err != nil {
		if isPermissionError(err) {
			return ErrPermission("delete link", err)
		}
		return ErrDeleteFailed(name, err)
	}

	return nil
}

// ListLinks returns a list of all network links
func (m *Manager) ListLinks() ([]*LinkInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	links, err := getOps().LinkList()
	if err != nil {
		return nil, ErrSetupFailed("all", "list links", err)
	}

	result := make([]*LinkInfo, 0, len(links))
	for _, link := range links {
		result = append(result, linkToInfo(link))
	}

	return result, nil
}

// linkToInfo converts a netlink.Link to LinkInfo
func linkToInfo(link vnl.Link) *LinkInfo {
	attrs := link.Attrs()

	var hwAddr string
	if attrs.HardwareAddr != nil {
		hwAddr = attrs.HardwareAddr.String()
	}

	var operState LinkState
	switch attrs.OperState {
	case vnl.OperUp:
		operState = LinkStateUp
	case vnl.OperDown:
		operState = LinkStateDown
	default:
		operState = LinkStateUnknown
	}

	return &LinkInfo{
		Index:        attrs.Index,
		Name:         attrs.Name,
		Type:         link.Type(),
		Flags:        uint32(attrs.Flags),
		MTU:          attrs.MTU,
		HardwareAddr: hwAddr,
		OperState:    operState,
		Master:       attrs.MasterIndex,
	}
}

// isNotFoundError checks if the error is a "not found" error
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common netlink "not found" errors
	return err.Error() == "Link not found" ||
		err == syscall.ENODEV ||
		err == syscall.ENXIO
}

// isPermissionError checks if the error is a permission error
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	return err == syscall.EPERM || err == syscall.EACCES
}

// isExistsError checks if the error indicates the resource already exists
func isExistsError(err error) bool {
	if err == nil {
		return false
	}
	return err == syscall.EEXIST
}

// IsFlagSet checks if a specific flag is set on the interface
func IsFlagSet(flags uint32, flag net.Flags) bool {
	return flags&uint32(flag) != 0
}

// IsUp checks if the interface is administratively up
func IsUp(flags uint32) bool {
	return IsFlagSet(flags, net.FlagUp)
}

// IsRunning checks if the interface is running (link detected)
func IsRunning(flags uint32) bool {
	return IsFlagSet(flags, net.FlagRunning)
}
