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
	vnl "github.com/vishvananda/netlink"
)

// CreateTAP creates a TAP device with the specified configuration
func (m *Manager) CreateTAP(config *TAPConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface already exists
	if _, err := getOps().LinkByName(config.Name); err == nil {
		return ErrAlreadyExists(config.Name)
	}

	// Create TAP interface attributes
	tapAttrs := vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Name: config.Name,
		},
		Mode:       vnl.TUNTAP_MODE_TAP,
		Flags:      vnl.TUNTAP_DEFAULTS,
		Queues:     1,
		Fds:        nil,
		Owner:      config.Owner,
		Group:      config.Group,
		NonPersist: !config.Persist,
	}

	// Enable multi-queue if requested
	if config.MultiQueue {
		tapAttrs.Flags |= vnl.TUNTAP_MULTI_QUEUE_DEFAULTS
		tapAttrs.Queues = 0 // Let kernel decide
	}

	// Create the TAP device
	if err := getOps().LinkAdd(&tapAttrs); err != nil {
		if isPermissionError(err) {
			return ErrPermission("create TAP device", err)
		}
		if isExistsError(err) {
			return ErrAlreadyExists(config.Name)
		}
		return ErrCreateFailed(config.Name, err)
	}

	// Set MTU if specified
	if config.MTU > 0 {
		link, err := getOps().LinkByName(config.Name)
		if err != nil {
			// Clean up the created interface
			_ = m.deleteLinkUnsafe(config.Name)
			return ErrSetupFailed(config.Name, "get link after create", err)
		}

		if err := getOps().LinkSetMTU(link, config.MTU); err != nil {
			// Clean up the created interface
			_ = m.deleteLinkUnsafe(config.Name)
			return ErrSetupFailed(config.Name, "set MTU", err)
		}
	}

	return nil
}

// CreateTAPSimple creates a TAP device with simple parameters
// This is a convenience wrapper around CreateTAP
func (m *Manager) CreateTAPSimple(name string, owner, group uint32) error {
	config := &TAPConfig{
		Name:       name,
		Owner:      owner,
		Group:      group,
		MultiQueue: false,
		Persist:    false,
		MTU:        0, // Use default
	}
	return m.CreateTAP(config)
}

// DeleteTAP deletes a TAP device
func (m *Manager) DeleteTAP(name string) error {
	return m.DeleteLink(name)
}

// GetTAP retrieves information about a TAP device
func (m *Manager) GetTAP(name string) (*TAPInfo, error) {
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
		return nil, ErrSetupFailed(name, "get TAP", err)
	}

	// Verify it's a TAP device
	tuntap, ok := link.(*vnl.Tuntap)
	if !ok {
		return nil, ErrSetupFailed(name, "not a TAP device", nil)
	}

	if tuntap.Mode != vnl.TUNTAP_MODE_TAP {
		return nil, ErrSetupFailed(name, "not a TAP device (is TUN)", nil)
	}

	return tuntapToTAPInfo(tuntap), nil
}

// ListTAPs returns a list of all TAP devices
func (m *Manager) ListTAPs() ([]*TAPInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	links, err := getOps().LinkList()
	if err != nil {
		return nil, ErrSetupFailed("all", "list TAPs", err)
	}

	result := make([]*TAPInfo, 0)
	for _, link := range links {
		if tuntap, ok := link.(*vnl.Tuntap); ok {
			if tuntap.Mode == vnl.TUNTAP_MODE_TAP {
				result = append(result, tuntapToTAPInfo(tuntap))
			}
		}
	}

	return result, nil
}

// SetTAPUp brings a TAP interface up
func (m *Manager) SetTAPUp(name string) error {
	return m.SetLinkUp(name)
}

// SetTAPDown brings a TAP interface down
func (m *Manager) SetTAPDown(name string) error {
	return m.SetLinkDown(name)
}

// tuntapToTAPInfo converts a netlink.Tuntap to TAPInfo
func tuntapToTAPInfo(tuntap *vnl.Tuntap) *TAPInfo {
	linkInfo := linkToInfo(tuntap)

	multiQueue := (tuntap.Flags & vnl.TUNTAP_MULTI_QUEUE) != 0
	persist := !tuntap.NonPersist

	return &TAPInfo{
		LinkInfo:   *linkInfo,
		Owner:      tuntap.Owner,
		Group:      tuntap.Group,
		MultiQueue: multiQueue,
		Persist:    persist,
	}
}

// deleteLinkUnsafe deletes a link without acquiring the mutex
// This is used internally for cleanup operations
func (m *Manager) deleteLinkUnsafe(name string) error {
	link, err := getOps().LinkByName(name)
	if err != nil {
		return err
	}
	return getOps().LinkDel(link)
}
