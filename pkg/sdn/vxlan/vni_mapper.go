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

package vxlan

import (
	"sync"
)

// VNIMapper handles bidirectional VNI to VLAN mapping.
// It provides thread-safe operations for managing the mapping between
// VLAN IDs and VXLAN Network Identifiers.
//
// The default mapping formula is: VNI = BaseVNI + VLAN_ID
// For example, with BaseVNI=1000000 and VLAN=100, VNI=1000100
type VNIMapper struct {
	config VNIMappingConfig

	// vlanToVNI maps VLAN IDs to VNIs
	vlanToVNI map[uint16]VNI

	// vniToVLAN maps VNIs to VLAN IDs
	vniToVLAN map[VNI]uint16

	mu sync.RWMutex
}

// NewVNIMapper creates a new VNI mapper with the given configuration.
func NewVNIMapper(config VNIMappingConfig) *VNIMapper {
	if config.BaseVNI == 0 {
		config.BaseVNI = DefaultBaseVNI
	}
	if config.MaxVLAN == 0 {
		config.MaxVLAN = 4094
	}

	return &VNIMapper{
		config:    config,
		vlanToVNI: make(map[uint16]VNI),
		vniToVLAN: make(map[VNI]uint16),
	}
}

// VLANToVNI returns the VNI for the given VLAN ID.
// If no explicit mapping exists, it calculates VNI = BaseVNI + VLAN.
func (m *VNIMapper) VLANToVNI(vlan uint16) (VNI, error) {
	if vlan > m.config.MaxVLAN {
		return 0, ErrVLANOutOfRange
	}

	m.mu.RLock()
	if vni, ok := m.vlanToVNI[vlan]; ok {
		m.mu.RUnlock()
		return vni, nil
	}
	m.mu.RUnlock()

	// Calculate default mapping
	vni := VNI(uint32(m.config.BaseVNI) + uint32(vlan))
	if !vni.Valid() {
		return 0, ErrVNIOutOfRange
	}

	return vni, nil
}

// VNIToVLAN returns the VLAN ID for the given VNI.
// If no explicit mapping exists, it calculates VLAN = VNI - BaseVNI.
func (m *VNIMapper) VNIToVLAN(vni VNI) (uint16, error) {
	if !vni.Valid() {
		return 0, ErrVNIOutOfRange
	}

	m.mu.RLock()
	if vlan, ok := m.vniToVLAN[vni]; ok {
		m.mu.RUnlock()
		return vlan, nil
	}
	m.mu.RUnlock()

	// Calculate reverse mapping
	if vni < m.config.BaseVNI {
		return 0, ErrMappingNotFound
	}

	vlan := uint32(vni) - uint32(m.config.BaseVNI)
	if vlan > uint32(m.config.MaxVLAN) {
		return 0, ErrVLANOutOfRange
	}

	return uint16(vlan), nil
}

// RegisterMapping registers an explicit VLAN to VNI mapping.
// This overrides the default calculation for this VLAN.
func (m *VNIMapper) RegisterMapping(vlan uint16, vni VNI) error {
	if vlan > m.config.MaxVLAN {
		return ErrVLANOutOfRange
	}
	if !vni.Valid() {
		return ErrVNIOutOfRange
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if VNI is already mapped to a different VLAN
	if existingVLAN, ok := m.vniToVLAN[vni]; ok && existingVLAN != vlan {
		return ErrVNIInUse
	}

	m.vlanToVNI[vlan] = vni
	m.vniToVLAN[vni] = vlan

	return nil
}

// UnregisterMapping removes the explicit mapping for a VLAN.
// After unregistration, the default calculation will be used.
func (m *VNIMapper) UnregisterMapping(vlan uint16) error {
	if vlan > m.config.MaxVLAN {
		return ErrVLANOutOfRange
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	vni, ok := m.vlanToVNI[vlan]
	if !ok {
		return ErrMappingNotFound
	}

	delete(m.vlanToVNI, vlan)
	delete(m.vniToVLAN, vni)

	return nil
}

// ListMappings returns a copy of all explicit VLAN to VNI mappings.
func (m *VNIMapper) ListMappings() map[uint16]VNI {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[uint16]VNI, len(m.vlanToVNI))
	for vlan, vni := range m.vlanToVNI {
		result[vlan] = vni
	}

	return result
}

// HasMapping returns true if an explicit mapping exists for the VLAN.
func (m *VNIMapper) HasMapping(vlan uint16) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.vlanToVNI[vlan]
	return ok
}

// HasVNI returns true if an explicit mapping exists for the VNI.
func (m *VNIMapper) HasVNI(vni VNI) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.vniToVLAN[vni]
	return ok
}

// Config returns a copy of the mapper configuration.
func (m *VNIMapper) Config() VNIMappingConfig {
	return m.config
}

// Count returns the number of explicit mappings.
func (m *VNIMapper) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.vlanToVNI)
}

// Clear removes all explicit mappings.
func (m *VNIMapper) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.vlanToVNI = make(map[uint16]VNI)
	m.vniToVLAN = make(map[VNI]uint16)
}

// ValidateVNIRange checks if a VNI is within the valid range for this mapper.
// The valid range is [BaseVNI, BaseVNI + MaxVLAN].
func (m *VNIMapper) ValidateVNIRange(vni VNI) bool {
	minVNI := m.config.BaseVNI
	maxVNI := VNI(uint32(m.config.BaseVNI) + uint32(m.config.MaxVLAN))

	return vni >= minVNI && vni <= maxVNI && vni.Valid()
}
