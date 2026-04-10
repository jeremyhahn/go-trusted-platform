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

package overlay

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// StateManager manages overlay network state storage and retrieval.
type StateManager struct {
	// VTEPs stores VTEP information by IP address.
	vteps map[netip.Addr]*VTEPInfo

	// Tunnels stores tunnel information by key (localVTEP:remoteVTEP:VNI).
	tunnels map[string]*TunnelInfo

	// VNIs stores VNI configuration by VNI number.
	vnis map[uint32]*VNIInfo

	// RemoteMACs stores remote MAC entries by key (VNI:MAC).
	remoteMACs map[string]*RemoteMACEntry

	// macByVNI provides VNI-based MAC lookup.
	macByVNI map[uint32]map[string]*RemoteMACEntry

	// Synchronization
	mu sync.RWMutex
}

// NewStateManager creates a new state manager.
func NewStateManager() *StateManager {
	return &StateManager{
		vteps:      make(map[netip.Addr]*VTEPInfo),
		tunnels:    make(map[string]*TunnelInfo),
		vnis:       make(map[uint32]*VNIInfo),
		remoteMACs: make(map[string]*RemoteMACEntry),
		macByVNI:   make(map[uint32]map[string]*RemoteMACEntry),
	}
}

// AddVTEP adds a VTEP to the state.
func (s *StateManager) AddVTEP(ctx context.Context, vtep *VTEPInfo) error {
	if vtep == nil {
		return ErrVTEPNotFound
	}
	if !vtep.IP.IsValid() {
		return &ErrInvalidIP{IP: vtep.IP, Reason: "VTEP IP is invalid"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vteps[vtep.IP]; exists {
		return ErrVTEPAlreadyExists
	}

	// Make a copy to store
	vtepCopy := *vtep
	s.vteps[vtep.IP] = &vtepCopy
	return nil
}

// GetVTEP retrieves a VTEP by IP address.
func (s *StateManager) GetVTEP(ctx context.Context, ip netip.Addr) (*VTEPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vtep, exists := s.vteps[ip]
	if !exists {
		return nil, ErrVTEPNotFound
	}

	// Return a copy
	vtepCopy := *vtep
	return &vtepCopy, nil
}

// UpdateVTEP updates an existing VTEP.
func (s *StateManager) UpdateVTEP(ctx context.Context, vtep *VTEPInfo) error {
	if vtep == nil {
		return ErrVTEPNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vteps[vtep.IP]; !exists {
		return ErrVTEPNotFound
	}

	vtepCopy := *vtep
	s.vteps[vtep.IP] = &vtepCopy
	return nil
}

// RemoveVTEP removes a VTEP from state.
func (s *StateManager) RemoveVTEP(ctx context.Context, ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vteps[ip]; !exists {
		return ErrVTEPNotFound
	}

	delete(s.vteps, ip)
	return nil
}

// ListVTEPs returns all VTEPs.
func (s *StateManager) ListVTEPs(ctx context.Context) ([]VTEPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]VTEPInfo, 0, len(s.vteps))
	for _, vtep := range s.vteps {
		result = append(result, *vtep)
	}
	return result, nil
}

// AddTunnel adds a tunnel to state.
func (s *StateManager) AddTunnel(ctx context.Context, tunnel *TunnelInfo) error {
	if tunnel == nil {
		return ErrTunnelNotFound
	}

	key := tunnelKey(tunnel.LocalVTEP, tunnel.RemoteVTEP, tunnel.VNI)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tunnels[key]; exists {
		return ErrTunnelAlreadyExists
	}

	tunnelCopy := *tunnel
	s.tunnels[key] = &tunnelCopy
	return nil
}

// GetTunnel retrieves a tunnel by key.
func (s *StateManager) GetTunnel(ctx context.Context, localVTEP, remoteVTEP netip.Addr, vni uint32) (*TunnelInfo, error) {
	key := tunnelKey(localVTEP, remoteVTEP, vni)

	s.mu.RLock()
	defer s.mu.RUnlock()

	tunnel, exists := s.tunnels[key]
	if !exists {
		return nil, ErrTunnelNotFound
	}

	tunnelCopy := *tunnel
	return &tunnelCopy, nil
}

// UpdateTunnel updates an existing tunnel.
func (s *StateManager) UpdateTunnel(ctx context.Context, tunnel *TunnelInfo) error {
	if tunnel == nil {
		return ErrTunnelNotFound
	}

	key := tunnelKey(tunnel.LocalVTEP, tunnel.RemoteVTEP, tunnel.VNI)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tunnels[key]; !exists {
		return ErrTunnelNotFound
	}

	tunnelCopy := *tunnel
	s.tunnels[key] = &tunnelCopy
	return nil
}

// RemoveTunnel removes a tunnel from state.
func (s *StateManager) RemoveTunnel(ctx context.Context, localVTEP, remoteVTEP netip.Addr, vni uint32) error {
	key := tunnelKey(localVTEP, remoteVTEP, vni)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tunnels[key]; !exists {
		return ErrTunnelNotFound
	}

	delete(s.tunnels, key)
	return nil
}

// ListTunnels returns all tunnels.
func (s *StateManager) ListTunnels(ctx context.Context) ([]TunnelInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]TunnelInfo, 0, len(s.tunnels))
	for _, tunnel := range s.tunnels {
		result = append(result, *tunnel)
	}
	return result, nil
}

// ListTunnelsByVNI returns all tunnels for a specific VNI.
func (s *StateManager) ListTunnelsByVNI(ctx context.Context, vni uint32) ([]TunnelInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]TunnelInfo, 0)
	for _, tunnel := range s.tunnels {
		if tunnel.VNI == vni {
			result = append(result, *tunnel)
		}
	}
	return result, nil
}

// AddVNI adds a VNI to state.
func (s *StateManager) AddVNI(ctx context.Context, vni *VNIInfo) error {
	if vni == nil {
		return ErrVNINotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vnis[vni.VNI]; exists {
		return ErrVNIAlreadyExists
	}

	vniCopy := *vni
	s.vnis[vni.VNI] = &vniCopy

	// Initialize MAC map for this VNI
	s.macByVNI[vni.VNI] = make(map[string]*RemoteMACEntry)

	return nil
}

// GetVNI retrieves a VNI by number.
func (s *StateManager) GetVNI(ctx context.Context, vni uint32) (*VNIInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, exists := s.vnis[vni]
	if !exists {
		return nil, ErrVNINotFound
	}

	vniCopy := *info
	return &vniCopy, nil
}

// UpdateVNI updates an existing VNI.
func (s *StateManager) UpdateVNI(ctx context.Context, vni *VNIInfo) error {
	if vni == nil {
		return ErrVNINotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vnis[vni.VNI]; !exists {
		return ErrVNINotFound
	}

	vniCopy := *vni
	s.vnis[vni.VNI] = &vniCopy
	return nil
}

// RemoveVNI removes a VNI from state.
func (s *StateManager) RemoveVNI(ctx context.Context, vni uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.vnis[vni]; !exists {
		return ErrVNINotFound
	}

	delete(s.vnis, vni)

	// Also remove all MACs for this VNI
	if macs, exists := s.macByVNI[vni]; exists {
		for key := range macs {
			delete(s.remoteMACs, key)
		}
		delete(s.macByVNI, vni)
	}

	return nil
}

// ListVNIs returns all VNIs.
func (s *StateManager) ListVNIs(ctx context.Context) ([]VNIInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]VNIInfo, 0, len(s.vnis))
	for _, vni := range s.vnis {
		result = append(result, *vni)
	}
	return result, nil
}

// AddRemoteMAC adds a remote MAC entry.
func (s *StateManager) AddRemoteMAC(ctx context.Context, entry *RemoteMACEntry) error {
	if entry == nil {
		return ErrMACNotFound
	}
	if entry.MAC == nil {
		return &ErrInvalidMAC{Reason: "MAC address is nil"}
	}

	key := formatMACKey(entry.VNI, entry.MAC)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.remoteMACs[key]; exists {
		return ErrMACAlreadyExists
	}

	entryCopy := &RemoteMACEntry{
		MAC:        make(net.HardwareAddr, len(entry.MAC)),
		VNI:        entry.VNI,
		RemoteVTEP: entry.RemoteVTEP,
		IP:         entry.IP,
		LearnedAt:  entry.LearnedAt,
		ExpiresAt:  entry.ExpiresAt,
		Source:     entry.Source,
	}
	copy(entryCopy.MAC, entry.MAC)

	s.remoteMACs[key] = entryCopy

	// Add to VNI index
	if _, exists := s.macByVNI[entry.VNI]; !exists {
		s.macByVNI[entry.VNI] = make(map[string]*RemoteMACEntry)
	}
	s.macByVNI[entry.VNI][key] = entryCopy

	return nil
}

// GetRemoteMAC retrieves a remote MAC entry.
func (s *StateManager) GetRemoteMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) (*RemoteMACEntry, error) {
	key := formatMACKey(vni, mac)

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.remoteMACs[key]
	if !exists {
		return nil, ErrMACNotFound
	}

	// Return a copy
	entryCopy := &RemoteMACEntry{
		MAC:        make(net.HardwareAddr, len(entry.MAC)),
		VNI:        entry.VNI,
		RemoteVTEP: entry.RemoteVTEP,
		IP:         entry.IP,
		LearnedAt:  entry.LearnedAt,
		ExpiresAt:  entry.ExpiresAt,
		Source:     entry.Source,
	}
	copy(entryCopy.MAC, entry.MAC)
	return entryCopy, nil
}

// UpdateRemoteMAC updates an existing remote MAC entry.
func (s *StateManager) UpdateRemoteMAC(ctx context.Context, entry *RemoteMACEntry) error {
	if entry == nil {
		return ErrMACNotFound
	}

	key := formatMACKey(entry.VNI, entry.MAC)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.remoteMACs[key]; !exists {
		return ErrMACNotFound
	}

	entryCopy := &RemoteMACEntry{
		MAC:        make(net.HardwareAddr, len(entry.MAC)),
		VNI:        entry.VNI,
		RemoteVTEP: entry.RemoteVTEP,
		IP:         entry.IP,
		LearnedAt:  entry.LearnedAt,
		ExpiresAt:  entry.ExpiresAt,
		Source:     entry.Source,
	}
	copy(entryCopy.MAC, entry.MAC)

	s.remoteMACs[key] = entryCopy

	if _, exists := s.macByVNI[entry.VNI]; exists {
		s.macByVNI[entry.VNI][key] = entryCopy
	}

	return nil
}

// RemoveRemoteMAC removes a remote MAC entry.
func (s *StateManager) RemoveRemoteMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) error {
	key := formatMACKey(vni, mac)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.remoteMACs[key]; !exists {
		return ErrMACNotFound
	}

	delete(s.remoteMACs, key)

	if macs, exists := s.macByVNI[vni]; exists {
		delete(macs, key)
	}

	return nil
}

// ListRemoteMACsByVNI returns all remote MACs for a specific VNI.
func (s *StateManager) ListRemoteMACsByVNI(ctx context.Context, vni uint32) ([]RemoteMACEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	macs, exists := s.macByVNI[vni]
	if !exists {
		return []RemoteMACEntry{}, nil
	}

	result := make([]RemoteMACEntry, 0, len(macs))
	for _, entry := range macs {
		entryCopy := RemoteMACEntry{
			MAC:        make(net.HardwareAddr, len(entry.MAC)),
			VNI:        entry.VNI,
			RemoteVTEP: entry.RemoteVTEP,
			IP:         entry.IP,
			LearnedAt:  entry.LearnedAt,
			ExpiresAt:  entry.ExpiresAt,
			Source:     entry.Source,
		}
		copy(entryCopy.MAC, entry.MAC)
		result = append(result, entryCopy)
	}
	return result, nil
}

// ListAllRemoteMACs returns all remote MACs.
func (s *StateManager) ListAllRemoteMACs(ctx context.Context) ([]RemoteMACEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]RemoteMACEntry, 0, len(s.remoteMACs))
	for _, entry := range s.remoteMACs {
		entryCopy := RemoteMACEntry{
			MAC:        make(net.HardwareAddr, len(entry.MAC)),
			VNI:        entry.VNI,
			RemoteVTEP: entry.RemoteVTEP,
			IP:         entry.IP,
			LearnedAt:  entry.LearnedAt,
			ExpiresAt:  entry.ExpiresAt,
			Source:     entry.Source,
		}
		copy(entryCopy.MAC, entry.MAC)
		result = append(result, entryCopy)
	}
	return result, nil
}

// ExpireMACs removes expired MAC entries and returns them.
func (s *StateManager) ExpireMACs(ctx context.Context) ([]RemoteMACEntry, error) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []RemoteMACEntry

	for key, entry := range s.remoteMACs {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			entryCopy := RemoteMACEntry{
				MAC:        make(net.HardwareAddr, len(entry.MAC)),
				VNI:        entry.VNI,
				RemoteVTEP: entry.RemoteVTEP,
				IP:         entry.IP,
				LearnedAt:  entry.LearnedAt,
				ExpiresAt:  entry.ExpiresAt,
				Source:     entry.Source,
			}
			copy(entryCopy.MAC, entry.MAC)
			expired = append(expired, entryCopy)

			delete(s.remoteMACs, key)
			if macs, exists := s.macByVNI[entry.VNI]; exists {
				delete(macs, key)
			}
		}
	}

	return expired, nil
}

// GetStats returns statistics about the state.
func (s *StateManager) GetStats(ctx context.Context) *StateStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &StateStats{
		VTEPCount:      len(s.vteps),
		TunnelCount:    len(s.tunnels),
		VNICount:       len(s.vnis),
		RemoteMACCount: len(s.remoteMACs),
	}
}

// Clear removes all state.
func (s *StateManager) Clear(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.vteps = make(map[netip.Addr]*VTEPInfo)
	s.tunnels = make(map[string]*TunnelInfo)
	s.vnis = make(map[uint32]*VNIInfo)
	s.remoteMACs = make(map[string]*RemoteMACEntry)
	s.macByVNI = make(map[uint32]map[string]*RemoteMACEntry)

	return nil
}

// StateStats contains statistics about the overlay state.
type StateStats struct {
	VTEPCount      int
	TunnelCount    int
	VNICount       int
	RemoteMACCount int
}

// tunnelKey creates a unique key for a tunnel.
func tunnelKey(localVTEP, remoteVTEP netip.Addr, vni uint32) string {
	// Build key efficiently
	buf := make([]byte, 0, 64)
	buf = append(buf, localVTEP.String()...)
	buf = append(buf, ':')
	buf = append(buf, remoteVTEP.String()...)
	buf = append(buf, ':')
	buf = append(buf, formatUint32(vni)...)
	return string(buf)
}
