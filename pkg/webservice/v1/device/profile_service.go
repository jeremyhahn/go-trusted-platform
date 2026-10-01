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

package device

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

var (
	ErrProfileServiceNotInitialized = errors.New("profile service not initialized")
	ErrProfileNotFoundBySerial      = errors.New("profile not found for serial")
)

// StaticProfileService provides a simple in-memory profile service for testing.
// In a full deployment this would be replaced with a database-backed implementation.
type StaticProfileService struct {
	mu       sync.RWMutex
	profiles map[string]*ProfileResponse // keyed by serial number
}

// NewStaticProfileService creates a new static profile service.
func NewStaticProfileService() *StaticProfileService {
	return &StaticProfileService{
		profiles: make(map[string]*ProfileResponse),
	}
}

// AddProfile adds a device profile to the service.
func (s *StaticProfileService) AddProfile(serial string, profile *ProfileResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[serial] = profile
}

// GetBySerial returns the profile for a given serial number.
func (s *StaticProfileService) GetBySerial(serial string) (*ProfileResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.profiles[serial]
	if !ok {
		return nil, ErrProfileNotFoundBySerial
	}
	return profile, nil
}

// RemoveProfile removes a profile by serial number.
func (s *StaticProfileService) RemoveProfile(serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, serial)
}

// DefaultAdmittedProfile returns a default admitted-phase profile for testing.
// This profile configures the device for admitted VLAN 200 with DHCP.
func DefaultAdmittedProfile(serial string) *ProfileResponse {
	return &ProfileResponse{
		SerialNumber: serial,
		AdmittedNetwork: NetworkConfig{
			VLAN:    200,
			UseDHCP: true,
			DNS:     []string{"10.99.99.2"},
		},
		ACLs: []ACLConfig{
			{
				Name:     "allow-https",
				Priority: 100,
				Match:    map[string]string{"tcp_dst": "443"},
				Action:   "allow",
			},
			{
				Name:     "allow-dns",
				Priority: 90,
				Match:    map[string]string{"udp_dst": "53"},
				Action:   "allow",
			},
		},
	}
}

// ProfileFromDeviceProfile converts a DeviceProfile to a ProfileResponse.
func ProfileFromDeviceProfile(dp *entities.DeviceProfile, serial string) *ProfileResponse {
	if dp == nil {
		return nil
	}

	resp := &ProfileResponse{
		SerialNumber: serial,
	}

	// Convert the provisioning (enrollment-phase) network config. Its VLAN
	// is the fail-closed revert target for the physical switch move.
	if provNet := dp.GetEnrollmentNetworkConfig(); provNet != nil {
		resp.ProvisioningNetwork = &NetworkConfig{
			VLAN:     provNet.VLAN,
			UseDHCP:  provNet.DHCP,
			StaticIP: provNet.StaticIP,
			Gateway:  provNet.Gateway,
			DNS:      provNet.DNS,
		}
	}

	// Convert the admitted network config
	if trustedNet := dp.GetPostEnrollmentNetworkConfig(); trustedNet != nil {
		resp.AdmittedNetwork = NetworkConfig{
			VLAN:     trustedNet.VLAN,
			UseDHCP:  trustedNet.DHCP,
			StaticIP: trustedNet.StaticIP,
			Gateway:  trustedNet.Gateway,
			DNS:      trustedNet.DNS,
		}

		// Convert ACLs
		for i, acl := range trustedNet.ACLs {
			// Build match map from ACL fields
			match := make(map[string]string)
			if acl.Protocol != "" && acl.Protocol != "any" {
				match["protocol"] = acl.Protocol
			}
			if acl.SrcIP != "" {
				match["src_ip"] = acl.SrcIP
			}
			if acl.DstIP != "" {
				match["dst_ip"] = acl.DstIP
			}
			if acl.SrcPort > 0 {
				match["src_port"] = strconv.Itoa(int(acl.SrcPort))
			}
			if acl.DstPort > 0 {
				match["dst_port"] = strconv.Itoa(int(acl.DstPort))
			}

			resp.ACLs = append(resp.ACLs, ACLConfig{
				Name:     fmt.Sprintf("acl-%d", i),
				Priority: acl.Priority,
				Match:    match,
				Action:   acl.Action,
			})
		}
	}

	return resp
}
