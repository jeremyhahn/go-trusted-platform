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
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// The profile wire shape has ONE mapping in each direction, and every handler
// in this package that accepts a ProfileRequest or emits a ProfileFullResponse
// calls it. Until #378 the template handler carried its own copy that mapped
// four fields of the request and omitted networks, selectors and identity from
// the response, so a network override sent to create-profile was discarded
// with a 2xx while the same body on the CRUD route was honoured. Two callers,
// one function: parity between the routes is structural, not tested.

// profileRequestToEntity maps a ProfileRequest onto a DeviceProfile entity.
// A nil request maps to a nil entity so callers that treat the body as
// optional (template overrides) need no guard of their own. An out-of-
// vocabulary role is an error, never stored as unknown.
func profileRequestToEntity(req *ProfileRequest) (*entities.DeviceProfile, error) {
	if req == nil {
		return nil, nil
	}
	role, err := entities.ParseDeviceRole(req.Role)
	if err != nil {
		return nil, err
	}
	profile := &entities.DeviceProfile{
		ID:         uint64(req.ID),
		Name:       req.Name,
		Model:      req.Model,
		Role:       role,
		EventLog:   req.EventLog,
		EKSerial:   req.EKSerial,
		EKCert:     req.EKCert,
		MACAddress: req.MACAddress,
		Config:     req.Config,
		Assigned:   req.Assigned,
		AssignedAt: req.AssignedAt,
	}

	profile.Zone = req.Zone
	profile.EnrollmentNetwork = req.EnrollmentNetwork
	profile.PostEnrollmentNetwork = req.PostEnrollmentNetwork
	profile.FailureNetwork = req.FailureNetwork
	if len(req.Networks) > 0 {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(req.Networks))
		for name, n := range req.Networks {
			if n != nil {
				profile.Networks[name] = networkPhaseRequestToEntity(n)
			}
		}
	} else {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	}
	if req.PlatformdConfig != nil {
		profile.PlatformdConfig = &entities.PlatformdConfigRef{
			ConfigType: req.PlatformdConfig.ConfigType,
			Reference:  req.PlatformdConfig.Reference,
			ConfigName: req.PlatformdConfig.ConfigName,
			ConfigPath: req.PlatformdConfig.ConfigPath,
			Version:    req.PlatformdConfig.Version,
		}
	}
	profile.MatchRules = matchRulesRequestToEntity(req.MatchRules)

	return profile, nil
}

// networkPhaseRequestToEntity maps one entry of the request's networks map.
func networkPhaseRequestToEntity(req *NetworkPhaseRequest) *entities.NetworkPhaseConfig {
	config := &entities.NetworkPhaseConfig{
		VLAN:       req.VLAN,
		StaticIP:   req.StaticIP,
		Gateway:    req.Gateway,
		DNS:        req.DNS,
		AuthMethod: parseAuthMethod(req.AuthMethod),
		Subnet:     req.Subnet,
		DNSServers: req.DNSServers,
		DHCP:       req.DHCP,
		Zone:       req.Zone,
	}

	if req.DHCPPool != nil {
		config.DHCPPool = &entities.DHCPPoolConfig{
			Network:    req.DHCPPool.Network,
			RangeStart: req.DHCPPool.RangeStart,
			RangeEnd:   req.DHCPPool.RangeEnd,
			LeaseTime:  req.DHCPPool.LeaseTime,
		}
	}

	for _, acl := range req.ACLs {
		config.ACLs = append(config.ACLs, entities.ACLConfig{
			Priority: acl.Priority,
			Protocol: acl.Protocol,
			SrcIP:    acl.SrcIP,
			DstIP:    acl.DstIP,
			SrcPort:  acl.SrcPort,
			DstPort:  acl.DstPort,
			Action:   acl.Action,
		})
	}

	return config
}

// parseAuthMethod resolves the wire spelling of a port authentication method.
// Anything other than 802.1X is "none"; the wire has exactly two values.
func parseAuthMethod(method string) entities.AuthMethod {
	switch strings.ToLower(method) {
	case "802.1x", "8021x":
		return entities.AuthMethod802_1X
	default:
		return entities.AuthMethodNone
	}
}

// profileToResponse maps a DeviceProfile entity onto the full operator wire
// shape, networks and selectors included.
func profileToResponse(p *entities.DeviceProfile) *ProfileFullResponse {
	if p == nil {
		return nil
	}

	resp := &ProfileFullResponse{
		ID:         ID(p.ID),
		Name:       p.Name,
		Model:      p.Model,
		Role:       string(p.Role),
		EventLog:   p.EventLog,
		EKSerial:   p.EKSerial,
		EKCert:     p.EKCert,
		MACAddress: p.MACAddress,
		Config:     p.Config,
		Assigned:   p.Assigned,
		AssignedAt: p.AssignedAt,
	}

	resp.Zone = p.Zone
	resp.EnrollmentNetwork = p.EnrollmentNetwork
	resp.PostEnrollmentNetwork = p.PostEnrollmentNetwork
	resp.FailureNetwork = p.FailureNetwork
	if len(p.Networks) > 0 {
		resp.Networks = make(map[string]*NetworkPhaseResponse, len(p.Networks))
		for name, n := range p.Networks {
			resp.Networks[name] = networkPhaseEntityToResponse(n)
		}
	}
	if p.PlatformdConfig != nil {
		resp.PlatformdConfig = &PlatformdConfigResponse{
			ConfigType: p.PlatformdConfig.ConfigType,
			Reference:  p.PlatformdConfig.Reference,
			ConfigName: p.PlatformdConfig.ConfigName,
			ConfigPath: p.PlatformdConfig.ConfigPath,
			Version:    p.PlatformdConfig.Version,
		}
	}
	resp.MatchRules = matchRulesEntityToResponse(p.MatchRules)
	resp.PCRBaseline = pcrBaselineEntityToResponse(p.PCRBaseline)

	return resp
}

// pcrBaselineEntityToResponse maps the profile's baseline for the read side
// only. There is no request-side counterpart on purpose (see
// ProfileFullResponse.PCRBaseline).
func pcrBaselineEntityToResponse(b *entities.PCRBaseline) *PCRBaselineResponse {
	if b == nil {
		return nil
	}
	values := make(map[string]string, len(b.Values))
	for idx, digest := range b.Values {
		values[strconv.Itoa(idx)] = hex.EncodeToString(digest)
	}
	return &PCRBaselineResponse{
		Values:               values,
		Source:               string(b.Source),
		RecordedAt:           b.RecordedAt,
		RecordedFromDeviceID: ID(b.RecordedFromDeviceID),
	}
}

// networkPhaseEntityToResponse maps one entry of the entity's networks map.
func networkPhaseEntityToResponse(c *entities.NetworkPhaseConfig) *NetworkPhaseResponse {
	if c == nil {
		return nil
	}

	resp := &NetworkPhaseResponse{
		VLAN:       c.VLAN,
		StaticIP:   c.StaticIP,
		Gateway:    c.Gateway,
		DNS:        c.DNS,
		AuthMethod: string(c.AuthMethod),
		Subnet:     c.Subnet,
		DNSServers: c.DNSServers,
		DHCP:       c.DHCP,
		Zone:       c.Zone,
	}

	if c.DHCPPool != nil {
		resp.DHCPPool = &DHCPPoolResponse{
			Network:    c.DHCPPool.Network,
			RangeStart: c.DHCPPool.RangeStart,
			RangeEnd:   c.DHCPPool.RangeEnd,
			LeaseTime:  c.DHCPPool.LeaseTime,
		}
	}

	for _, acl := range c.ACLs {
		resp.ACLs = append(resp.ACLs, ACLResponse{
			Priority: acl.Priority,
			Protocol: acl.Protocol,
			SrcIP:    acl.SrcIP,
			DstIP:    acl.DstIP,
			SrcPort:  acl.SrcPort,
			DstPort:  acl.DstPort,
			Action:   acl.Action,
		})
	}

	return resp
}
