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

package vpn

import "time"

const (
	entityTypePeer          = "VPNPeer"
	entityTypePosturePolicy = "VPNPosturePolicy"
)

// Peer is a device enrolled as a VPN peer of a tenant. The gateway admits
// only enrolled peers (docs/vpn/engineering.md §3, step 0).
type Peer struct {
	ID       uint64 `json:"id"`
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	// Zones narrows the zones the peer may request below the gateway's
	// allow-to set. Empty means every allow-to zone.
	Zones      []string  `json:"zones,omitempty"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// EntityID implements entities.KeyValueEntity.
func (p *Peer) EntityID() uint64 { return p.ID }

// SetEntityID implements entities.KeyValueEntity.
func (p *Peer) SetEntityID(id uint64) { p.ID = id }

// key is the peer's natural key.
func (p *Peer) key() string { return p.TenantID + "/" + p.DeviceID }

// PosturePolicy is a tenant's posture policy (Rego, package vpn.posture). A
// gateway evaluates the tenant policy whose name equals its configured
// posture-policy.
type PosturePolicy struct {
	ID        uint64    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Module    string    `json:"module"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID implements entities.KeyValueEntity.
func (p *PosturePolicy) EntityID() uint64 { return p.ID }

// SetEntityID implements entities.KeyValueEntity.
func (p *PosturePolicy) SetEntityID(id uint64) { p.ID = id }

// key is the policy's natural key.
func (p *PosturePolicy) key() string { return p.TenantID + "/" + p.Name }

// FNV-1a 64-bit parameters.
const (
	fnvOffset64 uint64 = 14695981039346656037
	fnvPrime64  uint64 = 1099511628211
)

// recordID derives a record ID (FNV-1a) from an entity kind and its natural
// key, so a record is found by key without a secondary index. The parts are
// separated by a zero byte, which no identifier contains. ID 0 means "assign
// one" to the DAO, so it is never returned.
func recordID(kind string, parts ...string) uint64 {
	h := fnvOffset64
	mix := func(s string) {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= fnvPrime64
		}
	}
	mix(kind)
	for _, p := range parts {
		mix("\x00")
		mix(p)
	}
	if h == 0 {
		return 1
	}
	return h
}
