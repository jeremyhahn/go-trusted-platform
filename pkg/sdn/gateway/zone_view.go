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

package gateway

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ZonePathSpec is the JSON form of a zone.ZonePath.
type ZonePathSpec struct {
	Zone     string   `json:"zone"`
	Services []string `json:"services,omitempty"`
}

// PrivilegedAccessSpec is the JSON form of a zone.PrivilegedAccess.
type PrivilegedAccessSpec struct {
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

// ZoneSpec is the JSON request form of a zone shared by the REST, web and
// MCP transports: every field of zone.ZoneConfig except omit (deleting a
// built-in omits it).
type ZoneSpec struct {
	Name             string                `json:"name,omitempty"`
	Offset           uint8                 `json:"offset,omitempty"`
	PortClasses      []string              `json:"port_classes,omitempty"`
	InternetIngress  bool                  `json:"internet_ingress,omitempty"`
	IsolateFrom      []string              `json:"isolate_from,omitempty"`
	AllowTo          []ZonePathSpec        `json:"allow_to,omitempty"`
	Services         []string              `json:"services,omitempty"`
	Isolate          bool                  `json:"isolate,omitempty"`
	OOB              bool                  `json:"oob,omitempty"`
	LifecycleRole    string                `json:"lifecycle_role,omitempty"`
	PrivilegedAccess *PrivilegedAccessSpec `json:"privileged_access,omitempty"`
}

// ZoneView is the JSON response form of a zone record: the resolved zone,
// its derived numbering (absent without an environment), whether the change
// needs a daemon restart, and its timestamps.
type ZoneView struct {
	ZoneSpec
	Numbering       *ZoneNumberingView `json:"numbering,omitempty"`
	RestartRequired bool               `json:"restart_required,omitempty"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// Config converts the spec to a zone.ZoneConfig. A non-empty name (an
// update's path parameter) replaces the spec's own name.
func (s ZoneSpec) Config(name string) zone.ZoneConfig {
	if name == "" {
		name = s.Name
	}
	cfg := zone.ZoneConfig{
		Name:            zone.Zone(name),
		Offset:          zone.Offset(s.Offset),
		InternetIngress: s.InternetIngress,
		Services:        s.Services,
		Isolate:         s.Isolate,
		OOB:             s.OOB,
		LifecycleRole:   zone.LifecycleRole(s.LifecycleRole),
	}
	for _, c := range s.PortClasses {
		cfg.PortClasses = append(cfg.PortClasses, zone.PortClass(c))
	}
	for _, z := range s.IsolateFrom {
		cfg.IsolateFrom = append(cfg.IsolateFrom, zone.Zone(z))
	}
	for _, p := range s.AllowTo {
		cfg.AllowTo = append(cfg.AllowTo, zone.ZonePath{Zone: zone.Zone(p.Zone), Services: p.Services})
	}
	if s.PrivilegedAccess != nil {
		cfg.PrivilegedAccess = &zone.PrivilegedAccess{
			Reason:     s.PrivilegedAccess.Reason,
			ApprovedBy: s.PrivilegedAccess.ApprovedBy,
		}
	}
	return cfg
}

// SpecFromConfig converts a zone.ZoneConfig to its JSON form.
func SpecFromConfig(cfg zone.ZoneConfig) ZoneSpec {
	s := ZoneSpec{
		Name:            string(cfg.Name),
		Offset:          uint8(cfg.Offset),
		InternetIngress: cfg.InternetIngress,
		Services:        cfg.Services,
		Isolate:         cfg.Isolate,
		OOB:             cfg.OOB,
		LifecycleRole:   string(cfg.LifecycleRole),
	}
	for _, c := range cfg.PortClasses {
		s.PortClasses = append(s.PortClasses, string(c))
	}
	for _, z := range cfg.IsolateFrom {
		s.IsolateFrom = append(s.IsolateFrom, string(z))
	}
	for _, p := range cfg.AllowTo {
		s.AllowTo = append(s.AllowTo, ZonePathSpec{Zone: string(p.Zone), Services: p.Services})
	}
	if cfg.PrivilegedAccess != nil {
		s.PrivilegedAccess = &PrivilegedAccessSpec{
			Reason:     cfg.PrivilegedAccess.Reason,
			ApprovedBy: cfg.PrivilegedAccess.ApprovedBy,
		}
	}
	return s
}

// ZoneNumberingView is the transport form of a zone's derived numbering:
// the VLAN, and the subnets and gateway as strings (empty when absent).
type ZoneNumberingView struct {
	VLAN    uint16 `json:"vlan"`
	Subnet4 string `json:"subnet4"`
	Subnet6 string `json:"subnet6,omitempty"`
	Gateway string `json:"gateway"`
}

// NumberingView returns the record's numbering in transport form, or nil
// when the record carries none (the service has no environment).
func (r *ZoneRecord) NumberingView() *ZoneNumberingView {
	if r == nil || r.Numbering == nil {
		return nil
	}
	v := &ZoneNumberingView{VLAN: r.Numbering.VLAN}
	if r.Numbering.Subnet4.IsValid() {
		v.Subnet4 = r.Numbering.Subnet4.String()
	}
	if r.Numbering.Subnet6.IsValid() {
		v.Subnet6 = r.Numbering.Subnet6.String()
	}
	if r.Numbering.Gateway.IsValid() {
		v.Gateway = r.Numbering.Gateway.String()
	}
	return v
}

// View returns the record's JSON response form.
func (r *ZoneRecord) View(restartRequired bool) ZoneView {
	return ZoneView{
		ZoneSpec:        SpecFromConfig(r.Config),
		Numbering:       r.NumberingView(),
		RestartRequired: restartRequired,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
