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

package entities

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// DeviceTemplate is a reusable configuration blueprint for device provisioning.
// Templates contain a full platform configuration that can be copied to create
// DeviceProfiles with device-specific customizations.
//
// The Config field stores the raw YAML bytes of the platform configuration
// (app.App). This avoids import cycles and allows the entity to be stored
// without depending on the app package. The service layer is responsible
// for marshaling and unmarshaling the config.
type DeviceTemplate struct {
	ID          uint64     `yaml:"id" json:"id"`
	TenantID    string     `yaml:"tenant_id" json:"tenant_id"`
	Name        string     `yaml:"name" json:"name"`
	Description string     `yaml:"description" json:"description"`
	Role        DeviceRole `yaml:"role" json:"role"`

	// Config stores the full platform configuration as raw YAML bytes.
	// The service layer marshals/unmarshals this to/from *app.App.
	Config []byte `yaml:"config,omitempty" json:"config,omitempty"`

	// MatchRules for auto-assignment when creating profiles from this template.
	MatchRules *ProfileMatchRules `yaml:"match-rules,omitempty" json:"match_rules,omitempty"`

	// BMC is the default baseboard management controller configuration for bare metal provisioning.
	// Profiles created from this template inherit this BMC config unless overridden.
	BMC *BMCConfig `yaml:"bmc,omitempty" json:"bmc,omitempty"`

	CreatedAt time.Time `yaml:"created_at" json:"created_at"`
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	entities.KeyValueEntity `yaml:"-" json:"-"`
}

// EntityID returns the template's unique identifier.
func (t *DeviceTemplate) EntityID() uint64 {
	return t.ID
}

// SetEntityID sets the template's unique identifier.
func (t *DeviceTemplate) SetEntityID(id uint64) {
	t.ID = id
}
