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

import "time"

// TemplateRequest represents the request body for template creation/update.
//
// Two shapes are accepted: flat fields (legacy) or a `{template: {...}}`
// envelope (matches the JS SDK's `createTemplate({template: {...}})`).
type TemplateRequest struct {
	ID          uint64                 `json:"id,omitempty"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Role        string                 `json:"role,omitempty"`
	Config      []byte                 `json:"config,omitempty"`
	MatchRules  *MatchRulesRequest     `json:"match_rules,omitempty"`
	Template    *TemplateRequestNested `json:"template,omitempty"`
}

// TemplateRequestNested mirrors TemplateRequest's flat fields for the
// `{template: {...}}` envelope shape produced by the JS SDK.
type TemplateRequestNested struct {
	ID          uint64             `json:"id,omitempty"`
	TenantID    string             `json:"tenant_id,omitempty"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Role        string             `json:"role,omitempty"`
	Config      []byte             `json:"config,omitempty"`
	MatchRules  *MatchRulesRequest `json:"match_rules,omitempty"`
}

// TemplateResponse represents a device template in API responses.
//
// IDs are emitted as JSON strings (`,string`) because the platform
// mints them above 2^53; encoding as plain numbers would truncate in
// JS clients and break detail navigation.
type TemplateResponse struct {
	ID          uint64              `json:"id,string"`
	TenantID    string              `json:"tenant_id,omitempty"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Role        string              `json:"role,omitempty"`
	Config      []byte              `json:"config,omitempty"`
	MatchRules  *MatchRulesResponse `json:"match_rules,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// TemplateListResponse represents a paginated list of templates.
type TemplateListResponse struct {
	Templates  []TemplateResponse `json:"templates"`
	Pagination PaginationResponse `json:"pagination"`
}

// CreateProfileFromTemplateRequest represents a request to create a profile from a template.
type CreateProfileFromTemplateRequest struct {
	TemplateID uint64          `json:"template_id"`
	Overrides  *ProfileRequest `json:"overrides,omitempty"`
}

// FindConfigForDeviceRequest represents a request to find config for a device.
type FindConfigForDeviceRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
}

// AssignProfileToDeviceRequest represents a request to assign a profile to a device.
type AssignProfileToDeviceRequest struct {
	ProfileID  uint64 `json:"profile_id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
}
