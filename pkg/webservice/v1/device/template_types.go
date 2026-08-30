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
	"encoding/json"
	"time"
)

// TemplateRequest represents the request body for template creation/update.
//
// Three shapes are accepted on create: flat fields (legacy), a
// `{template: {...}}` envelope (matches the JS SDK's
// `createTemplate({template: {...}})`), and the bootstrap seeder's
// `{role, template}` where `template` is the platform configuration document
// itself. The shapes are told apart without sniffing the document: a
// top-level `role` alongside `template` is the seeder shape; `template`
// without a top-level `role` is the envelope. Template is kept raw so the
// handler can decode it either way.
type TemplateRequest struct {
	ID          uint64             `json:"id,omitempty"`
	TenantID    string             `json:"tenant_id,omitempty"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Role        string             `json:"role,omitempty"`
	Config      []byte             `json:"config,omitempty"`
	MatchRules  *MatchRulesRequest `json:"match_rules,omitempty"`
	Template    json.RawMessage    `json:"template,omitempty"`
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
// EKCert optionally prestages the device's PEM-encoded TPM Endorsement Key
// certificate on the profile during assignment; the certificate is
// source-agnostic (swtpm-backed vTPM or physical hardware TPM). An empty
// EKCert leaves any previously prestaged certificate untouched.
type AssignProfileToDeviceRequest struct {
	ProfileID  uint64 `json:"profile_id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
}
