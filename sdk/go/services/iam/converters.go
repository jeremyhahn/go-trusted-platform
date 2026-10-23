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

package iam

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// UserFromProto converts a platformv1.IAMUser to a domain User.
func UserFromProto(p *platformv1.IAMUser) *User {
	if p == nil {
		return nil
	}
	u := &User{
		ID:          p.Id,
		TenantID:    p.TenantId,
		Email:       p.Email,
		Name:        p.Name,
		Roles:       p.Roles,
		Groups:      p.Groups,
		Attributes:  p.Attributes,
		MfaVerified: p.MfaVerified,
		CreatedAt:   timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		u.UpdatedAt = &t
	}
	if p.LastAuth != nil {
		t := p.LastAuth.AsTime()
		u.LastAuth = &t
	}
	return u
}

// GroupFromProto converts a platformv1.IAMGroup to a domain Group.
func GroupFromProto(p *platformv1.IAMGroup) *Group {
	if p == nil {
		return nil
	}
	g := &Group{
		ID:          p.Id,
		TenantID:    p.TenantId,
		Name:        p.Name,
		Description: p.Description,
		Members:     p.Members,
		CreatedAt:   timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		g.UpdatedAt = &t
	}
	return g
}

// RoleFromProto converts a platformv1.IAMRole to a domain Role.
func RoleFromProto(p *platformv1.IAMRole) *Role {
	if p == nil {
		return nil
	}
	r := &Role{
		ID:          p.Id,
		TenantID:    p.TenantId,
		Name:        p.Name,
		Description: p.Description,
		Permissions: p.Permissions,
		CreatedAt:   timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		r.UpdatedAt = &t
	}
	return r
}

// PolicyFromProto converts a platformv1.IAMPolicy to a domain Policy.
func PolicyFromProto(p *platformv1.IAMPolicy) *Policy {
	if p == nil {
		return nil
	}
	pol := &Policy{
		Name:        p.Name,
		TenantID:    p.TenantId,
		Description: p.Description,
		Priority:    p.Priority,
		SpecYAML:    p.SpecYaml,
		Labels:      p.Labels,
		CreatedAt:   timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		pol.UpdatedAt = &t
	}
	return pol
}

// TenantFromProto converts a platformv1.IAMTenant to a domain Tenant.
func TenantFromProto(p *platformv1.IAMTenant) *Tenant {
	if p == nil {
		return nil
	}
	t := &Tenant{
		ID:        p.Id,
		Name:      p.Name,
		CreatedAt: timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		ts := p.UpdatedAt.AsTime()
		t.UpdatedAt = &ts
	}
	if p.Settings != nil {
		t.Settings = &TenantSettings{
			MaxUsers:    p.Settings.MaxUsers,
			MfaRequired: p.Settings.MfaRequired,
		}
	}
	return t
}

// TenantSettingsToProto converts domain TenantSettings to proto.
func TenantSettingsToProto(s *TenantSettings) *platformv1.IAMTenantSettings {
	if s == nil {
		return nil
	}
	return &platformv1.IAMTenantSettings{
		MaxUsers:    s.MaxUsers,
		MfaRequired: s.MfaRequired,
	}
}

// AppFromProto converts a platformv1.IAMApp to a domain App.
func AppFromProto(p *platformv1.IAMApp) *App {
	if p == nil {
		return nil
	}
	a := &App{
		ClientID:       p.ClientId,
		ClientSecret:   p.ClientSecret,
		Name:           p.Name,
		TenantID:       p.TenantId,
		RedirectURIs:   p.RedirectUris,
		GrantTypes:     p.GrantTypes,
		ResponseTypes:  p.ResponseTypes,
		ResourcePrefix: p.ResourcePrefix,
		CreatedAt:      timestampToTime(p.CreatedAt),
	}
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.AsTime()
		a.UpdatedAt = &t
	}
	return a
}

// StatusFromProto converts a platformv1.Status to a domain OperationStatus.
func StatusFromProto(p *platformv1.Status) *OperationStatus {
	if p == nil {
		return nil
	}
	return &OperationStatus{
		Success: p.Success,
		Message: p.Message,
	}
}

// timestampToTime converts a protobuf Timestamp to time.Time.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
