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

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The converters below map QuicBaaS SDK IAM entities onto the platform proto
// messages. The gRPC IAM service and the REST list handlers share them, so a
// list reply carries the same items on every transport (#445).

// UserToProto converts a QuicBaaS SDK user to a platform user.
//
// Returns nil if the input is nil, enabling safe chaining.
func UserToProto(u *iamsdk.User) *platformv1.IAMUser {
	if u == nil {
		return nil
	}

	// Convert Metadata (map[string]string) to Attributes for platform compatibility
	result := &platformv1.IAMUser{
		Id:          u.ID,
		TenantId:    u.TenantID,
		Email:       u.Email,
		Name:        u.DisplayName,
		Roles:       u.Roles,
		Groups:      u.Groups,
		Attributes:  u.Metadata,
		MfaVerified: len(u.AuthMethods) > 0,
		CreatedAt:   timestamppb.New(u.CreatedAt),
		UpdatedAt:   timestamppb.New(u.UpdatedAt),
	}
	if u.LastLoginAt != nil {
		result.LastAuth = timestamppb.New(*u.LastLoginAt)
	}
	return result
}

// RoleToProto converts a QuicBaaS SDK role to a platform role.
//
// Returns nil if the input is nil, enabling safe chaining.
func RoleToProto(r *iamsdk.Role) *platformv1.IAMRole {
	if r == nil {
		return nil
	}
	return &platformv1.IAMRole{
		Id:          r.ID,
		TenantId:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
		CreatedAt:   timestamppb.New(r.CreatedAt),
		UpdatedAt:   timestamppb.New(r.UpdatedAt),
	}
}

// GroupToProto converts a QuicBaaS SDK group to a platform group.
//
// Returns nil if the input is nil, enabling safe chaining.
func GroupToProto(g *iamsdk.Group) *platformv1.IAMGroup {
	if g == nil {
		return nil
	}
	return &platformv1.IAMGroup{
		Id:          g.ID,
		TenantId:    g.TenantID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   timestamppb.New(g.CreatedAt),
		UpdatedAt:   timestamppb.New(g.UpdatedAt),
	}
}

// TenantToProto converts a QuicBaaS SDK tenant to a platform tenant.
//
// Returns nil if the input is nil, enabling safe chaining.
func TenantToProto(t *iamsdk.Tenant) *platformv1.IAMTenant {
	if t == nil {
		return nil
	}
	tenant := &platformv1.IAMTenant{
		Id:        t.ID,
		Name:      t.Name,
		CreatedAt: timestamppb.New(t.CreatedAt),
		UpdatedAt: timestamppb.New(t.UpdatedAt),
	}
	if t.Settings != nil {
		tenant.Settings = &platformv1.IAMTenantSettings{
			MfaRequired: t.Settings["mfa_required"] == "true",
		}
	}
	return tenant
}

// PolicyToProto converts a QuicBaaS SDK policy to a platform policy.
//
// Returns nil if the input is nil, enabling safe chaining.
func PolicyToProto(p *iamsdk.Policy) *platformv1.IAMPolicy {
	if p == nil {
		return nil
	}
	return &platformv1.IAMPolicy{
		Name:        p.Name,
		TenantId:    p.TenantID,
		Description: p.Description,
		Priority:    int32(p.Priority),
		SpecYaml:    p.SpecYAML,
		Labels:      p.Labels,
		CreatedAt:   timestamppb.New(p.CreatedAt),
		UpdatedAt:   timestamppb.New(p.UpdatedAt),
	}
}

// AppToProto converts a QuicBaaS SDK application to a platform application.
//
// Returns nil if the input is nil, enabling safe chaining.
func AppToProto(a *iamsdk.Application) *platformv1.IAMApp {
	if a == nil {
		return nil
	}
	return &platformv1.IAMApp{
		ClientId:      a.ClientID,
		ClientSecret:  a.ClientSecret,
		TenantId:      a.TenantID,
		Name:          a.Name,
		RedirectUris:  a.RedirectURIs,
		GrantTypes:    grantTypesToStrings(a.GrantTypes),
		ResponseTypes: a.ResponseTypes,
		CreatedAt:     timestamppb.New(a.CreatedAt),
		UpdatedAt:     timestamppb.New(a.UpdatedAt),
	}
}

// ListPagination is the page a list reply reports: the page the offset falls
// on, the page size, and the page and item totals. A page size of zero or
// less reports page 1 of no pages rather than dividing by zero.
func ListPagination(limit, offset int32, total int64) *platformv1.PaginationResponse {
	pagination := &platformv1.PaginationResponse{
		Page:       1,
		TotalItems: uint64(total),
	}
	if limit <= 0 {
		return pagination
	}
	pagination.PageSize = uint32(limit)
	if offset > 0 {
		pagination.Page = uint32(offset/limit) + 1
	}
	if total > 0 {
		pagination.TotalPages = uint32((total + int64(limit) - 1) / int64(limit))
	}
	return pagination
}

// The REST IAM client answers tenants, policies and apps as REST types; the
// converters below map those onto the same proto messages.

// tenantResponseToProto converts a REST tenant to a platform tenant.
func tenantResponseToProto(t *TenantResponse) *platformv1.IAMTenant {
	tenant := &platformv1.IAMTenant{
		Id:        t.ID,
		Name:      t.Name,
		CreatedAt: timestampOrNil(t.CreatedAt),
		UpdatedAt: timestampOrNil(t.UpdatedAt),
	}
	if t.Settings != nil {
		tenant.Settings = &platformv1.IAMTenantSettings{
			MaxUsers:    t.Settings.MaxUsers,
			MfaRequired: t.Settings.MFARequired,
		}
	}
	return tenant
}

// policyResponseToProto converts a REST policy to a platform policy.
func policyResponseToProto(p *PolicyResponse) *platformv1.IAMPolicy {
	return &platformv1.IAMPolicy{
		Name:        p.Name,
		TenantId:    p.TenantID,
		Description: p.Description,
		Priority:    p.Priority,
		SpecYaml:    []byte(p.SpecYAML),
		Labels:      p.Labels,
		CreatedAt:   timestampOrNil(p.CreatedAt),
		UpdatedAt:   timestampOrNil(p.UpdatedAt),
	}
}

// appResponseToProto converts a REST application to a platform application.
func appResponseToProto(a *AppResponse) *platformv1.IAMApp {
	return &platformv1.IAMApp{
		ClientId:       a.ClientID,
		ClientSecret:   a.ClientSecret,
		TenantId:       a.TenantID,
		Name:           a.Name,
		RedirectUris:   a.RedirectURIs,
		GrantTypes:     a.GrantTypes,
		ResponseTypes:  a.ResponseTypes,
		ResourcePrefix: a.ResourcePrefix,
		CreatedAt:      timestampOrNil(a.CreatedAt),
		UpdatedAt:      timestampOrNil(a.UpdatedAt),
	}
}

// timestampOrNil converts an optional time; an absent time stays absent.
func timestampOrNil(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}
