// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errTemplateServiceUnavailable answers a template RPC on a daemon that
// was started without a device template service.
var errTemplateServiceUnavailable = status.Error(codes.Unavailable, "device template service is not available")

// WithDeviceTemplateService supplies the device template service behind
// CreateTemplate and CreateProfileFromTemplate. It is the same
// device.DeviceTemplateService the REST template handlers use, so a
// template stored on one transport is the template every other transport
// reads. Without it both RPCs answer Unavailable.
func WithDeviceTemplateService(templateService device.DeviceTemplateService) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.templateService = templateService }
}

// CreateTemplate stores a device template. A zero id is assigned here,
// matching the REST handler; the template service rejects an unnamed
// template.
func (s *DeviceGRPCService) CreateTemplate(
	ctx context.Context,
	req *platformv1.DeviceTemplateCreateRequest,
) (*platformv1.DeviceTemplateCreateResponse, error) {
	if s.templateService == nil {
		return nil, errTemplateServiceUnavailable
	}
	if req.GetTemplate() == nil {
		return nil, status.Error(codes.InvalidArgument, "template is required")
	}

	template := s.pbToTemplate(req.GetTemplate())
	if template.ID == 0 {
		template.ID = device.NewID()
	}

	if err := s.templateService.Save(ctx, template); err != nil {
		s.logger.Error("failed to create device template", "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("device template created", "id", template.ID, "name", template.Name)

	return &platformv1.DeviceTemplateCreateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device template created successfully",
		},
		Template: s.templateToPb(template),
	}, nil
}

// CreateProfileFromTemplate creates and stores a profile copied from a
// template, with the request's overrides applied. It shares
// device.CreateProfileFromTemplate with the REST route, so a zero profile
// id is assigned there.
func (s *DeviceGRPCService) CreateProfileFromTemplate(
	ctx context.Context,
	req *platformv1.CreateProfileFromTemplateRequest,
) (*platformv1.CreateProfileResponse, error) {
	var overrides *entities.DeviceProfile
	if req.GetOverrides() != nil {
		converted, convErr := s.pbToProfile(req.GetOverrides())
		if convErr != nil {
			return nil, status.Error(codes.InvalidArgument, convErr.Error())
		}
		// proto3 cannot tell an unset role from DEVICE_ROLE_UNSPECIFIED, and
		// pbToProfile maps that to the "unknown" role. An unspecified role
		// is no override: the template's role stands.
		if req.GetOverrides().GetRole() == platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
			converted.Role = ""
		}
		overrides = converted
	}

	profile, err := device.CreateProfileFromTemplate(ctx, s.templateService, s.profileService, req.GetTemplateId(), overrides)
	if err != nil {
		s.logger.Error("failed to create profile from template", "template_id", req.GetTemplateId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile created from template", "template_id", req.GetTemplateId(), "id", profile.ID)

	return &platformv1.CreateProfileResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "profile created from template",
		},
		Profile: s.profileToPb(profile),
	}, nil
}

// pbToTemplate maps a protobuf DeviceTemplate onto the entity. The
// timestamps are owned by the template service and are not mapped in.
func (s *DeviceGRPCService) pbToTemplate(pb *platformv1.DeviceTemplate) *entities.DeviceTemplate {
	return &entities.DeviceTemplate{
		ID:          pb.GetId(),
		TenantID:    pb.GetTenantId(),
		Name:        pb.GetName(),
		Description: pb.GetDescription(),
		Role:        grpcapi.ProtoRoleToEntity(pb.GetRole()),
		Config:      pb.GetConfig(),
		MatchRules:  s.pbToProfileMatchRules(pb.GetMatchRules()),
		BMC:         s.pbToBMCConfig(pb.GetBmc()),
	}
}

// templateToPb maps an entity DeviceTemplate onto its protobuf form.
func (s *DeviceGRPCService) templateToPb(t *entities.DeviceTemplate) *platformv1.DeviceTemplate {
	if t == nil {
		return nil
	}
	pb := &platformv1.DeviceTemplate{
		Id:          t.ID,
		TenantId:    t.TenantID,
		Name:        t.Name,
		Description: t.Description,
		Role:        grpcapi.EntityRoleToProto(t.Role),
		Config:      t.Config,
		MatchRules:  s.profileMatchRulesToPb(t.MatchRules),
		Bmc:         s.bmcConfigToPb(t.BMC),
	}
	if !t.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	if !t.UpdatedAt.IsZero() {
		pb.UpdatedAt = timestamppb.New(t.UpdatedAt)
	}
	return pb
}
