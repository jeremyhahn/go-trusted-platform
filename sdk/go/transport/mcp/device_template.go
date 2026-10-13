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

package mcp

import (
	"errors"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// Device template methods ride the device_template_create and
// profile_create_from_template tools registered in
// pkg/api/mcp/device_template_tools.go. The tools take and return the
// domain JSON shapes, so both directions are translated here.
func init() {
	for method, tool := range map[string]string{
		platformv1.DeviceService_CreateTemplate_FullMethodName:            "device_template_create",
		platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName: "profile_create_from_template",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}
	mcpArgBuilders[platformv1.DeviceService_CreateTemplate_FullMethodName] = buildDeviceTemplateCreateArgs
	mcpArgBuilders[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName] = buildProfileFromTemplateArgs
	mcpReplyDecoders[platformv1.DeviceService_CreateTemplate_FullMethodName] = decodeDeviceTemplateCreateResult
	mcpReplyDecoders[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName] = decodeProfileFromTemplateResult
}

// buildDeviceTemplateCreateArgs builds the device_template_create tool
// arguments. The tool takes the template config as YAML text.
func buildDeviceTemplateCreateArgs(args interface{}) (map[string]interface{}, error) {
	method := platformv1.DeviceService_CreateTemplate_FullMethodName
	req, ok := args.(*platformv1.DeviceTemplateCreateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	out, err := provision.EncodeTemplateJSON(req.GetTemplate())
	if err != nil {
		return nil, fieldNotSupported(method, err)
	}
	if config := req.GetTemplate().GetConfig(); len(config) > 0 {
		out["config"] = string(config)
	}
	return out, nil
}

// buildProfileFromTemplateArgs builds the profile_create_from_template
// tool arguments, sending template_id as a decimal string so a uint64 id
// survives JSON number precision limits. Override fields the tool cannot
// carry are refused rather than dropped.
func buildProfileFromTemplateArgs(args interface{}) (map[string]interface{}, error) {
	method := platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName
	req, ok := args.(*platformv1.CreateProfileFromTemplateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	overrides, err := provision.EncodeProfileOverridesJSON(req.GetOverrides())
	if err != nil {
		return nil, fieldNotSupported(method, err)
	}
	return map[string]interface{}{
		"template_id": strconv.FormatUint(req.GetTemplateId(), 10),
		"overrides":   overrides,
	}, nil
}

// fieldNotSupported names the method on a field the shared encoder
// refused.
func fieldNotSupported(method string, err error) error {
	var refused provision.ErrFieldNotSupported
	if errors.As(err, &refused) {
		return ErrFieldNotSupported{Method: method, Field: refused.Field}
	}
	return err
}

// decodeDeviceTemplateCreateResult maps the tool's template JSON onto the
// CreateTemplate reply.
func decodeDeviceTemplateCreateResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateCreateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_CreateTemplate_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	template, err := provision.DecodeTemplateToolJSON(data)
	if err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Template = template
	out.Status = &platformv1.Status{Success: true, Message: "device template created successfully"}
	return nil
}

// decodeProfileFromTemplateResult maps the tool's profile JSON onto the
// CreateProfileFromTemplate reply.
func decodeProfileFromTemplateResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateProfileResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	profile, err := provision.DecodeProfileJSON(data)
	if err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Profile = profile
	out.Status = &platformv1.Status{Success: true, Message: "profile created from template"}
	return nil
}
