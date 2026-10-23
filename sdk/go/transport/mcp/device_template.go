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
	"encoding/json"
	"errors"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// Device template methods ride the device_template_{create,get,list,
// update,delete} and profile_create_from_template tools registered in
// pkg/api/mcp/device_template_tools.go. The tools take and return the
// domain JSON shapes, so both directions are translated here.
func init() {
	for method, tool := range map[string]string{
		platformv1.DeviceService_CreateTemplate_FullMethodName:            "device_template_create",
		platformv1.DeviceService_GetTemplate_FullMethodName:               "device_template_get",
		platformv1.DeviceService_ListTemplates_FullMethodName:             "device_template_list",
		platformv1.DeviceService_UpdateTemplate_FullMethodName:            "device_template_update",
		platformv1.DeviceService_DeleteTemplate_FullMethodName:            "device_template_delete",
		platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName: "profile_create_from_template",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}
	mcpArgBuilders[platformv1.DeviceService_CreateTemplate_FullMethodName] = buildDeviceTemplateCreateArgs
	mcpArgBuilders[platformv1.DeviceService_GetTemplate_FullMethodName] = buildDeviceTemplateGetArgs
	mcpArgBuilders[platformv1.DeviceService_ListTemplates_FullMethodName] = buildDeviceTemplateListArgs
	mcpArgBuilders[platformv1.DeviceService_UpdateTemplate_FullMethodName] = buildDeviceTemplateUpdateArgs
	mcpArgBuilders[platformv1.DeviceService_DeleteTemplate_FullMethodName] = buildDeviceTemplateDeleteArgs
	mcpArgBuilders[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName] = buildProfileFromTemplateArgs
	mcpReplyDecoders[platformv1.DeviceService_CreateTemplate_FullMethodName] = decodeDeviceTemplateCreateResult
	mcpReplyDecoders[platformv1.DeviceService_GetTemplate_FullMethodName] = decodeDeviceTemplateGetResult
	mcpReplyDecoders[platformv1.DeviceService_ListTemplates_FullMethodName] = decodeDeviceTemplateListResult
	mcpReplyDecoders[platformv1.DeviceService_UpdateTemplate_FullMethodName] = decodeDeviceTemplateUpdateResult
	mcpReplyDecoders[platformv1.DeviceService_DeleteTemplate_FullMethodName] = decodeDeviceTemplateDeleteResult
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
	return deviceTemplateToolArgs(method, req.GetTemplate())
}

// deviceTemplateToolArgs renders a template as the arguments the create and
// update tools take: the domain JSON shape with config as YAML text.
func deviceTemplateToolArgs(method string, template *platformv1.DeviceTemplate) (map[string]interface{}, error) {
	out, err := provision.EncodeTemplateJSON(template)
	if err != nil {
		return nil, fieldNotSupported(method, err)
	}
	if config := template.GetConfig(); len(config) > 0 {
		out["config"] = string(config)
	}
	return out, nil
}

// buildDeviceTemplateGetArgs names the template device_template_get reads.
// The id goes as a decimal string so a uint64 above 2^53 survives JSON.
func buildDeviceTemplateGetArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateGetRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_GetTemplate_FullMethodName}
	}
	return map[string]interface{}{"id": strconv.FormatUint(req.GetId(), 10)}, nil
}

// buildDeviceTemplateListArgs passes the page and page size; a zero one is
// left out so the tool's default applies.
func buildDeviceTemplateListArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateListRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_ListTemplates_FullMethodName}
	}
	out := map[string]interface{}{}
	if page := req.GetPagination().GetPage(); page > 0 {
		out["page"] = page
	}
	if size := req.GetPagination().GetPageSize(); size > 0 {
		out["page_size"] = size
	}
	return out, nil
}

// buildDeviceTemplateUpdateArgs renders the replacement template with the
// id that names the template to replace.
func buildDeviceTemplateUpdateArgs(args interface{}) (map[string]interface{}, error) {
	method := platformv1.DeviceService_UpdateTemplate_FullMethodName
	req, ok := args.(*platformv1.DeviceTemplateUpdateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	out, err := deviceTemplateToolArgs(method, req.GetTemplate())
	if err != nil {
		return nil, err
	}
	out["id"] = strconv.FormatUint(req.GetTemplate().GetId(), 10)
	return out, nil
}

// buildDeviceTemplateDeleteArgs names the template device_template_delete
// removes.
func buildDeviceTemplateDeleteArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateDeleteRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_DeleteTemplate_FullMethodName}
	}
	return map[string]interface{}{"id": strconv.FormatUint(req.GetId(), 10)}, nil
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
	template, err := decodeDeviceTemplateTool(result)
	if err != nil {
		return err
	}
	out.Template = template
	out.Status = &platformv1.Status{Success: true, Message: "device template created successfully"}
	return nil
}

// decodeDeviceTemplateTool decodes one template in the tools' result shape,
// config as YAML text.
func decodeDeviceTemplateTool(result interface{}) (*platformv1.DeviceTemplate, error) {
	data, err := resultJSON(result)
	if err != nil {
		return nil, err
	}
	template, err := provision.DecodeTemplateToolJSON(data)
	if err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return template, nil
}

// decodeDeviceTemplateGetResult maps device_template_get's template onto
// the GetTemplate reply.
func decodeDeviceTemplateGetResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateGetResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_GetTemplate_FullMethodName}
	}
	template, err := decodeDeviceTemplateTool(result)
	if err != nil {
		return err
	}
	out.Template = template
	return nil
}

// decodeDeviceTemplateUpdateResult maps device_template_update's stored
// template onto the UpdateTemplate reply.
func decodeDeviceTemplateUpdateResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateUpdateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_UpdateTemplate_FullMethodName}
	}
	template, err := decodeDeviceTemplateTool(result)
	if err != nil {
		return err
	}
	out.Template = template
	out.Status = &platformv1.Status{Success: true, Message: "device template updated successfully"}
	return nil
}

// decodeDeviceTemplateDeleteResult confirms the delete on the
// DeleteTemplate reply; the tool answers an error for a failed one.
func decodeDeviceTemplateDeleteResult(_ interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateDeleteResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_DeleteTemplate_FullMethodName}
	}
	out.Status = &platformv1.Status{Success: true, Message: "device template deleted successfully"}
	return nil
}

// deviceTemplateListResult is device_template_list's result: the page of
// templates and the total item count.
type deviceTemplateListResult struct {
	Templates []json.RawMessage `json:"templates"`
	Total     uint64            `json:"total"`
	Page      uint32            `json:"page"`
	PageSize  uint32            `json:"page_size"`
}

// decodeDeviceTemplateListResult maps device_template_list's page onto the
// ListTemplates reply. The tool reports no page count, so it is derived
// from the total and the page size.
func decodeDeviceTemplateListResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateListResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListTemplates_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	var list deviceTemplateListResult
	if err := json.Unmarshal(data, &list); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Templates = make([]*platformv1.DeviceTemplate, 0, len(list.Templates))
	for _, entry := range list.Templates {
		template, err := provision.DecodeTemplateToolJSON(entry)
		if err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
		out.Templates = append(out.Templates, template)
	}
	var totalPages uint32
	if list.PageSize > 0 {
		totalPages = uint32((list.Total + uint64(list.PageSize) - 1) / uint64(list.PageSize))
	}
	out.Pagination = &platformv1.PaginationResponse{
		Page:       list.Page,
		PageSize:   list.PageSize,
		TotalPages: totalPages,
		TotalItems: list.Total,
	}
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
