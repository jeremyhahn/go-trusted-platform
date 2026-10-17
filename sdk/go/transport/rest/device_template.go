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

package rest

import (
	"encoding/json"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// Device templates. The handlers in pkg/webservice/v1/device take and
// return the domain JSON shape (role as a string, ids as strings), so both
// directions are translated here rather than sent as pb JSON.
// CreateProfileFromTemplate shares the profile codecs in device.go.
func init() {
	grpcMethodToRESTMap[platformv1.DeviceService_CreateTemplate_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/device/templates", http.MethodPost}
	restRequestEncoders[platformv1.DeviceService_CreateTemplate_FullMethodName] = encodeCreateTemplate
	restRequestEncoders[platformv1.DeviceService_UpdateTemplate_FullMethodName] = encodeUpdateTemplate

	for _, method := range []string{
		platformv1.DeviceService_CreateTemplate_FullMethodName,
		platformv1.DeviceService_GetTemplate_FullMethodName,
		platformv1.DeviceService_UpdateTemplate_FullMethodName,
	} {
		restResponseDecoders[method] = templateReplyDecoder(method)
	}
	restResponseDecoders[platformv1.DeviceService_ListTemplates_FullMethodName] = decodeTemplateList
}

// encodeCreateTemplate renders the template as the handler's
// TemplateRequest.
func encodeCreateTemplate(args interface{}) (interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateCreateRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.DeviceService_CreateTemplate_FullMethodName}
	}
	return templateRequestJSON(req.GetTemplate())
}

// encodeUpdateTemplate renders the replacement template as the handler's
// TemplateRequest. The id travels in the path, so the body leaves it out.
func encodeUpdateTemplate(args interface{}) (interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateUpdateRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.DeviceService_UpdateTemplate_FullMethodName}
	}
	return templateRequestJSON(req.GetTemplate())
}

// templateRequestJSON is the TemplateRequest body both write verbs send.
// The config goes as bytes, which JSON carries as base64.
func templateRequestJSON(template *platformv1.DeviceTemplate) (map[string]any, error) {
	body, err := provision.EncodeTemplateJSON(template)
	if err != nil {
		return nil, err
	}
	if config := template.GetConfig(); len(config) > 0 {
		body["config"] = config
	}
	return body, nil
}

// templateReplyDecoder places the handler's bare TemplateResponse on the
// reply of method: CreateTemplate, GetTemplate or UpdateTemplate.
func templateReplyDecoder(method string) func(raw []byte, reply interface{}) error {
	return func(raw []byte, reply interface{}) error {
		template, err := provision.DecodeTemplateJSON(raw)
		if err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
		switch out := reply.(type) {
		case *platformv1.DeviceTemplateCreateResponse:
			out.Template = template
			out.Status = &platformv1.Status{Success: true, Message: "device template created successfully"}
		case *platformv1.DeviceTemplateGetResponse:
			out.Template = template
		case *platformv1.DeviceTemplateUpdateResponse:
			out.Template = template
			out.Status = &platformv1.Status{Success: true, Message: "device template updated successfully"}
		default:
			return ErrUnexpectedReplyType{Method: method}
		}
		return nil
	}
}

// templateListJSON is the handler's TemplateListResponse: each template in
// the domain shape and a pagination block that names its item count
// "total".
type templateListJSON struct {
	Templates  []json.RawMessage `json:"templates"`
	Pagination struct {
		Page       uint32 `json:"page"`
		PageSize   uint32 `json:"page_size"`
		Total      uint64 `json:"total"`
		TotalPages uint32 `json:"total_pages"`
	} `json:"pagination"`
}

// decodeTemplateList decodes the handler's TemplateListResponse onto the
// ListTemplates reply.
func decodeTemplateList(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateListResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListTemplates_FullMethodName}
	}
	var list templateListJSON
	if err := json.Unmarshal(raw, &list); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Templates = make([]*platformv1.DeviceTemplate, 0, len(list.Templates))
	for _, entry := range list.Templates {
		template, err := provision.DecodeTemplateJSON(entry)
		if err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
		out.Templates = append(out.Templates, template)
	}
	out.Pagination = &platformv1.PaginationResponse{
		Page:       list.Pagination.Page,
		PageSize:   list.Pagination.PageSize,
		TotalPages: list.Pagination.TotalPages,
		TotalItems: list.Pagination.Total,
	}
	return nil
}
