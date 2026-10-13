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
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// Device template creation. The handler in pkg/webservice/v1/device takes
// and returns the domain JSON shape (role as a string, ids as strings), so
// both directions are translated here rather than sent as pb JSON.
// CreateProfileFromTemplate shares the profile codecs in device.go.
func init() {
	grpcMethodToRESTMap[platformv1.DeviceService_CreateTemplate_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/device/templates", http.MethodPost}
	restRequestEncoders[platformv1.DeviceService_CreateTemplate_FullMethodName] = encodeCreateTemplate
	restResponseDecoders[platformv1.DeviceService_CreateTemplate_FullMethodName] = decodeCreateTemplate
}

// encodeCreateTemplate renders the template as the handler's
// TemplateRequest. The config goes as bytes, which JSON carries as base64.
func encodeCreateTemplate(args interface{}) (interface{}, error) {
	req, ok := args.(*platformv1.DeviceTemplateCreateRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.DeviceService_CreateTemplate_FullMethodName}
	}
	body, err := provision.EncodeTemplateJSON(req.GetTemplate())
	if err != nil {
		return nil, err
	}
	if config := req.GetTemplate().GetConfig(); len(config) > 0 {
		body["config"] = config
	}
	return body, nil
}

// decodeCreateTemplate places the handler's bare TemplateResponse on the
// CreateTemplate reply.
func decodeCreateTemplate(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DeviceTemplateCreateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_CreateTemplate_FullMethodName}
	}
	template, err := provision.DecodeTemplateJSON(raw)
	if err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Template = template
	out.Status = &platformv1.Status{Success: true, Message: "device template created successfully"}
	return nil
}
