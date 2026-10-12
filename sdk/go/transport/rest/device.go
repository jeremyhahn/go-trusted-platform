// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// DeviceService wire translation (#321, #859). The device webservice
// (pkg/webservice/v1/device) speaks its own JSON, not the pb messages:
//
//   - profile writes decode a flat ProfileRequest, not {"profile": {...}};
//     role and auth_method are domain strings and config is a JSON value;
//   - every single-resource read or write answers the bare resource, not
//     the pb reply that nests it under "device" or "profile";
//   - profile ids are strings, PCR baseline digests are hex, and the list
//     pagination names its item count "total";
//   - activation answers its state as a string under "status".
//
// The encoders and decoders below are the one translation between the two,
// so a REST call returns exactly what the same gRPC call returns.
func init() {
	restRequestEncoders[platformv1.DeviceService_CreateProfile_FullMethodName] =
		profileBodyEncoder(platformv1.DeviceService_CreateProfile_FullMethodName)
	restRequestEncoders[platformv1.DeviceService_UpdateProfile_FullMethodName] =
		profileBodyEncoder(platformv1.DeviceService_UpdateProfile_FullMethodName)
	restRequestEncoders[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName] = encodeTemplateOverrides

	for _, method := range []string{
		platformv1.DeviceService_CreateDevice_FullMethodName,
		platformv1.DeviceService_GetDevice_FullMethodName,
		platformv1.DeviceService_UpdateDevice_FullMethodName,
		platformv1.DeviceService_FindDeviceBySerial_FullMethodName,
	} {
		restResponseDecoders[method] = resourceReplyDecoder(method, "device", decodeDevice)
	}

	for _, method := range []string{
		platformv1.DeviceService_CreateProfile_FullMethodName,
		platformv1.DeviceService_GetProfile_FullMethodName,
		platformv1.DeviceService_UpdateProfile_FullMethodName,
		platformv1.DeviceService_FindProfileByMACAddress_FullMethodName,
		platformv1.DeviceService_FindProfileBySerial_FullMethodName,
		platformv1.DeviceService_FindMatchingProfile_FullMethodName,
		platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
		platformv1.DeviceService_FindConfigForDevice_FullMethodName,
		platformv1.DeviceService_AssignProfileToDevice_FullMethodName,
		platformv1.DeviceService_UnassignProfileFromDevice_FullMethodName,
	} {
		restResponseDecoders[method] = resourceReplyDecoder(method, "profile", decodeProfile)
	}

	restResponseDecoders[platformv1.DeviceService_ListDevices_FullMethodName] = decodeDeviceList
	restResponseDecoders[platformv1.DeviceService_ListProfiles_FullMethodName] = decodeProfileList
	restResponseDecoders[platformv1.DeviceService_ActivateDevice_FullMethodName] = decodeActivation
}

// profileRequestOptions encodes a DeviceProfile under its proto field
// names, which are the ProfileRequest JSON names.
var profileRequestOptions = protojson.MarshalOptions{UseProtoNames: true}

// statusName is the full name of the pb Status message replies carry.
var statusName = (&platformv1.Status{}).ProtoReflect().Descriptor().FullName()

// profileCarrier is a request that carries one DeviceProfile, as
// CreateProfileRequest and UpdateProfileRequest do.
type profileCarrier interface {
	GetProfile() *platformv1.DeviceProfile
}

// profileBodyEncoder sends a create or update request's profile as the flat
// ProfileRequest body the handler decodes.
func profileBodyEncoder(method string) restRequestEncoder {
	return func(body interface{}) (interface{}, error) {
		req, ok := body.(profileCarrier)
		if !ok {
			return nil, ErrUnexpectedRequestType{Method: method}
		}
		return profileRequestJSON(req.GetProfile())
	}
}

// encodeTemplateOverrides sends CreateProfileFromTemplate's overrides as the
// ProfileRequest the template handler decodes under "overrides". The template
// id travels in the path.
func encodeTemplateOverrides(body interface{}) (interface{}, error) {
	req, ok := body.(*platformv1.CreateProfileFromTemplateRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName}
	}
	if req.GetOverrides() == nil {
		return map[string]any{}, nil
	}
	overrides, err := profileRequestJSON(req.GetOverrides())
	if err != nil {
		return nil, err
	}
	return map[string]any{"overrides": overrides}, nil
}

// profileRequestJSON renders a DeviceProfile as a ProfileRequest object. The
// proto field names already match; role, every network's auth_method and
// config are rewritten into their domain form. An unspecified enum is
// omitted so the server applies its default. Fields ProfileRequest has no
// counterpart for (tenant_id, bmc, the read-only pcr_baseline, timestamps,
// an inline platformd config) are ignored by the handler.
func profileRequestJSON(profile *platformv1.DeviceProfile) (map[string]any, error) {
	body := map[string]any{}
	if profile == nil {
		return body, nil
	}
	encoded, err := profileRequestOptions.Marshal(profile)
	if err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}
	if err := decodeObject(encoded, &body); err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}

	delete(body, "role")
	if role, ok := restwire.DeviceRoleToJSON(profile.GetRole()); ok {
		body["role"] = role
	}

	delete(body, "config")
	if config := profile.GetConfig(); len(config) > 0 {
		if !json.Valid(config) {
			return nil, ErrProfileConfigNotJSON{}
		}
		body["config"] = json.RawMessage(config)
	}

	networks, _ := body["networks"].(map[string]any)
	for name, network := range profile.GetNetworks() {
		phase, ok := networks[name].(map[string]any)
		if !ok {
			continue
		}
		delete(phase, "auth_method")
		if method, ok := restwire.AuthMethodToJSON(network.GetAuthMethod()); ok {
			phase["auth_method"] = method
		}
	}
	return body, nil
}

// resourceDecoder decodes one bare resource object from a REST payload.
type resourceDecoder func(raw []byte) (proto.Message, error)

// resourceReplyDecoder places a bare resource on the reply's field (device
// or profile) and marks the reply's status successful when it has one.
func resourceReplyDecoder(method string, field protoreflect.Name, decode resourceDecoder) restResponseDecoder {
	return func(raw []byte, reply interface{}) error {
		resource, err := decode(raw)
		if err != nil {
			return err
		}
		return setReplyResource(reply, method, field, resource)
	}
}

// setReplyResource sets reply.<field> to resource. The field must be a
// singular message field of the resource's type; anything else is a routing
// defect reported as ErrUnexpectedReplyType.
func setReplyResource(reply interface{}, method string, field protoreflect.Name, resource proto.Message) error {
	msg, ok := reply.(proto.Message)
	if !ok {
		return ErrUnexpectedReplyType{Method: method}
	}
	rm := msg.ProtoReflect()
	fields := rm.Descriptor().Fields()

	fd := fields.ByName(field)
	if fd == nil || fd.IsList() || fd.IsMap() || fd.Message() == nil ||
		fd.Message().FullName() != resource.ProtoReflect().Descriptor().FullName() {
		return ErrUnexpectedReplyType{Method: method}
	}
	rm.Set(fd, protoreflect.ValueOfMessage(resource.ProtoReflect()))

	if sd := fields.ByName("status"); sd != nil && sd.Message() != nil && sd.Message().FullName() == statusName {
		rm.Set(sd, protoreflect.ValueOfMessage((&platformv1.Status{Success: true}).ProtoReflect()))
	}
	return nil
}

// decodeDevice decodes a bare DeviceResponse. Its field names, string id and
// RFC 3339 timestamps are all protojson-compatible; the liveness fields the
// pb Device does not carry are discarded.
func decodeDevice(raw []byte) (proto.Message, error) {
	device := &platformv1.Device{}
	if err := reportJSON.Unmarshal(raw, device); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return device, nil
}

// decodeProfile decodes a bare ProfileFullResponse.
func decodeProfile(raw []byte) (proto.Message, error) {
	profile := &platformv1.DeviceProfile{}
	if err := decodeRewritten(raw, rewriteProfile, profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// rewriteProfile turns a ProfileFullResponse object into the protojson shape
// of DeviceProfile.
func rewriteProfile(profile map[string]any) error {
	if err := pcrDigestsHexToBytes(profile); err != nil {
		return err
	}
	restwire.NormalizeProfileJSON(profile)
	return nil
}

// pcrDigestsHexToBytes re-encodes the PCR baseline digests, which the
// webservice writes as hex, as the base64 protojson reads into bytes.
func pcrDigestsHexToBytes(profile map[string]any) error {
	baseline, _ := profile["pcr_baseline"].(map[string]any)
	values, _ := baseline["values"].(map[string]any)
	for index, value := range values {
		digest, ok := value.(string)
		if !ok {
			// Left as is, protojson reports the malformed value.
			continue
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil {
			return ErrPCRDigestNotHex{Index: index, Err: err}
		}
		values[index] = base64.StdEncoding.EncodeToString(decoded)
	}
	return nil
}

// decodeDeviceList decodes the {"devices": [...], "pagination": {...}} list.
func decodeDeviceList(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListDevicesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListDevices_FullMethodName}
	}
	return decodeRewritten(raw, renamePaginationTotal, out)
}

// decodeProfileList decodes the {"profiles": [...], "pagination": {...}}
// list, translating each profile as decodeProfile does.
func decodeProfileList(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListProfilesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListProfiles_FullMethodName}
	}
	return decodeRewritten(raw, func(list map[string]any) error {
		profiles, _ := list["profiles"].([]any)
		for _, entry := range profiles {
			if profile, ok := entry.(map[string]any); ok {
				if err := rewriteProfile(profile); err != nil {
					return err
				}
			}
		}
		return renamePaginationTotal(list)
	}, out)
}

// renamePaginationTotal maps the webservice's pagination "total" onto the pb
// PaginationResponse total_items. has_more has no pb field and is discarded.
func renamePaginationTotal(list map[string]any) error {
	pagination, ok := list["pagination"].(map[string]any)
	if !ok {
		return nil
	}
	if total, present := pagination["total"]; present {
		pagination["total_items"] = total
		delete(pagination, "total")
	}
	return nil
}

// decodeActivation decodes ActivationResponse, whose "status" is the
// device's new state: the pb reply carries that as activation_status and
// keeps status for the call outcome.
func decodeActivation(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ActivateDeviceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ActivateDevice_FullMethodName}
	}
	err := decodeRewritten(raw, func(activation map[string]any) error {
		if state, present := activation["status"]; present {
			activation["activation_status"] = state
			delete(activation, "status")
		}
		return nil
	}, out)
	if err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeRewritten decodes a JSON object, applies rewrite to it and decodes
// the result into msg with protojson.
func decodeRewritten(raw []byte, rewrite func(map[string]any) error, msg proto.Message) error {
	obj := map[string]any{}
	if err := decodeObject(raw, &obj); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	if err := rewrite(obj); err != nil {
		return err
	}
	normalized, err := json.Marshal(obj)
	if err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	if err := reportJSON.Unmarshal(normalized, msg); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

// decodeObject decodes a JSON object keeping numbers as json.Number, so a
// uint64 id survives the round trip. A JSON null leaves obj empty.
func decodeObject(raw []byte, obj *map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(obj); err != nil {
		return err
	}
	if *obj == nil {
		*obj = map[string]any{}
	}
	return nil
}
