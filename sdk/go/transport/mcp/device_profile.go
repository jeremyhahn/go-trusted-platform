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
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// The profile read, delete, match and find-config tools (pkg/api/mcp/device_profile_tools.go)
// take decimal-string ids and answer with the profile in its domain JSON
// shape, so each method carries its own argument builder and reply decoder.
func init() {
	for method, tool := range map[string]string{
		platformv1.DeviceService_GetProfile_FullMethodName:              "profile_get_by_id",
		platformv1.DeviceService_ListProfiles_FullMethodName:            "profile_list_all",
		platformv1.DeviceService_DeleteProfile_FullMethodName:           "profile_delete_by_id",
		platformv1.DeviceService_FindMatchingProfile_FullMethodName:     "profile_find_matching",
		platformv1.DeviceService_FindProfileByMACAddress_FullMethodName: "profile_find_by_mac",
		platformv1.DeviceService_FindProfileBySerial_FullMethodName:     "profile_find_by_serial",
		platformv1.DeviceService_FindConfigForDevice_FullMethodName:     "profile_find_config",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}
	mcpArgBuilders[platformv1.DeviceService_GetProfile_FullMethodName] = buildProfileGetArgs
	mcpArgBuilders[platformv1.DeviceService_ListProfiles_FullMethodName] = buildProfileListArgs
	mcpArgBuilders[platformv1.DeviceService_DeleteProfile_FullMethodName] = buildProfileDeleteArgs
	mcpArgBuilders[platformv1.DeviceService_FindMatchingProfile_FullMethodName] = buildProfileMatchArgs
	mcpReplyDecoders[platformv1.DeviceService_GetProfile_FullMethodName] = decodeProfileGetResult
	mcpReplyDecoders[platformv1.DeviceService_ListProfiles_FullMethodName] = decodeProfileListResult
	mcpReplyDecoders[platformv1.DeviceService_DeleteProfile_FullMethodName] = decodeProfileDeleteResult
	mcpReplyDecoders[platformv1.DeviceService_FindMatchingProfile_FullMethodName] = decodeProfileMatchResult
	mcpArgBuilders[platformv1.DeviceService_FindProfileByMACAddress_FullMethodName] = buildProfileFindByMACArgs
	mcpArgBuilders[platformv1.DeviceService_FindProfileBySerial_FullMethodName] = buildProfileFindBySerialArgs
	mcpReplyDecoders[platformv1.DeviceService_FindProfileByMACAddress_FullMethodName] = decodeProfileFindByMACResult
	mcpReplyDecoders[platformv1.DeviceService_FindProfileBySerial_FullMethodName] = decodeProfileFindBySerialResult
	mcpArgBuilders[platformv1.DeviceService_FindConfigForDevice_FullMethodName] = buildProfileFindConfigArgs
	mcpReplyDecoders[platformv1.DeviceService_FindConfigForDevice_FullMethodName] = decodeProfileFindConfigResult
}

// buildProfileGetArgs sends the profile id as a decimal string, so a uint64
// above 2^53 survives the JSON number round-trip.
func buildProfileGetArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetProfileRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_GetProfile_FullMethodName}
	}
	return profileIDArgs(req.GetId()), nil
}

// buildProfileDeleteArgs sends the profile id as a decimal string.
func buildProfileDeleteArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeleteProfileRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_DeleteProfile_FullMethodName}
	}
	return profileIDArgs(req.GetId()), nil
}

// buildProfileListArgs sends the requested page. An unset page or page size
// is left out so the tool applies its defaults. The label selector is not
// sent: gRPC ignores it for profiles too.
func buildProfileListArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.ListProfilesRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_ListProfiles_FullMethodName}
	}
	out := map[string]interface{}{}
	if page := req.GetPagination().GetPage(); page > 0 {
		out["page"] = page
	}
	if pageSize := req.GetPagination().GetPageSize(); pageSize > 0 {
		out["page_size"] = pageSize
	}
	return out, nil
}

// buildProfileMatchArgs sends the device attributes to match on; empty ones
// are left out.
func buildProfileMatchArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.FindMatchingProfileRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_FindMatchingProfile_FullMethodName}
	}
	out := map[string]interface{}{}
	for key, value := range map[string]string{
		"mac_address": req.GetMacAddress(),
		"serial":      req.GetSerial(),
		"model":       req.GetModel(),
	} {
		if value != "" {
			out[key] = value
		}
	}
	return out, nil
}

// buildProfileFindByMACArgs sends the device MAC address to look up.
func buildProfileFindByMACArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.FindProfileByMACAddressRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_FindProfileByMACAddress_FullMethodName}
	}
	return map[string]interface{}{"mac_address": req.GetMacAddress()}, nil
}

// buildProfileFindBySerialArgs sends the device serial number to look up.
func buildProfileFindBySerialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.FindProfileBySerialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_FindProfileBySerial_FullMethodName}
	}
	return map[string]interface{}{"serial": req.GetSerial()}, nil
}

// buildProfileFindConfigArgs sends the device identity the daemon resolves a
// configuration profile for; an empty field is left out.
func buildProfileFindConfigArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.FindConfigForDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_FindConfigForDevice_FullMethodName}
	}
	out := map[string]interface{}{}
	for key, value := range map[string]string{"ek_serial": req.GetEkSerial(), "mac_address": req.GetMacAddress()} {
		if value != "" {
			out[key] = value
		}
	}
	return out, nil
}

// profileIDArgs is the argument map of the single-profile tools.
func profileIDArgs(id uint64) map[string]interface{} {
	return map[string]interface{}{"id": strconv.FormatUint(id, 10)}
}

// decodeProfileGetResult decodes the profile_get_by_id result.
func decodeProfileGetResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetProfileResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_GetProfile_FullMethodName}
	}
	profile, err := decodeProfileResult(result)
	if err != nil {
		return err
	}
	out.Profile = profile
	return nil
}

// decodeProfileMatchResult decodes the profile_find_matching result.
func decodeProfileMatchResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.FindMatchingProfileResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_FindMatchingProfile_FullMethodName}
	}
	profile, err := decodeProfileResult(result)
	if err != nil {
		return err
	}
	out.Profile = profile
	return nil
}

// decodeProfileFindByMACResult decodes the profile_find_by_mac result.
func decodeProfileFindByMACResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.FindProfileByMACAddressResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_FindProfileByMACAddress_FullMethodName}
	}
	profile, err := decodeProfileResult(result)
	if err != nil {
		return err
	}
	out.Profile = profile
	return nil
}

// decodeProfileFindBySerialResult decodes the profile_find_by_serial result.
func decodeProfileFindBySerialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.FindProfileBySerialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_FindProfileBySerial_FullMethodName}
	}
	profile, err := decodeProfileResult(result)
	if err != nil {
		return err
	}
	out.Profile = profile
	return nil
}

func decodeProfileFindConfigResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.FindConfigForDeviceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_FindConfigForDevice_FullMethodName}
	}
	profile, err := decodeProfileResult(result)
	if err != nil {
		return err
	}
	out.Profile = profile
	return nil
}

// decodeProfileDeleteResult reports success: the tool answers an error for
// a profile it could not delete, so any result means the profile is gone.
func decodeProfileDeleteResult(_ interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteProfileResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_DeleteProfile_FullMethodName}
	}
	out.Status = &platformv1.Status{Success: true, Message: "profile deleted"}
	return nil
}

// profileListToolResult is the profile_list_all result shape.
type profileListToolResult struct {
	Profiles []json.RawMessage `json:"profiles"`
	Total    uint64            `json:"total"`
	Page     uint32            `json:"page"`
	PageSize uint32            `json:"page_size"`
}

// decodeProfileListResult decodes the profile_list_all result into the pb
// reply, deriving the page count the tool does not report.
func decodeProfileListResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListProfilesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListProfiles_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	var list profileListToolResult
	if err := json.Unmarshal(data, &list); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	profiles := make([]*platformv1.DeviceProfile, 0, len(list.Profiles))
	for _, raw := range list.Profiles {
		profile, err := provision.DecodeProfileJSON(raw)
		if err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
		profiles = append(profiles, profile)
	}
	out.Profiles = profiles
	out.Pagination = &platformv1.PaginationResponse{
		Page:       list.Page,
		PageSize:   list.PageSize,
		TotalPages: totalPages(list.Total, list.PageSize),
		TotalItems: list.Total,
	}
	return nil
}

// totalPages is the number of pages of pageSize needed to hold total items.
func totalPages(total uint64, pageSize uint32) uint32 {
	if pageSize == 0 {
		return 0
	}
	return uint32((total + uint64(pageSize) - 1) / uint64(pageSize))
}

// decodeProfileResult decodes one profile in its domain JSON shape.
func decodeProfileResult(result interface{}) (*platformv1.DeviceProfile, error) {
	data, err := resultJSON(result)
	if err != nil {
		return nil, err
	}
	profile, err := provision.DecodeProfileJSON(data)
	if err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return profile, nil
}
