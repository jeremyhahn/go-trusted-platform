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
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// toolProfile is a profile as the MCP profile tools return it.
var toolProfile = map[string]interface{}{
	"id":          "9007199254740993",
	"name":        "rack-a",
	"model":       "R640",
	"role":        "server",
	"match_rules": map[string]interface{}{"serial_prefix": "SN100"},
}

func TestDeviceProfileMCP_GetProfile(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"profile_get_by_id": toolProfile}, &calls)

	resp := &platformv1.GetProfileResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_GetProfile_FullMethodName,
		&platformv1.GetProfileRequest{Id: 9007199254740993}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Name != "profile_get_by_id" || calls[0].Arguments["id"] != "9007199254740993" {
		t.Errorf("call = %+v, want profile_get_by_id with the decimal-string id", calls[0])
	}
	got := resp.GetProfile()
	if got.GetId() != 9007199254740993 || got.GetName() != "rack-a" {
		t.Errorf("profile = %v", got)
	}
	if got.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_SERVER {
		t.Errorf("role = %v, want the domain role decoded", got.GetRole())
	}
}

func TestDeviceProfileMCP_ListProfiles(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"profile_list_all": map[string]interface{}{
			"profiles":  []interface{}{toolProfile},
			"total":     21,
			"page":      2,
			"page_size": 10,
		},
	}, &calls)

	resp := &platformv1.ListProfilesResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_ListProfiles_FullMethodName,
		&platformv1.ListProfilesRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	args := calls[0].Arguments
	if args["page"] != float64(2) || args["page_size"] != float64(10) {
		t.Errorf("args = %v, want page 2 and page_size 10", args)
	}
	if len(resp.GetProfiles()) != 1 || resp.GetProfiles()[0].GetName() != "rack-a" {
		t.Errorf("profiles = %v", resp.GetProfiles())
	}
	pagination := resp.GetPagination()
	if pagination.GetTotalItems() != 21 || pagination.GetTotalPages() != 3 || pagination.GetPage() != 2 {
		t.Errorf("pagination = %v, want 21 items over 3 pages", pagination)
	}
}

func TestDeviceProfileMCP_DeleteProfile(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"profile_delete_by_id": map[string]interface{}{"success": true, "id": "42"},
	}, &calls)

	resp := &platformv1.DeleteProfileResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_DeleteProfile_FullMethodName,
		&platformv1.DeleteProfileRequest{Id: 42}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Name != "profile_delete_by_id" || calls[0].Arguments["id"] != "42" {
		t.Errorf("call = %+v", calls[0])
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("status must report success")
	}
}

func TestDeviceProfileMCP_FindMatchingProfile(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"profile_find_matching": toolProfile}, &calls)

	resp := &platformv1.FindMatchingProfileResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_FindMatchingProfile_FullMethodName,
		&platformv1.FindMatchingProfileRequest{Serial: "SN100-XYZ"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	args := calls[0].Arguments
	if calls[0].Name != "profile_find_matching" || args["serial"] != "SN100-XYZ" {
		t.Errorf("call = %+v", calls[0])
	}
	if _, sent := args["mac_address"]; sent {
		t.Error("an empty attribute must not be sent")
	}
	if resp.GetProfile().GetMatchRules().GetSerialPrefix() != "SN100" {
		t.Errorf("profile = %v", resp.GetProfile())
	}
}

func TestDeviceProfileMCP_FindConfigForDevice(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"profile_find_config": toolProfile}, &calls)

	resp := &platformv1.FindConfigForDeviceResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_FindConfigForDevice_FullMethodName,
		&platformv1.FindConfigForDeviceRequest{EkSerial: "EK-0042"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	args := calls[0].Arguments
	if calls[0].Name != "profile_find_config" || args["ek_serial"] != "EK-0042" {
		t.Errorf("call = %+v", calls[0])
	}
	if _, sent := args["mac_address"]; sent {
		t.Error("an empty identity field must not be sent")
	}
	if resp.GetProfile().GetMatchRules().GetSerialPrefix() != "SN100" {
		t.Errorf("profile = %v", resp.GetProfile())
	}
}

func TestDeviceProfileMCP_FindConfigForDeviceRejectsWrongMessageTypes(t *testing.T) {
	if _, err := buildProfileFindConfigArgs(&platformv1.FindMatchingProfileRequest{}); err == nil {
		t.Error("buildProfileFindConfigArgs accepted a FindMatchingProfileRequest")
	}
	if err := decodeProfileFindConfigResult(toolProfile, &platformv1.FindMatchingProfileResponse{}); err == nil {
		t.Error("decodeProfileFindConfigResult accepted a FindMatchingProfileResponse")
	}
}

func TestDeviceProfileMCP_FindProfileByMACAddress(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"profile_find_by_mac": toolProfile}, &calls)

	resp := &platformv1.FindProfileByMACAddressResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_FindProfileByMACAddress_FullMethodName,
		&platformv1.FindProfileByMACAddressRequest{MacAddress: "52:54:00:aa:bb:cc"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Name != "profile_find_by_mac" || calls[0].Arguments["mac_address"] != "52:54:00:aa:bb:cc" {
		t.Errorf("call = %+v", calls[0])
	}
	if resp.GetProfile().GetName() != "rack-a" {
		t.Errorf("profile = %v", resp.GetProfile())
	}
}

func TestDeviceProfileMCP_FindProfileBySerial(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"profile_find_by_serial": toolProfile}, &calls)

	resp := &platformv1.FindProfileBySerialResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_FindProfileBySerial_FullMethodName,
		&platformv1.FindProfileBySerialRequest{Serial: "SN100-XYZ"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Name != "profile_find_by_serial" || calls[0].Arguments["serial"] != "SN100-XYZ" {
		t.Errorf("call = %+v", calls[0])
	}
	if resp.GetProfile().GetMatchRules().GetSerialPrefix() != "SN100" {
		t.Errorf("profile = %v", resp.GetProfile())
	}
}

func TestDeviceProfileMCP_Errors(t *testing.T) {
	wrongArgs := map[string]func(interface{}) (map[string]interface{}, error){
		"Get":    buildProfileGetArgs,
		"List":   buildProfileListArgs,
		"Delete": buildProfileDeleteArgs,
		"Match":  buildProfileMatchArgs,
		"ByMAC":  buildProfileFindByMACArgs,
		"Serial": buildProfileFindBySerialArgs,
	}
	for name, build := range wrongArgs {
		t.Run("WrongArgsType/"+name, func(t *testing.T) {
			_, err := build(&platformv1.GetDeviceRequest{})
			if _, ok := err.(ErrUnexpectedArgsType); !ok {
				t.Fatalf("err = %v, want ErrUnexpectedArgsType", err)
			}
		})
	}

	wrongReply := map[string]func(interface{}, interface{}) error{
		"Get":    decodeProfileGetResult,
		"List":   decodeProfileListResult,
		"Delete": decodeProfileDeleteResult,
		"Match":  decodeProfileMatchResult,
		"ByMAC":  decodeProfileFindByMACResult,
		"Serial": decodeProfileFindBySerialResult,
	}
	for name, decode := range wrongReply {
		t.Run("WrongReplyType/"+name, func(t *testing.T) {
			err := decode(map[string]interface{}{}, &platformv1.CreateProfileResponse{})
			if _, ok := err.(ErrUnexpectedReplyType); !ok {
				t.Fatalf("err = %v, want ErrUnexpectedReplyType", err)
			}
		})
	}

	t.Run("ProfileNotAnObject", func(t *testing.T) {
		err := decodeProfileGetResult([]interface{}{"x"}, &platformv1.GetProfileResponse{})
		if _, ok := err.(ErrUnmarshalFailed); !ok {
			t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
		}
	})

	t.Run("ListEntryNotAnObject", func(t *testing.T) {
		err := decodeProfileListResult(map[string]interface{}{"profiles": []interface{}{"x"}},
			&platformv1.ListProfilesResponse{})
		if _, ok := err.(ErrUnmarshalFailed); !ok {
			t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
		}
	})

	t.Run("ListNotAnObject", func(t *testing.T) {
		err := decodeProfileListResult("x", &platformv1.ListProfilesResponse{})
		if _, ok := err.(ErrUnmarshalFailed); !ok {
			t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
		}
	})
}

func TestTotalPages(t *testing.T) {
	cases := []struct {
		total    uint64
		pageSize uint32
		want     uint32
	}{
		{0, 10, 0},
		{10, 10, 1},
		{21, 10, 3},
		{5, 0, 0},
	}
	for _, c := range cases {
		if got := totalPages(c.total, c.pageSize); got != c.want {
			t.Errorf("totalPages(%d, %d) = %d, want %d", c.total, c.pageSize, got, c.want)
		}
	}
}
